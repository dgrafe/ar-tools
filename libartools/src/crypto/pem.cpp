// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2026 Daniel Grafe <dgrafe@dgrafe.de>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <algorithm>
#include <cstdio>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "crypto/base64url.h"
#include "crypto/pem.h"
#include "crypto/sha256.h"

namespace artools {
namespace crypto {

/**
 * @brief Renders a single RSA key component as a lowercase hexadecimal string.
 *
 * Retrieves the named BIGNUM parameter from the EVP_PKEY via the OpenSSL 3.0
 * provider API (EVP_PKEY_get_bn_param), serialises it with BN_bn2hex() and
 * normalises the result to lowercase. BN_bn2hex() emits uppercase hex of the
 * minimal big-endian magnitude; the lowercase transform yields the canonical
 * textual form used for logging and interoperability.
 *
 * @param pKey      the EVP_PKEY whose component is read
 * @param paramName the OSSL_PKEY_PARAM_RSA_* name of the component
 * @return          the lowercase hex string of the component
 */
static std::string getKeyComponentAsHex(const PEM::PrivateKey_t &pKey,
                                        std::string paramName) {

  BIGNUM *bn_n = nullptr;
  EVP_PKEY_get_bn_param(pKey.get(), paramName.c_str(), &bn_n);
  char *pubKeyHex = BN_bn2hex(bn_n);
  std::string ret = pubKeyHex;

  OPENSSL_free(pubKeyHex);
  BN_free(bn_n);

  std::transform(ret.begin(), ret.end(), ret.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return ret;
}

/**
 * @brief Converts a big-endian byte container into a BIGNUM.
 *
 * Wraps BN_bin2bn() in a shared_ptr with a BN_free() deleter so the caller
 * never has to manage the BIGNUM lifetime manually. The input is the minimal
 * big-endian magnitude representation (as produced by BN_bn2bin()), which is
 * exactly the byte layout used by the Arweave JWK "Base64urlUInt" encoding.
 *
 * @param cont the big-endian byte sequence
 * @return     a shared_ptr owning the freshly allocated BIGNUM
 */
static std::shared_ptr<BIGNUM>
getBigNumFromBinary(PEM::BinaryContainer_t cont) {

  BIGNUM *bn = BN_bin2bn(cont.data(), cont.size(), nullptr);
  return std::shared_ptr<BIGNUM>(bn, BN_free);
}

/**
 * @brief Reads a named RSA component from an EVP_PKEY into a byte container.
 *
 * Retrieves the BIGNUM parameter, sizes the output container to the exact
 * byte length of the value and copies the minimal big-endian magnitude into
 * it. The container is resized to BN_num_bytes() so the result has no leading
 * zero padding, matching the JWK Base64urlUInt convention.
 *
 * @param pKey      the EVP_PKEY whose component is read
 * @param paramName the OSSL_PKEY_PARAM_RSA_* name of the component
 * @param cont      output container, resized and filled on return
 */
static void getKeyComponentAsUInt8(const PEM::PrivateKey_t &pKey,
                                   std::string paramName,
                                   PEM::BinaryContainer_t &cont) {

  BIGNUM *bn_n = nullptr;
  EVP_PKEY_get_bn_param(pKey.get(), paramName.c_str(), &bn_n);
  cont.resize(BN_num_bytes(bn_n));
  BN_bn2bin(bn_n, cont.data());
  BN_free(bn_n);
}

/**
 * @brief Writes a byte container into a named RSA component of an EVP_PKEY.
 *
 * Converts the big-endian byte sequence into a BIGNUM and installs it on the
 * key via EVP_PKEY_set_bn_param. Used when reconstructing a key from external
 * components (e.g. a JWK or a deterministic RSAKey).
 *
 * @param pKey      the EVP_PKEY whose component is written
 * @param paramName the OSSL_PKEY_PARAM_RSA_* name of the component
 * @param cont      the big-endian byte sequence to install
 */
static void setKeyComponentAsUInt8(const PEM::PrivateKey_t &pKey,
                                   std::string paramName,
                                   const PEM::BinaryContainer_t &cont) {

  BIGNUM *bn_n = BN_bin2bn(cont.data(), cont.size(), nullptr);
  EVP_PKEY_set_bn_param(pKey.get(), paramName.c_str(), bn_n);
  BN_free(bn_n);
}

/**
 * @brief Constructs a PEM with a freshly generated RSA-PSS key pair.
 *
 * Delegates to generateKeyPair(), which draws a new 4096-bit RSA-PSS key from
 * the operating-system CSPRNG. The result is non-deterministic: every call
 * produces a distinct key.
 */
PEM::PEM() { PEM::generateKeyPair(); }

/**
 * @brief Constructs a PEM whose key is deterministically derived from a
 *        BIP-39 instance.
 *
 * Recovers the wallet key from the BIP-39 root seed via
 * BIP39::getDeterministicRSAKey(), which replays the js-human-crypto-keys
 * key-generation state machine (HMAC-DRBG seeded from the seed plus forge's
 * PRIMEINC prime sweep). The same mnemonic therefore always reproduces the
 * same key, which is the property that makes wallet recovery from a BIP-39
 * phrase possible.
 *
 * @param bip39 the BIP-39 instance whose root seed seeds the derivation
 * @throws std::runtime_error if the deterministic derivation yields an
 *         incomplete key (missing n, e or d)
 */
PEM::PEM(const BIP39 &bip39) {

  // Deterministically derive the RSA key material from the BIP-39 instance,
  // bit-compatible with js-human-crypto-keys (see BIP39::getDeterministicRSAKey).
  const auto rsaKey = bip39.getDeterministicRSAKey();
  if (rsaKey.n.empty() || rsaKey.e.empty() || rsaKey.d.empty())
    throw std::runtime_error("Deterministic RSA key derivation failed");
  buildKeyFromRSAKey(rsaKey);
}

/**
 * @brief Assembles an EVP_PKEY from the components of a deterministic RSAKey.
 *
 * Uses the OpenSSL 3.0 provider API (EVP_PKEY_fromdata with an OSSL_PARAM_BLD)
 * to reconstruct a full RSA key pair from its CRT components. Each component
 * is converted from its big-endian byte representation into a BIGNUM and
 * pushed onto the parameter builder under the corresponding
 * OSSL_PKEY_PARAM_RSA_* name. The resulting EVP_PKEY is stored in _pkey.
 *
 * @param rsaKey the deterministic RSA key components (n, e, d, p, q, dP, dQ,
 *               qInv)
 * @throws std::runtime_error if EVP_PKEY_fromdata fails
 */
void PEM::buildKeyFromRSAKey(const RSAKey_t &rsaKey) {

  PrivateKeyContext_t ctx = PrivateKeyContext_t(
      EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
  EVP_PKEY_fromdata_init(ctx.get());

  auto param_bld = std::shared_ptr<OSSL_PARAM_BLD>(OSSL_PARAM_BLD_new(),
                                                   OSSL_PARAM_BLD_free);

  auto bn_e = getBigNumFromBinary(rsaKey.e);
  auto bn_n = getBigNumFromBinary(rsaKey.n);
  auto bn_d = getBigNumFromBinary(rsaKey.d);
  auto bn_p = getBigNumFromBinary(rsaKey.p);
  auto bn_q = getBigNumFromBinary(rsaKey.q);
  auto bn_dp = getBigNumFromBinary(rsaKey.dP);
  auto bn_dq = getBigNumFromBinary(rsaKey.dQ);
  auto bn_qi = getBigNumFromBinary(rsaKey.qInv);

  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_E, bn_e.get());
  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_N, bn_n.get());
  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_D, bn_d.get());
  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_FACTOR1,
                         bn_p.get());
  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_FACTOR2,
                         bn_q.get());
  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_EXPONENT1,
                         bn_dp.get());
  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_EXPONENT2,
                         bn_dq.get());
  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                         bn_qi.get());

  EVP_PKEY *key = nullptr;
  auto params = std::shared_ptr<OSSL_PARAM>(
      OSSL_PARAM_BLD_to_param(param_bld.get()), OSSL_PARAM_free);
  if (EVP_PKEY_fromdata(ctx.get(), &key, EVP_PKEY_KEYPAIR, params.get()) != 1)
    throw std::runtime_error(std::string("EVP_PKEY_fromdata failed: ") +
                             ERR_error_string(ERR_get_error(), nullptr));
  _pkey = PrivateKey_t(key, EVP_PKEY_free);
}

/**
 * @brief Constructs a PEM by reading a private key from a PEM file.
 *
 * Opens the file in binary mode and deserialises the PKCS#8/PKCS#1 private key
 * with PEM_read_PrivateKey(). The key is wrapped in a shared_ptr with an
 * EVP_PKEY_free() deleter.
 *
 * @param pathToPEM filesystem path of the PEM file
 * @throws std::runtime_error if the file cannot be opened or contains no
 *         readable private key
 */
PEM::PEM(const std::string &pathToPEM) {

  FILE *file = fopen(pathToPEM.c_str(), "r");
  if (nullptr == file)
    throw std::runtime_error("Could not open pem file");

  std::shared_ptr<FILE> fptr(file, fclose);

  _pkey =
      PrivateKey_t(PEM_read_PrivateKey(fptr.get(), nullptr, nullptr, nullptr),
                   EVP_PKEY_free);
  if (_pkey == nullptr)
    throw std::runtime_error("Could not read pem file");
}

/**
 * @brief Generates a fresh RSA-PSS key pair via the OpenSSL provider API.
 *
 * Configures an EVP_PKEY_CTX for RSA-PSS key generation with the public
 * exponent from PEM::PUB_EXP (0x010001 = 65537), a modulus size of
 * PEM::MODULUS_BITS (4096) and SHA-256 as the PSS digest, then runs
 * EVP_PKEY_keygen(). The key is drawn from the operating-system CSPRNG and is
 * therefore non-deterministic.
 *
 * @throws std::runtime_error on any OpenSSL failure during context setup or
 *         key generation
 */
void PEM::generateKeyPair() {

  PrivateKeyContext_t ctx = PrivateKeyContext_t(
      EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, nullptr), EVP_PKEY_CTX_free);
  if (ctx == nullptr)
    throw std::runtime_error(
        std::string("Setting up the RSA_PSS context failed: ") +
        ERR_error_string(ERR_get_error(), nullptr));

  if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
    throw std::runtime_error(std::string("EVP_PKEY_keygen_init failed: ") +
                             ERR_error_string(ERR_get_error(), nullptr));

  BIGNUM *bn = nullptr;
  if (BN_hex2bn(&bn, PEM::PUB_EXP) <= 0)
    throw std::runtime_error(
        std::string("Converting public exponent failed: ") +
        ERR_error_string(ERR_get_error(), nullptr));
  if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx.get(), bn) <= 0)
    throw std::runtime_error(
        std::string("EVP_PKEY_CTX_set1_rsa_keygen_pubexp failed: ") +
        ERR_error_string(ERR_get_error(), nullptr));

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), PEM::MODULUS_BITS) <= 0)
    throw std::runtime_error(
        std::string("EVP_PKEY_CTX_set_rsa_keygen_bits failed: ") +
        ERR_error_string(ERR_get_error(), nullptr));
  if (EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx.get(), "sha256", nullptr) <=
      0)
    throw std::runtime_error(
        std::string("EVP_PKEY_CTX_set_rsa_pss_keygen_md failed: ") +
        ERR_error_string(ERR_get_error(), nullptr));

  PrivateKey_t::element_type *p = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &p) != 1)
    throw std::runtime_error(std::string("EVP_PKEY_keygenfailed: ") +
                             ERR_error_string(ERR_get_error(), nullptr));
  _pkey = PrivateKey_t(p, EVP_PKEY_free);

  BN_free(bn);
}

/**
 * @brief Constructs a PEM by reconstructing the key from a JWK.
 *
 * Reads the eight RSA components (n, e, d, p, q, dp, dq, qi) from the JWK as
 * big-endian byte containers, converts each to a BIGNUM and assembles a full
 * key pair via the OpenSSL 3.0 provider API (EVP_PKEY_fromdata with an
 * OSSL_PARAM_BLD). This is the inverse of exporting a PEM to a JWK.
 *
 * @param jwkInstance the JWK whose components seed the key
 */
PEM::PEM(const JWK &jwkInstance) {

  PrivateKeyContext_t ctx = PrivateKeyContext_t(
      EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
  EVP_PKEY_fromdata_init(ctx.get());

  auto param_bld = std::shared_ptr<OSSL_PARAM_BLD>(OSSL_PARAM_BLD_new(),
                                                   OSSL_PARAM_BLD_free);

  auto bn_e = getBigNumFromBinary(jwkInstance.get_e());
  auto bn_n = getBigNumFromBinary(jwkInstance.get_n());
  auto bn_d = getBigNumFromBinary(jwkInstance.get_d());
  auto bn_p = getBigNumFromBinary(jwkInstance.get_p());
  auto bn_q = getBigNumFromBinary(jwkInstance.get_q());
  auto bn_dp = getBigNumFromBinary(jwkInstance.get_dp());
  auto bn_dq = getBigNumFromBinary(jwkInstance.get_dq());
  auto bn_qi = getBigNumFromBinary(jwkInstance.get_qi());

  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_E, bn_e.get());
  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_N, bn_n.get());
  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_D, bn_d.get());
  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_FACTOR1,
                         bn_p.get());
  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_FACTOR2,
                         bn_q.get());
  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_EXPONENT1,
                         bn_dp.get());
  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_EXPONENT2,
                         bn_dq.get());
  OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                         bn_qi.get());

  EVP_PKEY *key = nullptr;
  auto params = std::shared_ptr<OSSL_PARAM>(
      OSSL_PARAM_BLD_to_param(param_bld.get()), OSSL_PARAM_free);
  EVP_PKEY_fromdata(ctx.get(), &key, EVP_PKEY_KEYPAIR, params.get());
  _pkey = PrivateKey_t(key, EVP_PKEY_free);
}

/**
 * @brief Returns the public exponent e as a big-endian byte container.
 * @return the minimal big-endian magnitude of e
 */
PEM::BinaryContainer_t PEM::get_e() const {
  JWK::BinaryContainer_t buf;
  getKeyComponentAsUInt8(_pkey, OSSL_PKEY_PARAM_RSA_E, buf);
  return buf;
}
/**
 * @brief Returns the modulus n as a big-endian byte container.
 * @return the minimal big-endian magnitude of n
 */
PEM::BinaryContainer_t PEM::get_n() const {
  JWK::BinaryContainer_t buf;
  getKeyComponentAsUInt8(_pkey, OSSL_PKEY_PARAM_RSA_N, buf);
  return buf;
}
/**
 * @brief Returns the private exponent d as a big-endian byte container.
 * @return the minimal big-endian magnitude of d
 */
PEM::BinaryContainer_t PEM::get_d() const {
  JWK::BinaryContainer_t buf;
  getKeyComponentAsUInt8(_pkey, OSSL_PKEY_PARAM_RSA_D, buf);
  return buf;
}
/**
 * @brief Returns the first prime factor p as a big-endian byte container.
 * @return the minimal big-endian magnitude of p
 */
PEM::BinaryContainer_t PEM::get_p() const {
  JWK::BinaryContainer_t buf;
  getKeyComponentAsUInt8(_pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, buf);
  return buf;
}
/**
 * @brief Returns the second prime factor q as a big-endian byte container.
 * @return the minimal big-endian magnitude of q
 */
PEM::BinaryContainer_t PEM::get_q() const {
  JWK::BinaryContainer_t buf;
  getKeyComponentAsUInt8(_pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, buf);
  return buf;
}
/**
 * @brief Returns the CRT exponent dP (= d mod (p-1)) as a byte container.
 * @return the minimal big-endian magnitude of dP
 */
PEM::BinaryContainer_t PEM::get_dp() const {
  JWK::BinaryContainer_t buf;
  getKeyComponentAsUInt8(_pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, buf);
  return buf;
}
/**
 * @brief Returns the CRT exponent dQ (= d mod (q-1)) as a byte container.
 * @return the minimal big-endian magnitude of dQ
 */
PEM::BinaryContainer_t PEM::get_dq() const {
  JWK::BinaryContainer_t buf;
  getKeyComponentAsUInt8(_pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, buf);
  return buf;
}
/**
 * @brief Returns the CRT coefficient qInv (= q^-1 mod p) as a byte container.
 * @return the minimal big-endian magnitude of qInv
 */
PEM::BinaryContainer_t PEM::get_qi() const {
  JWK::BinaryContainer_t buf;
  getKeyComponentAsUInt8(_pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, buf);
  return buf;
}

/**
 * @brief Returns the public modulus n as a lowercase hexadecimal string.
 * @return the hex-encoded modulus (the Arweave transaction `owner` field)
 */
std::string PEM::getPublicKeyAsHex() {

  return getKeyComponentAsHex(_pkey, OSSL_PKEY_PARAM_RSA_N);
}

/**
 * @brief Returns the private exponent d as a lowercase hexadecimal string.
 * @return the hex-encoded private exponent
 */
std::string PEM::getPrivateKeyAsHex() {

  return getKeyComponentAsHex(_pkey, OSSL_PKEY_PARAM_RSA_D);
}

/**
 * @brief Serialises the private key to a PEM file.
 *
 * Writes the key in PKCS#8/PKCS#1 PEM format via PEM_write_PrivateKey() with
 * no encryption (NULL cipher). The file is opened in binary write mode.
 *
 * @param pathToPEM filesystem path of the output PEM file
 * @return          true on success, false if the file cannot be opened or the
 *                  serialisation fails
 */
bool PEM::exportAsFile(const std::string &pathToPEM) {

  std::shared_ptr<FILE> fptr(fopen(pathToPEM.c_str(), "w"), fclose);
  if (nullptr == fptr || !PEM_write_PrivateKey(fptr.get(), _pkey.get(), nullptr,
                                               nullptr, 0, 0, nullptr))
    return false;

  return true;
}

/**
 * @brief Signs a message with RSA-PSS and SHA-256.
 *
 * Hashes the message with SHA-256, then signs the digest using the private
 * key with RSA-PKCS1-PSS padding and SHA-256 as the signature digest. The
 * signature is returned base64url-encoded (unpadded, RFC 7515 alphabet).
 *
 * @param msg the message bytes to sign
 * @param sig output parameter receiving the base64url-encoded signature
 * @return    true on success
 * @throws std::runtime_error on any OpenSSL signing failure
 */
bool PEM::sign(const BinaryContainer_t &msg, std::string &sig) const {

  auto md = artools::crypto::SHA256(msg.data(), msg.size()).getHash();

  auto ctx = PrivateKeyContext_t(EVP_PKEY_CTX_new(_pkey.get(), nullptr),
                                 EVP_PKEY_CTX_free);
  if (EVP_PKEY_sign_init(ctx.get()) <= 0)
    throw std::runtime_error(std::string("EVP_PKEY_sign_init: ") +
                             ERR_error_string(ERR_get_error(), nullptr));
  if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PSS_PADDING) <= 0)
    throw std::runtime_error(std::string("EVP_PKEY_CTX_set_rsa_padding: ") +
                             ERR_error_string(ERR_get_error(), nullptr));
  if (EVP_PKEY_CTX_set_signature_md(ctx.get(), EVP_sha256()) <= 0)
    throw std::runtime_error(
        std::string("EVP_PKEVP_PKEY_CTX_set_signature_mdEY_sign_init: ") +
        ERR_error_string(ERR_get_error(), nullptr));

  size_t outlen = 0;
  if (EVP_PKEY_sign(ctx.get(), nullptr, &outlen, md.data(), md.size()) <= 0)
    throw std::runtime_error(std::string("EVP_PKEY_sign: ") +
                             ERR_error_string(ERR_get_error(), nullptr));

  BinaryContainer_t _sig;
  _sig.resize(outlen);

  if (EVP_PKEY_sign(ctx.get(), _sig.data(), &outlen, md.data(), md.size()) <= 0)
    throw std::runtime_error(std::string("EVP_PKEY_sign: ") +
                             ERR_error_string(ERR_get_error(), nullptr));

  BASE64url::encode(BASE64url::CodingDataType(_sig.begin(), _sig.end()), sig);

  return true;
}

/**
 * @brief Verifies an RSA-PSS signature over a message.
 *
 * Hashes the message with SHA-256 and verifies the supplied base64url-encoded
 * signature against the public key using RSA-PKCS1-PSS padding and SHA-256 as
 * the signature digest.
 *
 * @param msg the message bytes that were signed
 * @param sig the base64url-encoded signature to verify
 * @return    true if the signature is valid, false if it is invalid
 * @throws std::runtime_error on an OpenSSL verification error (ret < 0)
 */
bool PEM::verify(const BinaryContainer_t &msg, const std::string &sig) const {

  auto md = artools::crypto::SHA256(msg.data(), msg.size()).getHash();
  BinaryContainer_t _sig;
  BASE64url::decode(sig, _sig);

  auto ctx = PrivateKeyContext_t(EVP_PKEY_CTX_new(_pkey.get(), nullptr),
                                 EVP_PKEY_CTX_free);
  if (EVP_PKEY_verify_init(ctx.get()) <= 0)
    throw std::runtime_error(std::string("EVP_PKEY_verify_init :") +
                             ERR_error_string(ERR_get_error(), nullptr));
  if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PSS_PADDING) <= 0)
    throw std::runtime_error(std::string("EVP_PKEY_CTX_set_rsa_padding: ") +
                             ERR_error_string(ERR_get_error(), nullptr));
  if (EVP_PKEY_CTX_set_signature_md(ctx.get(), EVP_sha256()) <= 0)
    throw std::runtime_error(
        std::string(
            "EVP_PKEY_CTXEVP_PKEY_CTX_set_signature_md_set_rsa_padding: ") +
        ERR_error_string(ERR_get_error(), nullptr));

  auto ret = EVP_PKEY_verify(ctx.get(), _sig.data(), _sig.size(), md.data(),
                             md.size());
  if (ret == 0)
    return false; // verification failed
  else if (ret < 0)
    throw std::runtime_error(std::string("EVP_PKEY_verify: ") +
                             ERR_error_string(ERR_get_error(), nullptr));

  return true;
}

} // end of namespace crypto
} // end of namespace artools