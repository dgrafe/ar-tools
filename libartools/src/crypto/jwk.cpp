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

#include <cstdio>
#include <fstream>
#include <memory>
#include <string>

// O_* constants and mode bits for creating the key file with 0600.
#include <fcntl.h>
#include <sys/stat.h>

#include "rapidjson/document.h"
#include "rapidjson/filewritestream.h"
#include "rapidjson/writer.h"

#include "crypto/base64url.h"
#include "crypto/jwk.h"

namespace artools {
namespace crypto {

/**
 * @brief Constructs a JWK by parsing a JSON Web Key file.
 *
 * Reads the file into a string and parses it with rapidjson. The eight RSA
 * components (e, n, d, p, q, dp, dq, qi) are extracted as base64url strings
 * and stored verbatim. The document is validated before field access: it
 * must be a JSON object, its "kty" must be "RSA" and all eight components
 * must be present as strings. Unvalidated subscript access (doc["e"]) would
 * otherwise trip a rapidjson assertion on malformed input.
 *
 * @param pathToJWK filesystem path of the JWK JSON file
 * @throws std::runtime_error if the file cannot be opened, the JSON is
 *                             malformed or a required field is missing or of
 *                             the wrong type
 */
JWK::JWK(const std::string &pathToJWK) {

  std::ifstream file(pathToJWK);
  if (!file.is_open())
    throw std::runtime_error("JWK: cannot open file '" + pathToJWK + "'");

  std::string json((std::istreambuf_iterator<char>(file)),
                   std::istreambuf_iterator<char>());

  rapidjson::Document doc;
  doc.Parse(json.c_str());
  if (doc.HasParseError())
    // GetParseError() returns a ParseErrorCode enum, not a string: it must
    // be converted explicitly (appending it to a string literal would be
    // pointer arithmetic, i.e. undefined behaviour).
    throw std::runtime_error("JWK: JSON parse error in '" + pathToJWK +
                             "' (code " +
                             std::to_string(doc.GetParseError()) +
                             ", offset " +
                             std::to_string(doc.GetErrorOffset()) + ")");

  if (!doc.IsObject())
    throw std::runtime_error("JWK: root element is not a JSON object");

  // The JWK must describe an RSA key; anything else cannot seed the RSA
  // components this class stores.
  if (!doc.HasMember("kty") || !doc["kty"].IsString() ||
      std::string(doc["kty"].GetString()) != "RSA")
    throw std::runtime_error("JWK: missing or non-RSA 'kty' field");

  // Every component must be present as a string before it is read.
  static const char *kRequiredFields[] = {"e",  "n",  "d",  "p",
                                          "q",  "dp", "dq", "qi"};
  for (const char *field : kRequiredFields) {
    if (!doc.HasMember(field) || !doc[field].IsString())
      throw std::runtime_error(std::string("JWK: missing or non-string '") +
                               field + "' field");
  }

  _e = doc["e"].GetString();
  _n = doc["n"].GetString();
  _d = doc["d"].GetString();
  _p = doc["p"].GetString();
  _q = doc["q"].GetString();
  _dp = doc["dp"].GetString();
  _dq = doc["dq"].GetString();
  _qi = doc["qi"].GetString();
}

/**
 * @brief Constructs a JWK from the components of a PEM key.
 *
 * Reads each RSA component from the PEM instance as a big-endian byte
 * container and base64url-encodes it into the corresponding JWK field. This
 * is the inverse of PEM::PEM(const JWK&).
 *
 * @param pemInstance the PEM whose components seed the JWK
 */
JWK::JWK(const PEM &pemInstance) {

  JWK::set_e(pemInstance.get_e());
  JWK::set_n(pemInstance.get_n());
  JWK::set_d(pemInstance.get_d());
  JWK::set_p(pemInstance.get_p());
  JWK::set_q(pemInstance.get_q());
  JWK::set_dp(pemInstance.get_dp());
  JWK::set_dq(pemInstance.get_dq());
  JWK::set_qi(pemInstance.get_qi());
}

/**
 * @brief Constructs a JWK whose key is deterministically derived from a
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
 */
JWK::JWK(const BIP39 &bip39) {

  // Deterministically derive the RSA key material from the BIP-39 instance,
  // bit-compatible with js-human-crypto-keys (see BIP39::getDeterministicRSAKey).
  const auto rsaKey = bip39.getDeterministicRSAKey();

  JWK::set_e(rsaKey.e);
  JWK::set_n(rsaKey.n);
  JWK::set_d(rsaKey.d);
  JWK::set_p(rsaKey.p);
  JWK::set_q(rsaKey.q);
  JWK::set_dp(rsaKey.dP);
  JWK::set_dq(rsaKey.dQ);
  JWK::set_qi(rsaKey.qInv);
}

/**
 * @brief Serialises the JWK to a JSON file.
 *
 * Builds a rapidjson document with the "kty" field set to "RSA" and the eight
 * RSA components as base64url strings, then writes it to the given path. The
 * field names follow the Arweave JWKInterface convention (dp, dq, qi rather
 * than dP, dQ, qInv).
 *
 * The file holds the private key: it is created atomically with owner-only
 * permissions (0600) via open() + fdopen(). An ofstream would create it with
 * 0666 & ~umask (typically 0644) first, leaving a world-readable window until
 * a follow-up chmod.
 *
 * @param pathToJWP filesystem path of the output JWK JSON file
 * @return          true on success, false if the file cannot be opened
 */
bool JWK::exportToFile(const std::string &pathToJWP) {

  rapidjson::Document document;

  document.SetObject();
  rapidjson::Document::AllocatorType &allocator = document.GetAllocator();

  rapidjson::Value stringBuf;
  document.AddMember("kty", "RSA", allocator);

  stringBuf.SetString(_e.c_str(), allocator);
  document.AddMember("e", stringBuf, allocator);

  stringBuf.SetString(_n.c_str(), allocator);
  document.AddMember("n", stringBuf, allocator);

  stringBuf.SetString(_d.c_str(), allocator);
  document.AddMember("d", stringBuf, allocator);

  stringBuf.SetString(_p.c_str(), allocator);
  document.AddMember("p", stringBuf, allocator);

  stringBuf.SetString(_q.c_str(), allocator);
  document.AddMember("q", stringBuf, allocator);

  stringBuf.SetString(_dp.c_str(), allocator);
  document.AddMember("dp", stringBuf, allocator);

  stringBuf.SetString(_dq.c_str(), allocator);
  document.AddMember("dq", stringBuf, allocator);

  stringBuf.SetString(_qi.c_str(), allocator);
  document.AddMember("qi", stringBuf, allocator);

  // Create the file with owner-only permissions (0600) atomically; see the
  // function header for why ofstream must not be used here.
  const int fd =
      ::open(pathToJWP.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    return false;
  std::shared_ptr<FILE> fptr(fdopen(fd, "w"), fclose);
  if (nullptr == fptr)
    return false;

  char writeBuffer[65536];
  rapidjson::FileWriteStream fws(fptr.get(), writeBuffer, sizeof(writeBuffer));
  rapidjson::Writer<rapidjson::FileWriteStream> writer(fws);
  document.Accept(writer);

  return true;
}

/**
 * @brief Sets the public exponent e from a big-endian byte container.
 * @param e the minimal big-endian magnitude of e
 */
void JWK::set_e(const JWK::BinaryContainer_t &e) { BASE64url::encode(e, _e); }
/**
 * @brief Sets the modulus n from a big-endian byte container.
 * @param n the minimal big-endian magnitude of n
 */
void JWK::set_n(const JWK::BinaryContainer_t &n) { BASE64url::encode(n, _n); }
/**
 * @brief Sets the private exponent d from a big-endian byte container.
 * @param d the minimal big-endian magnitude of d
 */
void JWK::set_d(const JWK::BinaryContainer_t &d) { BASE64url::encode(d, _d); }
/**
 * @brief Sets the first prime factor p from a big-endian byte container.
 * @param p the minimal big-endian magnitude of p
 */
void JWK::set_p(const JWK::BinaryContainer_t &p) { BASE64url::encode(p, _p); }
/**
 * @brief Sets the second prime factor q from a big-endian byte container.
 * @param q the minimal big-endian magnitude of q
 */
void JWK::set_q(const JWK::BinaryContainer_t &q) { BASE64url::encode(q, _q); }
/**
 * @brief Sets the CRT exponent dp from a big-endian byte container.
 * @param dp the minimal big-endian magnitude of dp
 */
void JWK::set_dp(const JWK::BinaryContainer_t &dp) {
  BASE64url::encode(dp, _dp);
}
/**
 * @brief Sets the CRT exponent dq from a big-endian byte container.
 * @param dq the minimal big-endian magnitude of dq
 */
void JWK::set_dq(const JWK::BinaryContainer_t &dq) {
  BASE64url::encode(dq, _dq);
}
/**
 * @brief Sets the CRT coefficient qi from a big-endian byte container.
 * @param qi the minimal big-endian magnitude of qi
 */
void JWK::set_qi(const JWK::BinaryContainer_t &qi) {
  BASE64url::encode(qi, _qi);
}

/**
 * @brief Returns the public exponent e as a big-endian byte container.
 * @return the decoded minimal big-endian magnitude of e
 */
JWK::BinaryContainer_t JWK::get_e() const {
  JWK::BinaryContainer_t buf;
  BASE64url::decode(_e, buf);
  return buf;
}
/**
 * @brief Returns the modulus n as a big-endian byte container.
 * @return the decoded minimal big-endian magnitude of n
 */
JWK::BinaryContainer_t JWK::get_n() const {
  JWK::BinaryContainer_t buf;
  BASE64url::decode(_n, buf);
  return buf;
}
/**
 * @brief Returns the private exponent d as a big-endian byte container.
 * @return the decoded minimal big-endian magnitude of d
 */
JWK::BinaryContainer_t JWK::get_d() const {
  JWK::BinaryContainer_t buf;
  BASE64url::decode(_d, buf);
  return buf;
}
/**
 * @brief Returns the first prime factor p as a big-endian byte container.
 * @return the decoded minimal big-endian magnitude of p
 */
JWK::BinaryContainer_t JWK::get_p() const {
  JWK::BinaryContainer_t buf;
  BASE64url::decode(_p, buf);
  return buf;
}
/**
 * @brief Returns the second prime factor q as a big-endian byte container.
 * @return the decoded minimal big-endian magnitude of q
 */
JWK::BinaryContainer_t JWK::get_q() const {
  JWK::BinaryContainer_t buf;
  BASE64url::decode(_q, buf);
  return buf;
}
/**
 * @brief Returns the CRT exponent dp as a big-endian byte container.
 * @return the decoded minimal big-endian magnitude of dp
 */
JWK::BinaryContainer_t JWK::get_dp() const {
  JWK::BinaryContainer_t buf;
  BASE64url::decode(_dp, buf);
  return buf;
}
/**
 * @brief Returns the CRT exponent dq as a big-endian byte container.
 * @return the decoded minimal big-endian magnitude of dq
 */
JWK::BinaryContainer_t JWK::get_dq() const {
  JWK::BinaryContainer_t buf;
  BASE64url::decode(_dq, buf);
  return buf;
}
/**
 * @brief Returns the CRT coefficient qi as a big-endian byte container.
 * @return the decoded minimal big-endian magnitude of qi
 */
JWK::BinaryContainer_t JWK::get_qi() const {
  JWK::BinaryContainer_t buf;
  BASE64url::decode(_qi, buf);
  return buf;
}

} // end of namespace crypto
} // end of namespace artools