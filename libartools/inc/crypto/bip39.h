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

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <openssl/bn.h>

#include "types.h"

namespace artools {
namespace crypto {

class BIP39 {
public:
  static const auto NumberOfWords = 12;
  static const auto BitsPerWord = 11;
  static const uint16_t UNKNOWN_WORD = 0xFFFF;
  static const auto DigestLength = 64;
  using MnemonicSeedType = std::array<std::uint16_t, BIP39::NumberOfWords>;
  using RootSeedType = std::array<std::uint8_t, DigestLength>;
  using BinaryContainer_t = artools::types::BinaryContainer_t;

  /**
   * @brief Deterministic RSA private key material, bit-compatible with
   *        ipfs-shipyard/js-human-crypto-keys.
   *
   * Every component is stored as the minimal big-endian magnitude (the exact
   * byte sequence produced by OpenSSL's BN_bn2bin()), which is precisely the
   * representation required by the Arweave JWK "Base64urlUInt" encoding and
   * by the transaction `owner` field. A zero value therefore serialises to an
   * empty container, mirroring arweave-js.
   */
  struct RSAKey {
    BinaryContainer_t n;    ///< modulus, p * q
    BinaryContainer_t e;    ///< public exponent (65537)
    BinaryContainer_t d;    ///< private exponent, e^-1 mod phi
    BinaryContainer_t p;    ///< first prime factor (p > q)
    BinaryContainer_t q;    ///< second prime factor
    BinaryContainer_t dP;   ///< CRT exponent, d mod (p - 1)
    BinaryContainer_t dQ;   ///< CRT exponent, d mod (q - 1)
    BinaryContainer_t qInv; ///< CRT coefficient, q^-1 mod p
  };

  BIP39();

  bool initFromMnemonicString(const std::string &mnemonicString,
                              const std::string &password = "");
  std::string getMnemonicString() { return _mnemonicString; }
  MnemonicSeedType getMnemonicSeed() { return _mnemonicSeed; }
  RootSeedType getRootSeed() { return _rootSeed; }
  std::string getRootSeedAsHex();

  /**
   * @brief Derives the deterministic RSA key from the current root seed.
   *
   * Replays the js-human-crypto-keys key-generation state machine (HMAC-DRBG
   * seeded from the BIP-39 root seed plus forge's PRIMEINC prime sweep) so
   * that the same mnemonic always yields the same key. See the implementation
   * for the full compatibility contract.
   *
   * @return the RSA key components, or an empty RSAKey on failure.
   */
  RSAKey getDeterministicRSAKey() const;
  RSAKey getDeterministicRSAKey(const RootSeedType &seed) const;

private:
  void createMnemonicSeed();
  RootSeedType createRootSeed(const std::string &_mnemonicString,
                              const std::string password);
  std::uint16_t indexFromWord(const std::string &word);

  // --- Deterministic RSA key generation (js-human-crypto-keys replay) ---
  struct DrbgState {
    std::array<std::uint8_t, 32> K;
    std::array<std::uint8_t, 32> V;
  };
  void drbgInit(const RootSeedType &seed) const;
  void drbgUpdate(const std::uint8_t *seed, std::size_t seedLen) const;
  void drbgGenerate(std::uint8_t *out, std::size_t outLen) const;
  BIGNUM *randomBits(int bits) const;
  BIGNUM *randomCandidate(int bits) const;
  BIGNUM *findPrime(int bits, const BIGNUM *e, BN_CTX *ctx) const;
  bool generateRSAKey(RSAKey &key, const RootSeedType &seed, int bits,
                      unsigned long eInt) const;

  mutable DrbgState _drbg;
  MnemonicSeedType _mnemonicSeed;
  std::string _mnemonicString;
  RootSeedType _rootSeed;
};
} // end of namespace crypto
} // end of namespace artools
