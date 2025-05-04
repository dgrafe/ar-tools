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
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "crypto/bip39.h"
#include "crypto/jwk.h"
#include "types.h"

namespace artools {
namespace crypto {

class JWK;
class PEM {
public:
  static constexpr auto PUB_EXP = "010001";
  static const auto MODULUS_BITS = 4096;
  using PrivateKeyContext_t = std::shared_ptr<EVP_PKEY_CTX>;
  using PrivateKey_t = std::shared_ptr<EVP_PKEY>;
  using BinaryContainer_t = artools::types::BinaryContainer_t;
  using RSAKey_t = BIP39::RSAKey;

  // generate a new key pair
  PEM();
  // deterministically recover the key from a bip39 instance
  PEM(const BIP39 &bip39);
  // initialize from pem file
  PEM(const std::string &pathToPEM);
  // initialize from jwk
  PEM(const JWK &jwkInstance);

  bool exportAsFile(const std::string &pathToPEM);

  BinaryContainer_t get_e() const;
  BinaryContainer_t get_n() const;
  BinaryContainer_t get_d() const;
  BinaryContainer_t get_p() const;
  BinaryContainer_t get_q() const;
  BinaryContainer_t get_dp() const;
  BinaryContainer_t get_dq() const;
  BinaryContainer_t get_qi() const;

  std::string getPublicKeyAsHex();
  std::string getPrivateKeyAsHex();

  bool sign(const BinaryContainer_t &msg, std::string &sig) const;
  bool verify(const BinaryContainer_t &msg, const std::string &sig) const;

private:
  void generateKeyPair();
  void buildKeyFromRSAKey(const RSAKey_t &rsaKey);
  // PrivateKey_t getPrivateKey() const { return _pkey; }

  PrivateKey_t _pkey;
};
} // end of namespace crypto
} // end of namespace artools
