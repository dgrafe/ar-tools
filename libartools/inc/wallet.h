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

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "crypto/bip39.h"
#include "crypto/jwk.h"
#include "crypto/pem.h"

namespace artools {
struct wallet {

  using BinaryContainer_t = artools::types::BinaryContainer_t;

  /**
   * @brief Unit in which a balance can be requested.
   *
   * Each enumerator carries the number of Winston that make up one unit:
   *   - Winston : 1 Winston
   *   - picoAR  : 10^-12 AR = 1 Winston
   *   - nanoAR  : 10^-9  AR = 10^3 Winston
   *   - microAR : 10^-6  AR = 10^6 Winston
   *   - milliAR : 10^-3  AR = 10^9 Winston
   *   - AR      : 1 AR = 10^12 Winston
   */
  enum class Unit : std::uint64_t {
    Winston = 1ULL,
    picoAR = 1ULL,
    nanoAR = 1000ULL,
    microAR = 1000000ULL,
    milliAR = 1000000000ULL,
    AR = 1000000000000ULL,
  };

  class WalletInstance {
  public:
    WalletInstance() = delete;
    WalletInstance(const artools::crypto::PEM &pem);

    artools::crypto::PEM getPEM() { return _pem; }
    artools::crypto::PEM getJWK() { return crypto::JWK(_pem); }
    std::string getWalletAddress() const { return _walletAddress; }

    bool sign(const BinaryContainer_t &msg, std::string &sig) const {
      return _pem.sign(msg, sig);
    }
    bool verify(const BinaryContainer_t &msg, const std::string &sig) const {
      return _pem.verify(msg, sig);
    }

    /**
     * @brief Returns the wallet balance in Winston.
     * @return the balance as an unsigned 64-bit integer
     */
    std::uint64_t getBalance() const;

    /**
     * @brief Returns the wallet balance in the requested unit.
     * @param unit the unit to return the balance in
     * @return     the balance in the requested unit
     */
    double getBalance(Unit unit) const;

  private:
    std::string _walletAddress;
    const artools::crypto::PEM _pem;
  };
  using WalletInstance_t = std::unique_ptr<WalletInstance>;

  wallet() = delete;
  wallet(wallet &) = delete;
  wallet(wallet &&) = delete;
  ~wallet() = default;

  // factory functions
  static WalletInstance_t create() { return nullptr; }
  static WalletInstance_t create(const artools::crypto::PEM &pem) {
    return std::make_unique<wallet::WalletInstance>(pem);
  }
  static WalletInstance_t create(const artools::crypto::JWK &jwk) {
    artools::crypto::PEM buf(jwk);
    return std::make_unique<wallet::WalletInstance>(buf);
  }
  static WalletInstance_t create(const artools::crypto::BIP39 &bip39) {
    artools::crypto::PEM buf(bip39);
    return std::make_unique<wallet::WalletInstance>(buf);
  }
};

} // end of namespace artools