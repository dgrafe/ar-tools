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
#include <string>

#include "transport/TLSClient.h"
#include "wallet.h"

namespace artools {
namespace protocol {

/**
 * @brief Queries the Arweave balance of a wallet.
 *
 * Takes a wallet::WalletInstance, derives the Arweave wallet address from it,
 * and issues a GET /wallet/<address>/balance request to arweave.net over TLS.
 * The returned balance (in Winston) is made available via getBalance().
 */
class GetBalance {
public:
  using BinaryContainer_t = artools::types::BinaryContainer_t;

  static constexpr const char *kHost = "arweave.net";
  static constexpr const char *kPort = "443";

  // 1 AR = 10^12 Winston.
  static constexpr std::uint64_t kWinstonPerAR = 1000000000000ULL;

  // The balance unit enum is shared with wallet::WalletInstance.
  using Unit = artools::wallet::Unit;

  /**
   * @brief Constructs a balance query from a wallet instance.
   *
   * Uses the default Arweave gateway (arweave.net:443).
   *
   * @param wallet the wallet whose balance should be queried
   * @throws std::runtime_error if the balance request fails
   */
  explicit GetBalance(const artools::wallet::WalletInstance &wallet);

  /**
   * @brief Constructs a balance query from a wallet instance against a
   *        custom gateway.
   *
   * @param wallet the wallet whose balance should be queried
   * @param host   the gateway hostname
   * @param port   the gateway port as a string
   * @throws std::runtime_error if the balance request fails
   */
  GetBalance(const artools::wallet::WalletInstance &wallet,
             const std::string &host, const std::string &port);

  /**
   * @brief Returns the wallet address.
   * @return the Arweave wallet address
   */
  std::string getWalletAddress() const { return _walletAddress; }

  /**
   * @brief Returns the wallet balance in Winston.
   * @return the balance as an unsigned 64-bit integer
   */
  std::uint64_t getBalance() const { return _balance; }

  /**
   * @brief Returns the wallet balance in the requested unit.
   *
   * The balance is expressed as a floating-point number of the given unit,
   * e.g. getBalance(Unit::AR) returns AR, getBalance(Unit::microAR) returns
   * micro-AR. Winston is returned as an exact integer value.
   *
   * @param unit the unit to return the balance in
   * @return     the balance in the requested unit
   */
  double getBalance(Unit unit) const;

private:
  std::string _walletAddress;
  std::uint64_t _balance = 0;
};

} // namespace protocol
} // namespace artools