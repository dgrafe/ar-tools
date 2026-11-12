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
 * @brief Queries the ArDrive Turbo (winc) balance of a wallet.
 *
 * Takes a wallet::WalletInstance, derives the Arweave wallet address from it,
 * and issues a GET /v1/account/balance/arweave?address=<address> request to
 * the Turbo payment service (payment.ardrive.io) over TLS. The returned
 * "effectiveBalance" (in winc) is made available via getBalance().
 *
 * The balance is expressed in the smallest winc unit: 10^12 winc = 1 credit.
 * For example, an effectiveBalance of 412620266518 corresponds to
 * 0.412620266518 credits.
 *
 * See https://docs.ar.io/apis/turbo/payment-service/balance/
 */
class GetTurboBalance {
public:
  using BinaryContainer_t = artools::types::BinaryContainer_t;

  static constexpr const char *kHost = "payment.ardrive.io";
  static constexpr const char *kPort = "443";

  // 1 credit = 10^12 winc (smallest unit).
  static constexpr std::uint64_t kWincPerCredit = 1000000000000ULL;

  /**
   * @brief Constructs a Turbo balance query from a wallet instance.
   *
   * Uses the default Turbo service (payment.ardrive.io:443).
   *
   * @param wallet the wallet whose balance should be queried
   * @throws std::runtime_error if the balance request fails
   */
  explicit GetTurboBalance(const artools::wallet::WalletInstance &wallet);

  /**
   * @brief Constructs a Turbo balance query from a wallet instance against a
   *        custom service.
   *
   * @param wallet the wallet whose balance should be queried
   * @param host   the service hostname
   * @param port   the service port as a string
   * @throws std::runtime_error if the balance request fails
   */
  GetTurboBalance(const artools::wallet::WalletInstance &wallet,
                  const std::string &host, const std::string &port);

  /**
   * @brief Returns the wallet address.
   * @return the Arweave wallet address
   */
  std::string getWalletAddress() const { return _walletAddress; }

  /**
   * @brief Returns the Turbo balance in winc (smallest unit).
   *
   * 10^12 winc = 1 credit. Use getBalanceInCredits() for the value in
   * credits.
   *
   * @return the balance as an unsigned 64-bit integer
   */
  std::uint64_t getBalance() const { return _balance; }

  /**
   * @brief Returns the Turbo balance in credits.
   * @return the balance as a floating-point number of credits
   */
  double getBalanceInCredits() const {
    return static_cast<double>(_balance) /
           static_cast<double>(kWincPerCredit);
  }

private:
  std::string _walletAddress;
  std::uint64_t _balance = 0;
};

} // namespace protocol
} // namespace artools