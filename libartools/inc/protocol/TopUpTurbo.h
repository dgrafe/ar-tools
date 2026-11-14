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

#include "protocol/Transaction.h"
#include "transport/TLSClient.h"
#include "wallet.h"

namespace artools {
namespace protocol {

/**
 * @brief Tops up the ArDrive Turbo (winc) credit balance with AR.
 *
 * Sends a parameterisable amount of AR from the wallet to the ArDrive Turbo
 * payment service's Arweave address, then claims the resulting credits by
 * posting the transaction id to the Turbo payment service.
 *
 * The flow is:
 *   1. Build and submit a v2 token-transfer transaction of `quantity` Winston
 *      to the Turbo Arweave address (kTurboAddress).
 *   2. Remember the transaction id.
 *   3. POST /v1/account/balance/arweave with {"tx_id": "<id>"} to the Turbo
 *      payment service (payment.ardrive.io), which reads the transaction from
 *      the chain, verifies it pays the service, prices it and credits the
 *      sender's Turbo account.
 *
 * See https://docs.ar.io/apis/turbo/payment-service/ and
 * https://payment.ardrive.io/api-docs
 */
class TopUpTurbo {
public:
  using BinaryContainer_t = artools::types::BinaryContainer_t;

  // The ArDrive Turbo payment service's Arweave address (from GET /info).
  static constexpr const char *kTurboAddress =
      "JNC6vBhjHY1EPwV3pEeNmrsgFMxH5d38_LHsZ7jful8";

  // The Turbo payment service host/port.
  static constexpr const char *kHost = "payment.ardrive.io";
  static constexpr const char *kPort = "443";

  /**
   * @brief Constructs a Turbo top-up from a wallet instance.
   *
   * Uses the default Turbo service (payment.ardrive.io:443) and the default
   * Arweave gateway (arweave.net:443) for submitting the transaction.
   *
   * @param wallet   the wallet that pays for the top-up
   * @param quantity the amount to send, in Winston
   * @throws std::runtime_error if the transaction cannot be built, submitted
   *         or claimed
   */
  TopUpTurbo(artools::wallet::WalletInstance &wallet,
             std::uint64_t quantity);

  /**
   * @brief Constructs a Turbo top-up against custom services.
   *
   * @param wallet       the wallet that pays for the top-up
   * @param quantity     the amount to send, in Winston
   * @param turboHost    the Turbo payment service hostname
   * @param turboPort    the Turbo payment service port as a string
   * @param gatewayHost  the Arweave gateway hostname
   * @param gatewayPort  the Arweave gateway port as a string
   * @throws std::runtime_error if the transaction cannot be built, submitted
   *         or claimed
   */
  TopUpTurbo(artools::wallet::WalletInstance &wallet, std::uint64_t quantity,
             const std::string &turboHost, const std::string &turboPort,
             const std::string &gatewayHost, const std::string &gatewayPort);

  /**
   * @brief Returns the id of the submitted AR transaction.
   * @return the base64url-encoded transaction id
   */
  std::string getTransactionId() const { return _transactionId; }

  /**
   * @brief Returns the Turbo service's response message.
   *
   * E.g. "Transaction credited" or "Transaction pending".
   *
   * @return the message from the claim response
   */
  std::string getMessage() const { return _message; }

  /**
   * @brief Returns whether the claim was accepted (HTTP 200 or 202).
   * @return true if the transaction was credited or is pending
   */
  bool isAccepted() const { return _accepted; }

  /**
   * @brief Builds the JSON body for the claim request.
   *
   * Extracted as a static helper so it can be unit-tested without a network
   * connection.
   *
   * @param transactionId the transaction id to claim
   * @return              the JSON body {"tx_id": "<id>"}
   */
  static std::string buildClaimBody(const std::string &transactionId);

  /**
   * @brief Parses the claim response message.
   *
   * Extracts the "message" field from the JSON response. Extracted as a
   * static helper so the parsing logic can be unit-tested without a network
   * connection.
   *
   * @param payload the JSON response body
   * @return        the message string (empty if absent)
   */
  static std::string parseMessage(const std::string &payload);

private:
  std::string _transactionId;
  std::string _message;
  bool _accepted = false;
};

} // namespace protocol
} // namespace artools
