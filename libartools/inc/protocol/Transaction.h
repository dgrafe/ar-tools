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
#include <utility>
#include <vector>

#include "transport/TLSClient.h"
#include "wallet.h"

namespace artools {
namespace protocol {

/**
 * @brief Builds and submits an Arweave v2 token-transfer transaction.
 *
 * A transaction transfers `quantity` Winston from the sending wallet to a
 * `target` wallet address, paying a `reward` (fee) in Winston. The transaction
 * is signed per the Arweave specification: a merkle root (deepHash) of the
 * SHA-384 hashes of the transaction fields is computed and signed with
 * RSA-PSS using SHA-256. The transaction `id` is the SHA-256 hash of the
 * signature.
 *
 * The signed transaction can be serialised to JSON (getJson()) and submitted
 * to the network via submit().
 */
class Transaction {
public:
  using BinaryContainer_t = artools::types::BinaryContainer_t;

  static constexpr const char *kHost = "arweave.net";
  static constexpr const char *kPort = "443";

  // 1 AR = 10^12 Winston.
  static constexpr std::uint64_t kWinstonPerAR = 1000000000000ULL;

  // A single transaction tag (name/value pair).
  using Tag = std::pair<std::string, std::string>;

  /**
   * @brief Constructs a token-transfer transaction.
   *
   * @param wallet   the sending wallet
   * @param target   the recipient wallet address
   * @param quantity the amount to transfer, in Winston
   * @param reward   the transaction fee, in Winston
   * @param lastTx   the replay-protection anchor (from GET /tx_anchor)
   * @param tags     optional name/value tags
   * @throws std::runtime_error if signing fails
   */
  Transaction(artools::wallet::WalletInstance &wallet,
              const std::string &target, std::uint64_t quantity,
              std::uint64_t reward, const std::string &lastTx,
              const std::vector<Tag> &tags = {});

  /**
   * @brief Returns the transaction id (SHA-256 of the signature).
   * @return the base64url-encoded transaction id
   */
  std::string getId() const { return _id; }

  /**
   * @brief Returns the base64url-encoded RSA-PSS signature.
   * @return the signature
   */
  std::string getSignature() const { return _signature; }

  /**
   * @brief Returns the signed data (the deepHash merkle root).
   *
   * This is the 48-byte value that was signed with RSA-PSS. It is exposed for
   * verification purposes.
   *
   * @return the signed data as a byte container
   */
  BinaryContainer_t getSignatureData() const { return _signatureData; }

  /**
   * @brief Returns the transaction serialised as JSON.
   * @return the JSON body for POST /tx
   */
  std::string getJson() const { return _json; }

  /**
   * @brief Submits the transaction to the network via POST /tx.
   *
   * @return true if the node accepted the transaction
   * @throws std::runtime_error if the submission fails
   */
  bool submit() const;

private:
  std::string _id;
  std::string _signature;
  std::string _json;
  BinaryContainer_t _signatureData;
};

} // namespace protocol
} // namespace artools