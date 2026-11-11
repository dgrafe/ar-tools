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
#include "types.h"

namespace artools {
namespace protocol {

/**
 * @brief Fetches the current transaction anchor from the network.
 *
 * Issues a GET /tx_anchor request to the Arweave gateway. The anchor is a
 * replay-protection value (a hash of one of the last 50 blocks or the last
 * outgoing transaction id) that must be included in the `last_tx` field of a
 * new transaction.
 */
class GetTxAnchor {
public:
  using BinaryContainer_t = artools::types::BinaryContainer_t;

  static constexpr const char *kHost = "arweave.net";
  static constexpr const char *kPort = "443";

  /**
   * @brief Constructs an anchor query against the default gateway.
   * @throws std::runtime_error if the request fails
   */
  GetTxAnchor();

  /**
   * @brief Constructs an anchor query against a custom gateway.
   * @param host the gateway hostname
   * @param port the gateway port as a string
   * @throws std::runtime_error if the request fails
   */
  GetTxAnchor(const std::string &host, const std::string &port);

  /**
   * @brief Returns the transaction anchor.
   * @return the base64url-encoded anchor
   */
  std::string getAnchor() const { return _anchor; }

private:
  std::string _anchor;
};

} // namespace protocol
} // namespace artools