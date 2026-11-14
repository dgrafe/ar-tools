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
 * @brief Queries the Arweave transaction price (fee).
 *
 * Issues a GET /price/{bytes}/{target} request to the Arweave gateway. The
 * price is the minimum fee (reward) in Winston for a transaction of the given
 * data size, optionally to a specific target address.
 *
 * The target segment is only appended when a target address is given:
 *   - GetPrice(0, "abc")   -> /price/0/abc   : send tokens to "abc", no data
 *   - GetPrice(123)        -> /price/123     : upload 123 bytes, no transfer
 *   - GetPrice(123, "abc") -> /price/123/abc : send tokens and upload data
 */
class GetPrice {
public:
  using BinaryContainer_t = artools::types::BinaryContainer_t;

  static constexpr const char *kHost = "arweave.net";
  static constexpr const char *kPort = "443";

  /**
   * @brief Constructs a price query against the default gateway.
   *
   * @param bytes  the number of data bytes (0 for a pure token transfer)
   * @param target the target wallet address, or empty for no target
   * @throws std::runtime_error if the request fails
   */
  GetPrice(std::uint64_t bytes, const std::string &target = "");

  /**
   * @brief Constructs a price query against a custom gateway.
   *
   * @param bytes  the number of data bytes (0 for a pure token transfer)
   * @param target the target wallet address, or empty for no target
   * @param host   the gateway hostname
   * @param port   the gateway port as a string
   * @throws std::runtime_error if the request fails
   */
  GetPrice(std::uint64_t bytes, const std::string &target,
           const std::string &host, const std::string &port);

  /**
   * @brief Returns the transaction price in Winston.
   * @return the price as an unsigned 64-bit integer
   */
  std::uint64_t getPrice() const { return _price; }

  /**
   * @brief Builds the request path for a price query.
   *
   * The target segment is only appended when a target address is given:
   *   - /price/0/abc   : send tokens to "abc", no data
   *   - /price/123     : upload 123 bytes, no token transfer
   *   - /price/123/abc : send tokens to "abc" and upload 123 bytes
   *
   * Extracted as a static helper so the path logic can be unit-tested
   * without a network connection.
   *
   * @param bytes  the number of data bytes
   * @param target the target wallet address, or empty for no target
   * @return        the request path
   */
  static std::string buildPath(std::uint64_t bytes,
                               const std::string &target);

  /**
   * @brief Parses a price payload (a decimal number) into Winston.
   *
   * Extracted as a static helper so the parsing logic can be unit-tested
   * without a network connection. Parsing stops at the first non-digit.
   *
   * @param payload the response body
   * @return        the parsed price in Winston
   */
  static std::uint64_t parsePrice(const std::string &payload);

private:
  std::uint64_t _price = 0;
};

} // namespace protocol
} // namespace artools