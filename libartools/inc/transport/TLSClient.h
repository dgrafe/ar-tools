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
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace artools {
namespace transport {
class TLSClient {

public:
  using BinaryContainer_t = std::vector<std::uint8_t>;
  using TLSContext_t = std::shared_ptr<SSL_CTX>;
  using TLSConnection_t = std::shared_ptr<SSL>;
  static const auto SSL_RECORD_SIZE = 16384;

  TLSClient() = delete;
  TLSClient(TLSClient &) = delete;
  TLSClient(TLSClient &&) = delete;
  ~TLSClient();

  TLSClient(const std::string address, const std::string port);
  TLSClient(const std::string address) : TLSClient(address, "443") {}

  std::uint32_t write(const BinaryContainer_t &data);
  std::uint32_t read(BinaryContainer_t &data);

  /**
   * @brief Extracts the HTTP response body (payload) from a raw response.
   *
   * Splits the response at the first "\r\n\r\n" (end of headers) and returns
   * everything after it. If no header/body separator is found, the whole
   * input is returned unchanged.
   *
   * @param response the raw HTTP response bytes
   * @return         the payload (body) as a string
   */
  static std::string extractPayload(const BinaryContainer_t &response);

private:
  TLSContext_t _ctx;
  TLSConnection_t _ssl;
  std::string _hostname;
};
} // namespace transport
} // namespace artools