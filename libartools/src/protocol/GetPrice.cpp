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

#include "protocol/GetPrice.h"

#include <cctype>
#include <stdexcept>

namespace artools {
namespace protocol {

GetPrice::GetPrice(std::uint64_t bytes, const std::string &target)
    : GetPrice(bytes, target, kHost, kPort) {}

GetPrice::GetPrice(std::uint64_t bytes, const std::string &target,
                   const std::string &host, const std::string &port) {

  std::string path = buildPath(bytes, target);

  std::string request =
      "GET " + path + " HTTP/1.1\r\n"
      "Host: " + host + "\r\n"
      "User-Agent: ar-tools/" ARTOOLS_VERSION "\r\n"
      "Accept: application/json\r\n"
      "Connection: close\r\n"
      "\r\n";

  // Send the request over TLS and read the full response.
  artools::transport::TLSClient client(host, port);
  BinaryContainer_t reqBin(request.begin(), request.end());
  client.write(reqBin);

  BinaryContainer_t response;
  client.read(response);

  // Reject gateway error pages (4xx/5xx) instead of parsing them as a price.
  artools::transport::TLSClient::ensureHttpSuccess(response, "GetPrice");

  // Extract the payload (body) and parse it as an unsigned integer.
  std::string payload = artools::transport::TLSClient::extractPayload(response);
  if (payload.empty())
    throw std::runtime_error("GetPrice: empty response payload");

  _price = parsePrice(payload);
}

std::string GetPrice::buildPath(std::uint64_t bytes,
                                const std::string &target) {
  std::string path = "/price/" + std::to_string(bytes);
  if (!target.empty())
    path += "/" + target;
  return path;
}

std::uint64_t GetPrice::parsePrice(const std::string &payload) {
  std::uint64_t price = 0;
  for (char c : payload) {
    if (!std::isdigit(static_cast<unsigned char>(c))) break;
    price = price * 10 + static_cast<std::uint64_t>(c - '0');
  }
  return price;
}

} // namespace protocol
} // namespace artools