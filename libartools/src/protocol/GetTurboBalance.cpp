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

#include "protocol/GetTurboBalance.h"

#include <stdexcept>

#include <rapidjson/document.h>

namespace artools {
namespace protocol {

GetTurboBalance::GetTurboBalance(const artools::wallet::WalletInstance &wallet)
    : GetTurboBalance(wallet, kHost, kPort) {}

GetTurboBalance::GetTurboBalance(const artools::wallet::WalletInstance &wallet,
                                 const std::string &host,
                                 const std::string &port) {

  // The wallet already carries its Arweave address.
  _walletAddress = wallet.getWalletAddress();

  // Build the HTTP GET request for the Turbo (winc) account balance.
  std::string request =
      "GET /v1/account/balance/arweave?address=" + _walletAddress +
      " HTTP/1.1\r\n"
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

  // Extract the payload (body) and parse the JSON "effectiveBalance" field.
  std::string payload = artools::transport::TLSClient::extractPayload(response);
  if (payload.empty())
    throw std::runtime_error("GetTurboBalance: empty response payload");

  rapidjson::Document doc;
  if (doc.Parse(payload.c_str()).HasParseError() || !doc.IsObject() ||
      !doc.HasMember("effectiveBalance") ||
      !doc["effectiveBalance"].IsString())
    throw std::runtime_error("GetTurboBalance: invalid balance response");

  _balance = std::stoull(doc["effectiveBalance"].GetString());
}

} // namespace protocol
} // namespace artools