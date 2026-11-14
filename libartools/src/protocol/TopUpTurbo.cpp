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

#include "protocol/TopUpTurbo.h"

#include <stdexcept>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "protocol/GetPrice.h"
#include "protocol/GetTxAnchor.h"

namespace artools {
namespace protocol {

TopUpTurbo::TopUpTurbo(artools::wallet::WalletInstance &wallet,
                       std::uint64_t quantity)
    : TopUpTurbo(wallet, quantity, kHost, kPort, Transaction::kHost,
                 Transaction::kPort) {}

TopUpTurbo::TopUpTurbo(artools::wallet::WalletInstance &wallet,
                       std::uint64_t quantity, const std::string &turboHost,
                       const std::string &turboPort,
                       const std::string &gatewayHost,
                       const std::string &gatewayPort) {

  // 1. Fetch the replay-protection anchor and the transaction fee for a pure
  //    token transfer to the Turbo address.
  GetTxAnchor anchor(gatewayHost, gatewayPort);
  GetPrice price(0, kTurboAddress, gatewayHost, gatewayPort);
  const std::uint64_t fee = price.getPrice();

  // 2. Build and submit the signed v2 token-transfer transaction to the
  //    Turbo Arweave address.
  Transaction tx(wallet, kTurboAddress, quantity, fee, anchor.getAnchor());
  const bool submitted = tx.submit(gatewayHost, gatewayPort);
  if (!submitted)
    throw std::runtime_error("TopUpTurbo: transaction submission failed");

  _transactionId = tx.getId();

  // 3. Claim the credits by posting the transaction id to the Turbo payment
  //    service.
  std::string body = buildClaimBody(_transactionId);
  std::string request =
      "POST /v1/account/balance/arweave HTTP/1.1\r\n"
      "Host: " + turboHost + "\r\n"
      "User-Agent: ar-tools/" ARTOOLS_VERSION "\r\n"
      "Accept: application/json\r\n"
      "Content-Type: application/json\r\n"
      "Content-Length: " + std::to_string(body.size()) + "\r\n"
      "Connection: close\r\n"
      "\r\n" +
      body;

  artools::transport::TLSClient client(turboHost, turboPort);
  BinaryContainer_t reqBin(request.begin(), request.end());
  client.write(reqBin);

  BinaryContainer_t response;
  client.read(response);

  // The claim may return 200 (credited) or 202 (pending); both are accepted.
  const int status =
      artools::transport::TLSClient::getHttpStatusCode(response);
  if (status != 200 && status != 202)
    artools::transport::TLSClient::ensureHttpSuccess(response, "TopUpTurbo");

  _accepted = true;
  std::string payload =
      artools::transport::TLSClient::extractPayload(response);
  _message = parseMessage(payload);
}

std::string TopUpTurbo::buildClaimBody(const std::string &transactionId) {
  rapidjson::Document doc;
  doc.SetObject();
  rapidjson::Document::AllocatorType &alloc = doc.GetAllocator();
  doc.AddMember("tx_id",
                rapidjson::Value(transactionId.c_str(), alloc), alloc);
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  doc.Accept(writer);
  return buffer.GetString();
}

std::string TopUpTurbo::parseMessage(const std::string &payload) {
  rapidjson::Document doc;
  if (doc.Parse(payload.c_str()).HasParseError() || !doc.IsObject() ||
      !doc.HasMember("message") || !doc["message"].IsString())
    return "";
  return doc["message"].GetString();
}

} // namespace protocol
} // namespace artools
