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

#include "arfs/ANS104.h"
#include "arfs/Drives.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "crypto/base64url.h"

namespace artools {
namespace arfs {

namespace {

// Helper to read a tag value from a rapidjson tag array.
std::string findTag(const rapidjson::Value &tags, const char *name) {
  if (!tags.IsArray()) return "";
  for (auto &tag : tags.GetArray()) {
    if (tag.IsObject() && tag.HasMember("name") && tag["name"].IsString() &&
        std::string(tag["name"].GetString()) == name &&
        tag.HasMember("value") && tag["value"].IsString()) {
      return tag["value"].GetString();
    }
  }
  return "";
}

// Converts a UUID string (e.g. "12345678-9abc-def0-1234-56789abcdef0") into
// its 16 raw bytes, as the ArFS reference implementation does with the
// `uuid.parse()` function.
artools::crypto::PEM::BinaryContainer_t uuidToBytes(const std::string &uuid) {
  artools::crypto::PEM::BinaryContainer_t bytes;
  auto nibble = [](char c) -> unsigned char {
    if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<unsigned char>(c - 'A' + 10);
    return 0;
  };
  int hexCount = 0;
  for (char c : uuid) {
    if (c == '-') continue;
    if (hexCount % 2 == 0)
      bytes.push_back(static_cast<unsigned char>(nibble(c) << 4));
    else
      bytes.back() |= nibble(c);
    ++hexCount;
  }
  return bytes;
}

// Extracts the redirect target from a 3xx response.
//
// arweave.net sends redirects as JSON in the response body rather than as an
// HTTP Location header:
//   {"body":"Redirecting to canonical transaction subdomain: //<host>/<txid>",
//    "location":"//<host>/<txid>","status":302}
// The "location" field carries the target.
std::string extractLocation(const Drives::BinaryContainer_t &response) {
  std::string payload =
      artools::transport::TLSClient::extractPayload(response);
  rapidjson::Document doc;
  if (doc.Parse(payload.c_str()).HasParseError() || !doc.IsObject() ||
      !doc.HasMember("location") || !doc["location"].IsString())
    return "";
  return doc["location"].GetString();
}

} // namespace

Drives::Drives() : Drives(kHost, kPort) {}

Drives::Drives(const std::string &host, const std::string &port)
    : _host(host), _port(port) {}

Drives::Drives(const artools::crypto::PEM &wallet)
    : Drives(wallet, kHost, kPort) {}

Drives::Drives(const artools::crypto::PEM &wallet, const std::string &host,
               const std::string &port)
    : _host(host), _port(port), _wallet(wallet), _hasWallet(true) {}

std::string Drives::buildQuery(const std::string &address,
                               const std::string &cursor) {
  rapidjson::Document doc;
  doc.SetObject();
  rapidjson::Document::AllocatorType &alloc = doc.GetAllocator();

  std::string query =
      "query { transactions(owners: [\"" + address + "\"], "
      "tags: [{ name: \"Entity-Type\", values: [\"drive\"] }], "
      "first: " + std::to_string(kPageSize);
  if (!cursor.empty())
    query += ", after: \"" + cursor + "\"";
  query += ") { edges { cursor node { id owner { address } block { timestamp "
           "height } tags { name value } } } pageInfo { hasNextPage } } }";

  doc.AddMember("query", rapidjson::Value(query.c_str(), alloc), alloc);

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  doc.Accept(writer);
  return buffer.GetString();
}

std::vector<Drive> Drives::parseDrives(const std::string &payload) {
  rapidjson::Document doc;
  if (doc.Parse(payload.c_str()).HasParseError() || !doc.IsObject() ||
      !doc.HasMember("data") || !doc["data"].IsObject() ||
      !doc["data"].HasMember("transactions") ||
      !doc["data"]["transactions"].IsObject() ||
      !doc["data"]["transactions"].HasMember("edges") ||
      !doc["data"]["transactions"]["edges"].IsArray())
    throw std::runtime_error("Drives: invalid GraphQL response");

  std::vector<Drive> drives;
  for (auto &edge : doc["data"]["transactions"]["edges"].GetArray()) {
    if (!edge.IsObject() || !edge.HasMember("node") ||
        !edge["node"].IsObject())
      continue;

    const auto &node = edge["node"];
    Drive d;
    if (node.HasMember("id") && node["id"].IsString())
      d.txId = node["id"].GetString();

    if (node.HasMember("block") && node["block"].IsObject() &&
        node["block"].HasMember("timestamp") &&
        node["block"]["timestamp"].IsUint64())
      d.timestamp = node["block"]["timestamp"].GetUint64();

    if (node.HasMember("tags") && node["tags"].IsArray()) {
      d.driveId = findTag(node["tags"], "Drive-Id");
      d.privacy = findTag(node["tags"], "Drive-Privacy");
      d.cipher = findTag(node["tags"], "Cipher");
      d.cipherIv = findTag(node["tags"], "Cipher-IV");
      d.signatureType = findTag(node["tags"], "Signature-Type");
      d.driveAuthMode = findTag(node["tags"], "Drive-Auth-Mode");
    }

    if (!d.txId.empty())
      drives.push_back(std::move(d));
  }
  return drives;
}

std::vector<Drive> Drives::deduplicateByDriveId(const std::vector<Drive> &drives) {
  // Keep the newest transaction per Drive-Id. Drives without a Drive-Id are
  // kept as-is.
  std::vector<Drive> result;
  for (const auto &d : drives) {
    if (d.driveId.empty()) {
      result.push_back(d);
      continue;
    }
    auto it = std::find_if(result.begin(), result.end(),
                           [&](const Drive &existing) {
                             return existing.driveId == d.driveId;
                           });
    if (it == result.end()) {
      result.push_back(d);
    } else if (d.timestamp > it->timestamp) {
      *it = d;
    }
  }
  // Newest first.
  std::sort(result.begin(), result.end(),
            [](const Drive &a, const Drive &b) {
              return a.timestamp > b.timestamp;
            });
  return result;
}

std::vector<Drive> Drives::listDrives(const std::string &address,
                                      const std::string &password) {
  std::vector<Drive> allDrives;
  std::string cursor;

  for (;;) {
    // Build and send the GraphQL POST request.
    std::string body = buildQuery(address, cursor);
    std::string request =
        "POST /graphql HTTP/1.1\r\n"
        "Host: " + _host + "\r\n"
        "User-Agent: ar-tools/" ARTOOLS_VERSION "\r\n"
        "Accept: application/json\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n"
        "\r\n" +
        body;

    artools::transport::TLSClient client(_host, _port);
    BinaryContainer_t reqBin(request.begin(), request.end());
    client.write(reqBin);

    BinaryContainer_t response;
    client.read(response);

    artools::transport::TLSClient::ensureHttpSuccess(response, "Drives");

    std::string payload =
        artools::transport::TLSClient::extractPayload(response);
    if (payload.empty())
      throw std::runtime_error("Drives: empty GraphQL response");

    auto page = parseDrives(payload);
    allDrives.insert(allDrives.end(), page.begin(), page.end());

    // Check for a next page via the pageInfo cursor.
    rapidjson::Document doc;
    if (doc.Parse(payload.c_str()).HasParseError() || !doc.IsObject() ||
        !doc.HasMember("data") || !doc["data"].IsObject() ||
        !doc["data"].HasMember("transactions") ||
        !doc["data"]["transactions"].IsObject() ||
        !doc["data"]["transactions"].HasMember("pageInfo") ||
        !doc["data"]["transactions"]["pageInfo"].IsObject() ||
        !doc["data"]["transactions"]["pageInfo"].HasMember("hasNextPage") ||
        !doc["data"]["transactions"]["pageInfo"]["hasNextPage"].IsBool() ||
        !doc["data"]["transactions"]["pageInfo"]["hasNextPage"].GetBool())
      break;

    // The cursor is the last edge's cursor.
    const auto &edges = doc["data"]["transactions"]["edges"];
    if (!edges.IsArray() || edges.Empty()) break;
    const auto &lastEdge = edges[edges.Size() - 1];
    if (!lastEdge.IsObject() || !lastEdge.HasMember("cursor") ||
        !lastEdge["cursor"].IsString())
      break;
    cursor = lastEdge["cursor"].GetString();
  }

  auto drives = deduplicateByDriveId(allDrives);

  // Fetch the drive name from the metadata JSON of each drive.
  for (auto &d : drives) {
    try {
      std::string host = _host;
      std::string port = _port;
      std::string path = "/" + d.txId;
      std::string meta;
      // Follow up to a few redirects (arweave.net redirects to a canonical
      // transaction subdomain).
      for (int redirects = 0; redirects < 5; ++redirects) {
        std::string request =
            "GET " + path + " HTTP/1.1\r\n"
            "Host: " + host + "\r\n"
            "User-Agent: ar-tools/" ARTOOLS_VERSION "\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n"
            "\r\n";

        artools::transport::TLSClient client(host, port);
        BinaryContainer_t reqBin(request.begin(), request.end());
        client.write(reqBin);

        BinaryContainer_t response;
        client.read(response);

        int status =
            artools::transport::TLSClient::getHttpStatusCode(response);
        if (status >= 300 && status < 400) {
          // Redirect: follow the Location header.
          std::string loc = extractLocation(response);
          if (loc.empty()) break;
          // Location is like "//<subdomain>.arweave.net/<txid>".
          auto slash = loc.find("//");
          if (slash != std::string::npos) {
            auto pathStart = loc.find('/', slash + 2);
            if (pathStart != std::string::npos) {
              // Switch to the redirect host (canonical subdomain).
              host = loc.substr(slash + 2, pathStart - slash - 2);
              path = loc.substr(pathStart);
            } else {
              break;
            }
          } else {
            path = loc;
          }
          continue;
        }

        artools::transport::TLSClient::ensureHttpSuccess(response, "Drives");
        meta = artools::transport::TLSClient::extractPayload(response);
        break;
      }

      // The gateway returns the transaction data as JSON with a base64url
      // "data" field when the Accept: application/json header is sent. For
      // private drives the encrypted metadata is in that field; extract and
      // base64url-decode it before decrypting.
      if (d.privacy == "private") {
        rapidjson::Document dataDoc;
        if (!dataDoc.Parse(meta.c_str()).HasParseError() &&
            dataDoc.IsObject() && dataDoc.HasMember("data") &&
            dataDoc["data"].IsString()) {
          artools::crypto::BASE64url::CodingDataType dataBytes;
          artools::crypto::BASE64url::decode(dataDoc["data"].GetString(),
                                             dataBytes);
          meta.assign(dataBytes.begin(), dataBytes.end());
        }
      }

      // Private drives store their metadata AES-256-GCM encrypted. Decrypt it
      // when a wallet and password are available.
      if (d.privacy == "private" && _hasWallet && !password.empty() &&
          !d.cipherIv.empty()) {
        // 1. Build the signing key: "drive" || driveIdBytes (the UUID parsed
        //    into its 16 raw bytes), per the ArFS reference implementation.
        artools::crypto::PEM::BinaryContainer_t signingKey;
        const std::string kDrivePrefix = "drive";
        signingKey.insert(signingKey.end(), kDrivePrefix.begin(),
                          kDrivePrefix.end());
        auto driveIdBytes = uuidToBytes(d.driveId);
        signingKey.insert(signingKey.end(), driveIdBytes.begin(),
                          driveIdBytes.end());

        // 2. Sign the signing key with the wallet's private key. The ArFS
        //    signature type determines the scheme:
        //    - "1" (or absent): SHA-256 hash then unsalted RSA-PSS
        //      (PEM::signRaw).
        //    - "2": an ANS-104 DataItem deep-hash of the signing key, signed
        //      with unsalted RSA-PSS.
        std::string signature;
        if (d.signatureType == "2") {
          // ANS-104 DataItem deep-hash, matching arbundles'
          // getSignatureData(): the signature data is the deepHash of
          //   ["dataitem", "1", signatureType, owner, target, anchor,
          //    avroTags, data]
          // with no target/anchor, the tag Action: Drive-Signature-V2, and
          // the data being the signing key ("drive" || driveIdBytes).
          auto owner = _wallet.get_n();
          auto digest = ANS104::getSignatureData(
              "1", owner, {}, {},
              {{"Action", "Drive-Signature-V2"}}, signingKey);
          if (!_wallet.signRaw(digest, signature))
            throw std::runtime_error("Drives: wallet signing failed");
        } else {
          // v1: SHA-256 hash then unsalted RSA-PSS.
          if (!_wallet.signRaw(signingKey, signature))
            throw std::runtime_error("Drives: wallet signing failed");
        }

        // Decode the base64url signature to raw bytes.
        artools::crypto::BASE64url::CodingDataType sigBytes;
        artools::crypto::BASE64url::decode(signature, sigBytes);

        // 3. Derive the 256-bit drive key with HKDF-SHA256 per the ArFS
        //    reference implementation: the signature is the input key
        //    material, no salt, and the password as the info.
        auto key = artools::crypto::HKDF::derive(
            sigBytes, {},
            artools::crypto::HKDF::BinaryContainer_t(password.begin(),
                                                     password.end()),
            32);

        // 4. Decrypt the metadata with AES-256-GCM. The metadata body is raw
        //    bytes (ciphertext || 16-byte tag); the IV comes from the
        //    Cipher-IV tag (base64url).
        artools::crypto::BASE64url::CodingDataType ivBytes;
        artools::crypto::BASE64url::decode(d.cipherIv, ivBytes);

        artools::crypto::AESGCM::BinaryContainer_t cipherBytes(meta.begin(),
                                                               meta.end());
        meta = artools::crypto::AESGCM::decrypt(key, ivBytes, cipherBytes);
      }

      rapidjson::Document metaDoc;
      if (metaDoc.Parse(meta.c_str()).HasParseError() || !metaDoc.IsObject() ||
          !metaDoc.HasMember("name") || !metaDoc["name"].IsString())
        continue;
      d.name = metaDoc["name"].GetString();
    } catch (const std::exception &) {
      // Metadata not resolvable (e.g. private drive without password, or
      // wrong password): leave name empty.
    }
  }

  return drives;
}

} // namespace arfs
} // namespace artools