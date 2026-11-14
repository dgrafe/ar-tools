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

#include "protocol/Transaction.h"

#include <stdexcept>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "crypto/base64url.h"
#include "crypto/sha256.h"
#include "crypto/sha384.h"

namespace artools {
namespace protocol {

namespace {

using Hash384 = artools::crypto::SHA384::HashType;
using BinaryContainer_t = artools::types::BinaryContainer_t;

/**
 * @brief Computes the SHA-384 hash of a byte sequence.
 * @param data the input bytes
 * @return     the 48-byte SHA-384 digest
 */
Hash384 sha384(const BinaryContainer_t &data) {
  return artools::crypto::SHA384(data.data(), data.size()).getHash();
}

/**
 * @brief Computes the SHA-384 hash of a UTF-8 string.
 * @param str the input string
 * @return    the 48-byte SHA-384 digest
 */
Hash384 sha384(const std::string &str) {
  return artools::crypto::SHA384(
             reinterpret_cast<const unsigned char *>(str.data()), str.size())
      .getHash();
}

/**
 * @brief Concatenates two byte sequences.
 * @param a first sequence
 * @param b second sequence
 * @return  the concatenation a || b
 */
BinaryContainer_t concat(const BinaryContainer_t &a,
                         const BinaryContainer_t &b) {
  BinaryContainer_t ret;
  ret.reserve(a.size() + b.size());
  ret.insert(ret.end(), a.begin(), a.end());
  ret.insert(ret.end(), b.begin(), b.end());
  return ret;
}

/**
 * @brief Concatenates three byte sequences.
 * @param a first sequence
 * @param b second sequence
 * @param c third sequence
 * @return  the concatenation a || b || c
 */
BinaryContainer_t concat(const BinaryContainer_t &a, const BinaryContainer_t &b,
                         const BinaryContainer_t &c) {
  return concat(concat(a, b), c);
}

/**
 * @brief Converts a SHA-384 digest into a byte container.
 * @param hash the digest
 * @return     the digest as a byte container
 */
BinaryContainer_t toContainer(const Hash384 &hash) {
  return BinaryContainer_t(hash.begin(), hash.end());
}

/**
 * @brief A node in the deepHash input tree.
 *
 * A node is either a byte blob or a list of child nodes. This mirrors the
 * nested array/blob structure accepted by the arweave-js deepHash function.
 */
struct DeepHashNode {
  bool isList;
  BinaryContainer_t blob;             // valid when !isList
  std::vector<DeepHashNode> children; // valid when isList

  static DeepHashNode makeBlob(const BinaryContainer_t &b) {
    DeepHashNode n;
    n.isList = false;
    n.blob = b;
    return n;
  }
  static DeepHashNode makeBlob(const std::string &s) {
    return makeBlob(BinaryContainer_t(s.begin(), s.end()));
  }
  static DeepHashNode makeList(std::vector<DeepHashNode> children) {
    DeepHashNode n;
    n.isList = true;
    n.children = std::move(children);
    return n;
  }
};

/**
 * @brief Implements the Arweave deepHash algorithm.
 *
 * Matches the reference implementation in arweave-js (src/common/lib/deepHash).
 *
 * For a blob:
 *   SHA384( SHA384("blob" || byteLength) || SHA384(data) )
 *
 * For a list, the items are folded into a cumulative hash chain starting from
 * the tag hash:
 *   acc = SHA384("list" || length)
 *   acc = SHA384(acc || deepHash(item0))
 *   acc = SHA384(acc || deepHash(item1))
 *   ...
 *   result = acc
 *
 * @param node the node to hash
 * @return     the 48-byte deepHash digest
 */
Hash384 deepHash(const DeepHashNode &node) {
  if (!node.isList) {
    // Blob: SHA384( SHA384("blob" || byteLength) || SHA384(data) )
    std::string tag = "blob" + std::to_string(node.blob.size());
    Hash384 tagHash = sha384(tag);
    Hash384 dataHash = sha384(node.blob);
    return sha384(concat(toContainer(tagHash), toContainer(dataHash)));
  }

  // List: fold the items into a cumulative hash chain.
  std::string tag = "list" + std::to_string(node.children.size());
  Hash384 acc = sha384(tag);

  for (const auto &child : node.children) {
    Hash384 childHash = deepHash(child);
    acc = sha384(concat(toContainer(acc), toContainer(childHash)));
  }
  return acc;
}

} // namespace

Transaction::Transaction(artools::wallet::WalletInstance &wallet,
                         const std::string &target, std::uint64_t quantity,
                         std::uint64_t reward, const std::string &lastTx,
                         const std::vector<Tag> &tags) {

  // --- Transaction fields (v2) -------------------------------------------
  const std::string format = "2";
  // The owner is the base64url-encoded RSA modulus n (the JWK "n" value).
  std::string owner;
  artools::crypto::BASE64url::encode(wallet.getPEM().get_n(), owner);
  const std::string dataRoot = ""; // no data attached
  const std::string dataSize = "0";
  const std::string quantityStr = std::to_string(quantity);
  const std::string rewardStr = std::to_string(reward);

  // --- Build the deepHash input tree -------------------------------------
  // The field order and encoding match the arweave-js reference
  // implementation (getSignatureData, format 2):
  //   format, owner, target, quantity, reward, last_tx, tags, data_size,
  //   data_root
  //
  // The base64url-encoded fields (owner, target, last_tx, data_root) are
  // decoded to raw bytes before hashing; the numeric/string fields (format,
  // quantity, reward, data_size) are hashed as their UTF-8 string form.
  std::vector<DeepHashNode> tagNodes;
  for (const auto &tag : tags) {
    // Tag names and values are base64url-encoded; decode them to raw bytes.
    artools::crypto::BASE64url::CodingDataType nameBytes, valueBytes;
    artools::crypto::BASE64url::decode(tag.first, nameBytes);
    artools::crypto::BASE64url::decode(tag.second, valueBytes);
    tagNodes.push_back(DeepHashNode::makeList(
        {DeepHashNode::makeBlob(nameBytes), DeepHashNode::makeBlob(valueBytes)}));
  }

  // Decode the base64url-encoded fields to raw bytes.
  artools::crypto::BASE64url::CodingDataType ownerBytes, targetBytes,
      lastTxBytes, dataRootBytes;
  artools::crypto::BASE64url::decode(owner, ownerBytes);
  artools::crypto::BASE64url::decode(target, targetBytes);
  artools::crypto::BASE64url::decode(lastTx, lastTxBytes);
  artools::crypto::BASE64url::decode(dataRoot, dataRootBytes);

  std::vector<DeepHashNode> fieldNodes;
  fieldNodes.push_back(DeepHashNode::makeBlob(format));
  fieldNodes.push_back(DeepHashNode::makeBlob(ownerBytes));
  fieldNodes.push_back(DeepHashNode::makeBlob(targetBytes));
  fieldNodes.push_back(DeepHashNode::makeBlob(quantityStr));
  fieldNodes.push_back(DeepHashNode::makeBlob(rewardStr));
  fieldNodes.push_back(DeepHashNode::makeBlob(lastTxBytes));
  fieldNodes.push_back(DeepHashNode::makeList(std::move(tagNodes)));
  fieldNodes.push_back(DeepHashNode::makeBlob(dataSize));
  fieldNodes.push_back(DeepHashNode::makeBlob(dataRootBytes));

  Hash384 signatureData = deepHash(DeepHashNode::makeList(std::move(fieldNodes)));

  // --- Sign the merkle root with RSA-PSS / SHA-256 -----------------------
  _signatureData.assign(signatureData.begin(), signatureData.end());
  if (!wallet.sign(_signatureData, _signature))
    throw std::runtime_error("Transaction: signing failed");

  // --- Transaction id = SHA-256 of the signature -------------------------
  BinaryContainer_t sigBytes;
  artools::crypto::BASE64url::decode(_signature, sigBytes);
  auto idHash = artools::crypto::SHA256(sigBytes.data(), sigBytes.size())
                    .getHash();
  artools::crypto::BASE64url::encode(
      artools::crypto::BASE64url::CodingDataType(idHash.begin(), idHash.end()),
      _id);

  // --- Serialise the transaction to JSON ---------------------------------
  rapidjson::Document doc;
  doc.SetObject();
  rapidjson::Document::AllocatorType &alloc = doc.GetAllocator();

  doc.AddMember("format", 2, alloc);
  doc.AddMember("id", rapidjson::Value(_id.c_str(), alloc), alloc);
  doc.AddMember("last_tx", rapidjson::Value(lastTx.c_str(), alloc), alloc);
  doc.AddMember("owner", rapidjson::Value(owner.c_str(), alloc), alloc);

  rapidjson::Value tagsArr(rapidjson::kArrayType);
  for (const auto &tag : tags) {
    rapidjson::Value tagObj(rapidjson::kObjectType);
    tagObj.AddMember("name", rapidjson::Value(tag.first.c_str(), alloc), alloc);
    tagObj.AddMember("value", rapidjson::Value(tag.second.c_str(), alloc),
                     alloc);
    tagsArr.PushBack(tagObj, alloc);
  }
  doc.AddMember("tags", tagsArr, alloc);

  doc.AddMember("target", rapidjson::Value(target.c_str(), alloc), alloc);
  doc.AddMember("quantity", rapidjson::Value(quantityStr.c_str(), alloc), alloc);
  doc.AddMember("data_root", rapidjson::Value(dataRoot.c_str(), alloc), alloc);
  doc.AddMember("data", rapidjson::Value("", alloc), alloc);
  doc.AddMember("data_size", rapidjson::Value(dataSize.c_str(), alloc), alloc);
  doc.AddMember("reward", rapidjson::Value(rewardStr.c_str(), alloc), alloc);
  doc.AddMember("signature", rapidjson::Value(_signature.c_str(), alloc), alloc);

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  doc.Accept(writer);
  _json = buffer.GetString();
}

bool Transaction::submit() const { return submit(kHost, kPort); }

bool Transaction::submit(const std::string &host,
                         const std::string &port) const {

  std::string request =
      "POST /tx HTTP/1.1\r\n"
      "Host: " + host + "\r\n"
      "User-Agent: ar-tools/" ARTOOLS_VERSION "\r\n"
      "Accept: application/json\r\n"
      "Content-Type: application/json\r\n"
      "Content-Length: " + std::to_string(_json.size()) + "\r\n"
      "Connection: close\r\n"
      "\r\n" +
      _json;

  artools::transport::TLSClient client(host, port);
  BinaryContainer_t reqBin(request.begin(), request.end());
  client.write(reqBin);

  BinaryContainer_t response;
  client.read(response);

  // A successful submission returns HTTP 200 with body "OK"; anything else
  // (including an unparseable response) is an error.
  artools::transport::TLSClient::ensureHttpSuccess(response, "Transaction");

  return true;
}

} // namespace protocol
} // namespace artools