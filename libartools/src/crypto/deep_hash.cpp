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

#include "crypto/deep_hash.h"

#include "crypto/sha384.h"

namespace artools {
namespace crypto {

namespace {

using Hash384 = artools::crypto::SHA384::HashType;

Hash384 sha384(const DeepHash::BinaryContainer_t &data) {
  return artools::crypto::SHA384(data.data(), data.size()).getHash();
}

Hash384 sha384(const std::string &str) {
  return artools::crypto::SHA384(
             reinterpret_cast<const unsigned char *>(str.data()), str.size())
      .getHash();
}

DeepHash::BinaryContainer_t concat(const DeepHash::BinaryContainer_t &a,
                                   const DeepHash::BinaryContainer_t &b) {
  DeepHash::BinaryContainer_t ret;
  ret.reserve(a.size() + b.size());
  ret.insert(ret.end(), a.begin(), a.end());
  ret.insert(ret.end(), b.begin(), b.end());
  return ret;
}

DeepHash::BinaryContainer_t toContainer(const Hash384 &hash) {
  return DeepHash::BinaryContainer_t(hash.begin(), hash.end());
}

} // namespace

DeepHash::BinaryContainer_t DeepHash::hash(const Node &node) {
  if (!node.isList) {
    // Blob: SHA384( SHA384("blob" || byteLength) || SHA384(data) )
    std::string tag = "blob" + std::to_string(node.blob.size());
    Hash384 tagHash = sha384(tag);
    Hash384 dataHash = sha384(node.blob);
    return toContainer(sha384(concat(toContainer(tagHash),
                                     toContainer(dataHash))));
  }

  // List: fold the items into a cumulative hash chain.
  std::string tag = "list" + std::to_string(node.children.size());
  Hash384 acc = sha384(tag);

  for (const auto &child : node.children) {
    // hash(child) already returns the 48-byte SHA-384 digest.
    auto childHash = hash(child);
    acc = sha384(concat(toContainer(acc), childHash));
  }
  return toContainer(acc);
}

} // namespace crypto
} // namespace artools