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
#include <vector>

#include "types.h"

namespace artools {
namespace crypto {

/**
 * @brief Implements the Arweave deepHash algorithm.
 *
 * Computes a merkle root over a nested structure of byte blobs and lists,
 * matching the reference implementation in arweave-js
 * (src/common/lib/deepHash). Used for Arweave transaction signing and for
 * ANS-104 DataItem signing.
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
 */
class DeepHash {
public:
  using BinaryContainer_t = artools::types::BinaryContainer_t;

  /**
   * @brief A node in the deepHash input tree.
   *
   * A node is either a byte blob or a list of child nodes.
   */
  struct Node {
    bool isList;
    BinaryContainer_t blob;             // valid when !isList
    std::vector<Node> children;         // valid when isList

    static Node makeBlob(const BinaryContainer_t &b) {
      Node n;
      n.isList = false;
      n.blob = b;
      return n;
    }
    static Node makeBlob(const std::string &s) {
      return makeBlob(BinaryContainer_t(s.begin(), s.end()));
    }
    static Node makeList(std::vector<Node> children) {
      Node n;
      n.isList = true;
      n.children = std::move(children);
      return n;
    }
  };

  /**
   * @brief Computes the deepHash digest of a node.
   * @param node the node to hash
   * @return     the 48-byte SHA-384 digest
   */
  static BinaryContainer_t hash(const Node &node);
};

} // namespace crypto
} // namespace artools