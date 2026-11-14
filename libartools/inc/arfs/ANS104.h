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
#include <utility>
#include <vector>

#include "crypto/deep_hash.h"
#include "types.h"

namespace artools {
namespace arfs {

/**
 * @brief Implements the ANS-104 DataItem format (arbundles).
 *
 * ANS-104 (https://github.com/ArweaveTeam/arweave-standards/blob/ans104/ans/ANS-104.md)
 * defines the binary DataItem format used for bundling Arweave transactions.
 * ArFS v2 drive signatures sign the deepHash of a DataItem's signature data.
 *
 * This class provides the two pieces needed for that signature:
 *  - the Avro tag serialization (arbundles `serializeTags`), and
 *  - the signature-data deepHash (arbundles `getSignatureData`).
 */
class ANS104 {
public:
  using BinaryContainer_t = artools::types::BinaryContainer_t;
  // A single tag: {name, value}.
  using Tag = std::pair<std::string, std::string>;

  /**
   * @brief Serializes a list of tags into the Avro tag bytes used by
   *        ANS-104 DataItems (arbundles `serializeTags`).
   *
   * The encoding matches arbundles' AVSCTap:
   *   writeLong(count); for each tag: writeString(name), writeString(value);
   *   writeLong(0);
   * where writeLong is a ZigZag variable-length integer and writeString is a
   * length-prefixed UTF-8 string.
   *
   * @param tags the tags to serialize
   * @return     the Avro-encoded tag bytes (empty for no tags)
   */
  static std::vector<unsigned char> encodeTags(const std::vector<Tag> &tags);

  /**
   * @brief Computes the deepHash of a DataItem's signature data.
   *
   * Matches arbundles' `getSignatureData()`:
   *   deepHash(["dataitem", "1", signatureType, owner, target, anchor,
   *             avroTags, data])
   *
   * @param signatureType the signature type as a string (e.g. "1" for RSA)
   * @param owner         the raw owner bytes (e.g. the RSA modulus)
   * @param target        the raw target bytes (empty when absent)
   * @param anchor        the raw anchor bytes (empty when absent)
   * @param tags          the tags to include (Avro-encoded internally)
   * @param data          the raw data bytes
   * @return              the 48-byte SHA-384 deepHash digest
   */
  static BinaryContainer_t getSignatureData(
      const std::string &signatureType, const BinaryContainer_t &owner,
      const BinaryContainer_t &target, const BinaryContainer_t &anchor,
      const std::vector<Tag> &tags, const BinaryContainer_t &data);
};

} // namespace arfs
} // namespace artools
