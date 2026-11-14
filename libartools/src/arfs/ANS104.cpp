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

namespace artools {
namespace arfs {

namespace {

// Appends a ZigZag-encoded variable-length integer to `out`, matching the
// Avro `writeLong` used by arbundles' AVSCTap (tags.js):
//   m = n >= 0 ? n << 1 : (~n << 1) | 1;
//   do { buf[pos] = m & 0x7f; m >>= 7; } while (m && (buf[pos++] |= 0x80));
void avroWriteLong(std::vector<unsigned char> &out, int64_t n) {
  uint64_t m = n >= 0 ? static_cast<uint64_t>(n) << 1
                      : (static_cast<uint64_t>(~n) << 1) | 1;
  do {
    unsigned char b = static_cast<unsigned char>(m & 0x7f);
    m >>= 7;
    if (m) b |= 0x80;
    out.push_back(b);
  } while (m);
}

// Appends an Avro string (length-prefixed UTF-8) to `out`, matching
// arbundles' `writeString`.
void avroWriteString(std::vector<unsigned char> &out, const std::string &s) {
  avroWriteLong(out, static_cast<int64_t>(s.size()));
  out.insert(out.end(), s.begin(), s.end());
}

} // namespace

std::vector<unsigned char> ANS104::encodeTags(const std::vector<Tag> &tags) {
  std::vector<unsigned char> out;
  if (tags.empty()) return out;
  avroWriteLong(out, static_cast<int64_t>(tags.size()));
  for (const auto &tag : tags) {
    avroWriteString(out, tag.first);
    avroWriteString(out, tag.second);
  }
  avroWriteLong(out, 0);
  return out;
}

ANS104::BinaryContainer_t ANS104::getSignatureData(
    const std::string &signatureType, const BinaryContainer_t &owner,
    const BinaryContainer_t &target, const BinaryContainer_t &anchor,
    const std::vector<Tag> &tags, const BinaryContainer_t &data) {
  auto avroTags = encodeTags(tags);
  artools::crypto::DeepHash::Node dataItem =
      artools::crypto::DeepHash::Node::makeList({
          artools::crypto::DeepHash::Node::makeBlob("dataitem"),
          artools::crypto::DeepHash::Node::makeBlob("1"),
          artools::crypto::DeepHash::Node::makeBlob(signatureType),
          artools::crypto::DeepHash::Node::makeBlob(owner),
          artools::crypto::DeepHash::Node::makeBlob(target),
          artools::crypto::DeepHash::Node::makeBlob(anchor),
          artools::crypto::DeepHash::Node::makeBlob(avroTags),
          artools::crypto::DeepHash::Node::makeBlob(data),
      });
  return artools::crypto::DeepHash::hash(dataItem);
}

} // namespace arfs
} // namespace artools
