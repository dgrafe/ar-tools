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

#include <array>
#include <cstddef>
#include <string>

namespace artools {
namespace crypto {
class SHA256 {

public:
  static const auto DigestLength = 32;
  using HashType = std::array<unsigned char, DigestLength>;

  SHA256(const unsigned char *data, std::size_t length);
  SHA256() = delete;
  SHA256(SHA256 &) = delete;
  SHA256(SHA256 &&) = delete;

  HashType getHash() { return _hash; }
  std::string asHex();

private:
  HashType _hash;
};
} // end of namespace crypto
} // end of namespace artools
