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

#include <array>
#include <crypto/SHA256.h>
#include <cstdint>
#include <gtest/gtest.h>

// NIST Test vectors from
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
TEST(SHA256_tests, NIST_1) {
  std::array<std::uint8_t, 3> input = {0xb4, 0x19, 0x0e};
  artools::crypto::SHA256 nist(input.data(), input.size());

  ASSERT_EQ(nist.asHex(),
            "dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2");
}

TEST(SHA256_tests, NIST_2) {
  std::array<std::uint8_t, 14> input = {0xaf, 0x39, 0x7a, 0x8b, 0x8d,
                                        0xd7, 0x3a, 0xb7, 0x02, 0xce,
                                        0x8e, 0x53, 0xaa, 0x9f};
  artools::crypto::SHA256 nist(input.data(), input.size());

  ASSERT_EQ(nist.asHex(),
            "d189498a3463b18e846b8ab1b41583b0b7efc789dad8a7fb885bbf8fb5b45c5c");
}

TEST(SHA256_tests, NIST_empty) {
  artools::crypto::SHA256 nist(nullptr, 0);

  ASSERT_EQ(nist.asHex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}