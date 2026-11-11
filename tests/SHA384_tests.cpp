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
#include <crypto/SHA384.h>
#include <cstdint>
#include <gtest/gtest.h>

// NIST Test vectors from
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
TEST(SHA384_tests, NIST_abc) {
  std::array<std::uint8_t, 3> input = {0x61, 0x62, 0x63}; // "abc"
  artools::crypto::SHA384 nist(input.data(), input.size());

  ASSERT_EQ(nist.asHex(),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7");
}

TEST(SHA384_tests, NIST_empty) {
  artools::crypto::SHA384 nist(nullptr, 0);

  ASSERT_EQ(nist.asHex(),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
}