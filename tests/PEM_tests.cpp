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

#include <crypto/pem.h>
#include <crypto/sha256.h>
#include <gtest/gtest.h>

TEST(PEMl_tests, Test_Vector1) {

  std::string input("Das Reh springt hoch, das Reh springt weit");
  artools::crypto::PEM::BinaryContainer_t plaintext(input.begin(), input.end());
  std::string sig;

  artools::crypto::PEM pem_instance;
  ASSERT_EQ(true, pem_instance.sign(plaintext, sig));
  ASSERT_EQ(true, pem_instance.verify(plaintext, sig));
}