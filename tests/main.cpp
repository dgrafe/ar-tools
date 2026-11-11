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

#include <gtest/gtest.h>

#include <string>

// Directory of the test binary, used by tests to locate fixture files.
std::string g_testBinDir;

int main(int argc, char **argv) {
  if (argc > 0 && argv[0])
    g_testBinDir = argv[0];
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}