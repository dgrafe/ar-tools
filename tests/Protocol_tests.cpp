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

#include <protocol/GetBalance.h>
#include <protocol/GetPrice.h>
#include <protocol/GetTurboBalance.h>
#include <protocol/GetTxAnchor.h>

// Unit tests for the protocol classes' parsing helpers. These test the
// parsing and path-building logic without any network access.

TEST(Protocol_tests, GetBalance_parseBalance) {
  EXPECT_EQ(artools::protocol::GetBalance::parseBalance("9554799572505"), 9554799572505ULL);
  EXPECT_EQ(artools::protocol::GetBalance::parseBalance("0"), 0ULL);
  EXPECT_EQ(artools::protocol::GetBalance::parseBalance(""), 0ULL);
  // Parsing stops at the first non-digit.
  EXPECT_EQ(artools::protocol::GetBalance::parseBalance("123abc"), 123ULL);
  EXPECT_EQ(artools::protocol::GetBalance::parseBalance("abc123"), 0ULL);
}

TEST(Protocol_tests, GetPrice_parsePrice) {
  EXPECT_EQ(artools::protocol::GetPrice::parsePrice("42953872"), 42953872ULL);
  EXPECT_EQ(artools::protocol::GetPrice::parsePrice("0"), 0ULL);
  EXPECT_EQ(artools::protocol::GetPrice::parsePrice(""), 0ULL);
  EXPECT_EQ(artools::protocol::GetPrice::parsePrice("10000\n"), 10000ULL);
}

TEST(Protocol_tests, GetPrice_buildPath) {
  // Token transfer with no data.
  EXPECT_EQ(artools::protocol::GetPrice::buildPath(0, "abc"), "/price/0/abc");
  // Data upload with no target.
  EXPECT_EQ(artools::protocol::GetPrice::buildPath(123, ""), "/price/123");
  // Data upload with target.
  EXPECT_EQ(artools::protocol::GetPrice::buildPath(123, "abc"),
            "/price/123/abc");
}

TEST(Protocol_tests, GetTurboBalance_parseBalance) {
  EXPECT_EQ(artools::protocol::GetTurboBalance::parseBalance(
                R"({"winc":"412620266518","balance":"412620266518",)"
                R"("effectiveBalance":"412620266518"})"),
            412620266518ULL);
  EXPECT_EQ(artools::protocol::GetTurboBalance::parseBalance(
                R"({"effectiveBalance":"0"})"),
            0ULL);
  // Missing field must throw.
  EXPECT_THROW(artools::protocol::GetTurboBalance::parseBalance(R"({})"),
               std::runtime_error);
  EXPECT_THROW(artools::protocol::GetTurboBalance::parseBalance("not json"),
               std::runtime_error);
}

TEST(Protocol_tests, GetTxAnchor_parseAnchor) {
  EXPECT_EQ(artools::protocol::GetTxAnchor::parseAnchor("abc123"),
            "abc123");
  // Empty payload must throw.
  EXPECT_THROW(artools::protocol::GetTxAnchor::parseAnchor(""),
               std::runtime_error);
}
