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

#include <arfs/Drives.h>
#include <protocol/GetBalance.h>
#include <protocol/GetPrice.h>
#include <protocol/GetTurboBalance.h>
#include <protocol/GetTxAnchor.h>
#include <protocol/TopUpTurbo.h>

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

TEST(Protocol_tests, TopUpTurbo_buildClaimBody) {
  std::string body =
      artools::protocol::TopUpTurbo::buildClaimBody("tx123");
  EXPECT_NE(body.find("tx_id"), std::string::npos);
  EXPECT_NE(body.find("tx123"), std::string::npos);
}

TEST(Protocol_tests, TopUpTurbo_parseMessage) {
  EXPECT_EQ(artools::protocol::TopUpTurbo::parseMessage(
                R"({"message":"Transaction credited"})"),
            "Transaction credited");
  EXPECT_EQ(artools::protocol::TopUpTurbo::parseMessage(
                R"({"message":"Transaction pending"})"),
            "Transaction pending");
  // Missing field returns empty.
  EXPECT_EQ(artools::protocol::TopUpTurbo::parseMessage(R"({})"), "");
  EXPECT_EQ(artools::protocol::TopUpTurbo::parseMessage("not json"), "");
}

// ArFS drive helper tests (no network access).

TEST(Protocol_tests, Drives_buildQuery) {
  std::string q = artools::arfs::Drives::buildQuery("abc123");
  EXPECT_NE(q.find("abc123"), std::string::npos);
  EXPECT_NE(q.find("Entity-Type"), std::string::npos);
  EXPECT_NE(q.find("drive"), std::string::npos);
  // No cursor for the first page.
  EXPECT_EQ(q.find("after"), std::string::npos);

  std::string q2 = artools::arfs::Drives::buildQuery("abc123", "cursorXYZ");
  EXPECT_NE(q2.find("cursorXYZ"), std::string::npos);
}

TEST(Protocol_tests, Drives_parseDrives) {
  const std::string payload = R"({
    "data": {
      "transactions": {
        "edges": [
          {
            "node": {
              "id": "tx1",
              "block": { "timestamp": 1000, "height": 10 },
              "tags": [
                { "name": "Entity-Type", "value": "drive" },
                { "name": "Drive-Id", "value": "drive-1" },
                { "name": "Drive-Privacy", "value": "public" }
              ]
            }
          },
          {
            "node": {
              "id": "tx2",
              "block": { "timestamp": 2000, "height": 20 },
              "tags": [
                { "name": "Drive-Id", "value": "drive-2" },
                { "name": "Drive-Privacy", "value": "private" }
              ]
            }
          }
        ]
      }
    }
  })";

  auto drives = artools::arfs::Drives::parseDrives(payload);
  ASSERT_EQ(drives.size(), 2u);
  EXPECT_EQ(drives[0].txId, "tx1");
  EXPECT_EQ(drives[0].driveId, "drive-1");
  EXPECT_EQ(drives[0].privacy, "public");
  EXPECT_EQ(drives[0].timestamp, 1000u);
  EXPECT_EQ(drives[1].txId, "tx2");
  EXPECT_EQ(drives[1].driveId, "drive-2");
  EXPECT_EQ(drives[1].privacy, "private");

  // Invalid payload must throw.
  EXPECT_THROW(artools::arfs::Drives::parseDrives("not json"),
               std::runtime_error);
}

TEST(Protocol_tests, Drives_deduplicateByDriveId) {
  artools::arfs::Drive old1{"tx-old", "drive-1", "public", "", 1000};
  artools::arfs::Drive new1{"tx-new", "drive-1", "public", "", 2000};
  artools::arfs::Drive other{"tx-other", "drive-2", "private", "", 1500};

  auto dedup = artools::arfs::Drives::deduplicateByDriveId({old1, new1, other});
  ASSERT_EQ(dedup.size(), 2u);
  // Newest first.
  EXPECT_EQ(dedup[0].txId, "tx-new");
  EXPECT_EQ(dedup[0].driveId, "drive-1");
  EXPECT_EQ(dedup[1].txId, "tx-other");
}
