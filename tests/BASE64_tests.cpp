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

#include <crypto/Base64.h>
#include <gtest/gtest.h>
#include <string>

// Test vectors from rfc4648
TEST(BASE64_tests, rfc4648_1) {

  std::string input("");
  std::string encoded;
  artools::crypto::BASE64::CodingDataType decoded;

  artools::crypto::BASE64::encode(
      artools::crypto::BASE64::CodingDataType(input.begin(), input.end()),
      encoded);
  ASSERT_EQ("", encoded);
  artools::crypto::BASE64::decode(encoded, decoded);
  ASSERT_EQ(input, std::string(decoded.begin(), decoded.end()));
}

TEST(BASE64_tests, rfc4648_2) {

  std::string input("f");
  std::string encoded;
  artools::crypto::BASE64::CodingDataType decoded;

  artools::crypto::BASE64::encode(
      artools::crypto::BASE64::CodingDataType(input.begin(), input.end()),
      encoded);
  ASSERT_EQ("Zg==", encoded);
  artools::crypto::BASE64::decode(encoded, decoded);
  ASSERT_EQ(input, std::string(decoded.begin(), decoded.end()));
}

TEST(BASE64_tests, rfc4648_3) {

  std::string input("fo");
  std::string encoded;
  artools::crypto::BASE64::CodingDataType decoded;

  artools::crypto::BASE64::encode(
      artools::crypto::BASE64::CodingDataType(input.begin(), input.end()),
      encoded);
  ASSERT_EQ("Zm8=", encoded);
  artools::crypto::BASE64::decode(encoded, decoded);
  ASSERT_EQ(input, std::string(decoded.begin(), decoded.end()));
}

TEST(BASE64_tests, rfc4648_4) {

  std::string input("foo");
  std::string encoded;
  artools::crypto::BASE64::CodingDataType decoded;

  artools::crypto::BASE64::encode(
      artools::crypto::BASE64::CodingDataType(input.begin(), input.end()),
      encoded);
  ASSERT_EQ("Zm9v", encoded);
  artools::crypto::BASE64::decode(encoded, decoded);
  ASSERT_EQ(input, std::string(decoded.begin(), decoded.end()));
}

TEST(BASE64_tests, rfc4648_5) {

  std::string input("foob");
  std::string encoded;
  artools::crypto::BASE64::CodingDataType decoded;

  artools::crypto::BASE64::encode(
      artools::crypto::BASE64::CodingDataType(input.begin(), input.end()),
      encoded);
  ASSERT_EQ("Zm9vYg==", encoded);
  artools::crypto::BASE64::decode(encoded, decoded);
  ASSERT_EQ(input, std::string(decoded.begin(), decoded.end()));
}

TEST(BASE64_tests, rfc4648_6) {

  std::string input("fooba");
  std::string encoded;
  artools::crypto::BASE64::CodingDataType decoded;

  artools::crypto::BASE64::encode(
      artools::crypto::BASE64::CodingDataType(input.begin(), input.end()),
      encoded);
  ASSERT_EQ("Zm9vYmE=", encoded);
  artools::crypto::BASE64::decode(encoded, decoded);
  ASSERT_EQ(input, std::string(decoded.begin(), decoded.end()));
}

TEST(BASE64_tests, rfc4648_7) {

  std::string input("foobar");
  std::string encoded;
  artools::crypto::BASE64::CodingDataType decoded;

  artools::crypto::BASE64::encode(
      artools::crypto::BASE64::CodingDataType(input.begin(), input.end()),
      encoded);
  ASSERT_EQ("Zm9vYmFy", encoded);
  artools::crypto::BASE64::decode(encoded, decoded);
  ASSERT_EQ(input, std::string(decoded.begin(), decoded.end()));
}

TEST(BASE64_tests, custom_1) {

  std::string input("<<???>>");
  std::string encoded;
  artools::crypto::BASE64::CodingDataType decoded;

  artools::crypto::BASE64::encode(
      artools::crypto::BASE64::CodingDataType(input.begin(), input.end()),
      encoded);
  ASSERT_EQ("PDw/Pz8+Pg==", encoded);
  artools::crypto::BASE64::decode(encoded, decoded);
  ASSERT_EQ(input, std::string(decoded.begin(), decoded.end()));
}