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

#include <crypto/Base64url.h>
#include <gtest/gtest.h>

TEST(BASE64url_tests, Test_Vector1) {

  std::string input("Das Reh springt hoch, das Reh springt weit");
  std::string encoded;
  artools::crypto::BASE64url::CodingDataType decoded;

  artools::crypto::BASE64url::encode(
      artools::crypto::BASE64url::CodingDataType(input.begin(), input.end()),
      encoded);
  ASSERT_EQ("RGFzIFJlaCBzcHJpbmd0IGhvY2gsIGRhcyBSZWggc3ByaW5ndCB3ZWl0",
            encoded);
  artools::crypto::BASE64url::decode(encoded, decoded);
  ASSERT_EQ(input, std::string(decoded.begin(), decoded.end()));
}

TEST(BASE64url_tests, Test_Vector2) {

  std::string input(
      "Home is where the heart is, but the stars are made of latinum");
  std::string encoded;
  artools::crypto::BASE64url::CodingDataType decoded;

  artools::crypto::BASE64url::encode(
      artools::crypto::BASE64url::CodingDataType(input.begin(), input.end()),
      encoded);
  ASSERT_EQ("SG9tZSBpcyB3aGVyZSB0aGUgaGVhcnQgaXMsIGJ1dCB0aGUgc3RhcnMgYXJlIG1hZG"
            "Ugb2YgbGF0aW51bQ",
            encoded);
  artools::crypto::BASE64url::decode(encoded, decoded);
  ASSERT_EQ(input, std::string(decoded.begin(), decoded.end()));
}

TEST(BASE64url_tests, Test_Vector3) {

  std::string input("Vater Morgana, Eska Lation, Kalle Fornien");
  std::string encoded;
  artools::crypto::BASE64url::CodingDataType decoded;

  artools::crypto::BASE64url::encode(
      artools::crypto::BASE64url::CodingDataType(input.begin(), input.end()),
      encoded);
  ASSERT_EQ("VmF0ZXIgTW9yZ2FuYSwgRXNrYSBMYXRpb24sIEthbGxlIEZvcm5pZW4", encoded);
  artools::crypto::BASE64url::decode(encoded, decoded);
  ASSERT_EQ(input, std::string(decoded.begin(), decoded.end()));
}

TEST(BASE64url_tests, Test_Vector4) {

  std::string input("<<???>>");
  std::string encoded;
  artools::crypto::BASE64url::CodingDataType decoded;

  artools::crypto::BASE64url::encode(
      artools::crypto::BASE64url::CodingDataType(input.begin(), input.end()),
      encoded);
  ASSERT_EQ("PDw_Pz8-Pg", encoded);
  artools::crypto::BASE64url::decode(encoded, decoded);
  ASSERT_EQ(input, std::string(decoded.begin(), decoded.end()));
}

// RSA public exponent (binary) 0x010001 encoded as base64url
TEST(BASE64url_tests, Test_Vector5) {

  artools::crypto::BASE64url::CodingDataType input = {0x01, 0x00, 0x01};
  std::string encoded;
  artools::crypto::BASE64url::CodingDataType decoded;

  artools::crypto::BASE64url::encode(input, encoded);
  ASSERT_EQ("AQAB", encoded);
  artools::crypto::BASE64url::decode(encoded, decoded);
  ASSERT_EQ(input, decoded);
}
