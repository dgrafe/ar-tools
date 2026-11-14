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

#include <crypto/aesgcm.h>
#include <crypto/hkdf.h>

// Unit tests for the HKDF and AESGCM crypto helpers using published test
// vectors (RFC 5869 and NIST CAVP).

namespace {

// Converts a hex string to a byte container.
artools::crypto::HKDF::BinaryContainer_t fromHex(const std::string &hex) {
  artools::crypto::HKDF::BinaryContainer_t bytes;
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    auto nibble = [](char c) -> unsigned char {
      if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
      if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
      if (c >= 'A' && c <= 'F') return static_cast<unsigned char>(c - 'A' + 10);
      return 0;
    };
    bytes.push_back(static_cast<unsigned char>((nibble(hex[i]) << 4) |
                                               nibble(hex[i + 1])));
  }
  return bytes;
}

// Converts a byte container to a lowercase hex string.
std::string toHex(const artools::crypto::HKDF::BinaryContainer_t &bytes) {
  static const char *kDigits = "0123456789abcdef";
  std::string hex;
  for (auto b : bytes) {
    hex += kDigits[(b >> 4) & 0xf];
    hex += kDigits[b & 0xf];
  }
  return hex;
}

} // namespace

// RFC 5869 Test Case 1 (SHA-256).
TEST(Crypto_tests, HKDF_RFC5869_TestCase1) {
  auto ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  auto salt = fromHex("000102030405060708090a0b0c");
  auto info = fromHex("f0f1f2f3f4f5f6f7f8f9");

  auto okm = artools::crypto::HKDF::derive(ikm, salt, info, 42);

  EXPECT_EQ(toHex(okm),
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865");
}

// RFC 5869 Test Case 2 (SHA-256): longer inputs.
TEST(Crypto_tests, HKDF_RFC5869_TestCase2) {
  auto ikm = fromHex(
      "000102030405060708090a0b0c0d0e0f"
      "101112131415161718191a1b1c1d1e1f"
      "202122232425262728292a2b2c2d2e2f"
      "303132333435363738393a3b3c3d3e3f"
      "404142434445464748494a4b4c4d4e4f");
  auto salt = fromHex(
      "606162636465666768696a6b6c6d6e6f"
      "707172737475767778797a7b7c7d7e7f"
      "808182838485868788898a8b8c8d8e8f"
      "909192939495969798999a9b9c9d9e9f"
      "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
  auto info = fromHex(
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
      "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
      "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
      "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

  auto okm = artools::crypto::HKDF::derive(ikm, salt, info, 82);

  EXPECT_EQ(toHex(okm),
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87");
}

// RFC 5869 Test Case 3 (SHA-256): zero-length salt and info.
TEST(Crypto_tests, HKDF_RFC5869_TestCase3) {
  auto ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

  auto okm = artools::crypto::HKDF::derive(ikm, {}, {}, 42);

  EXPECT_EQ(toHex(okm),
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8");
}

// AES-256-GCM round trip (verified with an independent implementation).
TEST(Crypto_tests, AESGCM_RoundTrip) {
  auto key = fromHex("00000000000000000000000000000000"
                     "00000000000000000000000000000000");
  auto iv = fromHex("000000000000000000000000");
  auto ciphertext = fromHex(
      "cea7403d4d606b6e074ec5d3baf39d18"
      "d0d1c8a799996bf0265b98b5d48ab919"); // ciphertext || tag

  std::string plaintext =
      artools::crypto::AESGCM::decrypt(key, iv, ciphertext);

  EXPECT_EQ(toHex(artools::crypto::HKDF::BinaryContainer_t(
                plaintext.begin(), plaintext.end())),
            "00000000000000000000000000000000");
}

// Decryption with a wrong key must fail (GCM authentication).
TEST(Crypto_tests, AESGCM_WrongKeyFails) {
  auto key = fromHex("00000000000000000000000000000000"
                     "00000000000000000000000000000000");
  auto iv = fromHex("000000000000000000000000");
  auto ciphertext = fromHex(
      "cea7403d4d606b6e074ec5d3baf39d18"
      "d0d1c8a799996bf0265b98b5d48ab919");

  // Wrong key (all 0x11).
  auto wrongKey = fromHex("11111111111111111111111111111111"
                          "11111111111111111111111111111111");
  EXPECT_THROW(artools::crypto::AESGCM::decrypt(wrongKey, iv, ciphertext),
               std::runtime_error);
}

// Invalid key/IV lengths must be rejected.
TEST(Crypto_tests, AESGCM_InvalidLengths) {
  auto key = fromHex("00112233445566778899aabbccddeeff"); // 16 bytes
  auto iv = fromHex("cafebabefacedbaddecaf888");
  auto ciphertext = fromHex("00112233445566778899aabbccddeeff"
                            "00112233445566778899aabbccddeeff");

  EXPECT_THROW(artools::crypto::AESGCM::decrypt(key, iv, ciphertext),
               std::runtime_error);
}
