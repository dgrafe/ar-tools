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

#include <cstdio>
#include <filesystem>
#include <crypto/base64url.h>
#include <crypto/bip39.h>
#include <crypto/jwk.h>
#include <crypto/pem.h>
#include <crypto/sha256.h>
#include <gtest/gtest.h>
#include <protocol/Transaction.h>
#include <wallet.h>

// Set by tests/main.cpp to the test binary directory.
extern std::string g_testBinDir;

// Tests for the Arweave v2 token-transfer transaction.
//
// A deterministic wallet (recovered from a fixed BIP-39 mnemonic) is used so
// the tests are reproducible. The signature is verified against the wallet's
// public key, and the transaction id is checked to be the SHA-256 of the
// signature, as required by the Arweave specification.
namespace {

constexpr const char *kMnemonic =
    "during treat crunch squirrel erosion minor sing fortune settle drip "
    "spice prepare";

// A fixed recipient address and replay anchor.
constexpr const char *kTarget =
    "WxLW1MWiSWcuwxmvzokahENCbWurzvwcsukFTGrqwdw";
constexpr const char *kLastTx =
    "knQ5gf4Z_3i-NQ6_jFT2a9zShUOHh4lDZoAUzsWMxMQ";

artools::wallet::WalletInstance_t makeWallet() {
  artools::crypto::BIP39 bip39;
  if (!bip39.initFromMnemonicString(kMnemonic))
    return nullptr;
  artools::crypto::JWK jwk(bip39);
  return artools::wallet::create(jwk);
}

} // namespace

TEST(Transaction_tests, SignatureVerifies) {
  auto wallet = makeWallet();
  ASSERT_NE(wallet, nullptr);

  artools::protocol::Transaction tx(*wallet, kTarget, 1000000000000ULL,
                                    321179212ULL, kLastTx);

  // The signature must verify against the wallet's public key over the signed
  // data (the deepHash merkle root).
  EXPECT_TRUE(wallet->verify(tx.getSignatureData(), tx.getSignature()));
}

TEST(Transaction_tests, IdIsSha256OfSignature) {
  auto wallet = makeWallet();
  ASSERT_NE(wallet, nullptr);

  artools::protocol::Transaction tx(*wallet, kTarget, 1000000000000ULL,
                                    321179212ULL, kLastTx);

  // id = base64url(SHA-256(signature)).
  artools::crypto::BASE64url::CodingDataType sigBytes;
  ASSERT_TRUE(
      artools::crypto::BASE64url::decode(tx.getSignature(), sigBytes));
  auto idHash = artools::crypto::SHA256(sigBytes.data(), sigBytes.size())
                    .getHash();
  std::string expectedId;
  ASSERT_TRUE(artools::crypto::BASE64url::encode(
      artools::crypto::BASE64url::CodingDataType(idHash.begin(), idHash.end()),
      expectedId));

  EXPECT_EQ(tx.getId(), expectedId);
}

TEST(Transaction_tests, JsonContainsFields) {
  auto wallet = makeWallet();
  ASSERT_NE(wallet, nullptr);

  artools::protocol::Transaction tx(*wallet, kTarget, 1000000000000ULL,
                                    321179212ULL, kLastTx,
                                    {{"App-Name", "ar-tools"}});

  std::string json = tx.getJson();
  EXPECT_NE(json.find("\"format\":2"), std::string::npos);
  EXPECT_NE(json.find("\"target\":\"" + std::string(kTarget) + "\""),
            std::string::npos);
  EXPECT_NE(json.find("\"quantity\":\"1000000000000\""), std::string::npos);
  EXPECT_NE(json.find("\"reward\":\"321179212\""), std::string::npos);
  EXPECT_NE(json.find("\"last_tx\":\"" + std::string(kLastTx) + "\""),
            std::string::npos);
  EXPECT_NE(json.find("\"data_size\":\"0\""), std::string::npos);
  EXPECT_NE(json.find("\"data_root\":\"\""), std::string::npos);
  EXPECT_NE(json.find("\"App-Name\""), std::string::npos);
  EXPECT_NE(json.find("\"ar-tools\""), std::string::npos);
  EXPECT_NE(json.find("\"signature\":\""), std::string::npos);
  EXPECT_NE(json.find("\"id\":\""), std::string::npos);
  EXPECT_NE(json.find("\"owner\":\""), std::string::npos);
}

TEST(Transaction_tests, SignatureDataIs48Bytes) {
  auto wallet = makeWallet();
  ASSERT_NE(wallet, nullptr);

  artools::protocol::Transaction tx(*wallet, kTarget, 1000000000000ULL,
                                    321179212ULL, kLastTx);

  // The signed data is the SHA-384 deepHash root: 48 bytes.
  EXPECT_EQ(tx.getSignatureData().size(), 48u);
}

TEST(Transaction_tests, OwnerIsBase64urlModulus) {
  auto wallet = makeWallet();
  ASSERT_NE(wallet, nullptr);

  artools::protocol::Transaction tx(*wallet, kTarget, 1000000000000ULL,
                                    321179212ULL, kLastTx);

  // The owner field must be the base64url-encoded RSA modulus n (the JWK "n"
  // value), not a hex encoding.
  std::string json = tx.getJson();
  std::string expectedOwner;
  ASSERT_TRUE(artools::crypto::BASE64url::encode(
      wallet->getPEM().get_n(), expectedOwner));

  EXPECT_NE(json.find("\"owner\":\"" + expectedOwner + "\""),
            std::string::npos);
}

// Reference test against the arweave-js test fixture
// (test/fixtures/arweave-keyfile-fOVzBRTBnyt4VrUUYadBH8yras_-jhgpmNgg-5b3vEw.json).
// The expected signature data was computed with the reference deepHash
// implementation for a token transfer with the fixture key:
//   format="2", owner=jwk.n, target="", quantity="0", reward="100000000000000",
//   last_tx="", tags=[], data_size="0", data_root=""
TEST(Transaction_tests, SignatureDataMatchesArweaveJsReference) {
  // Resolve the fixture path relative to the test binary directory.
  std::filesystem::path binDir = std::filesystem::path(g_testBinDir).parent_path();
  std::filesystem::path fixturePath =
      binDir / "fixtures" / "arweave-keyfile.json";

  artools::crypto::JWK jwk(fixturePath.string());
  auto wallet = artools::wallet::create(jwk);
  ASSERT_NE(wallet, nullptr);

  artools::protocol::Transaction tx(*wallet, "", 0, 100000000000000ULL, "");

  // Expected deepHash root (hex) from the reference implementation.
  const std::string expectedHex =
      "deb9eaaec65296b3f9857395a2cb2195616c3aa250425f800bf1a40b0e7f9ef9e5e8d2b006fc834ad24a089f821bd170";

  // Convert the signature data to hex for comparison.
  std::string actualHex;
  for (auto b : tx.getSignatureData()) {
    char buf[3];
    std::snprintf(buf, sizeof(buf), "%02x", b);
    actualHex += buf;
  }

  EXPECT_EQ(actualHex, expectedHex);
}