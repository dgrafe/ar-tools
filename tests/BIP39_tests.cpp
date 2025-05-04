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

#include <crypto/Bip39.h>
#include <gtest/gtest.h>

// Test vectors from
// https://github.com/trezor/python-mnemonic/blob/master/vectors.json
TEST(BIP39_tests, Trezor_Vector1) {
  artools::crypto::BIP39 instance;

  instance.initFromMnemonicString(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon about",
      "TREZOR");
  ASSERT_EQ(instance.getRootSeedAsHex(),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f"
            "09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
}

TEST(BIP39_tests, Trezor_Vector2) {
  artools::crypto::BIP39 instance;

  instance.initFromMnemonicString("legal winner thank year wave sausage worth "
                                  "useful legal winner thank yellow",
                                  "TREZOR");
  ASSERT_EQ(instance.getRootSeedAsHex(),
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa4"
            "57fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607");
}

TEST(BIP39_tests, Trezor_Vector3) {
  artools::crypto::BIP39 instance;

  instance.initFromMnemonicString("letter advice cage absurd amount doctor "
                                  "acoustic avoid letter advice cage above",
                                  "TREZOR");
  ASSERT_EQ(instance.getRootSeedAsHex(),
            "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa"
            "280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8");
}

TEST(BIP39_tests, Trezor_Vector4) {
  artools::crypto::BIP39 instance;

  instance.initFromMnemonicString(
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", "TREZOR");
  ASSERT_EQ(instance.getRootSeedAsHex(),
            "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a1333"
            "2572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069");
}

TEST(BIP39_tests, Trezor_Vector5) {
  artools::crypto::BIP39 instance;

  instance.initFromMnemonicString("scheme spot photo card baby mountain device "
                                  "kick cradle pact join borrow",
                                  "TREZOR");
  ASSERT_EQ(instance.getRootSeedAsHex(),
            "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca0"
            "5aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612");
}

TEST(BIP39_tests, hin_und_her_test) {
  artools::crypto::BIP39 create;
  artools::crypto::BIP39 restore;

  auto mnemonic_string_created = create.getMnemonicString();
  auto root_seed_created = create.getRootSeedAsHex();

  ASSERT_EQ(restore.initFromMnemonicString(mnemonic_string_created), true);
  ASSERT_EQ(root_seed_created, restore.getRootSeedAsHex());
}
