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

#include <crypto/base64url.h>
#include <crypto/bip39.h>
#include <crypto/jwk.h>
#include <crypto/pem.h>
#include <gtest/gtest.h>
#include <wallet.h>

// Deterministic wallet recovery from a BIP-39 mnemonic.
//
// The expected values below pin the bit-for-bit compatibility contract with
// js-human-crypto-keys: the same mnemonic must always reproduce the same key,
// and therefore the same wallet address.
namespace {

constexpr const char *kMnemonic =
    "during treat crunch squirrel erosion minor sing fortune settle drip "
    "spice prepare";

// base64url(SHA-256(n)) -- the Arweave wallet address / transaction owner.
constexpr const char *kExpectedPublicKey =
    "PIjtH0UfClkyrkuuX4h7S7X20EaLmRcY7JIgL0J8zk0";

// Expected JWK components (unpadded base64url, RFC 7515 alphabet).
constexpr const char *kExpectedN =
    "gUT0sX1Ro6dCnnIRVWt7ZClwNHve_ogCT5gtpuXfbC-7I4Lp4oSCrvLoGgP6nbrKD34LmVx6k7m3uxSY-xFb78FaqqKz0G6m3y4oVd1xYHoVqZ6N2UEn-Zr3dvZ3hsctz-TKERu8Z3BunqU9nB7pCtTS1G3skrEx3g1DZ19YLLnprPZK5SGG33iGOa0VrpzNDNAbsx0ZOf2RZv6GIduduBEuiC2GnVwyu67YpGJkvcch5j7tWaYgxqZlg4iQxJh4UL7ZJct2QgrCqFQKkqcTlW74aKqjHGPcMnieVIcIjoec_PyGYmc_4dOQPTmbW_ObAyUfl5_y5xTMyLog9ZrFjSqAxzAAGd6hvyxcfa1AA9-3PPERcHdKCRDlG4V47dgJ806YNYINACeHPlhUM8yQ7YIKma5lZs632SW_lqcFMSIN1FX_lLaiCagd5f8JYUUS4yRUUdLZUk1We-Bt4y7MmqsaxFwjWKgp1gbRvyut9i181SltvWSVW3rp5yf4aQXqrc_I3mvSzxF5_w6bZ4EMGPDaol8-Jm9ZfvINPuX4Jxk17jCJia68hWI8YORr5Byhnv0Qv56swMTV8u6fvkmDUNSMzwk83bY5rdV-tFyfZsbA8MC_EkmarEASSoSCxg1-6y9La9H76KM_9vumEQ8kVJD-papolqGc2ikmreSwRIs";
constexpr const char *kExpectedE = "AQAB";
constexpr const char *kExpectedD =
    "SYoT9kEHx6UolgDocYLS0Hludr0dcAmp3uQA3JibUO2adapNKeseeS6A8gPfeAnCV6vqJ1Xf-dhGeKxQF0yZ07xYuwgSaXn5fq_AjJCMpkjtt_AWXEjf1_Tb4RZ3ivoWytUqSy9PMD1bAO-aLA29n8bRJb5fPliFuQAsn0szW0ZsdFQs6Ur4cnsbSQZ5djuHv0lI6M2eA0qIhGI5pltMz2Ee6qOTmEPSLMlcP7AmBXyagWS9HCoRLVGOIJT5Xo4qrCzWVdT4srtyX9ZnqWRZFMLrmIeygT0iEKhj0kx7hrIJkjaKsMJyKiN0RBBYnKfqQJDG9zgsNF-13F9ezro8taeL18IQUfFbunGtSA5m28hJluSGfxz1h6jI_aZdS14AfMinRqCNuHNFXA5b0E5MLRYngGvp-DESknA1PpWFKBjGpfobzoYDbQ3lJEOIybXEcJRr3JnmvctnywCsXZhzijKnt8i2IYi-sebz7ObBN_CJQPBMeIieV7wYYBxixxnqr3HC3XI9hpKhI0vOeT_nuyGvWzxCB2p260S9gfPrukXyARW1OKdzSWU9gcIOzuRCl8D8NjFcsHS09XFIci4fj2JCrhiwoIDetcgiwnlKzACjV3yDBoi8isj3uZ46h8D-J4f3Ctmc-xMHRi2tkSvidjC8QLQZ5VFbE1hMamIYtTk";
constexpr const char *kExpectedP =
    "-qRitt4sQhlcdJNIuNslk5YKBuJenwJGwmDNDSMvcs_pLpclPAqlGRF6-y1cQk8AR4sRhPNLyrkEdtsyxNKa5eevY1BsO2ni0bnz3y_TKVtKyEqm7bw__3Q6M-3_dntBdkYcKoe3zv-yw_OlyoNewAsLOLovk8Ql1LDSfm04gNZnFolntXAwUQf_aFMnQVpcN-APPNhR-s4MHssHSp5Q3kWIWNWp4dEL71NRLof4QEQ-QJK1zKhvuRJ2czD_k5vYf4ldomL-rnlzv6bON8p9a05Sw7oY9vQOXFKKs32p92XSZZ0jPmXkiCDqcxtD6inbQH81pZkp5d7c-4Z9-GUG_Q";
constexpr const char *kExpectedQ =
    "hAheoysIcNEPmq5htIX6E-z3BnbB5W6SDenLuXhRYeXDSIzCMJ_1zDidl_9nVeCXwpmUPK7E-rTx364bGDCcqZEcXd0DtMRZco74NdQtUpJiPVCATef9TIUt_5ZchZZ-2n81YLSEb5zba6Q1oxG6-f-VZtB7txp4vOblNdFzNxzZlEGo1-L32V2O0HpTxjULCbJlTANhtt1vaHlUPJ4NneqTLTGvTiqebz6Rk-XS3Bm64ZzB5dPFuxgkHeY11PLu9tAX9R4vBvy8auMJ-rDTm7xHbngtlaxafg-df5_n7PEDmOeiCMos5G2SWlxL1xTlMOxNJFRsjZjkUbzezoVEJw";
constexpr const char *kExpectedDp =
    "6Ds158A1e80p2C27fOQ4jeXARp6qE2S1kVbFxz1pslSn9u4-psIqNO74ZxChYiL23FMjmW8gM6Z4V3RENw_4S7r-y-NxVR-H9ND6ADq8yZ33zVs2DiKVnajgYMtNH0eW4PKXGGUFzzsmNN9lJx3Pxdq1vArvGFfuwYJQlqm2Z9HAVKZdvERF0F67rLsXLTt_JJprI_I_C0as_j8Z8256-WetrLnUHRJnn4kwOA_t2gYhNA17ezQ5yF4t-A9XTzpgP9NUOajF131a3SG-Av2QdcNtdkLQ7Mg3Ih2svCBcQolKh7IwPJmGRQdSk_KYW7gKmVkEqPogUwfK8xarU2KwNQ";
constexpr const char *kExpectedDq =
    "cetOzHY6yCx5zDqdrsbSaRLSaM9aqPzoI_0PfC2l-lPmVNiuTIoX6GcJArapkF1CU_NzBZC-AJrS_u4YDp0S7vN3iD1ED1pC2yckXj1-BXqsLL8ilRWPZdCbSaWQmuqo9RlBEvluM2choxSB-vs3WrD9VUKZG_lJJ6QJLJBVWr4XtWWZqvv4YaHpsVN6qM_ngCxeXmGkk8UndPsKhWrR0Okup5Xw7f6zyMQxk2x-rM2-gx9f5U79klpX_zw8QkqBiI8vvJyYcuzqHUdbuuOLERo4f8ZNfpDBW3dZq15rG_Mv6WQiWHcomMc5uaFdBmzO-5FHVgtJxjqe9S-DBqnRjQ";
constexpr const char *kExpectedQi =
    "pO-ON5RFf4G5nHJIR1pyttVR6YkQ6wR6gpfn-2ZaT7NX0qmQ2AWK3FhjCr4yGuoHgkfO6kv1O0BrAeQlvPUt--WqL6XjygDpueLbKbv1147HJD6usDqZ6omy1mcttrOVZIQAx0OzV_PEUSoK-j_QFXZ3Ms1rj5T2-11Hz-dkGKjpoh-KBn-XlkDJCtObeUSa_W5PmzqjVd7vfZOD7YIZP4OnkW97L5gxT9CqwVsabdq9Z9LG2vr8iQ_aD5wxzqW65hlSIa4uKnYJFMhGQ2QHNRg27VUME65VtwTW_lCujl8bz-W9YQSegTuVFqRVjSI7C5w4pumANbND2bl-QGXKWg";

} // namespace

TEST(WalletRecovery_tests, DeterministicKeyFromMnemonic) {
  artools::crypto::BIP39 bip39;
  ASSERT_TRUE(bip39.initFromMnemonicString(kMnemonic));

  // The deterministic RSA key must reproduce the reference JWK components.
  artools::crypto::JWK jwk(bip39);
  EXPECT_EQ(jwk.get_n(), kExpectedN);
  EXPECT_EQ(jwk.get_e(), kExpectedE);
  EXPECT_EQ(jwk.get_d(), kExpectedD);
  EXPECT_EQ(jwk.get_p(), kExpectedP);
  EXPECT_EQ(jwk.get_q(), kExpectedQ);
  EXPECT_EQ(jwk.get_dp(), kExpectedDp);
  EXPECT_EQ(jwk.get_dq(), kExpectedDq);
  EXPECT_EQ(jwk.get_qi(), kExpectedQi);
}

TEST(WalletRecovery_tests, WalletAddressFromMnemonic) {
  artools::crypto::BIP39 bip39;
  ASSERT_TRUE(bip39.initFromMnemonicString(kMnemonic));

  // Recover the wallet from the BIP-39 instance and check the address.
  artools::crypto::JWK jwk(bip39);
  auto walletInstance = artools::wallet::create(jwk);
  ASSERT_NE(walletInstance, nullptr);
  EXPECT_EQ(walletInstance->getWalletAddress(), kExpectedPublicKey);
}

TEST(WalletRecovery_tests, PublicKeyFromPEMMatchesJWK) {
  artools::crypto::BIP39 bip39;
  ASSERT_TRUE(bip39.initFromMnemonicString(kMnemonic));

  // The PEM and JWK paths must agree on the modulus n. PEM exposes the
  // modulus as raw bytes; JWK exposes it as unpadded base64url, so encode the
  // PEM bytes before comparing.
  artools::crypto::PEM pem(bip39);
  artools::crypto::JWK jwk(bip39);
  std::string pemN;
  ASSERT_TRUE(artools::crypto::BASE64url::encode(pem.get_n(), pemN));
  EXPECT_EQ(pemN, jwk.get_n());
}