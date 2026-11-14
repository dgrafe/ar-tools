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

#include "crypto/hkdf.h"

#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace artools {
namespace crypto {

HKDF::BinaryContainer_t HKDF::derive(const BinaryContainer_t &ikm,
                                     const BinaryContainer_t &salt,
                                     const BinaryContainer_t &info,
                                     std::size_t length) {

  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (pctx == nullptr)
    throw std::runtime_error("HKDF: context creation failed");

  // RFC 5869: an empty salt is replaced by a string of HashLen zeros.
  static const BinaryContainer_t kZeroSalt(32, 0);
  const BinaryContainer_t &effectiveSalt = salt.empty() ? kZeroSalt : salt;

  BinaryContainer_t key(length, 0);
  bool ok = false;
  do {
    if (EVP_PKEY_derive_init(pctx) <= 0) break;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) break;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, effectiveSalt.data(),
                                    effectiveSalt.size()) <= 0)
      break;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size()) <= 0) break;
    if (!info.empty() &&
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size()) <= 0)
      break;
    size_t keyLen = key.size();
    if (EVP_PKEY_derive(pctx, key.data(), &keyLen) <= 0) break;
    key.resize(keyLen);
    ok = true;
  } while (false);

  EVP_PKEY_CTX_free(pctx);
  if (!ok)
    throw std::runtime_error("HKDF: key derivation failed");

  return key;
}

HKDF::BinaryContainer_t HKDF::derive(const std::string &ikm,
                                     const std::string &salt,
                                     const std::string &info,
                                     std::size_t length) {
  return derive(BinaryContainer_t(ikm.begin(), ikm.end()),
                BinaryContainer_t(salt.begin(), salt.end()),
                BinaryContainer_t(info.begin(), info.end()), length);
}

} // namespace crypto
} // namespace artools