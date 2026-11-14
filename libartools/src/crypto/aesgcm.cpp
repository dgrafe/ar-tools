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

#include "crypto/aesgcm.h"

#include <stdexcept>

#include <openssl/evp.h>

namespace artools {
namespace crypto {

std::string AESGCM::decrypt(const BinaryContainer_t &key,
                            const BinaryContainer_t &iv,
                            const BinaryContainer_t &ciphertext) {

  if (key.size() != 32)
    throw std::runtime_error("AESGCM: AES key must be 32 bytes");
  if (iv.size() != kIvLength)
    throw std::runtime_error("AESGCM: GCM IV must be 12 bytes");
  if (ciphertext.size() < kTagLength)
    throw std::runtime_error("AESGCM: ciphertext too short (missing tag)");

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr)
    throw std::runtime_error("AESGCM: cipher context creation failed");

  std::string plaintext;
  bool ok = false;
  do {
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) !=
        1)
      break;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) !=
        1)
      break;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
      break;

    // The tag is the last kTagLength bytes of the ciphertext.
    std::size_t ctLen = ciphertext.size() - kTagLength;
    plaintext.resize(ctLen);
    int outLen = 0;
    if (EVP_DecryptUpdate(ctx,
                          reinterpret_cast<unsigned char *>(plaintext.data()),
                          &outLen, ciphertext.data(), ctLen) != 1)
      break;
    plaintext.resize(outLen);

    const unsigned char *tag = ciphertext.data() + ctLen;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLength,
                            const_cast<unsigned char *>(tag)) != 1)
      break;

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx,
                            reinterpret_cast<unsigned char *>(
                                plaintext.data() + outLen),
                            &finalLen) != 1)
      break;
    plaintext.resize(outLen + finalLen);
    ok = true;
  } while (false);

  EVP_CIPHER_CTX_free(ctx);
  if (!ok)
    throw std::runtime_error("AESGCM: AES-GCM decryption failed");

  return plaintext;
}

} // namespace crypto
} // namespace artools