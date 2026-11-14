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

#pragma once

#include <string>

#include "types.h"

namespace artools {
namespace crypto {

/**
 * @brief AES-256-GCM authenticated encryption/decryption.
 *
 * Implements AES-256 in Galois/Counter Mode (GCM) with a 12-byte IV and a
 * 16-byte authentication tag. Used by the ArFS standard to encrypt drive and
 * file metadata as well as file contents.
 */
class AESGCM {
public:
  using BinaryContainer_t = artools::types::BinaryContainer_t;

  // GCM IV length in bytes (standard 96-bit nonce).
  static constexpr std::size_t kIvLength = 12;
  // GCM authentication tag length in bytes.
  static constexpr std::size_t kTagLength = 16;

  /**
   * @brief Decrypts an AES-256-GCM ciphertext.
   *
   * The 16-byte authentication tag must be appended to the ciphertext (as in
   * the ArFS data layout).
   *
   * @param key        the 32-byte AES key
   * @param iv         the 12-byte GCM IV
   * @param ciphertext the encrypted bytes with the tag appended
   * @return           the decrypted plaintext
   * @throws std::runtime_error if decryption fails (e.g. wrong key, tampered
   *         data)
   */
  static std::string decrypt(const BinaryContainer_t &key,
                             const BinaryContainer_t &iv,
                             const BinaryContainer_t &ciphertext);
};

} // namespace crypto
} // namespace artools