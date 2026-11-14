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

#include <cstddef>
#include <string>

#include "types.h"

namespace artools {
namespace crypto {

/**
 * @brief HMAC-based Key Derivation Function (HKDF) with SHA-256.
 *
 * Implements HKDF per RFC 5869 using HMAC-SHA256 as the underlying hash.
 * Used by the ArFS standard to derive drive and file keys.
 */
class HKDF {
public:
  using BinaryContainer_t = artools::types::BinaryContainer_t;

  /**
   * @brief Derives a key of the requested length with HKDF-SHA256.
   *
   * @param ikm    the input key material
   * @param salt   the optional salt (may be empty)
   * @param info   the optional context info (may be empty)
   * @param length the desired output length in bytes
   * @return       the derived key
   * @throws std::runtime_error if key derivation fails
   */
  static BinaryContainer_t derive(const BinaryContainer_t &ikm,
                                  const BinaryContainer_t &salt,
                                  const BinaryContainer_t &info,
                                  std::size_t length);

  /**
   * @brief Derives a key with HKDF-SHA256 from string inputs.
   *
   * Convenience overload that treats the inputs as raw bytes.
   *
   * @param ikm    the input key material
   * @param salt   the optional salt (may be empty)
   * @param info   the optional context info (may be empty)
   * @param length the desired output length in bytes
   * @return       the derived key
   * @throws std::runtime_error if key derivation fails
   */
  static BinaryContainer_t derive(const std::string &ikm,
                                  const std::string &salt,
                                  const std::string &info,
                                  std::size_t length);
};

} // namespace crypto
} // namespace artools