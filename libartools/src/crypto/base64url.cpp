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

#include <algorithm>
#include <string>

#include "crypto/base64.h"
#include "crypto/base64url.h"
namespace artools {
namespace crypto {

/**
 * @brief Encodes a byte sequence into unpadded base64url (RFC 4648 §5).
 *
 * First delegates to BASE64::encode() to produce standard base64, then applies
 * the two URL-safe alphabet substitutions mandated by RFC 4648 §5: '+' maps to
 * '-' and '/' maps to '_'. Finally, all trailing '=' padding characters are
 * stripped. The result is the unpadded base64url form required by the Arweave
 * JWK fields, transaction `owner` and wallet addresses.
 *
 * @param codingInput the input bytes to encode
 * @param encodedData output parameter receiving the unpadded base64url string
 * @return            true on success, false if the underlying base64 encoding
 *                    fails
 */
bool BASE64url::encode(const CodingDataType &codingInput,
                       std::string &encodedData) {

  if (false == BASE64::encode(codingInput, encodedData))
    return false;

  // replace characters with special meaning in urls asccording to rfc4648
  std::replace(encodedData.begin(), encodedData.end(), '+', '-');
  std::replace(encodedData.begin(), encodedData.end(), '/', '_');

  // remove trailing padding chars (if any)
  while (encodedData.size() >= 1 && encodedData.back() == '=')
    encodedData.pop_back();

  return true;
}

/**
 * @brief Decodes an unpadded base64url string into bytes.
 *
 * Reverses the RFC 4648 §5 alphabet substitution ('-' back to '+', '_' back
 * to '/') on a working copy of the input, then restores the '=' padding that
 * the unpadded form omits: a length congruent to 2 mod 4 needs two padding
 * characters, a length congruent to 3 mod 4 needs one. The padded standard
 * base64 string is then decoded via BASE64::decode().
 *
 * @param decodingInput the unpadded base64url string
 * @param decodedData   output parameter receiving the decoded bytes
 * @return              true on success, false if the underlying base64
 *                      decoding fails
 */
bool BASE64url::decode(const std::string &decodingInput,
                       CodingDataType &decodedData) {

  std::string decodingCopy = decodingInput;

  // revert character replacement
  std::replace(decodingCopy.begin(), decodingCopy.end(), '-', '+');
  std::replace(decodingCopy.begin(), decodingCopy.end(), '_', '/');

  // fill up with missing padding bytes (if required)
  if (decodingCopy.size() % 4 == 2)
    decodingCopy += std::string("==");
  else if (decodingCopy.size() % 4 == 3)
    decodingCopy += std::string("=");

  return BASE64::decode(decodingCopy, decodedData);
}

} // end of namespace crypto
} // end of namespace artools