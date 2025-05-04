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

#include <math.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "crypto/Base64.h"

namespace artools {
namespace crypto {

/**
 * @brief Estimates the decoded byte length of a base64 string.
 *
 * Base64 encodes 3 input bytes into 4 output characters, so the decoded length
 * is 3/4 of the encoded length, minus one byte for each '=' padding character
 * (padding replaces a full 3-byte group's tail). The trailing padding is
 * counted by inspecting the last one or two characters. This is an upper-bound
 * estimate used to size the output buffer before decoding; the actual decoded
 * length may be smaller if the input is not a multiple of 4.
 *
 * @param deodingInput the base64-encoded string
 * @return             the estimated decoded length in bytes
 */
static std::uint32_t estimateDecodedLength(const std::string &deodingInput) {

  std::uint32_t paddingLength = 0;

  if (deodingInput.size() >= 1 && deodingInput.back() == '=')
    paddingLength++;
  if (deodingInput.size() >= 2 && deodingInput[deodingInput.size() - 2] == '=')
    paddingLength++;

  return (std::uint32_t)(0.75 * deodingInput.size() - paddingLength);
}

/**
 * @brief Encodes a byte sequence into standard base64.
 *
 * Uses the OpenSSL BIO filter chain (BIO_f_base64 over a memory FILE stream)
 * to perform the encoding. The BIO_FLAGS_BASE64_NO_NL flag suppresses the
 * trailing newline that OpenSSL would otherwise append, so the output is a
 * pure base64 string without line breaks. The output buffer is sized to
 * 4 * ceil(n/3) characters plus one byte for the NUL terminator that
 * fmemopen() requires; the terminator is stripped before returning.
 *
 * @param codingInput the input bytes to encode
 * @param encodedData output parameter receiving the base64 string
 * @return            true on success
 */
bool BASE64::encode(const CodingDataType &codingInput,
                    std::string &encodedData) {

  BIO *bio, *b64;
  FILE *stream;
  const int encodedSize = 4 * ceil((double)codingInput.size() / 3);
  encodedData.resize(encodedSize +
                     1); // account for the annoying terminating zero

  stream = fmemopen(encodedData.data(), encodedData.size(), "w");
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stream, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, codingInput.data(), codingInput.size());
  BIO_flush(bio);
  BIO_free_all(bio);
  fclose(stream);

  // cut off the terminating zero
  encodedData.pop_back();

  return true;
}

/**
 * @brief Decodes a standard base64 string into bytes.
 *
 * Uses the OpenSSL BIO filter chain (BIO_f_base64 over a memory FILE stream)
 * to perform the decoding. The output buffer is pre-sized with
 * estimateDecodedLength() and filled by BIO_read(). The BIO_FLAGS_BASE64_NO_NL
 * flag matches the encoding side, so no newline handling is performed.
 *
 * @param decodingInput the base64-encoded string
 * @param decodedData   output parameter receiving the decoded bytes
 * @return              true on success
 */
bool BASE64::decode(const std::string &decodingInput,
                    CodingDataType &decodedData) {

  BIO *bio, *b64;
  decodedData.resize(estimateDecodedLength(decodingInput));
  FILE *stream = fmemopen(const_cast<char *>(decodingInput.data()),
                          decodingInput.size(), "r");

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stream, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_read(bio, decodedData.data(), decodedData.size());

  BIO_free_all(bio);
  fclose(stream);

  return true;
}

} // end of namespace crypto
} // end of namespace artools