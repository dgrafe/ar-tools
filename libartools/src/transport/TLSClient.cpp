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
#include <cctype>
#include <cstring>
#include <stdexcept>
#include <string>

#include "transport/TLSClient.h"

namespace artools {
namespace transport {

namespace {

// HTTP header/body separator.
constexpr char kHeaderSep[] = "\r\n\r\n";

/**
 * @brief Parses the Content-Length header value from an HTTP response.
 *
 * @param response the raw HTTP response bytes
 * @return         the body length in bytes, or -1 if the header is absent
 */
long parseContentLength(const TLSClient::BinaryContainer_t &response) {
  std::string text(response.begin(), response.end());
  std::string::size_type pos = text.find("Content-Length:");
  if (pos == std::string::npos) return -1;
  pos += std::string("Content-Length:").size();
  while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos])))
    ++pos;
  long value = 0;
  while (pos < text.size() &&
         std::isdigit(static_cast<unsigned char>(text[pos]))) {
    value = value * 10 + (text[pos] - '0');
    ++pos;
  }
  return value;
}

} // namespace

/**
 * @brief Establishes a TCP connection to a host:port using OpenSSL's BIO
 *        socket abstraction.
 *
 * Uses BIO_new_connect() to create a cross-platform socket BIO that performs
 * address resolution and connection internally. This removes the dependency
 * on POSIX socket headers (arpa/inet.h, netdb.h, sys/socket.h), making the
 * transport layer portable across Windows and Unix.
 *
 * The returned BIO is handed to the caller and must be bound to the SSL
 * object (via SSL_set_bio) so that the underlying socket stays open for the
 * duration of the TLS session. It must NOT be freed here: freeing the BIO
 * closes the socket, which would break the subsequent handshake.
 *
 * @param address the hostname or IP address to connect to
 * @param port    the TCP port as a string
 * @return        the connected socket BIO (caller owns it)
 * @throws std::runtime_error if the connection cannot be established
 */
static BIO *createSocket(const std::string &address, const std::string port) {

  BIO *bio = BIO_new_connect((address + ":" + port).c_str());
  if (bio == nullptr)
    throw std::runtime_error(std::string("Creating connect BIO failed: ") +
                             ERR_error_string(ERR_get_error(), nullptr));

  if (BIO_do_connect(bio) <= 0) {
    std::string err = ERR_error_string(ERR_get_error(), nullptr);
    BIO_free_all(bio);
    throw std::runtime_error(std::string("Connection failed: ") + err);
  }

  return bio;
}

/**
 * @brief Establishes a TLS connection to a remote host.
 *
 * Creates a TLS client context, configures peer verification with the system
 * trust store, and binds the connected socket to a new SSL object. The
 * hostname is stored and enforced via SSL_set1_host() so that the certificate
 * chain is validated against the expected server identity (mitigating
 * man-in-the-middle attacks). Only TLS >= 1.2 is accepted.
 *
 * @param address the hostname or IP address to connect to
 * @param port    the TCP port as a string
 * @throws std::runtime_error on any TLS setup or handshake failure
 */
TLSClient::TLSClient(const std::string address, const std::string port)
    : _hostname(address) {

  BIO *conn = createSocket(address, port);

  _ctx = TLSContext_t(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
  if (_ctx == nullptr) {
    BIO_free_all(conn);
    throw std::runtime_error(std::string("Creating TLS context failed: ") +
                             ERR_error_string(ERR_get_error(), nullptr));
  }

  SSL_CTX_set_min_proto_version(_ctx.get(), TLS1_2_VERSION);
  SSL_CTX_set_default_verify_paths(_ctx.get());
  SSL_CTX_set_verify(_ctx.get(), SSL_VERIFY_PEER, nullptr);

  _ssl = TLSConnection_t(SSL_new(_ctx.get()), SSL_free);
  if (_ssl == nullptr) {
    BIO_free_all(conn);
    throw std::runtime_error(std::string("Creating SSL object failed: ") +
                             ERR_error_string(ERR_get_error(), nullptr));
  }

  // Enforce the expected server hostname during certificate verification.
  if (SSL_set1_host(_ssl.get(), _hostname.c_str()) != 1) {
    BIO_free_all(conn);
    throw std::runtime_error(std::string("Setting hostname verification failed: ") +
                             ERR_error_string(ERR_get_error(), nullptr));
  }

  // Send SNI (Server Name Indication) so the server presents the certificate
  // for the requested hostname. Without SNI the server may return a default
  // certificate that does not match the hostname, causing a verification
  // failure.
  if (SSL_set_tlsext_host_name(_ssl.get(), _hostname.c_str()) != 1) {
    BIO_free_all(conn);
    throw std::runtime_error(std::string("Setting SNI failed: ") +
                             ERR_error_string(ERR_get_error(), nullptr));
  }

  SSL_set_connect_state(_ssl.get());
  // Bind the connected socket BIO directly to the SSL object. SSL_set_bio
  // takes ownership of the BIO, so it must not be freed by us afterwards.
  SSL_set_bio(_ssl.get(), conn, conn);

  if (SSL_connect(_ssl.get()) != 1)
    throw std::runtime_error(std::string("TLS handshake failed: ") +
                             ERR_error_string(ERR_get_error(), nullptr));
}

TLSClient::~TLSClient() {
  if (_ssl) SSL_shutdown(_ssl.get());
}

/**
 * @brief Writes data over the TLS connection.
 *
 * @param data the bytes to send
 * @return     the number of bytes written
 * @throws std::runtime_error if the write fails
 */
std::uint32_t TLSClient::write(const BinaryContainer_t &data) {
  auto ret = SSL_write(_ssl.get(), data.data(), data.size());
  if (ret <= 0)
    throw std::runtime_error(std::string("Error Writing: ") +
                             ERR_error_string(ERR_get_error(), nullptr));
  return ret;
}

/**
 * @brief Reads the complete HTTP response from the TLS connection.
 *
 * Reads in a loop until the full response has been received. The loop stops
 * when:
 *   - the peer closes the connection (SSL_read returns 0), or
 *   - the number of bytes received reaches the advertised Content-Length
 *     (header size + body size), or
 *   - a read error occurs.
 *
 * This is necessary because a single SSL_read call only returns whatever is
 * currently buffered (up to SSL_RECORD_SIZE bytes); a response body larger
 * than that arrives over multiple reads.
 *
 * @param data output container receiving the complete response bytes
 * @return     the total number of bytes read
 * @throws std::runtime_error if the read fails
 */
std::uint32_t TLSClient::read(BinaryContainer_t &data) {

  data.clear();
  uint8_t buf[SSL_RECORD_SIZE];

  for (;;) {
    int size = SSL_read(_ssl.get(), buf, sizeof(buf));
    if (size < 0)
      throw std::runtime_error(std::string("Error reading: ") +
                               ERR_error_string(ERR_get_error(), nullptr));
    if (size == 0) break; // clean connection close

    data.insert(data.end(), buf, buf + size);

    // If we already have the full response (headers + Content-Length body),
    // stop reading. Otherwise keep going.
    auto headerEnd = std::search(data.begin(), data.end(),
                                 std::begin(kHeaderSep), std::end(kHeaderSep) - 1);
    if (headerEnd != data.end()) {
      auto contentLength = parseContentLength(data);
      if (contentLength >= 0) {
        std::size_t headerSize =
            static_cast<std::size_t>(headerEnd - data.begin()) + 4;
        if (data.size() >= headerSize + static_cast<std::size_t>(contentLength))
          break;
      }
    }
  }

  return static_cast<std::uint32_t>(data.size());
}

/**
 * @brief Extracts the HTTP response body (payload) from a raw response.
 *
 * @param response the raw HTTP response bytes
 * @return         the payload (body) as a string
 */
std::string TLSClient::extractPayload(const BinaryContainer_t &response) {
  auto headerEnd = std::search(response.begin(), response.end(),
                               std::begin(kHeaderSep), std::end(kHeaderSep) - 1);
  if (headerEnd == response.end()) {
    // No header/body separator found: treat the whole response as payload.
    return std::string(response.begin(), response.end());
  }
  auto bodyStart = headerEnd + 4; // skip "\r\n\r\n"
  return std::string(bodyStart, response.end());
}

} // namespace transport
} // namespace artools