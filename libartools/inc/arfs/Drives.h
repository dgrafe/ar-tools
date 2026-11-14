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

#include <cstdint>
#include <string>
#include <vector>

#include "crypto/aesgcm.h"
#include "crypto/hkdf.h"
#include "crypto/pem.h"
#include "transport/TLSClient.h"
#include "types.h"

namespace artools {
namespace arfs {

/**
 * @brief A single ArFS drive owned by a wallet.
 *
 * Drives are Arweave transactions tagged with Entity-Type=drive. Renaming a
 * drive creates a new transaction with the same Drive-Id; the newest
 * transaction per Drive-Id is the current state.
 */
struct Drive {
  // Transaction id of the newest drive metadata transaction.
  std::string txId;
  // Stable drive identifier (UUID), shared across renames.
  std::string driveId;
  // "public" or "private".
  std::string privacy;
  // Drive name from the metadata JSON; empty if not resolvable (e.g. private
  // drive without a password, or metadata could not be fetched).
  std::string name;
  // Block timestamp of the newest transaction (unix seconds).
  std::uint64_t timestamp = 0;
  // Cipher used for private drives ("AES256-GCM"), empty for public drives.
  std::string cipher;
  // Base64url-encoded GCM IV (from the Cipher-IV tag), empty for public.
  std::string cipherIv;
  // Drive signature type ("1" or "2", ArFS v0.15); empty for public drives.
  std::string signatureType;
  // Drive auth mode ("password"); empty for public drives.
  std::string driveAuthMode;
};

/**
 * @brief Lists the ArFS drives owned by a wallet.
 *
 * Queries the Arweave GraphQL endpoint for transactions tagged
 * Entity-Type=drive owned by the given address, groups them by Drive-Id
 * (keeping only the newest transaction per drive) and fetches the drive name
 * from the metadata JSON.
 *
 * Private drives store their metadata AES-256-GCM encrypted. To decrypt them,
 * construct the helper with the owning wallet's PEM and pass the drive
 * password to listDrives(). The drive key is derived per the ArFS
 * specification: the wallet signs the Drive-Id, and HKDF-SHA256 derives a
 * 256-bit key from the signature and the password.
 *
 * See https://github.com/ArweaveTeam/arweave-js and the ArFS specification.
 */
class Drives {
public:
  using BinaryContainer_t = artools::types::BinaryContainer_t;

  static constexpr const char *kHost = "arweave.net";
  static constexpr const char *kPort = "443";

  // GraphQL pagination limit per request.
  static constexpr int kPageSize = 100;

  /**
   * @brief Constructs a drives query helper against the default gateway.
   *
   * Without a wallet, private drives cannot be decrypted (their names stay
   * empty).
   *
   * @throws std::runtime_error if the request fails
   */
  Drives();

  /**
   * @brief Constructs a drives query helper against a custom gateway.
   *
   * Without a wallet, private drives cannot be decrypted (their names stay
   * empty).
   *
   * @param host the gateway hostname
   * @param port the gateway port as a string
   * @throws std::runtime_error if the request fails
   */
  Drives(const std::string &host, const std::string &port);

  /**
   * @brief Constructs a drives query helper with the owning wallet.
   *
   * The wallet's private key is used to derive drive keys for decrypting
   * private drive metadata.
   *
   * @param wallet the wallet that owns the drives
   * @throws std::runtime_error if the request fails
   */
  explicit Drives(const artools::crypto::PEM &wallet);

  /**
   * @brief Constructs a drives query helper with the owning wallet against a
   *        custom gateway.
   *
   * @param wallet the wallet that owns the drives
   * @param host   the gateway hostname
   * @param port   the gateway port as a string
   * @throws std::runtime_error if the request fails
   */
  Drives(const artools::crypto::PEM &wallet, const std::string &host,
         const std::string &port);

  /**
   * @brief Lists all drives owned by an address.
   *
   * Queries the GraphQL endpoint, groups the results by Drive-Id (keeping
   * only the newest transaction per drive) and fetches the drive name from
   * the metadata JSON of each drive. Private drives are decrypted with the
   * given password when a wallet was provided.
   *
   * @param address  the Arweave wallet address
   * @param password the password for private drives (optional; empty for
   *                 public drives only)
   * @return         the list of drives (newest first)
   * @throws std::runtime_error if the GraphQL request fails
   */
  std::vector<Drive> listDrives(const std::string &address,
                                const std::string &password = "");

  /**
   * @brief Builds the GraphQL query body for listing drives.
   *
   * Extracted as a static helper so the query construction can be unit-tested
   * without a network connection.
   *
   * @param address the Arweave wallet address
   * @param cursor  pagination cursor, or empty for the first page
   * @return        the JSON query body
   */
  static std::string buildQuery(const std::string &address,
                                const std::string &cursor = "");

  /**
   * @brief Parses a GraphQL response into raw drive transactions.
   *
   * Extracted as a static helper so the parsing logic can be unit-tested
   * without a network connection.
   *
   * @param payload the GraphQL JSON response body
   * @return        the raw drive transactions (id, driveId, privacy,
   *                timestamp)
   * @throws std::runtime_error if the payload is not valid GraphQL JSON
   */
  static std::vector<Drive> parseDrives(const std::string &payload);

  /**
   * @brief Groups raw drive transactions by Drive-Id, keeping only the newest
   *        transaction per drive.
   *
   * Extracted as a static helper so the grouping logic can be unit-tested
   * without a network connection.
   *
   * @param drives the raw drive transactions
   * @return       the deduplicated drives (newest first)
   */
  static std::vector<Drive> deduplicateByDriveId(
      const std::vector<Drive> &drives);

private:
  std::string _host;
  std::string _port;
  // Optional wallet for decrypting private drives.
  artools::crypto::PEM _wallet;
  bool _hasWallet = false;
};

} // namespace arfs
} // namespace artools