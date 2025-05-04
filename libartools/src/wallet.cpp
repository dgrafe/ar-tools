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

#include "wallet.h"
#include "crypto/base64url.h"
#include "crypto/sha256.h"
#include "protocol/GetBalance.h"

namespace artools {

wallet::WalletInstance::WalletInstance(const artools::crypto::PEM &pem)
    : _pem(pem) {

  auto pubKey = _pem.get_n();
  auto hash = artools::crypto::SHA256(pubKey.data(), pubKey.size()).getHash();
  artools::crypto::BASE64url::encode(
      artools::crypto::BASE64url::CodingDataType(hash.begin(), hash.end()),
      _walletAddress);
}

std::uint64_t wallet::WalletInstance::getBalance() const {
  return artools::protocol::GetBalance(*this).getBalance();
}

double wallet::WalletInstance::getBalance(Unit unit) const {
  return artools::protocol::GetBalance(*this).getBalance(unit);
}

} // namespace artools
