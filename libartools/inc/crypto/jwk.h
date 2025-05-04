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

#include "crypto/bip39.h"
#include "crypto/pem.h"
#include "types.h"

namespace artools {
namespace crypto {

class PEM;
class JWK {

public:
  using BinaryContainer_t = artools::types::BinaryContainer_t;

  JWK() = delete;
  JWK(const std::string &pathToJWK);
  JWK(const PEM &pemInstance);
  JWK(const BIP39 &bip39);

  bool exportToFile(const std::string &pathToJWP);

  void set_e(const std::string &e) { _e = e; }
  void set_n(const std::string &n) { _n = n; }
  void set_d(const std::string &d) { _d = d; }
  void set_p(const std::string &p) { _p = p; }
  void set_q(const std::string &q) { _q = q; }
  void set_dp(const std::string &dp) { _dp = dp; }
  void set_dq(const std::string &dq) { _dq = dq; }
  void set_qi(const std::string &qi) { _qi = qi; }

  void set_e(const BinaryContainer_t &e);
  void set_n(const BinaryContainer_t &n);
  void set_d(const BinaryContainer_t &d);
  void set_p(const BinaryContainer_t &p);
  void set_q(const BinaryContainer_t &q);
  void set_dp(const BinaryContainer_t &dp);
  void set_dq(const BinaryContainer_t &dq);
  void set_qi(const BinaryContainer_t &qi);

  std::string get_e() { return _e; }
  std::string get_n() { return _n; }
  std::string get_d() { return _d; }
  std::string get_p() { return _p; }
  std::string get_q() { return _q; }
  std::string get_dp() { return _dp; }
  std::string get_dq() { return _dq; }
  std::string get_qi() { return _qi; }

  BinaryContainer_t get_e() const;
  BinaryContainer_t get_n() const;
  BinaryContainer_t get_d() const;
  BinaryContainer_t get_p() const;
  BinaryContainer_t get_q() const;
  BinaryContainer_t get_dp() const;
  BinaryContainer_t get_dq() const;
  BinaryContainer_t get_qi() const;

private:
  std::string _e;
  std::string _n;
  std::string _d;
  std::string _p;
  std::string _q;
  std::string _dp;
  std::string _dq;
  std::string _qi;
};

} // end of namespace crypto
} // end of namespace artools
