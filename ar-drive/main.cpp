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

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

// Terminal echo control for the interactive mnemonic prompt (POSIX termios).
#include <termios.h>
#include <unistd.h>

#include <arfs/Drives.h>
#include <crypto/bip39.h>
#include <crypto/jwk.h>
#include <crypto/pem.h>
#include <wallet.h>

namespace {

// Default location of the wallet PEM file for the calling user.
constexpr const char *kDefaultPemDir = ".ar-tools";
constexpr const char *kDefaultPemName = "wallet.pem";

/**
 * @brief Returns the default PEM file path for the calling user.
 *
 * Resolves to $HOME/.ar-tools/wallet.pem (falling back to the current
 * directory if $HOME is not set).
 */
std::string defaultPemPath() {
  const char *home = std::getenv("HOME");
  std::filesystem::path base =
      home ? std::filesystem::path(home) : std::filesystem::current_path();
  return (base / kDefaultPemDir / kDefaultPemName).string();
}

/**
 * @brief Prints usage information.
 */
void printUsage(const char *prog) {
  std::cerr << "Usage: " << prog << " <command> [global options]\n\n"
            << "Commands:\n"
            << "  list-drives     list the ArFS drives of the wallet\n"
            << "  help            show this help\n"
            << "  version         show the version\n\n"
            << "Global options (select the wallet source):\n"
            << "  --mnemonic [\"<phrase>\"]  load wallet from a BIP-39 mnemonic "
               "phrase; without a phrase, prompt for it\n"
            << "  --jwk <path>            load wallet from a JWK file\n"
            << "  --pem <path>            load wallet from a PEM file (overrides "
               "the default)\n"
            << "  --gateway <host[:port]> use a custom Arweave gateway "
               "(default: arweave.net:443)\n\n"
            << "If no wallet source is given, the default PEM file "
               "~/.ar-tools/wallet.pem is used.\n"
            << "Run '" << prog << " <command> --help' for command-specific "
               "help.\n";
}

/**
 * @brief Prints command-specific usage information.
 */
void printCommandUsage(const char *prog, const std::string &command) {
  if (command == "list-drives") {
    std::cerr << "Usage: " << prog << " list-drives [--password <pw>] "
                 "[global options]\n"
              << "Lists the ArFS drives owned by the wallet.\n"
              << "  --password <pw>  password for deriving the drive key; "
                 "without a value, prompts interactively\n";
  } else {
    printUsage(prog);
  }
}

/**
 * @brief Reads a line from stdin with the terminal echo disabled.
 *
 * The mnemonic phrase is a secret: with echo enabled it would remain readable
 * in the terminal scrollback. This helper turns off ECHO around the read and
 * restores the original terminal attributes afterwards.
 *
 * @return the line read from stdin
 */
std::string readSecretLine() {
  std::string line;

  termios saved{};
  const bool haveTty = isatty(STDIN_FILENO) == 1 &&
                       tcgetattr(STDIN_FILENO, &saved) == 0;
  if (haveTty) {
    termios masked = saved;
    masked.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &masked);
  }

  std::getline(std::cin, line);

  if (haveTty) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved);
    std::cout << std::endl; // terminate the masked line visually
  }

  return line;
}

/**
 * @brief Parses a --gateway argument into host and port.
 *
 * Accepts "host" (port defaults to 443) and "host:port".
 *
 * @param value the raw --gateway value
 * @param host  receives the hostname
 * @param port  receives the port as a string
 * @throws std::runtime_error if the value is empty or has an empty host
 */
void parseGateway(const std::string &value, std::string &host,
                  std::string &port) {
  if (value.empty())
    throw std::runtime_error("--gateway requires a hostname");

  const auto colon = value.rfind(':');
  if (colon == std::string::npos) {
    host = value;
    port = "443";
    return;
  }

  host = value.substr(0, colon);
  port = value.substr(colon + 1);
  if (host.empty() || port.empty())
    throw std::runtime_error("--gateway requires 'host[:port]'");
}

/**
 * @brief Loads a wallet from the global source options.
 *
 * Scans the argument list (starting at @p start) for one of --mnemonic,
 * --jwk or --pem and builds the corresponding wallet. If none of these
 * options is present, the default PEM file (~/.ar-tools/wallet.pem) is used.
 *
 * @param argv the argument vector
 * @param argc the number of arguments
 * @param start index of the first global option
 * @return     the loaded wallet
 */
artools::wallet::WalletInstance_t loadWallet(char **argv, int argc, int start) {
  artools::wallet::WalletInstance_t wallet;

  for (int i = start; i < argc; ++i) {
    std::string opt = argv[i];
    if (opt == "--mnemonic") {
      std::string phrase;
      if (i + 1 < argc && argv[i + 1][0] != '-') {
        phrase = argv[++i];
      } else {
        // No phrase given: prompt for it interactively, with the terminal
        // echo disabled so the phrase does not end up in the scrollback.
        std::cout << "Enter mnemonic phrase: " << std::flush;
        phrase = readSecretLine();
      }
      artools::crypto::BIP39 bip39;
      if (!bip39.initFromMnemonicString(phrase))
        throw std::runtime_error("Invalid mnemonic phrase");
      wallet = artools::wallet::create(artools::crypto::JWK(bip39));
    } else if (opt == "--jwk") {
      if (i + 1 >= argc)
        throw std::runtime_error("--jwk requires a file path");
      artools::crypto::JWK jwk(argv[++i]);
      wallet = artools::wallet::create(jwk);
    } else if (opt == "--pem") {
      // --pem requires an explicit path and overrides the default.
      if (i + 1 >= argc || argv[i + 1][0] == '-')
        throw std::runtime_error("--pem requires a file path");
      artools::crypto::PEM pem(argv[++i]);
      wallet = artools::wallet::create(pem);
    } else if (opt == "--password") {
      // Command-specific option; may be given without a value (interactive
      // prompt). Skip the value if present.
      if (i + 1 < argc && argv[i + 1][0] != '-')
        ++i;
    } else if (opt == "--gateway") {
      // Command-specific option; skip it and its value here. It is parsed by
      // the command handler.
      if (i + 1 >= argc)
        throw std::runtime_error("--gateway requires a value");
      ++i;
    } else {
      throw std::runtime_error("unknown global option '" + opt + "'");
    }
  }

  // No explicit source given: fall back to the default PEM file.
  if (!wallet) {
    artools::crypto::PEM pem(defaultPemPath());
    wallet = artools::wallet::create(pem);
  }

  return wallet;
}

/**
 * @brief Lists the ArFS drives owned by the wallet.
 *
 * Parses --password and --gateway, then uses the arfs::Drives helper to list
 * the drives. Private drives are decrypted when a password is given.
 *
 * @param wallet the wallet whose drives are listed
 * @param argv   the argument vector
 * @param argc   the number of arguments
 * @param start  index of the first option
 * @return       0 on success, non-zero on failure
 */
int cmdListDrives(const artools::wallet::WalletInstance_t &wallet, char **argv,
                  int argc, int start) {
  std::string password;
  std::string gateway;

  for (int i = start; i < argc; ++i) {
    std::string opt = argv[i];
    if (opt == "--password") {
      if (i + 1 < argc && argv[i + 1][0] != '-') {
        password = argv[++i];
      } else {
        // No password given: prompt for it interactively, with the terminal
        // echo disabled so it does not end up in the scrollback or shell
        // history.
        std::cout << "Enter drive password: " << std::flush;
        password = readSecretLine();
      }
    } else if (opt == "--gateway") {
      if (i + 1 >= argc)
        throw std::runtime_error("--gateway requires a value");
      gateway = argv[++i];
    } else if (opt == "--mnemonic" || opt == "--jwk" || opt == "--pem") {
      // Global wallet-source options; skip them and their value here. They
      // are handled by loadWallet.
      if (opt == "--mnemonic") {
        // --mnemonic may be given without a value (interactive prompt).
        if (i + 1 < argc && argv[i + 1][0] != '-')
          ++i;
      } else {
        if (i + 1 >= argc)
          throw std::runtime_error(opt + " requires a file path");
        ++i;
      }
    } else {
      throw std::runtime_error("unknown option '" + opt + "'");
    }
  }

  // Build the drives helper, optionally with the wallet (for private drives)
  // and a custom gateway.
  artools::arfs::Drives drives;
  if (!gateway.empty()) {
    std::string host, port;
    parseGateway(gateway, host, port);
    drives = artools::arfs::Drives(wallet->getPEM(), host, port);
  } else {
    drives = artools::arfs::Drives(wallet->getPEM());
  }

  // The password is required: private drives cannot be decrypted without it
  // (the drive key is derived from the wallet signature and the password).
  if (password.empty())
    throw std::runtime_error(
        "--password is required (private drives need it to derive the drive "
        "key)");

  auto list = drives.listDrives(wallet->getWalletAddress(), password);

  if (list.empty()) {
    std::cout << "No drives found." << std::endl;
    return 0;
  }

  for (const auto &d : list) {
    std::cout << "Drive: " << (d.name.empty() ? "(unnamed)" : d.name)
              << std::endl;
    std::cout << "  id:      " << d.driveId << std::endl;
    std::cout << "  privacy: " << d.privacy << std::endl;
    std::cout << "  tx:      " << d.txId << std::endl;
  }
  return 0;
}

} // namespace

int main(int argc, char **argv) {

  if (argc < 2) {
    printUsage(argv[0]);
    return 1;
  }

  const std::string command = argv[1];

  try {
    if (command == "help" || command == "-h" || command == "--help") {
      printUsage(argv[0]);
      return 0;
    }

    if (command == "version" || command == "--version") {
      std::cout << "ar-tools " ARTOOLS_VERSION << std::endl;
      return 0;
    }

    // Command-specific help: <command> --help / -h.
    if (argc >= 3 &&
        (std::string(argv[2]) == "--help" || std::string(argv[2]) == "-h")) {
      printCommandUsage(argv[0], command);
      return 0;
    }

    if (command != "list-drives") {
      std::cerr << "Error: unknown command '" << command << "'\n";
      printUsage(argv[0]);
      return 1;
    }

    // Global options follow the command. loadWallet falls back to the
    // default PEM file if no explicit source is given.
    auto wallet = loadWallet(argv, argc, 2);

    return cmdListDrives(wallet, argv, argc, 2);

  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
}