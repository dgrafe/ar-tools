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
            << "  balance         print the wallet balance (AR)\n"
            << "  address         print the wallet address\n"
            << "  create-pem      create a new wallet and save it as PEM "
               "(--out <path>)\n"
            << "  create-jwk      create a new wallet and save it as JWK "
               "(--out <path>)\n"
            << "  create-mnemonic create a new wallet and print its mnemonic\n"
            << "  pem-to-jwk      convert a PEM file to JWK (--pem <in> "
               "--out <path>)\n"
            << "  jwk-to-pem      convert a JWK file to PEM (--jwk <in> "
               "--out <path>)\n"
            << "  help            show this help\n"
            << "  version         show the version\n\n"
            << "Global options (select the wallet source):\n"
            << "  --mnemonic [\"<phrase>\"]  load wallet from a BIP-39 mnemonic "
               "phrase; without a phrase, prompt for it\n"
            << "  --jwk <path>            load wallet from a JWK file\n"
            << "  --pem <path>            load wallet from a PEM file (overrides "
               "the default)\n"
            << "  --force                 overwrite an existing file (only with "
               "create-pem/create-jwk)\n\n"
            << "If no wallet source is given, the default PEM file "
               "~/.ar-tools/wallet.pem is used.\n"
            << "Run '" << prog << " <command> --help' for command-specific "
               "help.\n";
}

/**
 * @brief Prints command-specific usage information.
 */
void printCommandUsage(const char *prog, const std::string &command) {
  if (command == "balance") {
    std::cerr << "Usage: " << prog << " balance [global options]\n"
              << "Prints the wallet balance in AR.\n";
  } else if (command == "address") {
    std::cerr << "Usage: " << prog << " address [global options]\n"
              << "Prints the wallet address.\n";
  } else if (command == "create-pem") {
    std::cerr << "Usage: " << prog << " create-pem --out <path> [--force]\n"
              << "Creates a new wallet and saves it as a PEM file.\n"
              << "  --out <path>  destination file\n"
              << "  --force       overwrite an existing file\n";
  } else if (command == "create-jwk") {
    std::cerr << "Usage: " << prog << " create-jwk --out <path> [--force]\n"
              << "Creates a new wallet and saves it as a JWK file.\n"
              << "  --out <path>  destination file\n"
              << "  --force       overwrite an existing file\n";
  } else if (command == "create-mnemonic") {
    std::cerr << "Usage: " << prog << " create-mnemonic\n"
              << "Creates a new wallet and prints its mnemonic and address.\n";
  } else if (command == "pem-to-jwk") {
    std::cerr << "Usage: " << prog << " pem-to-jwk --pem <in> --out <path> "
                 "[--force]\n"
              << "Converts a PEM file to a JWK file.\n"
              << "  --pem <in>    source PEM file\n"
              << "  --out <path>  destination JWK file\n"
              << "  --force       overwrite an existing file\n";
  } else if (command == "jwk-to-pem") {
    std::cerr << "Usage: " << prog << " jwk-to-pem --jwk <in> --out <path> "
                 "[--force]\n"
              << "Converts a JWK file to a PEM file.\n"
              << "  --jwk <in>    source JWK file\n"
              << "  --out <path>  destination PEM file\n"
              << "  --force       overwrite an existing file\n";
  } else {
    printUsage(prog);
  }
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
        // No phrase given: prompt for it interactively.
        std::cout << "Enter mnemonic phrase: " << std::flush;
        std::getline(std::cin, phrase);
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
 * @brief Prints the wallet balance in AR as a floating-point number.
 */
int cmdBalance(const artools::wallet::WalletInstance_t &wallet) {
  std::cout << wallet->getBalance(artools::wallet::Unit::AR) << std::endl;
  return 0;
}

/**
 * @brief Prints the wallet address.
 */
int cmdAddress(const artools::wallet::WalletInstance_t &wallet) {
  std::cout << wallet->getWalletAddress() << std::endl;
  return 0;
}

/**
 * @brief Parses --out <path> and --force from the argument list.
 *
 * @param argv the argument vector
 * @param argc the number of arguments
 * @param start index of the first option
 * @param outPath receives the --out path
 * @param force receives whether --force was given
 */
void parseOutOptions(char **argv, int argc, int start, std::string &outPath,
                     bool &force) {
  for (int i = start; i < argc; ++i) {
    std::string opt = argv[i];
    if (opt == "--out") {
      if (i + 1 >= argc)
        throw std::runtime_error("--out requires a file path");
      outPath = argv[++i];
    } else if (opt == "--force") {
      force = true;
    } else {
      throw std::runtime_error("unknown option '" + opt + "'");
    }
  }
  if (outPath.empty())
    throw std::runtime_error("--out is required");
}

/**
 * @brief Refuses to overwrite an existing file unless --force is given.
 * @return true if the caller may proceed, false if it should abort
 */
bool checkOverwrite(const std::string &outPath, bool force) {
  if (!force && std::filesystem::exists(outPath)) {
    std::cerr << "Error: '" << outPath
              << "' already exists (use --force to overwrite)\n";
    return false;
  }
  return true;
}

/**
 * @brief Creates a new wallet and saves it as a PEM file.
 */
int cmdCreatePem(char **argv, int argc, int start) {
  std::string outPath;
  bool force = false;
  parseOutOptions(argv, argc, start, outPath, force);
  if (!checkOverwrite(outPath, force)) return 1;

  artools::crypto::BIP39 bip39;
  auto wallet = artools::wallet::create(bip39);
  if (!wallet->getPEM().exportAsFile(outPath))
    throw std::runtime_error("Failed to export wallet to '" + outPath + "'");

  std::cout << "mnemonic: " << bip39.getMnemonicString() << std::endl;
  std::cout << "address: " << wallet->getWalletAddress() << std::endl;
  std::cout << "wallet saved to " << outPath << std::endl;
  return 0;
}

/**
 * @brief Creates a new wallet and saves it as a JWK file.
 */
int cmdCreateJwk(char **argv, int argc, int start) {
  std::string outPath;
  bool force = false;
  parseOutOptions(argv, argc, start, outPath, force);
  if (!checkOverwrite(outPath, force)) return 1;

  artools::crypto::BIP39 bip39;
  auto wallet = artools::wallet::create(bip39);
  artools::crypto::JWK jwk(wallet->getPEM());
  if (!jwk.exportToFile(outPath))
    throw std::runtime_error("Failed to export wallet to '" + outPath + "'");

  std::cout << "mnemonic: " << bip39.getMnemonicString() << std::endl;
  std::cout << "address: " << wallet->getWalletAddress() << std::endl;
  std::cout << "wallet saved to " << outPath << std::endl;
  return 0;
}

/**
 * @brief Creates a new wallet and prints its mnemonic and address (no --out).
 */
int cmdCreateMnemonic(char **argv, int argc, int start) {
  if (start < argc)
    throw std::runtime_error("create-mnemonic takes no options");

  artools::crypto::BIP39 bip39;
  auto wallet = artools::wallet::create(bip39);
  std::cout << "mnemonic: " << bip39.getMnemonicString() << std::endl;
  std::cout << "address: " << wallet->getWalletAddress() << std::endl;
  return 0;
}

/**
 * @brief Converts a PEM file to a JWK file.
 */
int cmdPemToJwk(char **argv, int argc, int start) {
  std::string inPath, outPath;
  bool force = false;
  for (int i = start; i < argc; ++i) {
    std::string opt = argv[i];
    if (opt == "--pem") {
      if (i + 1 >= argc)
        throw std::runtime_error("--pem requires a file path");
      inPath = argv[++i];
    } else if (opt == "--out") {
      if (i + 1 >= argc)
        throw std::runtime_error("--out requires a file path");
      outPath = argv[++i];
    } else if (opt == "--force") {
      force = true;
    } else {
      throw std::runtime_error("unknown option '" + opt + "'");
    }
  }
  if (inPath.empty())
    throw std::runtime_error("--pem is required");
  if (outPath.empty())
    throw std::runtime_error("--out is required");
  if (!checkOverwrite(outPath, force)) return 1;

  artools::crypto::PEM pem(inPath);
  artools::crypto::JWK jwk(pem);
  if (!jwk.exportToFile(outPath))
    throw std::runtime_error("Failed to export JWK to '" + outPath + "'");

  std::cout << "converted " << inPath << " -> " << outPath << std::endl;
  return 0;
}

/**
 * @brief Converts a JWK file to a PEM file.
 */
int cmdJwkToPem(char **argv, int argc, int start) {
  std::string inPath, outPath;
  bool force = false;
  for (int i = start; i < argc; ++i) {
    std::string opt = argv[i];
    if (opt == "--jwk") {
      if (i + 1 >= argc)
        throw std::runtime_error("--jwk requires a file path");
      inPath = argv[++i];
    } else if (opt == "--out") {
      if (i + 1 >= argc)
        throw std::runtime_error("--out requires a file path");
      outPath = argv[++i];
    } else if (opt == "--force") {
      force = true;
    } else {
      throw std::runtime_error("unknown option '" + opt + "'");
    }
  }
  if (inPath.empty())
    throw std::runtime_error("--jwk is required");
  if (outPath.empty())
    throw std::runtime_error("--out is required");
  if (!checkOverwrite(outPath, force)) return 1;

  artools::crypto::JWK jwk(inPath);
  artools::crypto::PEM pem(jwk);
  if (!pem.exportAsFile(outPath))
    throw std::runtime_error("Failed to export PEM to '" + outPath + "'");

  std::cout << "converted " << inPath << " -> " << outPath << std::endl;
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

    if (command == "create-pem")
      return cmdCreatePem(argv, argc, 2);
    if (command == "create-jwk")
      return cmdCreateJwk(argv, argc, 2);
    if (command == "create-mnemonic")
      return cmdCreateMnemonic(argv, argc, 2);
    if (command == "pem-to-jwk")
      return cmdPemToJwk(argv, argc, 2);
    if (command == "jwk-to-pem")
      return cmdJwkToPem(argv, argc, 2);

    if (command != "balance" && command != "address") {
      std::cerr << "Error: unknown command '" << command << "'\n";
      printUsage(argv[0]);
      return 1;
    }

    // Global options follow the command. loadWallet falls back to the
    // default PEM file if no explicit source is given.
    auto wallet = loadWallet(argv, argc, 2);

    if (command == "balance")
      return cmdBalance(wallet);
    return cmdAddress(wallet);

  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
}
