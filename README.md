# ar-tools

C++ tooling for the [Arweave](https://arweave.org) blockchain, engineered for
bit-level compatibility with the Arweave ecosystem (arweave-js, ardrive,
js-human-crypto-keys).

## Project Goals

`ar-tools` provides a C++ library (`libartools`) and a command-line utility
(`ar-wallet`) that interoperate with the Arweave ecosystem:

- **Arweave/ArDrive compatibility**: Wallet keys derived from BIP-39 mnemonics
  are **bit-compatible** with `ipfs-shipyard/js-human-crypto-keys`, the
  reference implementation of the Arweave ecosystem. The same mnemonic always
  yields the same RSA key and therefore the same wallet address.
- **Deterministic key derivation**: The RSA key is derived as a pure function
  of the BIP-39 root seed (HMAC-DRBG per SP 800-90A plus the forge PRIMEINC
  prime sweep), rather than through OpenSSL's own key generation.
- **Wallet formats**: PEM (PKCS#8/PKCS#1) and JWK (RFC 7517) are supported and
  mutually convertible.
- **Network access**: TLS client for requests to Arweave gateways (balance
  queries, transaction anchors, transaction prices, token transfers).

## Project Structure

```
ar-tools/
├── CMakeLists.txt              # CMake build configuration
├── LICENSE                     # GPL-3.0 license
├── README.md
├── ar-wallet/
│   └── main.cpp                # ar-wallet CLI utility
├── ar-drive/
│   └── main.cpp                # ar-drive CLI utility (ArFS drives)
├── libartools/
│   ├── inc/                    # Public headers
│   │   ├── crypto/
│   │   │   ├── aesgcm.h        # AES-256-GCM encryption/decryption
│   │   │   ├── base64.h        # Base64 encoding
│   │   │   ├── base64url.h     # Base64url encoding (RFC 7515)
│   │   │   ├── bip39.h         # BIP-39 mnemonics + deterministic RSA derivation
│   │   │   ├── deep_hash.h     # Arweave deepHash (SHA-384 merkle root)
│   │   │   ├── hkdf.h          # HKDF-SHA256 key derivation (RFC 5869)
│   │   │   ├── jwk.h           # JWK import/export
│   │   │   ├── pem.h           # PEM import/export, RSA-PSS signing/verification
│   │   │   ├── sha256.h        # SHA-256 hashing
│   │   │   └── sha384.h        # SHA-384 hashing
│   │   ├── arfs/
│   │   │   ├── ANS104.h        # ANS-104 DataItem format (Avro tags, signature data)
│   │   │   └── Drives.h        # ArFS drive listing + private drive decryption
│   │   ├── protocol/
│   │   │   ├── GetBalance.h      # Balance query via the Arweave gateway
│   │   │   ├── GetPrice.h        # Transaction price (fee) query
│   │   │   ├── GetTurboBalance.h # ArDrive Turbo (winc) balance query
│   │   │   ├── GetTxAnchor.h     # Transaction anchor query
│   │   │   └── Transaction.h     # Signed v2 token-transfer transaction
│   │   ├── transport/
│   │   │   └── TLSClient.h     # TLS client (OpenSSL)
│   │   ├── types.h             # Shared type definitions
│   │   └── wallet.h            # Wallet abstraction (address, balance, signing)
│   └── src/                    # Implementations (mirrors inc/)
└── tests/                      # GoogleTest unit tests
    ├── BASE64_tests.cpp
    ├── BASE64url_tests.cpp
    ├── BIP39_tests.cpp
    ├── Crypto_tests.cpp
    ├── PEM_tests.cpp
    ├── Protocol_tests.cpp
    ├── SHA256_tests.cpp
    ├── SHA384_tests.cpp
    ├── Transaction_tests.cpp
    ├── WalletRecovery_tests.cpp
    └── main.cpp
```

## Dependencies

| Dependency | Purpose | Notes |
|---|---|---|
| **CMake ≥ 3.25** | Build system | |
| **C++20 compiler** | Language standard | tested with GCC 15 / Clang 21 |
| **OpenSSL (libssl-dev)** | Cryptography (RSA, SHA-256, HMAC, TLS) | `find_package(OpenSSL REQUIRED)` |
| **GoogleTest (libgtest-dev)** | Unit tests | `find_package(GTest REQUIRED)` |
| **RapidJSON (rapidjson-dev)** | JSON parsing for JWK | header-only; system package preferred, otherwise FetchContent (v1.1.0) |

## Building

```bash
# Configure (once)
cmake -S . -B build

# Build
cmake --build build -j$(nproc)

# Run unit tests
cd build && ctest --output-on-failure
```

> **Note**: If RapidJSON is not installed as a system package, CMake fetches a
> pinned release (v1.1.0) via FetchContent. Under CMake ≥ 4 the option
> `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` may be required.

The build artifacts are placed in `build/`:
- `build/libartools.so` – the library
- `build/ar-wallet` – the wallet CLI utility
- `build/ar-drive` – the ArFS drives CLI utility
- `build/tests/ar-test` – the test binary

## User Documentation: `ar-wallet`

`ar-wallet` is a command-line utility for managing Arweave wallets.

### Invocation

```
ar-wallet <command> [global options]
```

### Commands

| Command | Description |
|---|---|
| `balance` | Prints the wallet balance in AR and ArDrive Turbo credits |
| `address` | Prints the wallet address |
| `send --target <addr> --quantity <amt> [--unit <unit>]` | Sends AR tokens to another wallet |
| `create-pem --out <path> [--force]` | Creates a new wallet and saves it as PEM |
| `create-jwk --out <path> [--force]` | Creates a new wallet and saves it as JWK |
| `create-mnemonic` | Creates a new wallet and prints mnemonic + address |
| `pem-to-jwk --pem <in> --out <path> [--force]` | Converts PEM → JWK |
| `jwk-to-pem --jwk <in> --out <path> [--force]` | Converts JWK → PEM |
| `help` | Shows the help |
| `version` | Shows the version |

Each command provides command-specific help: `ar-wallet <command> --help`.

### Global Options (Wallet Source)

| Option | Description |
|---|---|
| `--mnemonic ["<phrase>"]` | Loads the wallet from a BIP-39 phrase; without a phrase, prompts interactively |
| `--jwk <path>` | Loads the wallet from a JWK file |
| `--pem <path>` | Loads the wallet from a PEM file (overrides the default) |
| `--force` | Overwrites an existing output file (with `create-pem`, `create-jwk`, `pem-to-jwk`, `jwk-to-pem`) |
| `--gateway <host[:port]>` | Uses a custom Arweave gateway for network queries (`balance`, `send`); default: `arweave.net:443` |

If **no** source is given, the default wallet at `~/.ar-tools/wallet.pem` is
used.

### Examples

```bash
# Create a new wallet as PEM (prints mnemonic + address)
ar-wallet create-pem --out ~/.ar-tools/wallet.pem

# Create a new wallet as JWK
ar-wallet create-jwk --out wallet.json

# Generate a mnemonic only (with address)
ar-wallet create-mnemonic

# Show the wallet address (default wallet)
ar-wallet address

# Query the balance (default wallet)
ar-wallet balance

# Query the balance of a wallet from a JWK file
ar-wallet balance --jwk wallet.json

# Query the balance via a custom gateway
ar-wallet balance --gateway arweave.net:443

# Send 1.5 AR to another wallet (default wallet)
ar-wallet send --target <address> --quantity 1.5

# Send 1000000000000 Winston to another wallet
ar-wallet send --target <address> --quantity 1000000000000 --unit winston

# Send AR using a specific wallet source
ar-wallet send --target <address> --quantity 0.5 --pem wallet.pem

# Send AR via a custom gateway
ar-wallet send --target <address> --quantity 0.5 --gateway arweave.net:443

# Load a wallet from a mnemonic (interactive input)
ar-wallet address --mnemonic

# Convert PEM to JWK
ar-wallet pem-to-jwk --pem wallet.pem --out wallet.json

# Convert JWK to PEM (overwrite an existing file)
ar-wallet jwk-to-pem --jwk wallet.json --out wallet.pem --force
```

### Querying Balances (`balance`)

The `balance` command prints two balances for the wallet:

1. **AR balance** — the on-chain AR balance, queried via
   `GET /wallet/<address>/balance` on `arweave.net` (or a custom gateway via
   `--gateway`). If the gateway is unreachable or returns an error, `0 AR` is
   shown.
2. **Turbo balance** — the ArDrive Turbo (winc) credit balance, queried via
   `GET /v1/account/balance/arweave?address=<address>` on
   `payment.ardrive.io`. The value is shown in credits (10^12 winc = 1
   credit). If the wallet has no Turbo account or the response is invalid,
   `0.0` credits is shown.

```
ar-wallet balance [global options]
```

Example output:

```
AR balance: 1.23456 AR
Turbo balance: 0.412620266518 credits
```

### Sending Tokens (`send`)

The `send` command transfers AR tokens to another wallet address. It performs
the following steps automatically:

1. Fetches the current transaction anchor (`GET /tx_anchor`) for replay
   protection.
2. Fetches the current transaction fee (`GET /price/0/<target>`) for a pure
   token transfer with no data.
3. Builds a signed **v2** token-transfer transaction and submits it to the
   network (`POST /tx`).

The transaction is signed per the Arweave specification: a merkle root
(`deepHash`) of the SHA-384 hashes of the transaction fields is computed and
signed with **RSA-PSS using SHA-256** (fixed 32-byte salt). The transaction
`id` is the SHA-256 hash of the signature.

```
ar-wallet send --target <address> --quantity <amount> [--unit <unit>]
```

| Option | Description |
|---|---|
| `--target <address>` | Recipient wallet address (required) |
| `--quantity <amount>` | Amount to send (required) |
| `--unit <unit>` | `AR` (default) or `winston` |
| `--gateway <host[:port]>` | Custom Arweave gateway (default: `arweave.net:443`) |

> **Note**: `send` makes live network requests and submits a real transaction.
> It requires the wallet to hold sufficient balance to cover the amount plus
> the transaction fee.

### ArFS Drives (`arfs::Drives`)

The `arfs::Drives` helper lists the ArFS drives owned by a wallet. It queries
the Arweave GraphQL endpoint for transactions tagged `Entity-Type=drive`,
groups them by `Drive-Id` (keeping only the newest transaction per drive, so
renames are handled) and fetches the drive name from the metadata JSON.

```cpp
// List public drives (no wallet needed).
artools::arfs::Drives drives;
auto list = drives.listDrives("WALLET_ADDRESS");

// List drives including private ones (wallet + password).
artools::crypto::PEM wallet("wallet.pem");
artools::arfs::Drives drivesWithWallet(wallet);
auto list2 = drivesWithWallet.listDrives("WALLET_ADDRESS", "drive-password");
```

Private drives encrypt their metadata with **AES-256-GCM**. The drive key is
derived per the ArFS specification:

1. The wallet signs the signing key `"drive" || driveIdBytes` (the drive UUID
   parsed into its 16 raw bytes) with its private key. The signature scheme
   depends on the drive's `Signature-Type` tag:
   - **v1** (type `1` or absent): SHA-256 hash then **unsalted RSA-PSS**
     (`PEM::signRaw`).
   - **v2** (type `2`): the **ANS-104 DataItem** deepHash of the signing key
     (arbundles `getSignatureData`), signed with unsalted RSA-PSS.
2. **HKDF-SHA256** derives a 256-bit drive key from the signature (input key
   material), an empty salt and the drive password as the info.
3. The metadata is decrypted with **AES-256-GCM** using the drive key and the
   `Cipher-IV` tag.

The generic primitives are exposed as reusable classes:

- `crypto::DeepHash` — the Arweave deepHash algorithm (SHA-384 merkle root
  over nested blobs/lists), used for transaction and DataItem signing.
- `arfs::ANS104` — the ANS-104 DataItem format: Avro tag serialization
  (`encodeTags`) and the signature-data deepHash (`getSignatureData`).
- `crypto::HKDF` — HKDF-SHA256 key derivation (RFC 5869).
- `crypto::AESGCM` — AES-256-GCM authenticated decryption.

## User Documentation: `ar-drive`

`ar-drive` is a command-line utility for listing the ArFS drives owned by a
wallet. It shares the wallet-loading options with `ar-wallet`.

### Invocation

```
ar-drive <command> [global options]
```

### Commands

| Command | Description |
|---|---|
| `list-drives [--password <pw>]` | Lists the ArFS drives of the wallet |
| `help` | Shows the help |
| `version` | Shows the version |

### Global Options (Wallet Source)

| Option | Description |
|---|---|
| `--mnemonic ["<phrase>"]` | Loads the wallet from a BIP-39 phrase; without a phrase, prompts interactively |
| `--jwk <path>` | Loads the wallet from a JWK file |
| `--pem <path>` | Loads the wallet from a PEM file (overrides the default) |
| `--gateway <host[:port]>` | Custom Arweave gateway (default: `arweave.net:443`) |

If **no** source is given, the default wallet at `~/.ar-tools/wallet.pem` is
used.

### Examples

```bash
# List the drives of the default wallet
ar-drive list-drives

# List drives including private ones (with password)
ar-drive list-drives --password "drive-password"

# List drives of a wallet from a JWK file
ar-drive list-drives --jwk wallet.json

# List drives via a custom gateway
ar-drive list-drives --gateway arweave.net:443
```

Private drives are decrypted when a password is given; without it their names
are shown as `(unnamed)`.

### Security Notes

- The mnemonic is only shown when creating a wallet (`create-*`) and is the
  only way to restore a wallet **without** a PEM/JWK file. Store it securely
  and offline. It **cannot** be reconstructed from a PEM/JWK (one-way
  function: mnemonic → root seed → RSA key).
- A wallet can be restored from a PEM or JWK file at any time; the mnemonic
  is only required if no such file exists.
- Mnemonic phrases are validated against the **BIP-39 checksum**: a mistyped
  word is rejected instead of silently deriving a different (empty) wallet.
- `create-pem`/`create-jwk` refuse to overwrite an existing file unless
  `--force` is given.
- Written key files (PEM/JWK) are created atomically with **owner-only
  permissions** (`0600`), so other users on the system cannot read the
  private key.
- Sensitive in-memory state (mnemonic, root seed, DRBG state) is
  cryptographically overwritten (`OPENSSL_cleanse`) when a BIP-39 instance is
  destroyed.
- The interactive mnemonic input (`--mnemonic` without an argument) prevents
  the phrase from appearing in the shell history, and disables the terminal
  echo so it does not remain in the scrollback either. Prefer it over passing
  the phrase as a command-line argument, which is visible in the process list.
- `send` checks the wallet balance locally before signing: an amount that
  exceeds the balance plus the transaction fee is rejected without a network
  submission.
- Network requests enforce TLS ≥ 1.2 with certificate and hostname
  verification, and use a 30-second connect/read/write timeout so a stalled
  gateway cannot hang the client.

## License

This project is licensed under the **GNU General Public License v3.0 or later**
(GPL-3.0-or-later). See [LICENSE](LICENSE).

