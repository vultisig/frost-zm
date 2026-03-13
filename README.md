# frost-zm

Threshold signing for Zcash Sapling and Monero in a single workspace. Two FROST-based libraries — **frozt** (Zcash) and **fromt** (Monero) — sharing generic ceremony infrastructure, FFI plumbing, and relay orchestration.

No single party ever holds a full private key. T-of-N parties run distributed key generation, threshold signing, resharing, and key import ceremonies.

## Architecture

```
crates/
  frost-ffi/           Shared FFI infrastructure (handle table, buffers, codec, errors)
  frost-ceremony/      Generic FROST ceremonies over any Ciphersuite (DKG, sign, reshare, key import)
  frost-session/       Session-based ceremony driver (setup, message routing, state machine)
  frozt-lib/           Zcash Sapling — signing, z-addresses, tx building, ceremony metadata
  frozt-sdk/           Zcash SDK — native scanner (lightwalletd gRPC + zcash_client_backend)
  fromt-lib/           Monero — Ed25519 signing, view keys, CKD, key image ceremony, subaddresses
  fromt-sdk/           Monero SDK — native spend FFI (daemon RPC, scanning, decoy selection)
  frozt-wasm/          Zcash WASM bindings (wasm-bindgen)
  fromt-wasm/          Monero WASM bindings (wasm-bindgen)

go/
  frostgo/             Shared Go codec and error handling
  frozt/               Zcash Go bindings (CGo) — core crypto
  frozt-sdk/           Zcash Go SDK bindings (CGo) — scanner
  fromt/               Monero Go bindings (CGo)
  fromt-sdk/           Monero Go SDK bindings (CGo) — spend FFI

packages/
  frozt-sdk-ts/        Zcash TypeScript SDK — wallet, ceremony, scanner, lightwalletd client
  fromt-sdk-ts/        Monero TypeScript SDK

client/
  shared/              Shared relay, session runner, vault format, config, keystore base
  frozt/               Zcash client — Sapling spend, lightwalletd, Docker orchestration
  fromt/               Monero client — daemon RPC, address derivation, Docker orchestration
  vult/                Combined vault tests — multi-chain key import, vault round-trip
```

### Shared Crates

**frost-ffi** — C FFI infrastructure used by both chain libraries:
- Global handle table for opaque secret state across the FFI boundary
- `go_slice` / `tss_buffer` FFI buffer types
- Binary map codec (`[count:u32 LE] then N × {key_len, key, val_len, val}`)
- Unified error enum (`lib_error`)

**frost-ceremony** — Generic FROST protocol functions parameterized by `C: Ciphersuite`:
- `dkg_part1/2/3<C>` — 3-round distributed key generation
- `sign_commit/sign/sign_aggregate<C>` — 4-step threshold signing
- `reshare_part1/3<C>` — threshold parameter rotation preserving the public key
- `key_import_part1/3<C>` — import existing keys into threshold shares
- `lagrange_coeff<C>` — Lagrange interpolation over the scalar field

---

## frozt — Zcash Sapling

Threshold signing on the RedJubjub curve (`JubjubBlake2b512`) with rerandomization for Zcash Sapling's unlinkability guarantees.

### Curve & Ciphersuite

RedJubjub with Blake2b-512 — the curve used by Zcash Sapling for spend authorization signatures. Signing uses `frost-rerandomized` to produce rerandomized signatures.

### Protocols

- **DKG** — 3-round FROST key generation. Each party gets a `KeyPackage` (signing share) and `PublicKeyPackage` (group verifying key).
- **Signing** — 4-phase rerandomized threshold signing via `frost_rerandomized`. Any T signers produce a valid RedJubjub signature.
- **Resharing** — Change threshold (e.g., 2-of-2 → 2-of-3) preserving the group key. Uses the session-based API (setup → feed/take message loop → result).
- **Key Import** — Import existing Zcash Sapling spending keys (BIP39 seed → ZIP 32 path `m/32'/133'/account'`) into the threshold scheme. Verified against expected verifying key.
- **Sapling** — Z-address generation, note decryption, nullifier computation, Merkle tree witness management, and Sapling transaction building.
- **Ceremony Metadata** — Coordinator bundles birthday + sapling extras into a versioned metadata blob, broadcast to all parties during DKG/import. Hash-verified for consistency.
- **Scanner** (SDK) — Full wallet sync via `zcash_client_backend` + `zcash_client_memory` against lightwalletd. Native build in `frozt-sdk` (gRPC via tonic), TypeScript SDK in `packages/frozt-sdk-ts` (gRPC-web via Connect).

### KeyShareBundle

Self-contained binary blob storing all per-party data:

```
[version:1][birthday:8][extras_len:4][sapling_extras][kp_len:4][KeyPackage][pkp_len:4][PublicKeyPackage]
```

Birthday records the block height at wallet creation — user-provided for seed imports, chain tip for seedless DKG. Used as the scan start height. Pack/unpack via `frozt_keyshare_bundle_*` FFI functions.

### Sapling Extras

96-byte blob (`nsk || ovk || dk`) needed for z-address derivation. For seed imports, derived from the seed. For seedless DKG, generated randomly. Combined with the group public key to produce a `DiversifiableFullViewingKey` and z-address. Stored inside the KeyShareBundle.

### Upstream Sources

| Component | Source | What it does for us |
|-----------|--------|---------------------|
| FROST DKG & signing | [`frost-core`](https://crates.io/crates/frost-core) v2.2 | Standard FROST distributed key generation and threshold signing |
| Rerandomized signing | [`frost-rerandomized`](https://crates.io/crates/frost-rerandomized) v2.2 | Rerandomization layer for Zcash Sapling unlinkability |
| RedJubjub ciphersuite | [`reddsa`](https://github.com/ZcashFoundation/reddsa) (ZcashFoundation) | `JubjubBlake2b512` curve definition + FROST ciphersuite |
| Sapling key derivation | [`sapling-crypto`](https://crates.io/crates/sapling-crypto) v0.6 | ZIP 32 extended spending keys, note encryption, Groth16 spend/output provers |
| Address encoding | [`zcash_address`](https://crates.io/crates/zcash_address) v0.6 | Bech32 Sapling z-address encoding |
| JubJub field ops | [`jubjub`](https://crates.io/crates/jubjub) v0.10 | Scalar field and group operations |
| ZIP 32 paths | [`zip32`](https://crates.io/crates/zip32) v0.2 | Hardened path derivation (`m/32'/133'/account'`) |
| Note encryption | [`zcash_note_encryption`](https://crates.io/crates/zcash_note_encryption) v0.4 | Sapling note plaintext encryption/decryption |
| Merkle tree | [`incrementalmerkletree`](https://crates.io/crates/incrementalmerkletree) v0.8 | Sapling commitment tree (depth 32) |
| Wallet sync (SDK) | [`zcash_client_backend`](https://github.com/ChainSafe/librustzcash-nu61) | Full chain scanning, sync engine, lightwalletd gRPC protocol |
| In-memory wallet (SDK) | [`zcash_client_memory`](https://github.com/ChainSafe/librustzcash-nu61) | In-memory wallet database for scanning |
| Unified keys (SDK) | [`zcash_keys`](https://github.com/ChainSafe/librustzcash-nu61) | `UnifiedFullViewingKey` construction from Sapling DFVK |
| gRPC transport (SDK) | [`tonic`](https://crates.io/crates/tonic) v0.14 | Native gRPC client for lightwalletd (frozt-sdk) |

The SDK scanner deps use the [ChainSafe librustzcash-nu61 fork](https://github.com/ChainSafe/librustzcash-nu61) for NU6.1 compatibility.

DKG delegates to `frost_core::keys::dkg::part1/2/3`. Signing delegates to `frost_rerandomized::sign` and `frost_rerandomized::aggregate`. Key derivation delegates to `sapling_crypto::zip32::ExtendedSpendingKey`. Z-addresses delegate to `sapling_crypto::keys::DiversifiableFullViewingKey`. Groth16 proofs delegate to `sapling_crypto::prover`.

### What we implement ourselves

Three protocol extensions compose upstream primitives without introducing new cryptographic assumptions. All live in `frost-ceremony/` (generic) and `frozt-lib/` (Zcash-specific):

**Resharing** (`frost-ceremony/src/reshare.rs`) — Changes the threshold scheme (e.g., 2-of-2 to 2-of-3) while preserving the group public key. The only custom math is Lagrange interpolation coefficients over the scalar field — textbook polynomial evaluation using upstream field arithmetic. The result feeds into standard `frost-core` DKG rounds 2 and 3 and is verified against the expected verifying key.

**Key Import** (`frost-ceremony/src/key_import.rs`, `frozt-lib/src/key_import.rs`) — Imports an existing Zcash spending key into the threshold scheme. The importing party sets their polynomial constant to `ask - (N-1)` while others use `1`, so shares sum to the original key. This is a single field subtraction on top of upstream ZIP 32 derivation and standard FROST DKG. The group public key is verified against the expected verifying key.

**Sapling extras & z-address composition** (`frozt-lib/src/sapling.rs`) — Constructs a `DiversifiableFullViewingKey` by combining the FROST group public key with Sapling scalars (`nsk`, `ovk`, `dk`). For seed imports, extracted from upstream `ExtendedSpendingKey`. For seedless DKG, `nsk` via `jubjub::Fr::random()`, rest via `OsRng`. The z-address is produced by upstream `DiversifiableFullViewingKey::default_address()`.

**Transaction building** (`frozt-lib/src/tx.rs`) — Assembles Sapling v5 transactions from threshold-signed spend proofs and output proofs. Delegates proof generation to `sapling-crypto`'s Groth16 provers. The transaction serialization format follows the Zcash specification.

**Ceremony metadata** (`frozt-lib/src/ceremony_metadata.rs`) — Versioned blob bundling birthday + sapling extras for broadcast during DKG/import. Coordinator creates metadata, all parties verify via Blake2b hash. Format: `[version:1][birthday:8][extras:96]`.

Everything else (FFI handle table, binary codec, Go/WASM/SDK bindings, relay client) is non-cryptographic plumbing.

### frozt-sdk — Native Scanner

`frozt-sdk` is a separate native crate (not WASM) that wraps `zcash_client_backend` for full wallet synchronization against a lightwalletd gRPC endpoint. Provides C FFI functions (`frozt_sdk_scan`, `frozt_sdk_scan_balance`) and Go bindings in `go/frozt-sdk/`.

### frozt-sdk-ts — TypeScript SDK

`packages/frozt-sdk-ts` is a TypeScript package (`@vultisig/frozt-sdk`) for browser/Node.js integration:

- **`FroztWallet`** — High-level wallet: init from keyshare bundle, derive addresses, scan balance
- **`ceremony`** — DKG, key import, signing, reshare orchestration with metadata broadcast
- **`scanner`** — Scan chain for owned notes using IVK + lightwalletd compact blocks
- **`LightwalletClient`** — gRPC-web client for lightwalletd (Connect protocol)
- **`types`** — `ScanResult`, `FoundNote`, `SaplingKeys`, `KeygenMetadata`, compact block types

Uses `frozt-wasm` for crypto operations and `@connectrpc/connect-web` for gRPC-web transport.

---

## fromt — Monero

Threshold signing on Ed25519 (`Ed25519Sha512`) for Monero. Manages both spend keys (FROST-distributed) and view keys (aggregated scalars). Transaction construction uses threshold CLSAG ring signatures via the monero-oxide ecosystem.

### Spend Key & View Key

- **Spend key** — FROST-distributed Ed25519 secret. Generated as Shamir shares during DKG. Never leaves a party except as encrypted round messages.
- **View key** — Each party generates a random 32-byte share during DKG; shares are summed to produce the aggregate. For key import, derived as `Keccak256(spend_key)`. Grants read access but not spending authority.

### KeyShareBundle

Self-contained binary blob storing all per-party data:

```
[version:1][network:1][view_key:32][birthday:8][kp_len:4][KeyPackage][pkp_len:4][PublicKeyPackage]
```

Birthday records the block height at wallet creation — user-provided for seed imports, chain tip for seedless DKG. Used as the scan start height.

### Protocols

- **DKG** — 3-round FROST key generation with view key share aggregation. Each party gets a `KeyShareBundle` containing signing share, group public key, shared view key, and birthday.
- **Signing** — 4-step standard Ed25519 threshold signing (no rerandomization).
- **Resharing** — Threshold rotation preserving public key, view key, and birthday. Uses the session-based API (setup → feed/take message loop → result).
- **Key Import** — Split existing Monero spend key into threshold shares. View key derived via `Keccak256(spend_key)`.
- **CKD** — 2-round child key derivation by `(account, index)` using path `Keccak256("fromt/ckd" || account || index)`.
- **Key Image Generation** — 2-round ceremony (`key_image_part1` / `key_image_part2`) computing Monero key images for scanned outputs without reconstructing the aggregate spend key. Each signer contributes a point share; the final output is the standard `(key_offset + spend_key) * Hp(P)` key image.
- **Spend** — 3-phase threshold CLSAG transaction signing: preprocess → sign → complete. Network operations (scanning, decoy selection) require the `rpc` feature.

### Address Derivation

Main address:
```
payload = [network_prefix] || spend_pub (32) || view_pub (32)
address = monero_base58(payload || keccak256(payload)[0..4])
```

Subaddresses per (account, index):
```
hash = Keccak256("SubAddr\0" || view_key || account || index)
sub_spend = spend_point + G * hash
```

| Network  | Address Prefix | Subaddress Prefix |
|----------|---------------|-------------------|
| Mainnet  | 18            | 42                |

### Feature Flags

`fromt-lib` uses Cargo features to separate crypto from network I/O:

| Feature | Default | What it enables |
|---------|---------|-----------------|
| `rpc`   | no      | `tokio`, `reqwest`, `monero-simple-request-rpc` — daemon RPC scanning, decoy selection, key image checking |

Without `rpc` (default, including WASM builds), all pure crypto operations are available: DKG, signing, resharing, key import, CKD, key image generation, address derivation, spend preprocess/sign/complete. Only `scan_balance` and `prepare_spend` (which talk to a Monero daemon) are gated. `fromt-sdk` enables `rpc` for native builds.

### Upstream Sources

| Component | Source | What it does for us |
|-----------|--------|---------------------|
| FROST DKG & signing | [`frost-core`](https://crates.io/crates/frost-core) v2 | Standard FROST distributed key generation and threshold signing |
| Ed25519 ciphersuite | [`frost-ed25519`](https://crates.io/crates/frost-ed25519) v2 | `Ed25519Sha512` ciphersuite definition for FROST |
| Ed25519 arithmetic | [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek) v4 | Scalar field ops, point multiplication, `Scalar::from_canonical_bytes` |
| Ed25519 group for modular-frost | [`dalek-ff-group`](https://crates.io/crates/dalek-ff-group) v0.5 | `ff`/`group` trait adaptor over `curve25519-dalek` for modular-frost compatibility |
| Keccak256 | [`tiny-keccak`](https://crates.io/crates/tiny-keccak) v2 | Address checksums, view key derivation, CKD path hashing, subaddress hashing |
| Threshold CLSAG | [`modular-frost`](https://crates.io/crates/modular-frost) v0.11 | FROST-compatible threshold signing adaptor for Monero's CLSAG ring signature scheme |
| CLSAG ring signatures | [`monero-clsag`](https://github.com/monero-oxide/monero-oxide) | Compact Linkable Spontaneous Anonymous Group signatures with multisig support |
| Wallet & transaction | [`monero-wallet`](https://github.com/monero-oxide/monero-oxide) | `SignableTransaction` construction, `Scanner` for output detection, `ViewPair`, RingCT output/decoy types, transaction serialization |
| Address types | [`monero-address`](https://github.com/monero-oxide/monero-oxide) | `MoneroAddress` parsing and formatting (standard, subaddress, integrated) |
| Blockchain interface | [`monero-interface`](https://github.com/monero-oxide/monero-oxide) | Trait definitions: `ProvidesBlockchain`, `ProvidesDecoys`, `ProvidesOutputs`, `ExpandToScannableBlock`, `ProvidesFeeRates` |
| Daemon RPC | [`monero-simple-request-rpc`](https://github.com/monero-oxide/monero-oxide) | HTTP RPC client implementing `monero-interface` traits against a Monero daemon (optional, `rpc` feature) |
| Monero primitives | [`monero-oxide`](https://github.com/monero-oxide/monero-oxide) | Core Monero types, Ed25519 point/scalar wrappers, commitment types |

All monero-oxide crates come from a single monorepo at [`github.com/monero-oxide/monero-oxide`](https://github.com/monero-oxide/monero-oxide).

**How threshold spending works:**

1. `monero-wallet::Scanner` + `ViewPair` detect owned outputs by scanning blocks (via `monero-interface` traits)
2. `monero-wallet::send::SignableTransaction` constructs an unsigned transaction with selected inputs, decoys, outputs, and fee
3. `modular-frost` adapts our FROST Ed25519 keyshares (`ThresholdKeys<dalek_ff_group::Ed25519>`) into `monero-clsag::ClsagMultisig` for threshold CLSAG signing
4. Standard FROST preprocess → sign → complete rounds produce a valid CLSAG ring signature per input
5. `monero-wallet` serializes the final signed transaction

DKG delegates to `frost_core::keys::dkg::part1/2/3`. FROST keyshare conversion to Monero format uses `dalek-ff-group` to bridge between `frost-ed25519` scalar/point types and `monero-wallet`'s Ed25519 types. View key derivation uses `Keccak256(spend_key)`. Address encoding uses `monero-address` with Keccak256 checksums.

### What we implement ourselves

Six protocol extensions compose upstream primitives. All live in `frost-ceremony/` (generic) and `fromt-lib/` (Monero-specific):

**Resharing** (`frost-ceremony/src/reshare.rs`) — Same generic reshare as frozt. Lagrange interpolation over the Ed25519 scalar field using upstream `curve25519-dalek` arithmetic. Result feeds into standard FROST DKG rounds.

**Key Import** (`frost-ceremony/src/key_import.rs`, `fromt-lib/src/ceremony/key_import.rs`) — Splits an existing Monero spend key into threshold shares. Same `secret - (N-1)` polynomial trick as frozt. The Monero-specific part is deriving the view key as `Keccak256(spend_key)` and aggregating view key shares across parties (`fromt-lib/src/ceremony/key_import.rs:aggregate_import_view_key`).

**View key aggregation** (`fromt-lib/src/ceremony/dkg.rs`, `fromt-lib/src/ceremony/reshare.rs`) — During DKG and reshare, each party generates a random 32-byte view key share. These are exchanged alongside FROST round packages and summed to produce the aggregate view key. This is simple scalar addition — no new cryptographic assumptions. The aggregate is stored in `KeyShareBundle.view_key`.

**CKD — Child Key Derivation** (`fromt-lib/src/ceremony/ckd.rs`) — 2-round protocol deriving child signing shares by `(account, index)`. Path scalar is `Keccak256("fromt/ckd" || account_le32 || index_le32)`. Each party tweaks their share by this deterministic scalar. Uses upstream `curve25519-dalek` for scalar math.

**Threshold key image generation** (`fromt-lib/src/ceremony/key_image.rs`) — 2-round protocol computing Monero key images for one or more outputs without reconstructing the spend key. For output public key `P` and scan-derived `key_offset`, each signer broadcasts the point `lambda_i * x_i * Hp(P)`, where `x_i` is its FROST signing share and `lambda_i` is the Lagrange coefficient for the selected signer set. Summing these point partials and adding `key_offset * Hp(P)` yields the standard Monero key image `(key_offset + x) * Hp(P)`. Only points cross the wire, so no party learns the aggregate spend key.

**Address derivation** (`fromt-lib/src/monero/address.rs`, `fromt-lib/src/monero/subaddress.rs`) — Monero base58 encoding with Keccak256 checksums. Main address is `prefix || spend_pub || view_pub || checksum`. Subaddresses use the standard `"SubAddr\0"` domain-separated hash. All crypto ops use upstream `curve25519-dalek` point/scalar arithmetic and `tiny-keccak` for hashing.

**Keyshare ↔ Monero key conversion** (`fromt-lib/src/monero/spend.rs:convert_keyshare`) — Bridges FROST `KeyPackage<Ed25519Sha512>` into `modular-frost`'s `ThresholdKeys<dalek_ff_group::Ed25519>` by extracting scalar shares and verification points. This is pure format conversion — no new crypto, just re-encoding the same values for the `monero-clsag` API.

Everything else (FFI handle table, binary codec, Go/WASM/SDK bindings, relay client) is non-cryptographic plumbing.

---

## Shared Client Infrastructure

### Session Runner (`client/shared/session`)

Generic message-loop driver for all session-based ceremonies (DKG, reshare). Instead of manually orchestrating barriers and round collection, a ceremony exposes three callbacks via `SessionFuncs`:

- **TakeMsg** — Drain the next outbound message from the session (nil when empty)
- **Feed** — Feed an inbound message; returns `true` when the ceremony is complete
- **MsgReceiver** — Iterate recipients of an outbound message by index

The runner (`RunSession`) loops: drain outbox → poll inbox → feed messages, until the session signals completion. Party identifiers are derived deterministically from sorted party names (1-indexed).

### Config (`client/shared/config`)

Shared `.env` file parser (`LoadDotEnv`) used by tests and client binaries.

### Vault (`client/shared/vault`)

Protobuf vault format helpers — `FroztChainKeyEntry`, `FromtChainKeyEntry`, `FindChainKeyEntry`. Chain name constants: `ChainZcashSapling`, `ChainMonero`.

---

### fromt-sdk — Native Spend FFI

`fromt-sdk` is a separate native crate that enables the `rpc` feature on `fromt-lib` and exposes the network-dependent spend operations (`fromt_scan_balance`, `fromt_spend_prepare`) as C FFI. This keeps `fromt-lib` itself free of network deps by default, while providing a linkable library for native Go/server consumers that need daemon RPC access.

---

## Prerequisites

- Rust stable toolchain + `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`)
- Go 1.22+
- [`wasm-pack`](https://rustwasm.github.io/wasm-pack/) for WASM builds
- Node.js 18+ (for TypeScript SDK)
- Docker & Docker Compose (for the client demos)

## Build

```bash
make build-rust          # Both Rust libraries (release)
make build-frozt         # Zcash only
make build-fromt         # Monero only

make build-go            # Both Go bindings (builds Rust, copies libs)
make build-go-frozt      # Zcash Go only
make build-go-fromt      # Monero Go only
```

### WASM

Both WASM crates are pure crypto (no network deps) and build with standard wasm-pack:

```bash
wasm-pack build crates/frozt-wasm --target web --out-dir ../../pkg/frozt
wasm-pack build crates/fromt-wasm --target web --out-dir ../../pkg/fromt
```

### TypeScript SDK

```bash
cd packages/frozt-sdk-ts
npm install
npm run build
```

Cross-compilation:

```bash
make build-frozt-linux-amd64
make build-frozt-linux-arm64
make build-fromt-linux-amd64
make build-fromt-linux-arm64
```

## Test

```bash
make test-rust           # All Rust tests (frost-ffi, frost-ceremony, frozt-lib, fromt-lib, wasm)
make test-go             # All Go tests
make test                # Both

# Docker-based integration test
docker build -f Dockerfile.test .
```

## Client: Docker Multi-Party Demos

### Zcash (frozt)

```bash
make docker-keygen SESSION=my-session
make docker-sign SESSION=my-session MESSAGE="hello zcash" SIGNERS="party-1,party-2"
```

Or directly:

```bash
cd client/frozt
./scripts/run-keygen.sh my-session
./scripts/run-sign.sh my-session "hello zcash" "party-1,party-2"
```

### Monero (fromt)

```bash
cd client/fromt
./scripts/run-keygen.sh
KEYGEN_SESSION_ID=<session> ./scripts/run-sign.sh
./scripts/run-import.sh   # Import from FROMT_MNEMONIC in .env
```

### Environment

All configuration is in the root `.env` file. Variables are prefixed by chain (`FROZT_`, `FROMT_`) and mapped to unprefixed names inside containers by docker-compose.

| Variable | Description |
|----------|-------------|
| `FROZT_MNEMONIC` | Zcash BIP39 mnemonic for key import |
| `FROZT_BIRTHDAY` | Zcash wallet birthday height |
| `FROZT_EXPECTED_ADDRESS` | Expected z-address for verification |
| `FROMT_MNEMONIC` | Monero BIP39 mnemonic for key import |
| `FROMT_BIRTHDAY` | Monero wallet birthday height |
| `FROMT_EXPECTED_ADDRESS` | Expected Monero address for verification |

Runtime env vars set per container by docker-compose:

| Variable | Description | Default |
|----------|-------------|---------|
| `RELAY_URL` | Relay server address | `http://localhost:9090` |
| `PARTY_ID` | Unique party name | required |
| `IDENTIFIER` | Numeric party ID (1-65535) | required |
| `SESSION_ID` | Ceremony session ID | required |
| `OPERATION` | `keygen`, `sign`, `key_import`, `spend`, `address` | required |
| `MAX_SIGNERS` / `MIN_SIGNERS` | Threshold parameters | 3 / 2 |
| `PARTIES` | Comma-separated party list | required |
| `ENCRYPTION_KEY` | 32-byte hex for relay encryption | optional |
| `KEYSTORE_PASSPHRASE` | AES-GCM passphrase for stored keyshares | optional |

## License

See individual crate licenses.
