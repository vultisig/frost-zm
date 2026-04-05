# Zcash Orchard Support

Orchard uses the Pallas curve (Pasta/Halo 2), not Jubjub. Separate FROST ciphersuite, keygen, keyshares, and signing required — cannot share the existing `JubjubBlake2b512` setup. Transactions can contain both Sapling and Orchard actions simultaneously.

## Crate naming

- `frozts-*` — Sapling (RedJubjub / `JubjubBlake2b512`)
- `frozto-*` — Orchard (RedPallas / `PallasBlake2b512`)

## Extras layout (64 bytes)

```
[0..32]:   nk  (NullifierDerivingKey, pallas::Base)
[32..64]:  rivk (CommitIvkRandomness, pallas::Scalar)
```

FVK = [ak(32) | nk(32) | rivk(32)] where ak comes from the FROST group verifying key.

## Implemented

### Core library (frozto-lib) — 28 tests
- [x] RedPallas FROST ciphersuite (`PallasBlake2b512`)
- [x] Keygen/reshare/key-import sessions
- [x] Sign session with RedPallas spend auth signatures + randomizer
- [x] Key derivation — build FVK from FROST PKP + extras (nk, rivk)
- [x] Extras generation — random nk + rivk; deterministic from seed via ZIP-32
- [x] Key import with seed — derive ask via PRF, FROST constant term
- [x] Address derivation — 43-byte Orchard raw address from FVK
- [x] IVK derivation — 64-byte IncomingViewingKey
- [x] Compact + full note decryption via PreparedIVK + CompactAction
- [x] Nullifier computation from FVK + note plaintext
- [x] Pallas-based incremental Merkle tree (MerkleHashOrchard, depth 32)
- [x] Keyshare bundle with Orchard extras
- [x] Ceremony metadata with blake2b personalization
- [x] Session-based DKG, sign, reshare, key-import protocols

### WASM exports (frozto-wasm) — 17 tests
- [x] wasm-bindgen exports for keygen, sign, reshare, key import
- [x] Orchard key derivation, note decryption, nullifier computation
- [x] Tree/witness operations with MerkleHashOrchard
- [x] Session management
- [x] Cross-verification

### Scanner SDK (frozto-sdk)
- [x] Orchard wallet scanning via lightwalletd (gRPC tonic client)
- [x] UnifiedFullViewingKey construction from Orchard FVK
- [x] FFI exports: frozto_scan, frozto_scan_balance

### Go wrappers (go/frozto, go/frozto-sdk)
- [x] CGo FFI bindings for all frozto-lib functions
- [x] C header files
- [x] Platform-specific linker configurations (darwin, linux, windows)
- [x] Session wrappers (DKG, sign, reshare, key import)
- [x] Scanner wrapper (Scan, ScanBalance)

## Remaining

- [ ] **Transaction builder** — Orchard actions with Halo 2 proofs (requires `orchard::builder`)
- [ ] **Combined Sapling+Orchard tx** — replace `hash_empty_orchard()` stubs in frozts-lib
- [ ] **TypeScript SDK** — packages/frozto-sdk-ts (TS wrapper around WASM module)
