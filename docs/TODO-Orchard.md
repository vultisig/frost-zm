# Zcash Orchard Support

Orchard uses the Pallas curve (Pasta/Halo 2), not Jubjub. Separate FROST ciphersuite, keygen, keyshares, and signing required — cannot share the existing `JubjubBlake2b512` setup. Transactions can contain both Sapling and Orchard actions simultaneously.

## Prerequisites

- [ ] Verify `reddsa` crate has a RedPallas FROST ciphersuite (or implement one)
- [ ] Add `orchard`, `halo2_proofs`, `pasta_curves` crate dependencies
- [ ] Confirm `frost-core` works with Pallas curve parameterization

## Reusable (curve-agnostic)

- Session protocol (`frost-ceremony` feed/takeMsg/result pattern)
- Relay message exchange, encryption, party ID encoding
- TypeScript SDK structure (ceremony.ts, scanner.ts, wallet.ts)
- Bundle pack/unpack format (swap Jubjub fields for Pallas)
- Go wrapper FFI pattern, WASM build pipeline
- `incrementalmerkletree` crate (works with any node type)

## Reusable with curve swap (Jubjub → Pallas)

- Keygen/reshare/key-import sessions — same FROST protocol, different type parameter
- Sign session — RedPallas instead of RedJubjub
- Identifier encoding — identical across ciphersuites

## Must rewrite

- [ ] **Key derivation** — different ZIP-32 path, different viewing key structure (FVK, IVK, OVK, rivk)
- [ ] **Extras generation** — different key material than Sapling (nsk, ovk, rivk)
- [ ] **Note encryption/decryption** — different scheme (Orchard note plaintext format)
- [ ] **Transaction builder** — Orchard actions ≠ Sapling spends/outputs; Halo 2 proofs ≠ Groth16
- [ ] **Tree/witness** — Pallas-based nodes, shard tree structure
- [ ] **Address handling** — Orchard receivers in unified addresses
- [ ] **Scanner** — Orchard compact block decryption, different nullifier computation

## Implementation order

1. RedPallas FROST ciphersuite (if not already in `reddsa`)
2. Orchard keygen session (parallel to Sapling, new ciphersuite)
3. Orchard key derivation + extras (FVK from FROST public key)
4. Orchard note decryption + scanning
5. Orchard action/bundle builder with Halo 2 proving
6. Orchard sign session (RedPallas spend auth signatures)
7. Combined Sapling+Orchard transaction serialization (replace `hash_empty_orchard()` stubs)
8. WASM exports, TypeScript SDK, Go wrappers

## Current Orchard stubs

- `crates/frozt-lib/src/tx.rs` — `hash_empty_orchard()` produces empty digest
- `crates/frozt-lib/src/shielding_tx.rs` — v5 sighash uses empty Orchard digest
- These stubs get replaced in step 7
