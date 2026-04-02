# Audit Guide

This document identifies the security-critical code in frost-zm and the properties it claims. It is intended for cryptographic auditors.

For build instructions, architecture overview, and upstream dependency tables, see [README.md](README.md).

## Threat Model

**Participants**: Up to N parties, of which at most T-1 may be malicious (for a T-of-N threshold scheme).

**Trusted**: The Rust compiler, `frost-core` v2.2 (ZcashFoundation), `curve25519-dalek` v4, `sapling-crypto` v0.6, `monero-oxide` ecosystem. These are upstream dependencies — not in scope.

**Adversarial**: Any individual party. A malicious party may:
- Send malformed or invalid messages during any ceremony round
- Abort mid-ceremony (stop sending messages)
- Attempt to learn other parties' secret shares from observed messages
- Attempt to bias the group public key or signing output
- Collude with up to T-2 other parties

**Relay**: The relay server is untrusted for confidentiality (messages are encrypted with AES-256-GCM) but semi-trusted for availability. A compromised relay can drop or delay messages but cannot forge them (HMAC-SHA256 integrity). Message replay is detected via sequence numbers.

**Not in scope**: Side channels, implementation bugs in upstream crates, OS-level compromise, key storage at rest (delegated to the application layer).

## Security Properties

### DKG (Distributed Key Generation)
- No party learns any other party's signing share
- The group public key is deterministic given the parties' commitments
- A malicious party providing a bad proof of knowledge is detected and identified (`InvalidProofOfKnowledge`)
- A malicious party providing a bad secret share is detected and identified (`InvalidSecretShare`)

### Threshold Signing
- Any T parties can produce a valid signature
- T-1 parties learn nothing about the full signing key
- A malicious party providing a bad signature share is detected and identified (`InvalidSignatureShare`)
- (Zcash only) Rerandomized signatures are unlinkable to the group public key

### Resharing
- The group public key is preserved across threshold changes
- New parties receive valid shares without learning the original shares
- The final verifying key is checked against the expected value — mismatch aborts

### Key Import
- The imported key is split such that shares sum to the original secret
- Only the seed holder knows the original secret; other parties learn nothing beyond their share
- The final verifying key is checked against the expected value — mismatch aborts

### Blame
- frost-core's `culprit()` identifies the misbehaving party for proof, share, and signature errors
- Blame consensus requires majority agreement (>N/2) — a single malicious party cannot frame an honest one
- Absence detection relies on context timeout at the Go layer

## Custom Cryptographic Code

These are the files that implement protocol logic beyond calling upstream libraries. **This is where auditors should focus.**

### Generic (both chains)

| File | What it does | Custom math |
|------|-------------|-------------|
| `crates/frost-ceremony/src/reshare.rs` | Threshold resharing (change T-of-N while preserving group key) | Lagrange interpolation coefficients over scalar field; additive share computation with adjustment for new parties |
| `crates/frost-ceremony/src/key_import.rs` | Import existing secret key into threshold shares | Polynomial constant term = `secret - (N-1)`, others use `1`; feeds into standard DKG part2/part3 |
| `crates/frost-ceremony/src/blame.rs` | Extract culprit from frost-core errors | No crypto — reverse-maps `Identifier<C>` to u16 |

### Zcash (frozt)

| File | What it does | Custom math |
|------|-------------|-------------|
| `crates/frozt-lib/src/sapling.rs` | Compose FROST group key with Sapling scalars (nsk, ovk, dk) to derive DiversifiableFullViewingKey and z-address | `nk = G_nk * nsk` point multiplication; rest delegates to `sapling-crypto` |
| `crates/frozt-lib/src/key_import.rs` | Zcash-specific key import — derives `ask` from BIP39 seed via ZIP 32 path | Calls `derive_spending_key` then generic `key_import_part1` |
| `crates/frozt-lib/src/session.rs` (sign section) | Session-based rerandomized signing — coordinator generates randomizer, broadcasts SigningPackage + Randomizer | Delegates to `frost_rerandomized::sign` and `frost_rerandomized::aggregate` |
| `crates/frozt-lib/src/tx.rs` | Sapling v5 transaction assembly | Serialization only — proof generation delegates to `sapling-crypto` Groth16 provers |
| `crates/frozt-lib/src/ceremony_metadata.rs` | Versioned metadata blob with Blake2b hash verification | Blake2b hash comparison — no custom crypto |

### Monero (fromt)

| File | What it does | Custom math |
|------|-------------|-------------|
| `crates/fromt-lib/src/ceremony/dkg.rs` | DKG with view key share aggregation | Random scalar generation + scalar addition for view key aggregation |
| `crates/fromt-lib/src/ceremony/key_import.rs` | Key import with view key derivation | `Keccak256(spend_key)` → Ed25519 scalar via `from_bytes_mod_order` for view key share |
| `crates/fromt-lib/src/ceremony/reshare.rs` | Reshare with view key re-aggregation | Same view key scalar addition as DKG |
| `crates/fromt-lib/src/ceremony/ckd.rs` | Child key derivation by (account, index) | Path scalar = `Keccak256("fromt/ckd" \|\| account_le32 \|\| index_le32)`; each party adds this to their share |
| `crates/fromt-lib/src/ceremony/key_image.rs` | Threshold key image generation | Each signer: `lambda_i * x_i * Hp(P)` point; sum + `key_offset * Hp(P)` = key image. Lagrange coefficients. |
| `crates/fromt-lib/src/monero/spend.rs` | Keyshare conversion for threshold CLSAG | Format conversion: FROST `KeyPackage<Ed25519Sha512>` → `ThresholdKeys<dalek_ff_group::Ed25519>` |
| `crates/fromt-lib/src/monero/address.rs` | Main address derivation | `network_prefix \|\| spend_pub \|\| view_pub \|\| keccak256_checksum` — standard Monero encoding |
| `crates/fromt-lib/src/monero/subaddress.rs` | Subaddress derivation | `Keccak256("SubAddr\0" \|\| view_key \|\| account \|\| index)` — standard Monero subaddress scheme |

## FFI Boundary

The Rust ↔ Go boundary (`frost-ffi`) is security-relevant for memory safety:

| File | Concern |
|------|---------|
| `crates/frost-ffi/src/handle.rs` | Global handle table — stores secret state (KeyPackage, nonces). Double-free / use-after-free would leak or corrupt secrets. |
| `crates/frost-ffi/src/bytes.rs` | `go_slice` / `tss_buffer` — raw pointer exchange. Lifetime must not exceed the CGo call. |
| `crates/frost-ffi/src/errors.rs` | `with_error_handler` catches panics at FFI boundary. Thread-local blamed party storage for blame protocol. |

Go side uses `runtime.Pinner` to prevent GC from moving slices during CGo calls.

## Session & Relay Security

| File | Concern |
|------|---------|
| `crates/frost-session/src/relay.rs` | In-memory message buffers — no persistence, no replay log |
| `crates/frost-session/src/session.rs` | `Protocol` drives async ceremony via manual polling — no timeout at Rust layer (relies on Go context) |
| `client/shared/relay/encryption.go` | AES-256-GCM with HKDF key derivation; HMAC-SHA256 message integrity |
| `client/shared/relay/client.go` | Sequence number tracking for replay detection |
| `client/shared/session/blame.go` | Post-failure blame exchange — majority tally, barrier synchronization |

## Wire Formats

### KeyShareBundle (frozt)
```
[version:u8][birthday:u64 LE][extras_len:u32 LE][sapling_extras:96][kp_len:u32 LE][KeyPackage][pkp_len:u32 LE][PublicKeyPackage]
```

### KeyShareBundle (fromt)
```
[version:u8][network:u8][view_key:32][birthday:u64 LE][kp_len:u32 LE][KeyPackage][pkp_len:u32 LE][PublicKeyPackage]
```

### Ceremony Messages
```
Outbox frame: [recipient:u16 LE][payload]     (recipient=0 for broadcast)
Inbox frame:  [sender:u16 LE][payload]
```

### Relay Messages (Go layer)
```json
{
  "session_id": "...",
  "from": "party-name",
  "to": ["recipient-name"],
  "body": "base64-encoded-payload",
  "hash": "hmac-sha256-hex",
  "sequence_no": 42
}
```

## Known Limitations

1. **No timeout in Rust ceremony layer** — `recv()` blocks indefinitely. Absence detection relies entirely on Go context cancellation.
2. **Thread-local blame state** — `LAST_BLAMED_ID` is thread-local. Works because CGo pins goroutines to OS threads. Would break under a thread pool model.
3. **Blame for sign ceremony** — The sign orchestration (explicit round collection, not session-based) returns `CeremonyResult` but does not yet call `handleBlame()`. Blame error codes ARE propagated from Rust; the exchange step is not wired up.
4. **No equivocation detection** — A party sending different messages to different recipients is not detected. Would require a commitment round or echo broadcast, which is not implemented.
5. **Relay availability** — A compromised relay can prevent ceremonies from completing by dropping messages. Encrypted messages prevent content inspection.
6. **View key shares (Monero)** — View key shares are simple random scalars summed across parties. The security of the aggregate view key depends on at least one honest party contributing a truly random share.

## Test Coverage

```bash
cargo test -p frost-ceremony    # 5 tests (blame unit tests)
cargo test -p frost-session     # 7 tests (protocol state machine)
cargo test -p frozt-lib         # 56 tests (DKG, sign, reshare, key import, sapling, tx building)
cargo test -p fromt-lib         # 26 tests (DKG, sign, reshare, key import, CKD, key image, spend)
```

All ceremony tests run complete multi-party protocols in-process (no network). Signing tests verify output signatures against the group public key.
