# FROST Blame / Accountability

## Context

FROST protocol errors currently discard all blame information. Every `dkg::part2`, `dkg::part3`, and `aggregate` call uses `.map_err(|_| lib_error::LIB_DKG_ERROR)`, throwing away the culprit identifier that frost-core provides natively (no extra rounds needed).

frost-core v2.2.0 has a `culprit()` method on `Error<C>` that returns the misbehaving party's `Identifier<C>` for:
- `InvalidProofOfKnowledge { culprit }` — from `dkg::part2` (bad proof in R1 package)
- `InvalidSecretShare { culprit }` — from `dkg::part3` (bad share vs commitments)
- `InvalidSignatureShare { culprit }` — from `aggregate()` (bad signature share)

DKLS23 already has blame (error codes 100-109). This plan brings FROST to parity.

## Implementation

### 1. Add blame error codes — `crates/frost-ffi/src/errors.rs`

Add 10 variants (codes 100-109, matching DKLS pattern):

```rust
#[error("Blame party 1")]
LIB_BLAME_PARTY_1 = 100,
// ... through
#[error("Blame party 10")]
LIB_BLAME_PARTY_10 = 109,
```

Add helper:
```rust
impl lib_error {
    pub fn blame_party(id: u16) -> Option<lib_error> { ... }
}
```

### 2. Add blame helper — NEW `crates/frost-ceremony/src/blame.rs`

```rust
pub fn identifier_to_u16<C: Ciphersuite>(ident: &Identifier<C>) -> Option<u16> {
    // Try 1..=10, compare serialized bytes
}

pub fn frost_err_to_blame<C: Ciphersuite>(
    err: frost_core::Error<C>, default: lib_error,
) -> lib_error {
    // Extract culprit → reverse to u16 → blame_party(u16)
    // Falls back to `default` if no culprit or party > 10
}
```

Register in `crates/frost-ceremony/src/lib.rs`: `pub mod blame;`

### 3. Replace error-discarding `map_err` calls

Change all `.map_err(|_| lib_error::LIB_*_ERROR)` on frost-core DKG/sign calls to `.map_err(|e| blame::frost_err_to_blame(e, lib_error::LIB_*_ERROR))`.

**frost-ceremony (8 call sites):**

| File | Call | Default |
|------|------|---------|
| `dkg.rs:68` | `dkg::part1` | `LIB_DKG_ERROR` |
| `dkg.rs:82` | `dkg::part2` | `LIB_DKG_ERROR` |
| `dkg.rs:99` | `dkg::part3` | `LIB_DKG_ERROR` |
| `sign.rs:62` | `round2::sign` | `LIB_SIGNING_ERROR` |
| `sign.rs:78` | `aggregate` | `LIB_SIGNING_ERROR` |
| `key_import.rs:69` | `dkg::part3` | `LIB_DKG_ERROR` |
| `reshare.rs:102` | `compute_proof_of_knowledge` | `LIB_RESHARE_ERROR` |
| `reshare.rs:133` | `dkg::part3` | `LIB_DKG_ERROR` |

**frost-ceremony sessions (8 call sites):**

| File | Call | Default |
|------|------|---------|
| `session_dkg.rs:23` | `dkg::part1` | `LIB_DKG_ERROR` |
| `session_dkg.rs:40` | `dkg::part2` | `LIB_DKG_ERROR` |
| `session_dkg.rs:59` | `dkg::part3` | `LIB_DKG_ERROR` |
| `session_sign.rs:46` | `round2::sign` | `LIB_SIGNING_ERROR` |
| `session_sign.rs:62` | `aggregate` | `LIB_SIGNING_ERROR` |
| `session_reshare.rs:38` | `dkg::part2` | `LIB_DKG_ERROR` |
| `session_reshare.rs:57` | `dkg::part3` | `LIB_DKG_ERROR` |
| `session_key_import.rs:36,55` | `dkg::part2`, `part3` | `LIB_DKG_ERROR` |

**fromt-lib (6 call sites, calls frost-core directly for vk_share handling):**

| File | Call |
|------|------|
| `ceremony/dkg.rs:131` | `dkg::part2` |
| `ceremony/dkg.rs:155` | `dkg::part3` |
| `ceremony/key_import.rs:100` | `dkg::part3` |
| `ceremony/reshare.rs:71` | `dkg::part3` |
| `session.rs:89,667` | `dkg::part2` (DKG + key import) |
| `session.rs:107,685` | `dkg::part3` (DKG + key import) |

**frozt-lib (2 call sites, uses frost_rerandomized::aggregate):**

| File | Call |
|------|------|
| `sign.rs:161` | `frost_rerandomized::aggregate` |
| `session.rs:182` | `frost_rerandomized::aggregate` |

**frozt-wasm (session only, non-session uses `to_js_err` which already preserves info):**

| File | Call |
|------|------|
| `session.rs:116-118` | `frost_rerandomized::aggregate` |

**fromt-wasm (4 call sites in session async fns):**

| File | Call |
|------|------|
| `session.rs:97` | `dkg::part2` (DKG run) |
| `session.rs:115` | `dkg::part3` (DKG run) |
| `session.rs:209` | `dkg::part2` (key import run) |
| `session.rs:227` | `dkg::part3` (key import run) |

### 4. Update C headers

Both `go/frozt/includes/frozt-lib.h` and `go/fromt/includes/fromt-lib.h` — add `LIB_BLAME_PARTY_1 = 100` through `LIB_BLAME_PARTY_10` to enum.

### 5. Update Go error mappings — `go/frostgo/errors.go`

Add constants `LibBlameParty1 = 100` through `LibBlameParty10 = 109` and messages to `sharedErrorMessages` map: `"blame party N"`.

## Verification

1. `cargo test -p frost-ceremony` — existing tests pass
2. `cargo test -p frozt-lib` — existing tests pass
3. `cargo test -p fromt-lib` — existing tests pass
4. `cargo check -p frozt-wasm && cargo check -p fromt-wasm` — compiles
