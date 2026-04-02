# FCMP++ Integration into FROMT: Analysis & Impact

## Executive Summary

FCMP++ (Full-Chain Membership Proofs++) replaces Monero's CLSAG ring signatures with a zero-knowledge proof that the spent output exists *anywhere* on the blockchain. The anonymity set jumps from 16 decoys to ~150M+ outputs. **FROMT continues to exist and is still needed** — FCMP++ changes *what* is being signed, not *whether* threshold signing is required. However, the signing protocol, transaction building, and several ceremonies require significant rework.

**Bottom line:** FROMT's DKG, resharing, key import, view key aggregation, CKD, and address derivation are **unchanged**. The signing ceremony, key image ceremony, and transaction builder require **major rework** to produce FCMP++ proofs instead of CLSAG ring signatures.

---

## 1. What Stays the Same

These FROMT components are **unaffected** by FCMP++:

| Component | Why Unchanged |
|-----------|--------------|
| DKG (`ceremony/dkg.rs`) | FROST polynomial DKG over Ed25519 — FCMP++ doesn't change key generation |
| Resharing (`ceremony/reshare.rs`) | Lagrange re-sharing of Ed25519 shares — independent of signing protocol |
| Key Import (`ceremony/key_import.rs`) | Importing existing spend keys into threshold shares — key format unchanged |
| View Key Aggregation | Sum of scalar shares — view key derivation is unchanged |
| CKD (`ceremony/ckd.rs`) | Deterministic child key derivation via Keccak256 — independent of signing |
| Address Derivation (`monero/address.rs`) | Standard Monero addresses (spend_pub + view_pub) — backward compatible |
| Subaddresses (`monero/subaddress.rs`) | SubAddr hash derivation — unchanged |
| KeyShareBundle (`keyshare/bundle.rs`) | Bundle format stores FROST KeyPackage — still valid |
| FFI architecture | Handle table, buffer types, codec — all reusable |
| Go wrappers (DKG, reshare, CKD) | FFI calls to unchanged ceremonies — no changes |
| TypeScript SDK (wallet, scanner, ceremony) | DKG ceremony, address derivation — unchanged |

**FROMT's core identity — threshold key management over Ed25519 — is fully preserved.**

---

## 2. What Must Change

### 2.1 Signing Ceremony (Major Rework)

**Current:** 3-phase CLSAG threshold signing via `modular-frost` + `monero-wallet`:
```
Preprocess → Sign → Complete → CLSAG ring signature
```

**FCMP++:** The CLSAG ring signature is entirely replaced. The new signing must produce:
1. **FCMP++ membership proof** — proves the output is in the Curve Tree (no secret key needed for this part)
2. **Spend authorization via Generalized Schnorr Protocol (GSP)** — proves knowledge of spend key `x`
3. **Key image correctness via DLEq proof** — proves `I = x * H(K)`

The GSP is a Schnorr-like proof using a matrix composition:
```
Matrix: [G, T, 0]   (Open re-randomized key K')
        [0, 0, V]   (Open blinding B)
        [U, 0, 0]   (Create xU)
        [I', 0, -Z] (Form key image)
```

**Impact on FROMT:**

- **`modular-frost` dependency must be replaced or extended.** The current `modular-frost` v0.11 adapts FROST Ed25519 shares to CLSAG. A new adapter is needed that adapts FROST shares to the GSP protocol.
- **The GSP is fundamentally Schnorr-like**, meaning FROST's threshold Schnorr framework should be adaptable. The spend authorization proves knowledge of `x` (the aggregate spend key) — exactly what FROST distributes.
- **The membership proof (Curve Tree path)** does NOT require the secret key. It requires:
  - The output's position in the Curve Tree
  - Re-randomization scalars
  - The Curve Tree root (from `referenceBlock`)

  This can be constructed by any party with access to the blockchain data. It does NOT need threshold distribution.

- **The DLEq proof** requires `x` and `H(K)`. In a threshold setting, this requires a **distributed DLEq protocol** — each signer contributes their share of the DLEq proof.

**Estimated complexity:** This is the largest single work item. Requires:
- New Rust crate or module for threshold GSP signing
- Distributed DLEq proof protocol
- Curve Tree membership proof construction (non-threshold, but new code)
- New FFI surface for the changed signing rounds
- Updated Go and TypeScript wrappers

### 2.2 Key Image Ceremony (Moderate Rework)

**Current (`ceremony/key_image.rs`):** 2-round protocol where each signer computes:
```
partial_i = λ_i * x_i * H_p(P)
key_image = Σ partials + key_offset * H_p(P)
```

**FCMP++:** Key images remain conceptually the same (`I = x * H(K)`), but with one change:
- The **sign bit is cleared** before database insertion (`crypto::key_image_y` type)
- `crypto::key_image_to_y()` clears the sign bit

**Impact on FROMT:**
- The threshold key image generation protocol itself is still valid
- Add a post-processing step: clear sign bit on the final key image
- The `H_p` hash-to-point function must match FCMP++'s definition (should be the same as current Monero)
- Update the key image ceremony output format

**Estimated complexity:** Small — add sign-bit clearing to the existing ceremony's output.

### 2.3 Transaction Building (Major Rework)

**Current (`monero/spend.rs`):** Constructs `SignableTransaction` with:
- `RctType::ClsagBulletproofPlus`
- Inputs: `OutputWithDecoys` (ring of 16 members, real index)
- Decoy selection from daemon RPC

**FCMP++:**
- `RctType::FcmpPlusPlus` (type 7)
- Inputs: `referenceBlock` hash + key image + FCMP++ proof bytes
- **No decoy selection** — eliminated entirely
- Curve Tree leaf lookup replaces ring member selection
- Outputs use **CARROT** addressing (new output format with `janus_anchor_t` and `view_tag_t`)
- Range proofs: **Generalized Bulletproofs** replace Bulletproofs+

**Impact on FROMT:**

| Sub-component | Change |
|---------------|--------|
| Decoy selection | **Removed entirely** — no more ring member fetching from daemon |
| Input construction | Replace ring members with `referenceBlock` + Curve Tree leaf index |
| Output construction | Add CARROT fields (janus anchor, view tag) |
| Range proofs | Switch from Bulletproofs+ to Generalized Bulletproofs |
| Transaction serialization | New format for RCTTypeFcmpPlusPlus |
| RPC interaction | Need Curve Tree root queries + leaf position lookups |

**Estimated complexity:** Large — the entire transaction builder must be rewritten.

### 2.4 Output Scanning (Moderate Changes)

**Current:** Scanner detects owned outputs using incoming view key (IVK), derives key offset and commitment mask.

**FCMP++ with CARROT:**
- Scanning still uses the view key but with updated derivation (CARROT protocol)
- **Outgoing view keys** added — can detect when received outputs are spent
- **View tags** enable faster scanning (single-byte tag check before full derivation)
- Output detection formula changes to match CARROT's rerandomization

**Impact on FROMT:**
- `FromtWallet.scanBalance()` needs updated output detection logic
- View tag pre-filtering can significantly speed up scanning
- Outgoing view key derivation may need new threshold protocol or may be derivable from existing view key

### 2.5 Upstream Dependencies

**Must be added or replaced:**

| Dependency | Purpose | Status |
|------------|---------|--------|
| `fcmp-plus-plus` (Rust) | FCMP++ proof construction/verification | kayabaNerve's impl, migrated to monero-oxide `fcmp++` branch |
| `helioselene` | Helios/Selene curve cycle | Part of fcmp-plus-plus |
| `generalized-bulletproofs` | Range proofs + FCMP++ circuit proofs | Part of fcmp-plus-plus / monero-oxide |
| `ec-divisors` | Efficient scalar multiplication verification | Part of fcmp-plus-plus |
| CARROT addressing | New output format | jeffro256/carrot |

**Must be removed or made optional:**
- `monero-clsag` — no longer used for signing (keep for legacy verification?)
- `modular-frost` — CLSAG adapter no longer needed; need GSP adapter instead
- Decoy selection RPC calls

---

## 3. The GSP: Deep Dive & Threshold Feasibility

### 3.1 What the SAL Proof Actually Is

The FCMP++ "Spend Authorization and Linkability" (SAL) proof is **NOT a simple 4-row GSP matrix**. The actual implementation (in `fcmp-plus-plus/networks/monero/ringct/fcmp++/src/sal/mod.rs`) is a **BP+ and GSP Conjunction** — a hybrid proof combining a Bulletproof+-style quadratic verification equation with three GSP-style linear verification equations.

#### The Proof Data (`SpendAuthAndLinkability`)
- 6 group elements: `P, A, B, R_O, R_P, R_L`
- 6 scalars: `s_alpha, s_beta, s_delta, s_y, s_z, s_r_p`

#### The Secret Witnesses
- `x` = spend key (THE critical secret — this is what FROST distributes)
- `y` = blinding in output key `O = xG + yT`
- `r_i` = re-randomization scalar for linking tag generator
- `r_o, r_c, r_r_i, r_p` = other re-randomization/blinding scalars

#### The Four Verification Equations

**Equation 1 — BP+ Verification (quadratic in challenge `e`):**
```
e^2 * P + e * A + B == s_alpha*e * G + s_beta*e * V + s_alpha*s_beta * U + s_delta * T
```
This verifies the polynomial identity binding three "levels":
- `B = (alpha*beta)*U + mu*T` (nonce product)
- `A = (alpha*r_i + beta*x)*U + delta*T` (cross-terms)
- `P = x*G + r_i*V + x*r_i*U + r_p*T` (commitment)

**The `s_alpha * s_beta` product** on the verifier side is what makes this non-trivially different from a standard Schnorr proof.

**Equation 2 — Output Key GSP:**
```
R_O + e*O_tilde == s_alpha*G + s_y*T
```
Proves: `O_tilde = x*G + y*T` (opening of the re-randomized output key)

**Equation 3 — P' GSP:**
```
R_P + e*(P - O_tilde - R_input) == s_z*U + s_r_p*T
```
Proves consistency between `P`, `O_tilde`, and `R_input`, binding `x*r_i` via `s_z`.

**Equation 4 — Key Image GSP:**
```
R_L + e*L == s_alpha*I_tilde - s_z*U
```
Proves: `L = x*I_tilde - x_r_i*U = x*H(K)` (correct key image)

### 3.2 Where the Secret Key `x` Appears

| Operation | Expression | Linear in `x`? |
|-----------|-----------|----------------|
| Key image | `L = I_tilde * x - U * (r_i * x)` | Yes (given known `r_i`) |
| Cross-term | `x_r_i = x * r_i` | Yes (given known `r_i`) |
| Commitment P | `P = x*G + r_i*V + x_r_i*U + r_p*T` | Yes |
| Commitment A | `(alpha*r_i + beta*x)*U` | Yes |
| Response `s_alpha` | `s_alpha = alpha + e*x` | **Yes — standard Schnorr** |
| Response `s_z` | `s_z = r_z + e*(x*r_i)` | Yes (given known `r_i`) |

**Critical finding: ALL operations on `x` are linear**, provided `r_i` is known to all signers. The apparent non-linearity (`x * r_i`) is only non-linear if BOTH are secret-shared. Since `r_i` is a re-randomization scalar chosen by the proving parties (not a distributed secret), the product `x * r_i` is simply `r_i * x` — linear in `x`.

### 3.3 kayabaNerve Already Built Threshold SAL

The `fcmp-plus-plus` repo contains TWO multisig implementations:

**`sal/multisig.rs` — Modern (shares `y`, knows `x`):**
- Each signer holds the full spend key `x`
- The view key blinding `y` is secret-shared via FROST
- Uses FROST over a modified `Ed25519T` ciphersuite (generator `T` instead of `G`)
- Only `s_y` is computed as a threshold share
- Supports CARROT outgoing view keys

**`sal/legacy_multisig.rs` — Legacy (shares `x`, knows `y`):**
- The spend key `x` is secret-shared via FROST (standard Ed25519 generator `G`)
- All other nonces computed deterministically from shared transcript
- `s_alpha = alpha + e*x` computed as threshold shares
- This is the model closest to FROMT's architecture

Both use `modular-frost`'s `Algorithm` trait — the same plugin system FROMT already uses for CLSAG.

### 3.4 Can We Build It? Assessment

**Mathematical feasibility: YES.**
The SAL proof is threshold-compatible because `x` enters only linearly. This is confirmed by kayabaNerve's working implementations.

**Code exists: YES.**
`sal/legacy_multisig.rs` implements exactly what FROMT needs — FROST-distributed `x` producing SAL proofs. The code uses `modular-frost` which is the same framework FROMT already depends on.

**What we'd actually build:**

| Component | Effort | Notes |
|-----------|--------|-------|
| Port `SalLegacyAlgorithm` to FROMT | Medium | Adapt kayabaNerve's impl to our crate structure |
| `helioselene` + `ec-divisors` deps | Small | Add Cargo dependencies |
| `generalized-bulletproofs` integration | Medium | Range proof swap |
| Curve Tree membership proof builder | Large | Non-threshold but substantial new infrastructure |
| CARROT output construction | Medium | New output format |
| FFI + Go/WASM wrappers | Medium | New function signatures for SAL rounds |

**What we should NOT build from scratch:**
- The SAL proof math — use kayabaNerve's implementation directly
- The Curve Tree data structure — use monero-oxide's implementation
- The GBP prover/verifier — use the audited implementation

### 3.5 Available Test Infrastructure (monero-oxide)

kayabaNerve's repo provides complete test coverage we can reuse:

**Single-signer SAL test** (`tests/sal/mod.rs`):
- Generate random `(x, y)`, create output `O = xG + yT`, rerandomize, prove, verify with batch verifier
- 4 batch equations checked, binary pass/fail

**Threshold SAL tests** (feature-gated behind `multisig`):
- `test_sal_legacy_multisig()` — FROST over standard Ed25519, secret-shares `x` (our model)
- `test_sal_multisig()` — FROST over Ed25519T, secret-shares `y`
- Both use `modular_frost::tests::{key_gen, algorithm_machines, sign}` — full t-of-n ceremony in-memory, no network

**Full FCMP++ pipeline test** (`tests/mod.rs`):
- Builds a minimal 1-leaf Curve Tree in-memory (mock, no chain connection)
- Proves membership + SAL + key image
- Verifies with three batch verifiers (Ed25519, Selene, Helios)
- Tests serialization/deserialization roundtrip
- Uses real Monero generators (compiled via `build.rs`)

**Malleation/soundness test** (`crypto/fcmps/src/tests.rs`):
- Flips every byte of serialized proof, asserts none verify — catches subtle encoding bugs

All tests are generative (random keys, prove-then-verify). No pre-computed test vectors. No chain connection needed. Verification is binary — either we produce a valid proof or we don't.

### 3.6 API Surface Impact: No New Functions Needed

The FCMP++ transition does NOT require branching the FROMT API or adding parallel code paths.

**Key image ceremony**: Unchanged math. `I = x * H(K)` via threshold Lagrange. Add one line to clear the sign bit. Same functions (`key_image_part1`, `key_image_part2`).

**Signing ceremony**: `spend_preprocess` / `spend_sign` / `spend_complete` swap `ClsagMultisig` for `SalLegacyAlgorithm` internally. Both implement the same `modular-frost::Algorithm` trait. Same 3-phase round structure:

```
Current (CLSAG):     preprocess → sign → complete
FCMP++ (SAL Legacy): preprocess → sign → complete
```

SAL Legacy's preprocess round includes an **addendum** (each party's `key_image_share` + `x_U_share`), but modular-frost handles addendum exchange as part of the preprocess round — not as an extra round. Bigger payload, same round count.

**No runtime branching.** After the FCMP++ hard fork, CLSAG is dead on-chain. It's a wholesale swap of the `Algorithm` implementation, not a flag. Existing keyshares are forward-compatible — same FROST Ed25519 shares, different proof produced.

The FFI surface (`fromt_spend_preprocess`, `fromt_spend_sign`, `fromt_spend_complete`) keeps the same signatures. The Go wrappers, WASM bindings, and TypeScript SDK ceremony code don't need to know which `Algorithm` is running underneath.

**The signing flow stays:**
```
1. Key image ceremony (unchanged) → check if outputs are spent
2. Signing ceremony (SAL instead of CLSAG) → produces SAL proof
   └── SAL also recomputes key images internally via addendum
       (should match step 1 — free consistency check)
3. Assemble tx with membership proof + SAL proof → broadcast
```

### 3.7 The Honest Answer

**We know enough to build it.** The math is understood, the code exists, the test infrastructure exists, and it plugs into our existing `modular-frost` framework. The question isn't capability — it's **risk**:

1. **Spec instability**: FCMP++ is pre-mainnet. The SAL proof structure could change. Building now means potential rework.
2. **Dependency chain**: We'd depend on kayabaNerve's `fcmp-plus-plus` crates which are archived and migrating to `monero-oxide`. The API surface is moving.
3. **Audit gap**: The GBP security proofs are still being developed by Cypher Stack. Building on unfinished audit work is a risk for production deployment.
4. **Verification is binary**: Either we produce a valid tx or we don't. The network doesn't care how the proof was constructed — no "multisig support" gate at the consensus layer. We can test against the stressnet now and ship on mainnet hard fork day.

---

## 4. New Components Required

### 4.1 Threshold SAL Signing Protocol (SalLegacyAlgorithm Port)

Port `SalLegacyAlgorithm` from kayabaNerve's `fcmp-plus-plus` to FROMT. This is the `Algorithm` trait implementation for `modular-frost` that produces SAL proofs with FROST-distributed `x`.

**Round structure (2 rounds, same as current CLSAG):**
1. **Preprocess**: Each signer generates nonces (`alpha_i, beta_i, delta_i, mu_i, ...`), computes commitments (`A_i, B_i, R_O_i, R_P_i, R_L_i`), broadcasts
2. **Sign**: Collect all commitments, compute challenge `e`, each signer computes response shares (`s_alpha_i = alpha_i + e*x_i`, etc.), aggregate via Lagrange

### 4.2 Curve Tree Client

A new module to:
- Query the daemon for Curve Tree roots at specific blocks
- Look up output positions (leaf indices) in the Curve Tree
- Construct membership proofs (Merkle-like paths through alternating Helios/Selene layers)

This is non-threshold (no secret key involvement) but is new infrastructure.

### 4.3 CARROT Output Handler

New output construction following the CARROT protocol:
- Janus anchor generation
- View tag computation
- Updated one-time address derivation
- Forward secrecy envelope

---

## 5. Migration Strategy

### Phase 1: Preparation (Can Start Now)
- [ ] Add `helioselene`, `generalized-bulletproofs`, `ec-divisors` as dependencies
- [ ] Implement Curve Tree client (non-threshold, pure blockchain queries)
- [ ] Implement CARROT output construction
- [ ] Update output scanner for CARROT view tags
- [ ] Add key image sign-bit clearing

### Phase 2: Core Crypto (Can Start Now)
- [ ] Port `SalLegacyAlgorithm` from kayabaNerve's fcmp-plus-plus to FROMT
- [ ] Implement distributed DLEq proof protocol
- [ ] Build FCMP++ proof assembly (membership proof + threshold SAL + DLEq)
- [ ] Unit-test threshold SAL against verifier equations
- [ ] Integration-test full tx against FCMP++ stressnet (network validates proofs regardless of how they were constructed — no "multisig support" needed)

### Phase 3: Transaction Builder
- [ ] New transaction type `RCTTypeFcmpPlusPlus`
- [ ] Replace decoy selection with Curve Tree leaf lookup
- [ ] Wire up FCMP++ proof into transaction inputs
- [ ] Generalized Bulletproofs for range proofs
- [ ] End-to-end transaction construction + broadcast

### Phase 4: FFI & Wrappers
- [ ] New FFI functions for FCMP++ signing rounds
- [ ] Updated Go wrappers
- [ ] Updated WASM bindings
- [ ] Updated TypeScript SDK
- [ ] Remove or gate CLSAG-specific code behind feature flag

### Phase 5: Testing & Hardening
- [ ] Test against FCMP++ stressnet/testnet
- [ ] Cross-party signing tests (2-of-3, 2-of-2)
- [ ] Performance benchmarks (FCMP++ proof generation is ~1 min on consumer hardware — may need optimization for mobile/WASM)
- [ ] Security review of threshold GSP implementation

---

## 6. Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| FCMP++ spec not finalized | High | Track monero-project/monero PR #9436; design paper is v0.5.2 |
| SAL proof structure changes before mainnet | Medium | kayabaNerve's code is the reference; changes will be visible in monero-oxide |
| Proof generation too slow for WASM/mobile | Medium | ~1 min on desktop; may need native-only signing or WebWorker offload |
| `modular-frost` API drift (repo archived → monero-oxide) | Medium | Pin specific commits; track migration |
| GBP security proofs incomplete (Cypher Stack) | Medium | Don't deploy to production until audit finishes |
| Stressnet wallet lacks multisig UX | Low | Irrelevant — network validates proofs regardless of construction method; we bypass their wallet and submit raw transactions |
| CARROT addressing spec changes | Low | CARROT has been audited; relatively stable |
| Helioselene curve security | Low | 127.3 bits ECDLP security; audited by Veridise |
| Timeline uncertainty | Medium | FCMP++ mainnet tentatively mid-late 2026; plan accordingly |

---

## 7. Architecture Diagram: Before and After

### Current FROMT Signing Flow
```
Wallet scans outputs (view key)
  → Select decoys from daemon (16-ring per input)
  → Build SignableTransaction (CLSAG + Bulletproofs+)
  → Threshold CLSAG signing via modular-frost:
      Party 1: preprocess → share → aggregate
      Party 2: preprocess → share → (sent to aggregator)
  → Broadcast signed transaction
```

### FCMP++ FROMT Signing Flow
```
Wallet scans outputs (view key + CARROT view tags)
  → Query Curve Tree root at referenceBlock
  → Look up output leaf position in Curve Tree
  → Build FCMP++ transaction:
      [Non-threshold] Construct Curve Tree membership proof
      [Threshold] GSP spend authorization:
          Party 1: nonce commit → GSP share → aggregate
          Party 2: nonce commit → GSP share → (sent to aggregator)
      [Threshold] DLEq key image proof:
          Party 1: DLEq share
          Party 2: DLEq share → aggregate
      Assemble: membership proof + GSP proof + DLEq proof
  → Generalized Bulletproofs for range proofs
  → Broadcast signed transaction
```

---

## 8. Answers to Key Questions

**Q: Do we still use FROMT?**
**A: Yes, absolutely.** FROMT's core purpose — distributing Monero spend key authority across multiple parties via FROST — is unchanged. FCMP++ changes the *proof format* for spending, not the *need* for threshold signing.

**Q: Does FROMT change?**
**A: The signing layer changes significantly; everything else stays.**
- DKG, resharing, key import, CKD, address derivation: **no changes**
- Signing ceremony: **major rework** (CLSAG → GSP + DLEq)
- Key image ceremony: **minor update** (sign-bit clearing)
- Transaction builder: **major rework** (rings → Curve Tree proofs, Bulletproofs+ → GBP, CARROT outputs)
- Scanner: **moderate update** (CARROT view tags, outgoing view keys)

**Q: Can we build the threshold GSP ourselves?**
**A: Yes.** kayabaNerve already built it (`sal/legacy_multisig.rs` in fcmp-plus-plus). The math is linear in `x`, compatible with FROST, and plugs into `modular-frost`'s `Algorithm` trait — the same framework FROMT already uses. We wouldn't be inventing new crypto; we'd be porting existing, working code. The real risk isn't mathematical — it's spec instability (FCMP++ is pre-mainnet) and the lack of a multisig-enabled test network.

**Q: What's the biggest blocker?**
**A: Spec stability.** The FCMP++ SAL proof structure could change before mainnet. The math and code are available now — we can build, unit-test against the verifier, and integration-test against the stressnet immediately. The network validates proofs regardless of whether they were constructed by one signer or by threshold parties — there is no "multisig support" gate at the consensus layer.

**Q: What's the timeline?**
**A: We can start building now and ship on FCMP++ hard fork day.** The threshold SAL code exists (kayabaNerve's `legacy_multisig.rs`), the stressnet is live for integration testing, and the network doesn't distinguish threshold-constructed proofs from single-signer proofs. FCMP++ mainnet hard fork is tentatively mid-late 2026.

**Q: Is the proof too slow for our use case?**
**A: Potentially, for WASM/mobile.** FCMP++ proof generation takes ~1 minute on consumer desktop hardware. In WASM or on mobile devices, this could be significantly slower. The membership proof construction (Curve Tree traversal with Helios/Selene arithmetic) is the expensive part. Native signing may be required, with WASM used only for DKG/resharing/key management.

---

## 9. References

- [FCMP++ Specification (kayabaNerve)](https://gist.github.com/kayabaNerve/0e1f7719e5797c826b87249f21ab6f86)
- [FCMP++ Design Paper v0.5.2](https://moneroresearch.info/index.php?action=attachments_ATTACHMENTS_CORE&method=downloadAttachment&id=220&resourceId=227)
- [FCMP++ Integration PR #9436](https://github.com/monero-project/monero/pull/9436)
- [FCMP++ Development CCS](https://ccs.getmonero.org/proposals/fcmp++-development.html)
- [Veridise Security Audit](https://veridise.com/audits-archive/company/monero-research-lab/)
- [CARROT Addressing Protocol](https://github.com/jeffro256/carrot/blob/master/carrot.md)
- [Helioselene Curve Cycle](https://gist.github.com/tevador/4524c2092178df08996487d4e272b096)
- [Alpha Stressnet Release](https://github.com/seraphis-migration/monero/releases/tag/v0.19.0.0-alpha.1)
- [kayabaNerve fcmp-plus-plus repo](https://github.com/kayabaNerve/fcmp-plus-plus)
- [monero-oxide (fcmp++ branch)](https://github.com/serai-dex/monero-oxide)
