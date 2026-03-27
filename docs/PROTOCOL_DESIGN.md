# Cross-Chain Private Liquidity Protocol

## Overview

A cross-chain DEX operated by a bonded 30-node co-operative. Nodes run a BFT state machine with FROST TSS signing across connected chains. All swaps route through a **protocol-native shielded pool** — every deposit, swap, and withdrawal is private by default. An observer sees assets entering and leaving vaults but **cannot link any deposit to any withdrawal**.

The bond asset "B" is the routing asset in all pools and can only be bought and bonded, never sold.

## Connected Chains

Any chain where FROST can control a vault:

| Chain | Method | Notes |
|-------|--------|-------|
| BTC (frobt) | Taproot / BIP32 derivation | Native Schnorr, FROST-friendly |
| ETH | FROST-to-ECDSA adaptor | Smart contract optional |
| ZEC (frozt) | ZIP32 + diversifiers | Native shielded transactions |
| XMR (fromt) | Custom Keccak 2-round threshold CKD | Pre-derive address batches |
| Others | Per-chain adaptor | SOL, LTC, etc. added over time |

## Architecture

### Pools

Constant-product AMM pools with B on one side of every pair:

```
Pool 1: BTC : B
Pool 2: ETH : B
Pool 3: ZEC : B
Pool 4: XMR : B
...
```

Cross-chain swaps route through B: `BTC → B → ETH`.

B is only tradeable within these pools. External assets trade on external markets. Arbitrageurs keep pool prices aligned with external markets through real capital flow.

### Impact Propagation

Buy pressure on B in any single pool propagates across all pools via arbitrage. More pools = more resilience. With N pools, a buy shock is distributed across N pathways, reducing per-pool depth loss.

## Protocol State

Validators maintain all state internally — no external chain needed:

```
1. Shielded UTXO Merkle Tree (Poseidon hash)
   - Every balance in the protocol is a commitment
   - commitment = H(asset, amount, secret, owner_pubkey)

2. Nullifier Set
   - Spent UTXO identifiers (prevents double-spend)
   - nullifier = H(utxo_secret, leaf_index)

3. Liquidity Pools
   - Pool depths for each asset pair (BTC:B, ETH:B, ...)
   - Streaming swap queue
   - Rapid swap matching engine

4. Fee Accumulator
   - All fees collected in B
   - 10% dev fund allocation tracked separately
```

## Two-Phase User Model

All user interaction follows two phases: a public deposit (no intent), then private commitments (swap, hold, withdraw) via zk proofs. The deposit carries zero information about what the user intends to do — every deposit looks identical. The user decides what to do with their shielded balance later, entirely client-side.

### Phase 1: Deposit (Public, Dumb)

```
1. User → GET /deposit?chain=BTC
2. ← { address: "bc1q...", index: 42 }
3. User sends 1 BTC to that address. No memo, no intent, no amount specified.
4. Validators observe inbound, reach consensus
5. Protocol state updated:
   - New shielded UTXO added to Merkle tree
   - commitment = H(asset=BTC, amount=1, secret=user_random, owner=user_pubkey)
6. User receives a note (commitment + secret) — this is their private balance
```

The deposit API returns only a fresh address. It logs nothing about intent, destination, or amount. Every user who requests a BTC deposit address looks identical in the logs.

**What an observer sees:** Someone sent 1 BTC to the vault. Nothing else.

### Phase 2: Commit (Private, Client-Side)

Once funds are shielded, the user submits zk proofs to the protocol's P2P network. No API calls. The user can do any of the following, at any time, in any order:

**Hold:** Do nothing. The shielded UTXO sits in the Merkle tree. The protocol acts as a shielded wrapper. The longer the user holds and the more other users deposit/withdraw around them, the larger the anonymity set. Users can also do private transfers of wrapped assets to other users within the protocol without ever touching an external chain.

**Swap:** Submit a zk proof to stream-swap into another asset:

```
User submits: zk proof + streaming params (chunks=10, interval=~10min)

The proof proves:
  - "I own a valid BTC UTXO in the Merkle tree" (without revealing which one)
  - "Here is a nullifier for it"
  - "Here are new commitments for the sub-swap outputs"

Each chunk:
  1. Nullify a portion-sized BTC UTXO
  2. Execute chunk against BTC:B pool → get B
  3. Execute B against B:ETH pool → get ETH
  4. Create new shielded ETH UTXO + remaining BTC UTXO
  5. Multiple users' chunks interleave — cannot attribute any chunk to any user
```

Streaming swaps naturally add a time delay, strengthening privacy. Users can configure longer intervals for additional privacy (artificial delay).

Rapid swap matching still applies — opposing streams are matched directly:

```
Stream A: 10 BTC → ETH (shielded)
Stream B: 5 ETH → BTC (shielded)

Matched portion executes at pool price with zero slippage.
Remainder hits the AMM.
All participants are shielded — the matching engine sees proven amounts but not identities.
```

**Withdraw:** Submit a zk proof to burn a shielded UTXO and receive native assets on any chain:

```
1. User constructs a zk proof locally:
   - Proves ownership of a UTXO in the tree (any asset)
   - Nullifies it
   - Commits to a fresh destination address: dest_hash = H(dest_address)

2. User submits proof + plaintext dest_address to validators via P2P

3. Validators verify:
   - Proof is valid
   - Nullifier not already spent
   - H(dest_address) matches dest_hash in proof

4. Validators FROST-sign an outbound tx on the target chain

5. User receives native assets at their fresh address
```

**What an observer sees:** Some assets left the vault to an address. Cannot link to any deposit.

### The zk Circuit

```
Public inputs:
  merkle_root, nullifiers[], new_commitments[], tx_type (transfer|swap|withdraw)
  dest_address_hash (withdrawals only)

Private inputs:
  old_utxo_secrets, merkle_paths, amounts, asset_types, new_secrets

Constraints:
  1. Each input UTXO exists in the tree (Merkle inclusion proof)
  2. Each nullifier is correctly derived from UTXO secret + index
  3. Sum of inputs = sum of outputs (value conservation)
  4. New commitments are correctly formed
  5. (Swaps) amount_in and amount_out are consistent with pool pricing
  6. (Withdrawals) dest_address_hash = H(dest_address)
```

Proving system: Noir / UltraPlonk (no trusted setup) or Groth16 (smaller proofs, trusted setup ceremony). Proofs generated on user's device via client SDK (WASM).

### Privacy Properties

| Scenario | What observer sees | What observer CANNOT see |
|---|---|---|
| Deposit | X BTC entered the vault | Who owns the shielded UTXO |
| Hold (wrapped) | Nothing | That a user is holding wrapped assets |
| Transfer | Nothing (protocol-internal) | Sender, receiver, amount, asset |
| Swap | Pool depth shifts gradually | Who swapped, how much, which direction |
| Withdrawal | X ETH left vault to 0x...fresh | Which deposit it came from |
| Streaming swap | Pool shifts over time | Individual chunk attribution |

### Anonymity Set

The anonymity set for any withdrawal is **all deposits across all chains since the last keygen**. Because:

- All assets pool into the same shielded state
- Swaps change the asset type (breaks amount correlation)
- Streaming swaps spread execution over time (breaks timing correlation)
- Rapid swap matching merges flows (breaks direction correlation)
- Wrapped asset holds add dwell time (breaks temporal correlation)
- Weekly keygen migrates all UTXOs (periodic anonymity set refresh)

## Swap Mechanics

### Streaming Swaps

Large swaps are broken into chunks executed over multiple blocks to reduce price impact:

```
10 BTC swap streamed as 100 × 0.1 BTC chunks
Each chunk executes at current pool price
Arbers rebalance between chunks
Swapper gets TWAP-like execution
```

Users can configure longer intervals between chunks for additional privacy. The protocol does not distinguish between price-motivated and privacy-motivated streaming — both look identical.

### Rapid Swaps (Opposing Stream Matching)

Simultaneous opposite-direction streaming swaps are matched directly:

```
Stream A: 10 BTC → ETH
Stream B: 8 ETH → BTC

Matched:   8 BTC ↔ 8 ETH (direct swap, zero pool impact, zero slippage)
Remainder: 2 BTC → ETH (executes against pool)
Fees charged on both sides regardless
```

The BFT state machine acts as a matching engine. The AMM pools are the market maker of last resort.

### Block Execution Order

```
Each block:
  1. Verify all submitted zk proofs
  2. Collect pending streaming swap chunks
  3. Match opposing flows (rapid swaps)
  4. Execute unmatched remainder against pools
  5. Update pool depths
  6. Add new UTXO commitments to Merkle tree
  7. Add nullifiers to spent set
  8. Accrue fees in B
  9. Emit withdrawal outputs when streams complete
```

## Node Economics

### Bond Model

- 30 node slots, each earning 1/30th of all swap fees
- Nodes buy B from pools and bond it — this is the only way in
- B principal is permanently locked — nodes cannot withdraw it
- Entry cost increases over time as earlier bonds drain B from pools
- Acts as a fair launch: early = cheap but risky, late = expensive but proven

### Fee Collection

All fees are collected in B. When a swap occurs, the fee (30 bps) is taken from the swap amount and converted to B within the pool:

```
Swap: 1.00 BTC in
  → Fee: 0.003 BTC worth of B retained from the pool swap
  → 0.997 BTC effective swap input
  → B fee accumulated in protocol state
```

### Fee Distribution (At Churn)

At weekly churn, accumulated B fees are distributed:

```
Total B fees accumulated during the epoch
  → 90% to validators (split 30 ways)
  → 10% to dev fund

Each validator's share of B is then streamed (swapped via streaming swap)
into the asset of the validator's choice:

  Validator 1: stream B → BTC to bc1q...
  Validator 2: stream B → ETH to 0x...
  Validator 3: stream B → BTC to bc1q...
  ...
```

Validators nominate their preferred payout asset and destination address. The protocol executes a streaming swap from B to that asset, then FROST-signs the outbound transaction. This creates natural buy-then-sell pressure on B at churn — the buy already happened during fee collection, the sell happens during distribution, netting out over time.

### Dev Fund

10% of all B fees are allocated to the dev fund. At churn, the dev fund's B is streamed (swapped) to the dev team's preferred asset and sent to the dev address:

```
Dev fund B → streaming swap to preferred asset → FROST-sign to dev address
```

The dev address and payout asset are set by governance (node vote).

### Slot Secondary Market

Nodes cannot sell B, but can sell their slot OTC. Buyer pays seller directly (any asset, off-protocol), protocol churns old node out, new node in. No pool impact. Slot value is priced on fee revenue fundamentals.

```
slot value ≈ (annual fees / 30) / discount rate
```

## Key Management

### Weekly Keygen

Fresh keygen every week. No resharing, no stale share tracking. UTXO chains naturally support this — every transaction consumes old outputs and creates new ones to the current vault key. Old UTXOs drain through normal swap activity.

```
Monday:     keygen new key across 30 nodes
Week:       swaps send change to new key
Next Monday: keygen again, clean slate
```

Benefits:
- No stale share accumulation problem
- No migration cost (change outputs migrate naturally)
- Resets address index space weekly
- Clean security boundary every cycle

### Threshold

21-of-30 (BFT 2/3 + 1). Tolerates up to 9 nodes offline for maintenance while maintaining honest majority security. Nodes co-sign their own pooled capital — structural incentive alignment.

## Deposit Addresses

### Derivation

Each chain's FROST library supports unique deposit address derivation:

| Chain | Method | Interactive? |
|-------|--------|-------------|
| BTC (frobt) | BIP32 `change/index` | No — any node derives from public key |
| ETH | Standard derivation | No — derived from FROST public key |
| ZEC (frozt) | ZIP32 + diversifiers | No — single-party derivation |
| XMR (fromt) | Custom Keccak 2-round threshold CKD | Yes — requires signer coordination |

For Monero, pre-derive batches of addresses during quiet periods to avoid live CKD rounds on every quote.

### Deposit Address API

The only API the user ever calls. Returns a fresh deposit address with zero intent:

```
1. User → GET /deposit?chain=BTC
2. Node assigns next index, derives deposit address
3. ← { address: "bc1q..." }
4. User sends any amount of BTC to that address
5. Nodes observe UTXO, create shielded UTXO in Merkle tree
6. User decides what to do later (swap, hold, withdraw) via zk proofs
```

No amount, no destination, no intent is communicated. The API log for every user is identical: "requested a BTC deposit address."

### Index Management

- Indices are never recycled within a vault lifetime (prevents late-deposit misattribution)
- BIP32 supports 2^31 indices — more than sufficient for one week of activity
- Weekly keygen resets the counter to 0
- DOS protection via HTTP-layer rate limiting (no gas needed)

## Arbitrage

### External Only

Nodes cannot arb — their capital is bonded B, locked and non-transferable. Only external arbers with real capital can rebalance pools:

1. Deposit real assets (BTC, ETH, ZEC, XMR)
2. Swap through the mispriced pool
3. Withdraw output asset
4. Realize profit on external markets

### Implications

- Slower price convergence (limited by on-chain confirmation times)
- Acceptable for chains where users already expect confirmation waits
- Fees must be low enough that arb remains profitable, or pools stay mispriced
- Pools are slow oracles that converge to external prices through real capital flow

## User Flows

### Private Swap

```
Phase 1: GET /deposit?chain=BTC → send 1 BTC (public, dumb)
Phase 2: zk proof to stream swap BTC→ETH (private, client-side)
Phase 2: zk proof to withdraw ETH to fresh address (private, client-side)
Observer sees: BTC in ... ETH out (unlinkable)
```

### Shielded Hold (Wrapped Assets)

```
Phase 1: GET /deposit?chain=BTC → send 1 BTC (public, dumb)
Phase 2: do nothing — hold shielded wBTC
Phase 2: zk proof to withdraw BTC to fresh address (days/weeks later)
Observer sees: BTC in ... BTC out (unlinkable, different time, different address)
```

### Private Transfer

```
Phase 1: GET /deposit?chain=ETH → send ETH (public, dumb)
Phase 2: zk proof to transfer shielded wETH to another user
Phase 2: recipient submits zk proof to withdraw
Observer sees: ETH in ... ETH out to unknown party (unlinkable)
```

### Multi-Hop Privacy

```
Deposit BTC → Swap to ETH → Hold → Swap to ZEC → Withdraw to z-address
Observer sees: BTC in ... nothing (ZEC z-address is fully shielded)
```

## Node Lifecycle

| Scenario | Action |
|----------|--------|
| Protocol thriving | Nodes earn fees in B, stream to preferred asset at churn |
| Protocol dying | Nodes vote to dissolve, TSS-sign all assets back to themselves |
| Node wants out | Sells slot OTC, new node churned in |
| Node dies (keys lost) | Capital locked forever (deflationary burn), slot eventually freed |
| Node maintenance | Threshold (21/30) covers temporary downtime |

## Security Properties

- **Self-securing:** nodes guard their own bonded capital
- **No sell pressure:** B cannot be sold directly, only earned and distributed at churn
- **No mercenary capital:** only node operators have capital in the system
- **No inflation tax:** fees are real swap revenue, not token emissions
- **Natural quality filter:** increasing slot cost self-selects for serious operators
- **Graceful shutdown:** nodes can always vote to dissolve and recover pooled assets
- **Default privacy:** every operation is shielded — no opt-in required
- **Cross-chain unlinkability:** asset type change + time delay + shielded state = no correlation

## Component Stack

| Component | Language | Notes |
|---|---|---|
| FROST keygen/signing | Rust (frozt-lib, frobt, fromt) | Exists |
| BFT state machine | Go or Rust | Consensus on state transitions |
| Chain watchers | Go | One per connected chain |
| Shielded pool state | Rust | Merkle tree, nullifier set |
| zk circuit | Noir or Circom | Proof generation + verification |
| Client SDK | TypeScript (WASM) | Local proof generation, note management |
| AMM + streaming engine | Go or Rust | Pool math, stream scheduling, rapid matching |
| Deposit API | Go | HTTP endpoint, address derivation (no intent) |

## Adding New Chains

A new chain can be added at any time via node governance vote. When a new chain is added, the protocol bootstraps its pool:

### Pool Bootstrap

```
Existing pools: N (e.g. BTC:B, ETH:B, ZEC:B → N=3)
New chain: SOL

1. Protocol mints 1/N of existing B supply as new B
   (if total B across all pools = 300, mint 100 new B)

2. New pool created: SOL:B with the minted B on the B side

3. First depositor sends SOL to the new vault
   - The minted B is streamed (sold) into the new SOL deposit
   - This "buys" SOL to a target depth of total_liquidity / (N+1)
   - Streaming prevents massive price impact

4. Result: SOL:B pool is bootstrapped at fair depth
   - All pools now hold roughly equal B depth
   - Arbitrageurs correct any mispricing across pools
```

### Example

```
Before:  3 pools, each ~100 B depth (300 B total)
Add SOL: mint 100 B (1/3 of 300)
Target:  4 pools, each ~100 B depth (400 B total)

Someone donates SOL to the new vault address.
The 100 minted B streams into the SOL:B pool, buying SOL from the donation.
Result: SOL:B pool is seeded at fair depth. The donation is non-refundable.
Arbers equalize pricing across all 4 pools.
```

There are no LPs. The initial deposit is a **donation** — the depositor does not receive pool shares, B tokens, or any claim on the liquidity. This is the cost of bootstrapping a new chain. In practice, the dev fund or node operators fund this to grow the protocol.

### Safeguards

- Node supermajority (21/30) required to approve new chain addition
- New FROST keygen required for the new chain's vault
- Minted B is not bonded — it enters circulation in the new pool
- Streaming the mint prevents a single-block shock to B pricing
- Pool must reach minimum depth before swaps are enabled
- Donation is irreversible — no withdrawal mechanism for bootstrap liquidity

## Build Order

1. FROST vaults on BTC + ETH (deposit → return loop)
2. BFT state machine + pool state (consensus on state transitions)
3. AMM with routing asset B (functional swaps, no privacy yet)
4. Streaming swaps + rapid swap matching
5. Shielded UTXO Merkle tree + nullifier set
6. zk circuit (transfers first, then swaps, then withdrawals)
7. Client SDK with WASM proof generation
8. Fee collection in B + churn distribution + dev fund
9. Additional chains
