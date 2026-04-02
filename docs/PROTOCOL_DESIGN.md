# Cross-Chain Liquidity Protocol

## Overview

A cross-chain DEX operated by a bonded 30-node co-operative. Nodes run a BFT state machine with FROST TSS signing across connected chains.

The bond asset "B" is the routing asset in all pools and can only be bought and bonded, never sold.

## Connected Chains

Any chain where FROST can control a vault:

| Chain | Method | Notes |
|-------|--------|-------|
| BTC (frobt) | Taproot / BIP32 derivation | Native Schnorr, FROST-friendly |
| ZEC (frozt) | ZIP32 + diversifiers | Native shielded transactions |
| XMR (fromt) | Custom Keccak 2-round threshold CKD | Pre-derive address batches |

ZEC and XMR provide native on-chain privacy. The protocol does not implement its own shielded pool — privacy comes from the chains themselves. See [TODO-PRIVACY.md](TODO-PRIVACY.md) for an archived protocol-level shielded pool design.

## Architecture

### Pools

Constant-product AMM pools with B on one side of every pair:

```
Pool 1: BTC : B
Pool 2: ZEC : B
Pool 3: XMR : B
```

Cross-chain swaps route through B: `BTC → B → ZEC`.

B is only tradeable within these pools. External assets trade on external markets. Arbitrageurs keep pool prices aligned with external markets through real capital flow.

### Impact Propagation

Buy pressure on B in any single pool propagates across all pools via arbitrage. More pools = more resilience. With N pools, a buy shock is distributed across N pathways, reducing per-pool depth loss.

## Protocol State

Validators maintain all state internally — no external chain needed:

```
1. Observed Deposits
   - Tracked per-chain UTXOs / transactions to vault addresses
   - Confirmed via BFT consensus

2. User Balances
   - Internal ledger of deposited assets per user

3. Liquidity Pools
   - Pool depths for each asset pair (BTC:B, ZEC:B, XMR:B)
   - Streaming swap queue
   - Rapid swap matching engine

4. Fee Accumulator
   - All fees collected in B
   - 10% dev fund allocation tracked separately
```

## User Model

### Deposit

```
1. User → GET /deposit?chain=BTC
2. ← { address: "bc1q...", index: 42 }
3. User sends BTC to that address
4. Validators observe inbound, reach consensus
5. User's balance is credited internally
```

### Swap

User submits a swap request specifying source asset, destination asset, destination address, and streaming parameters:

```
User submits: swap BTC → ZEC, dest=zs1..., chunks=10, interval=~10min

Each chunk:
  1. Debit portion of user's BTC balance
  2. Execute chunk against BTC:B pool → get B
  3. Execute B against B:ZEC pool → get ZEC
  4. Queue ZEC withdrawal to destination address
```

Streaming swaps naturally spread execution over time, reducing price impact.

Rapid swap matching still applies — opposing streams are matched directly:

```
Stream A: 10 BTC → ZEC
Stream B: 5 ZEC → BTC

Matched portion executes at pool price with zero slippage.
Remainder hits the AMM.
```

### Withdraw

```
1. User requests withdrawal of their internal balance
2. Validators verify sufficient balance
3. Validators FROST-sign an outbound tx on the target chain
4. User receives native assets at their specified address
```

For ZEC withdrawals to z-addresses and XMR withdrawals, the transactions are natively private on-chain.

## Swap Mechanics

### Streaming Swaps

Large swaps are broken into chunks executed over multiple blocks to reduce price impact:

```
10 BTC swap streamed as 100 × 0.1 BTC chunks
Each chunk executes at current pool price
Arbers rebalance between chunks
Swapper gets TWAP-like execution
```

### Rapid Swaps (Opposing Stream Matching)

Simultaneous opposite-direction streaming swaps are matched directly:

```
Stream A: 10 BTC → ZEC
Stream B: 8 ZEC → BTC

Matched:   8 BTC ↔ 8 ZEC (direct swap, zero pool impact, zero slippage)
Remainder: 2 BTC → ZEC (executes against pool)
Fees charged on both sides regardless
```

The BFT state machine acts as a matching engine. The AMM pools are the market maker of last resort.

### Block Execution Order

```
Each block:
  1. Process deposit confirmations
  2. Collect pending streaming swap chunks
  3. Match opposing flows (rapid swaps)
  4. Execute unmatched remainder against pools
  5. Update pool depths
  6. Update user balances
  7. Accrue fees in B
  8. Emit withdrawal outputs when streams complete
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
  Validator 2: stream B → ZEC to zs1...
  Validator 3: stream B → XMR to 4...
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
| ZEC (frozt) | ZIP32 + diversifiers | No — single-party derivation |
| XMR (fromt) | Custom Keccak 2-round threshold CKD | Yes — requires signer coordination |

For Monero, pre-derive batches of addresses during quiet periods to avoid live CKD rounds on every quote.

### Deposit Address API

```
1. User → GET /deposit?chain=BTC
2. Node assigns next index, derives deposit address
3. ← { address: "bc1q..." }
4. User sends any amount of BTC to that address
5. Nodes observe UTXO, credit user's internal balance
```

### Index Management

- Indices are never recycled within a vault lifetime (prevents late-deposit misattribution)
- BIP32 supports 2^31 indices — more than sufficient for one week of activity
- Weekly keygen resets the counter to 0
- DOS protection via HTTP-layer rate limiting (no gas needed)

## Arbitrage

### External Only

Nodes cannot arb — their capital is bonded B, locked and non-transferable. Only external arbers with real capital can rebalance pools:

1. Deposit real assets (BTC, ZEC, XMR)
2. Swap through the mispriced pool
3. Withdraw output asset
4. Realize profit on external markets

### Implications

- Slower price convergence (limited by on-chain confirmation times)
- Acceptable for chains where users already expect confirmation waits
- Fees must be low enough that arb remains profitable, or pools stay mispriced
- Pools are slow oracles that converge to external prices through real capital flow

## User Flows

### Basic Swap (BTC → ZEC)

```
1. GET /deposit?chain=BTC → send BTC
2. Submit swap request: BTC → ZEC, dest=zs1..., stream over 10 chunks
3. Protocol streams the swap, FROST-signs ZEC outputs to z-address
Observer sees: BTC entered vault. ZEC left vault to a shielded z-address.
```

### Basic Swap (BTC → XMR)

```
1. GET /deposit?chain=BTC → send BTC
2. Submit swap request: BTC → XMR, dest=4..., stream over 10 chunks
3. Protocol streams the swap, FROST-signs XMR outputs
Observer sees: BTC entered vault. XMR tx is opaque by default.
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
- **Native chain privacy:** ZEC (shielded txs) and XMR (opaque by default) provide privacy at the chain level

## Component Stack

| Component | Language | Notes |
|---|---|---|
| FROST keygen/signing | Rust (frozt-lib, frobt, fromt) | Exists |
| BFT state machine | Go or Rust | Consensus on state transitions |
| Chain watchers | Go | One per connected chain (BTC, ZEC, XMR) |
| AMM + streaming engine | Go or Rust | Pool math, stream scheduling, rapid matching |
| Deposit API | Go | HTTP endpoint, address derivation |

## Adding New Chains

A new chain can be added at any time via node governance vote. When a new chain is added, the protocol bootstraps its pool:

### Pool Bootstrap

```
Existing pools: N (e.g. BTC:B, ZEC:B, XMR:B → N=3)
New chain: LTC

1. Protocol mints 1/N of existing B supply as new B
   (if total B across all pools = 300, mint 100 new B)

2. New pool created: LTC:B with the minted B on the B side

3. First depositor sends LTC to the new vault
   - The minted B is streamed (sold) into the new LTC deposit
   - This "buys" LTC to a target depth of total_liquidity / (N+1)
   - Streaming prevents massive price impact

4. Result: LTC:B pool is bootstrapped at fair depth
   - All pools now hold roughly equal B depth
   - Arbitrageurs correct any mispricing across pools
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

1. FROST vaults on BTC + ZEC + XMR (deposit → return loop)
2. BFT state machine + pool state (consensus on state transitions)
3. AMM with routing asset B (functional swaps)
4. Streaming swaps + rapid swap matching
5. Fee collection in B + churn distribution + dev fund
6. Additional chains
