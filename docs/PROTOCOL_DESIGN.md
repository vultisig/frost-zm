# Cross-Chain Liquidity Protocol Design

## Overview

A cross-chain DEX operated by a bonded node co-operative. 30 nodes run a BFT state machine with TSS signing across 3 UTXO chains (BTC, ZEC, XMR). The bond asset "B" is the routing asset in all pools and can only be bought and bonded, never sold.

## Architecture

### Pools

Constant-product AMM pools with B on one side of every pair:

```
Pool 1: A : B  (e.g. BTC:B)
Pool 2: B : C  (e.g. B:ZEC)
Pool 3: B : D  (e.g. B:XMR)
```

Cross-chain swaps route through B: `BTC → B → ZEC`.

B is only tradeable within these pools. External assets (BTC, ZEC, XMR) trade on external markets. Arbitrageurs keep pool prices aligned with external markets through real capital flow.

### Impact Propagation

Buy pressure on B in any single pool propagates across all pools via arbitrage. More pools = more resilience. With N pools, a buy shock is distributed across N pathways, reducing per-pool depth loss.

## Node Economics

### Bond Model

- 30 node slots, each earning 1/30th of all swap fees
- Nodes buy B from pools and bond it — this is the only way in
- B principal is permanently locked — nodes cannot withdraw it
- Entry cost increases over time as earlier bonds drain B from pools
- Acts as a fair launch: early = cheap but risky, late = expensive but proven

### Fee Distribution

Fees are skimmed from swap input/output in the external asset (BTC, ZEC, XMR) before touching the AMM curve. Distributed weekly at churn:

```
Swap: 1.00 BTC in
  → 0.003 BTC to fee vault (30 bps)
  → 0.997 BTC enters pool
```

Each node receives 1/30th from each chain's fee vault, paid in native chain assets. TSS signs the distribution transactions.

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

### Quote Flow

No gas, no wallet, no on-chain transaction required to get a quote:

```
1. Swapper → GET /quote?from=BTC&to=ZEC&amount=0.5
2. Node assigns next index, derives deposit address
3. ← { deposit: "bc1q...", expiry: 10min }
4. Swapper sends BTC to deposit address
5. Nodes see UTXO, execute swap
6. Nodes TSS-sign ZEC output to swapper
```

### Index Management

- Indices are never recycled within a vault lifetime (prevents late-deposit misattribution)
- BIP32 supports 2^31 indices — more than sufficient for one week of activity
- Weekly keygen resets the counter to 0
- DOS protection via HTTP-layer rate limiting (no gas needed)

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
  1. Collect pending streaming swap chunks
  2. Match opposing flows (rapid swaps)
  3. Execute unmatched remainder against pools
  4. Update pool depths
  5. Accrue fees
  6. Emit outputs when streams complete
```

## Arbitrage

### External Only

Nodes cannot arb — their capital is bonded B, locked and non-transferable. Only external arbers with real capital can rebalance pools:

1. Deposit real assets (BTC, ZEC, XMR)
2. Swap through the mispriced pool
3. Withdraw output asset
4. Realize profit on external markets

### Implications

- Slower price convergence (limited by on-chain confirmation times)
- Acceptable for UTXO chains where users already expect confirmation waits
- Fees must be low enough that arb remains profitable, or pools stay mispriced
- Pools are slow oracles that converge to external prices through real capital flow

## Node Lifecycle

| Scenario | Action |
|----------|--------|
| Protocol thriving | Nodes earn fees, slots appreciate |
| Protocol dying | Nodes vote to dissolve, TSS-sign all assets back to themselves |
| Node wants out | Sells slot OTC, new node churned in |
| Node dies (keys lost) | Capital locked forever (deflationary burn), slot eventually freed for new entrant |
| Node maintenance | Threshold (21/30) covers temporary downtime |

## Security Properties

- **Self-securing:** nodes guard their own bonded capital
- **No sell pressure:** B cannot be sold, price ratchets upward
- **No mercenary capital:** only node operators have capital in the system
- **No inflation tax:** fees are real swap revenue, not token emissions
- **Natural quality filter:** increasing slot cost self-selects for serious operators
- **Graceful shutdown:** nodes can always vote to dissolve and recover pooled assets
