# TODO: Protocol-Native Shielded Pool (Archived)

> **Status:** Archived. Extracted from PROTOCOL_DESIGN.md. The protocol currently targets BTC, ZEC, and XMR only — ZEC and XMR provide native on-chain privacy, making a protocol-level shielded pool unnecessary for the initial design. This document preserves the shielded pool design for potential future use (e.g., if non-private chains like ETH are added).

---

## Shielded Pool Overview

All swaps route through a **protocol-native shielded pool** — every deposit, swap, and withdrawal is private by default. An observer sees assets entering and leaving vaults but **cannot link any deposit to any withdrawal**.

## Protocol State (Shielded)

```
1. Shielded UTXO Merkle Tree (Poseidon hash)
   - Every balance in the protocol is a commitment
   - commitment = H(asset, amount, secret, owner_pubkey)

2. Nullifier Set
   - Spent UTXO identifiers (prevents double-spend)
   - nullifier = H(utxo_secret, leaf_index)
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

## Shielded User Flows

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

## Shielded Components

| Component | Language | Notes |
|---|---|---|
| Shielded pool state | Rust | Merkle tree, nullifier set |
| zk circuit | Noir or Circom | Proof generation + verification |
| Client SDK | TypeScript (WASM) | Local proof generation, note management |
