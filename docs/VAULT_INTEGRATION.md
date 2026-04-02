# Vault Integration Spec

How frozt (Zcash) and fromt (Monero) key material is stored inside a Vultisig `.vult` vault backup.

## Vault-Level Fields

These fields are unchanged. ECDSA public key remains the vault identifier.

| Field | Description |
|-------|-------------|
| `name` | Vault name |
| `public_key_ecdsa` | DKLS ECDSA public key (vault identifier) |
| `public_key_eddsa` | Schnorr EdDSA public key |
| `signers` | List of party IDs |
| `local_party_id` | This device's party ID |
| `hex_chain_code` | BIP32 chain code (ECDSA) |
| `lib_type` | 1 = seedless keygen, 2 = key-import (applies to the whole vault) |
| `key_shares` | DKLS + Schnorr + chain-specific key shares |
| `chain_public_keys` | Chain-specific public keys |

## lib_type

`lib_type` describes how the vault was created:

- **1** — Seedless distributed key generation (no pre-existing key material)
- **2** — Key import from seed/mnemonic (pre-existing key material split into threshold shares)

This is a vault-level concept. If the user provides a seed, ALL schemes (DKLS, Schnorr, Frozt, Fromt) derive from it — `lib_type=2`. If no seed, all schemes are generated fresh — `lib_type=1`.

## Frozt (Zcash Sapling)

### Storage

**One `chain_public_keys` entry:**
```
chain: "ZcashSapling"
public_key: <32-byte hex verifying key>   // e.g. "1f33c692fdefd..."
is_eddsa: false
```

**One `key_shares` entry:**
```
public_key: <same 32-byte hex verifying key>
keyshare: <base64-encoded KeyShareBundle>
```

The `public_key` in both entries is the **hex-encoded 32-byte frozt group verifying key** — consistent with how ECDSA and EdDSA public keys are stored (plain hex strings, not binary blobs).

### KeyShareBundle Format

Self-contained binary blob. All frozt per-party data in one place:

```
[version: u8]           // 1
[birthday: u64 LE]      // scan-start block height
[extras_len: u32 LE]    // 96
[sapling_extras: 96B]   // nsk(32) || ovk(32) || dk(32)
[kp_len: u32 LE]        // KeyPackage serialized length
[key_package: ...]       // FROST KeyPackage (signing share)
[pkp_len: u32 LE]       // PubKeyPackage serialized length
[pub_key_package: ...]   // FROST PubKeyPackage (group verifying key + all shares)
```

Access via FFI:
- `frozt_keyshare_bundle_pack(kp, pkp, extras, birthday) → bundle`
- `frozt_keyshare_bundle_birthday(bundle) → u64`
- `frozt_keyshare_bundle_key_package(bundle) → bytes`
- `frozt_keyshare_bundle_pub_key_package(bundle) → bytes`
- `frozt_keyshare_bundle_sapling_extras(bundle) → bytes`

### What NOT to do

- Do NOT store a second chain key entry for "Zcash" or "ZcashShielded" — one entry suffices
- Do NOT store SaplingExtras as a separate `chain_public_keys` entry — extras live inside the bundle
- Do NOT use the serialized PubKeyPackage as the `public_key` — use the 32-byte hex verifying key

## Fromt (Monero)

### Storage

**One `chain_public_keys` entry:**
```
chain: "Monero"
public_key: <32-byte hex verifying key>   // e.g. "700ef6a74d415d..."
is_eddsa: false
```

**One `key_shares` entry:**
```
public_key: <same 32-byte hex verifying key>
keyshare: <base64-encoded KeyShareBundle>
```

### KeyShareBundle Format

Self-contained binary blob:

```
[version: u8]           // 1
[network: u8]           // 0=mainnet, 1=testnet, 2=stagenet
[view_key: 32B]         // aggregated view key scalar
[birthday: u64 LE]      // scan-start block height
[kp_len: u32 LE]        // KeyPackage serialized length
[key_package: ...]       // FROST KeyPackage (signing share)
[pkp_len: u32 LE]       // PubKeyPackage serialized length
[pub_key_package: ...]   // FROST PubKeyPackage
```

Access via FFI:
- `fromt_keyshare_view_key(bundle) → 32 bytes`
- `fromt_keyshare_birthday(bundle) → u64`
- `fromt_keyshare_public_key(bundle) → 32 bytes`
- `fromt_keyshare_identifier(bundle) → u16`

### What NOT to do

- Do NOT store the view key as a separate `chain_public_keys` entry — it lives inside the bundle
- Do NOT store duplicate chain key entries — one "Monero" entry suffices

## Migration from Current Format

### Frozt (current → clean)

Current state in existing .vult files:
- Two chain key entries: "Zcash" and "ZcashShielded" (identical bundles)
- SaplingExtras in `chain_public_keys` with `chain="SaplingExtras"`
- `public_key` set to base64 PubKeyPackage blob instead of hex verifying key

Migration:
1. Read the bundle from either "Zcash" or "ZcashShielded" key share
2. Extract the 32-byte verifying key via `frozt_pubkeypackage_verifying_key(pkp)`
3. Store as single "ZcashSapling" entry with hex verifying key
4. Drop the "SaplingExtras" chain_public_keys entry (data is in the bundle)
5. Drop the duplicate chain key entry

### Fromt

No migration needed — fromt is new.
