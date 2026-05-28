use wasm_bindgen::prelude::*;

use fromtlib::keyshare::bundle::KeyShareBundle;
use fromtlib::monero::spend;
use fromtlib::handle::Handle;

use crate::to_js_err;

struct ParsedInput {
    amount: u64,
    key_offset: [u8; 32],
    output_key: [u8; 32],
    commitment_mask: [u8; 32],
    global_index: u64,
}

struct RingMember {
    output_key: [u8; 32],
    commitment: [u8; 32],
    global_index: u64,
}

struct ParsedRing {
    members: Vec<RingMember>,
    real_index: u32,
}

fn parse_ts_inputs(data: &[u8]) -> Result<Vec<ParsedInput>, String> {
    if data.len() < 4 {
        return Err("inputs data too short".into());
    }
    let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let record_size = 8 + 32 + 32 + 32 + 8;
    let expected = 4 + count * record_size;
    if data.len() < expected {
        return Err(format!("inputs data: expected {} bytes, got {}", expected, data.len()));
    }

    let mut inputs = Vec::with_capacity(count);
    let mut off = 4;
    for _ in 0..count {
        let amount = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        off += 8;
        let mut key_offset = [0u8; 32];
        key_offset.copy_from_slice(&data[off..off + 32]);
        off += 32;
        let mut output_key = [0u8; 32];
        output_key.copy_from_slice(&data[off..off + 32]);
        off += 32;
        let mut commitment_mask = [0u8; 32];
        commitment_mask.copy_from_slice(&data[off..off + 32]);
        off += 32;
        let global_index = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        off += 8;
        inputs.push(ParsedInput { amount, key_offset, output_key, commitment_mask, global_index });
    }
    if off != expected {
        return Err(format!("inputs data: parsed {} bytes, expected {}", off, expected));
    }
    Ok(inputs)
}

fn parse_ts_decoys(data: &[u8]) -> Result<Vec<ParsedRing>, String> {
    if data.len() < 4 {
        return Err("decoys data too short".into());
    }
    let ring_count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut rings = Vec::with_capacity(ring_count);
    let mut off = 4;

    for _ in 0..ring_count {
        if data.len() < off + 8 {
            return Err("decoys data truncated at ring header".into());
        }
        let member_count = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let real_index = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;

        let member_size = 32 + 32 + 8;
        if data.len() < off + member_count * member_size {
            return Err("decoys data truncated at ring members".into());
        }
        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            let mut output_key = [0u8; 32];
            output_key.copy_from_slice(&data[off..off + 32]);
            off += 32;
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&data[off..off + 32]);
            off += 32;
            let global_index = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            off += 8;
            members.push(RingMember { output_key, commitment, global_index });
        }
        rings.push(ParsedRing { members, real_index });
    }
    if off != data.len() {
        return Err(format!(
            "decoys data has {} trailing bytes",
            data.len().saturating_sub(off)
        ));
    }
    Ok(rings)
}

fn write_varint(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            buf.push(byte | 0x80);
        } else {
            buf.push(byte);
            break;
        }
    }
}

fn serialize_output_with_decoys(input: &ParsedInput, ring: &ParsedRing) -> Result<Vec<u8>, String> {
    if ring.members.is_empty() {
        return Err("ring must contain at least one member".into());
    }

    let real_index = ring.real_index as usize;
    let real_member = ring
        .members
        .get(real_index)
        .ok_or_else(|| format!("real_index {} out of range for ring of size {}", ring.real_index, ring.members.len()))?;

    if real_member.global_index != input.global_index {
        return Err(format!(
            "real member global index {} does not match input global index {}",
            real_member.global_index, input.global_index
        ));
    }

    let mut buf = Vec::with_capacity(256);

    buf.extend_from_slice(&input.output_key);
    buf.extend_from_slice(&input.key_offset);
    buf.extend_from_slice(&input.commitment_mask);
    buf.extend_from_slice(&input.amount.to_le_bytes());

    let mut indexed: Vec<(usize, &RingMember)> = ring.members.iter().enumerate().collect();
    indexed.sort_by_key(|(_, m)| m.global_index);

    let mut sorted_signer_index = None;
    for (new_pos, (orig_idx, _)) in indexed.iter().enumerate() {
        if *orig_idx == ring.real_index as usize {
            sorted_signer_index = Some(new_pos as u8);
            break;
        }
    }
    let sorted_signer_index = sorted_signer_index.ok_or_else(|| {
        format!(
            "real_index {} not found after sorting ring of size {}",
            ring.real_index,
            ring.members.len()
        )
    })?;

    let mut offsets = Vec::with_capacity(indexed.len());
    let mut prev = 0u64;
    for (_, member) in &indexed {
        offsets.push(member.global_index - prev);
        prev = member.global_index;
    }

    write_varint(&mut buf, indexed.len() as u64);
    for &offset in &offsets {
        write_varint(&mut buf, offset);
    }

    buf.push(sorted_signer_index);

    for (_, member) in &indexed {
        buf.extend_from_slice(&member.output_key);
        buf.extend_from_slice(&member.commitment);
    }

    Ok(buf)
}

#[wasm_bindgen]
pub fn fromt_build_signable_tx(
    key_share: &[u8],
    recipient: &str,
    amount: u64,
    fee_per_weight: u64,
    fee_mask: u64,
    inputs_data: &[u8],
    decoys_data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    // Backwards-compatible thin wrapper: any caller that hasn't
    // migrated to the multi-output form keeps working as before.
    let dests = encode_single_destination(recipient, amount);
    fromt_build_signable_tx_multi(
        key_share,
        &dests,
        fee_per_weight,
        fee_mask,
        inputs_data,
        decoys_data,
    )
}

/// Multi-output variant. `destinations_data` carries the full
/// `(address, amount)` list — see [`encode_single_destination`] for
/// the wire format (also implemented in TS by
/// `encodeDestinationsBlob` in `moneroSpendCoordinator.ts`).
///
/// Use this when the wizard needs to add commission / donation
/// outputs alongside the primary recipient. The Monero protocol
/// supports up to 16 outputs in a single tx; we don't cap it here
/// because `monero_wallet::send::SignableTransaction::new` already
/// rejects bad shapes upstream.
#[wasm_bindgen]
pub fn fromt_build_signable_tx_multi(
    key_share: &[u8],
    destinations_data: &[u8],
    fee_per_weight: u64,
    fee_mask: u64,
    inputs_data: &[u8],
    decoys_data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    use zeroize::Zeroizing;
    use rand::rngs::OsRng;
    use rand::RngCore;

    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    let view_pair = spend::view_pair_from_bundle(&bundle).map_err(to_js_err)?;

    // Accept both legacy 0/1/2 indices and the Monero standard
    // address-prefix bytes (0x12 / 0x35 / 0x18) so we stay consistent
    // with `fromtlib::monero::address::network_prefix`, which is what
    // the DKG ceremony actually stores in `KeyShareBundle::network`.
    let network = match bundle.network {
        0 | 0x12 => monero_wallet::address::Network::Mainnet,
        1 | 0x35 => monero_wallet::address::Network::Testnet,
        2 | 0x18 => monero_wallet::address::Network::Stagenet,
        other => return Err(JsValue::from_str(&format!("unknown network byte {other}"))),
    };
    let destinations = parse_destinations(destinations_data, network)
        .map_err(|e| JsValue::from_str(&e))?;
    if destinations.is_empty() {
        return Err(JsValue::from_str("at least one destination is required"));
    }

    let fee_rate = monero_wallet::interface::FeeRate::new(fee_per_weight, fee_mask)
        .ok_or_else(|| JsValue::from_str("invalid fee rate"))?;

    let inputs = parse_ts_inputs(inputs_data).map_err(|e| JsValue::from_str(&e))?;
    let rings = parse_ts_decoys(decoys_data).map_err(|e| JsValue::from_str(&e))?;

    if inputs.len() != rings.len() {
        return Err(JsValue::from_str("inputs and decoys count mismatch"));
    }

    let mut outputs_with_decoys = Vec::new();
    for (input, ring) in inputs.iter().zip(rings.iter()) {
        let serialized = serialize_output_with_decoys(input, ring)
            .map_err(|e| JsValue::from_str(&e))?;
        let owd = monero_wallet::OutputWithDecoys::read(&mut &serialized[..])
            .map_err(|e| JsValue::from_str(&format!("OutputWithDecoys deserialize: {:?}", e)))?;
        outputs_with_decoys.push(owd);
    }

    let mut outgoing_view = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(outgoing_view.as_mut());

    let change = monero_wallet::send::Change::new(view_pair, None);

    let signable = monero_wallet::send::SignableTransaction::new(
        monero_wallet::ringct::RctType::ClsagBulletproofPlus,
        outgoing_view,
        outputs_with_decoys,
        destinations,
        change,
        vec![],
        fee_rate,
    ).map_err(to_js_err)?;

    Ok(signable.serialize())
}

/// Build the destinations blob for a single-recipient transaction.
/// Layout (little-endian throughout):
///
/// ```text
///   u32 count
///   for each destination:
///     u32 address_len
///     bytes address (utf-8)
///     u64 amount (piconero)
/// ```
fn encode_single_destination(recipient: &str, amount: u64) -> Vec<u8> {
    let addr_bytes = recipient.as_bytes();
    let mut buf = Vec::with_capacity(4 + 4 + addr_bytes.len() + 8);
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(addr_bytes);
    buf.extend_from_slice(&amount.to_le_bytes());
    buf
}

fn parse_destinations(
    data: &[u8],
    network: monero_wallet::address::Network,
) -> Result<Vec<(monero_wallet::address::MoneroAddress, u64)>, String> {
    if data.len() < 4 {
        return Err(format!("destinations blob too short: {} bytes", data.len()));
    }
    let count = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    let mut offset = 4;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        if data.len() < offset + 4 {
            return Err(format!("destinations[{}]: truncated at addr_len header", i));
        }
        let addr_len = u32::from_le_bytes(
            data[offset..offset + 4].try_into().unwrap(),
        ) as usize;
        offset += 4;
        if data.len() < offset + addr_len + 8 {
            return Err(format!(
                "destinations[{}]: truncated (need {} address bytes + 8 amount bytes)",
                i, addr_len,
            ));
        }
        let addr_str = std::str::from_utf8(&data[offset..offset + addr_len])
            .map_err(|e| format!("destinations[{}]: invalid utf-8 address: {}", i, e))?;
        offset += addr_len;
        let amount = u64::from_le_bytes(
            data[offset..offset + 8].try_into().unwrap(),
        );
        offset += 8;
        let addr = monero_wallet::address::MoneroAddress::from_str(network, addr_str)
            .map_err(|e| format!("destinations[{}]: parse address: {:?}", i, e))?;
        out.push((addr, amount));
    }
    Ok(out)
}

#[wasm_bindgen]
pub struct SpendPreprocessResult {
    handle_id: i32,
    preprocess: Vec<u8>,
}

#[wasm_bindgen]
impl SpendPreprocessResult {
    #[wasm_bindgen(getter)]
    pub fn handle_id(&self) -> i32 {
        self.handle_id
    }

    #[wasm_bindgen(getter)]
    pub fn preprocess(&self) -> Vec<u8> {
        self.preprocess.clone()
    }
}

#[wasm_bindgen]
pub fn fromt_spend_preprocess(
    key_share: &[u8],
    signable_tx: &[u8],
) -> Result<SpendPreprocessResult, JsValue> {
    let bundle = KeyShareBundle::deserialize(key_share).map_err(to_js_err)?;
    let keys = spend::convert_keyshare(&bundle).map_err(to_js_err)?;

    let signable = monero_wallet::send::SignableTransaction::read(&mut &signable_tx[..])
        .map_err(|e| JsValue::from_str(&format!("parse signable tx: {:?}", e)))?;

    let (sign_machine, preprocess_bytes) = spend::spend_preprocess(signable, keys)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;

    let handle = Handle::allocate(sign_machine).map_err(to_js_err)?;
    let handle_id = unsafe { std::mem::transmute::<Handle, i32>(handle) };

    Ok(SpendPreprocessResult {
        handle_id,
        preprocess: preprocess_bytes,
    })
}

#[wasm_bindgen]
pub struct SpendSignResult {
    handle_id: i32,
    share: Vec<u8>,
}

#[wasm_bindgen]
impl SpendSignResult {
    #[wasm_bindgen(getter)]
    pub fn handle_id(&self) -> i32 {
        self.handle_id
    }

    #[wasm_bindgen(getter)]
    pub fn share(&self) -> Vec<u8> {
        self.share.clone()
    }
}

#[wasm_bindgen]
pub fn fromt_spend_sign(
    handle_id: i32,
    preprocesses_map: &[u8],
) -> Result<SpendSignResult, JsValue> {
    use std::collections::HashMap;
    use modular_frost::Participant;

    let handle = unsafe { std::mem::transmute::<i32, Handle>(handle_id) };
    let sign_machine = handle.take::<monero_wallet::send::TransactionSignMachine>()
        .map_err(to_js_err)?;

    let raw_map = fromtlib::codec::decode_u16_map(preprocesses_map).map_err(to_js_err)?;
    let mut preprocesses = HashMap::new();
    for (id, bytes) in raw_map {
        preprocesses.insert(Participant::new(id).unwrap(), bytes);
    }

    let (sig_machine, share_bytes) = spend::spend_sign(sign_machine, preprocesses)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;

    let new_handle = Handle::allocate(sig_machine).map_err(to_js_err)?;
    let new_handle_id = unsafe { std::mem::transmute::<Handle, i32>(new_handle) };

    Ok(SpendSignResult {
        handle_id: new_handle_id,
        share: share_bytes,
    })
}

#[wasm_bindgen]
pub fn fromt_spend_complete(
    handle_id: i32,
    shares_map: &[u8],
) -> Result<Vec<u8>, JsValue> {
    use std::collections::HashMap;
    use modular_frost::Participant;

    let handle = unsafe { std::mem::transmute::<i32, Handle>(handle_id) };
    let sig_machine = handle.take::<monero_wallet::send::TransactionSignatureMachine>()
        .map_err(to_js_err)?;

    let raw_map = fromtlib::codec::decode_u16_map(shares_map).map_err(to_js_err)?;
    let mut shares = HashMap::new();
    for (id, bytes) in raw_map {
        shares.insert(Participant::new(id).unwrap(), bytes);
    }

    spend::spend_complete(sig_machine, shares)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))
}

#[wasm_bindgen]
pub fn fromt_tx_hash(raw_tx: &[u8]) -> Result<Vec<u8>, JsValue> {
    let tx = monero_wallet::transaction::Transaction::<monero_wallet::transaction::NotPruned>::read(
        &mut &raw_tx[..],
    )
    .map_err(|e| JsValue::from_str(&format!("parse tx: {:?}", e)))?;
    Ok(tx.hash().to_vec())
}
