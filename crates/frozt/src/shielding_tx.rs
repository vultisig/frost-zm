use blake2b_simd::Params as Blake2bParams;
use byteorder::{LittleEndian, WriteBytesExt};
use rand::thread_rng;
use sapling_crypto::{
    keys::OutgoingViewingKey,
    note_encryption::Zip212Enforcement,
    value::{NoteValue, ValueCommitTrapdoor},
};
use std::io::Write;

use crate::{
    bytes::*,
    errors::*,
    handle::Handle,
    sapling::zip212_for_height,
    tx::{
        branch_id_for_height, compute_bsk, get_output_params, hash_empty_orchard, hash_header,
        hash_sapling, make_output, parse_payment_address, write_compactsize, OutputParts,
    },
};

const SEQUENCE: u32 = 0xFFFF_FFFE;

pub struct TransparentInput {
    pub prev_txid: [u8; 32],
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

pub struct TransparentOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

struct ShieldingBuildState {
    inputs: Vec<TransparentInput>,
    transparent_outputs: Vec<TransparentOutput>,
    sapling_outputs: Vec<OutputParts>,
    value_balance: i64,
    consensus_branch_id: u32,
    expiry_height: u32,
    txid_sighash: [u8; 32],
}

pub struct ShieldingTxBuilder {
    ovk: OutgoingViewingKey,
    target_height: u32,
    zip212: Zip212Enforcement,
    inputs: Vec<TransparentInput>,
    transparent_outputs: Vec<TransparentOutput>,
    sapling_outputs: Vec<OutputParts>,
    total_input: u64,
    total_sapling_output: u64,
    total_transparent_output: u64,
    finished: Option<ShieldingBuildState>,
}

fn hash_prevouts(inputs: &[TransparentInput]) -> [u8; 32] {
    let mut h = Blake2bParams::new()
        .hash_length(32)
        .personal(b"ZTxIdPrevoutHash")
        .to_state();
    for inp in inputs {
        h.update(&inp.prev_txid);
        h.update(&inp.vout.to_le_bytes());
    }
    h.finalize().as_bytes().try_into().unwrap()
}

fn hash_amounts(inputs: &[TransparentInput]) -> [u8; 32] {
    let mut h = Blake2bParams::new()
        .hash_length(32)
        .personal(b"ZTxIdAmountsHash")
        .to_state();
    for inp in inputs {
        h.update(&inp.value.to_le_bytes());
    }
    h.finalize().as_bytes().try_into().unwrap()
}

fn hash_script_pubkeys(inputs: &[TransparentInput]) -> [u8; 32] {
    let mut h = Blake2bParams::new()
        .hash_length(32)
        .personal(b"ZTxIdScriptsHash")
        .to_state();
    for inp in inputs {
        write_compactsize_raw(&mut h, inp.script_pubkey.len() as u64);
        h.update(&inp.script_pubkey);
    }
    h.finalize().as_bytes().try_into().unwrap()
}

fn hash_sequences(inputs: &[TransparentInput]) -> [u8; 32] {
    let mut h = Blake2bParams::new()
        .hash_length(32)
        .personal(b"ZTxIdSequencHash")
        .to_state();
    for _ in inputs {
        h.update(&SEQUENCE.to_le_bytes());
    }
    h.finalize().as_bytes().try_into().unwrap()
}

fn hash_transparent_outputs(t_outputs: &[TransparentOutput]) -> [u8; 32] {
    let mut h = Blake2bParams::new()
        .hash_length(32)
        .personal(b"ZTxIdTOutputHash")
        .to_state();
    for out in t_outputs {
        h.update(&(out.value as i64).to_le_bytes());
        write_compactsize_raw(&mut h, out.script_pubkey.len() as u64);
        h.update(&out.script_pubkey);
    }
    h.finalize().as_bytes().try_into().unwrap()
}

fn hash_transparent_txid_digest(
    inputs: &[TransparentInput],
    t_outputs: &[TransparentOutput],
) -> [u8; 32] {
    let prevouts = hash_prevouts(inputs);
    let amounts = hash_amounts(inputs);
    let scripts = hash_script_pubkeys(inputs);
    let sequences = hash_sequences(inputs);
    let outputs = hash_transparent_outputs(t_outputs);

    let mut h = Blake2bParams::new()
        .hash_length(32)
        .personal(b"ZTxIdTranspaHash")
        .to_state();
    h.update(&prevouts);
    h.update(&amounts);
    h.update(&scripts);
    h.update(&sequences);
    h.update(&outputs);
    h.finalize().as_bytes().try_into().unwrap()
}

fn hash_transparent_sig_digest(
    inputs: &[TransparentInput],
    t_outputs: &[TransparentOutput],
    index: usize,
) -> [u8; 32] {
    let prevouts = hash_prevouts(inputs);
    let amounts = hash_amounts(inputs);
    let scripts = hash_script_pubkeys(inputs);
    let sequences = hash_sequences(inputs);
    let outputs = hash_transparent_outputs(t_outputs);

    let inp = &inputs[index];

    let mut h = Blake2bParams::new()
        .hash_length(32)
        .personal(b"ZTxIdTranspaHash")
        .to_state();
    h.update(&[0x01]); // SIGHASH_ALL
    h.update(&prevouts);
    h.update(&amounts);
    h.update(&scripts);
    h.update(&sequences);
    h.update(&outputs);
    // per-input fields
    h.update(&inp.prev_txid);
    h.update(&inp.vout.to_le_bytes());
    h.update(&inp.value.to_le_bytes());
    write_compactsize_raw(&mut h, inp.script_pubkey.len() as u64);
    h.update(&inp.script_pubkey);
    h.update(&SEQUENCE.to_le_bytes());
    h.finalize().as_bytes().try_into().unwrap()
}

pub fn compute_shielding_sighash(
    inputs: &[TransparentInput],
    transparent_outputs: &[TransparentOutput],
    sapling_outputs: &[OutputParts],
    value_balance: i64,
    consensus_branch_id: u32,
    expiry_height: u32,
    input_index: Option<usize>,
) -> [u8; 32] {
    let header_digest = hash_header(consensus_branch_id, expiry_height);
    let transparent_digest = match input_index {
        None => hash_transparent_txid_digest(inputs, transparent_outputs),
        Some(idx) => hash_transparent_sig_digest(inputs, transparent_outputs, idx),
    };
    let sapling_digest = hash_sapling(&[], sapling_outputs, value_balance);
    let orchard_digest = hash_empty_orchard();

    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(b"ZcashTxHash_");
    personal[12..].copy_from_slice(&consensus_branch_id.to_le_bytes());

    let mut h = Blake2bParams::new()
        .hash_length(32)
        .personal(&personal)
        .to_state();
    h.update(&header_digest);
    h.update(&transparent_digest);
    h.update(&sapling_digest);
    h.update(&orchard_digest);
    h.finalize().as_bytes().try_into().unwrap()
}

pub fn parse_transparent_address(addr_str: &str) -> Result<[u8; 20], lib_error> {
    let decoded = bs58::decode(addr_str)
        .with_check(None)
        .into_vec()
        .map_err(|_| lib_error::LIB_ADDRESS_ERROR)?;
    if decoded.len() != 22 {
        return Err(lib_error::LIB_ADDRESS_ERROR);
    }
    if decoded[0] != 0x1C || decoded[1] != 0xB8 {
        return Err(lib_error::LIB_ADDRESS_ERROR);
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&decoded[2..22]);
    Ok(hash)
}

pub fn build_p2pkh_script_pubkey(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

pub fn build_p2pkh_script_sig(der_sig: &[u8], pubkey: &[u8]) -> Vec<u8> {
    let sig_plus_hashtype_len = der_sig.len() + 1;
    let mut script = Vec::with_capacity(1 + sig_plus_hashtype_len + 1 + pubkey.len());
    script.push(sig_plus_hashtype_len as u8);
    script.extend_from_slice(der_sig);
    script.push(0x01); // SIGHASH_ALL
    script.push(pubkey.len() as u8);
    script.extend_from_slice(pubkey);
    script
}

pub fn serialize_shielding_v5_tx(
    inputs: &[TransparentInput],
    script_sigs: &[Vec<u8>],
    transparent_outputs: &[TransparentOutput],
    sapling_outputs: &[OutputParts],
    value_balance: i64,
    binding_sig: &redjubjub::Signature<redjubjub::Binding>,
    consensus_branch_id: u32,
    expiry_height: u32,
) -> Result<Vec<u8>, lib_error> {
    let mut tx = Vec::with_capacity(4096);
    let w = |_e: std::io::Error| lib_error::LIB_SERIALIZATION_ERROR;

    // header
    tx.write_u32::<LittleEndian>(5 | (1 << 31)).map_err(w)?;
    tx.write_u32::<LittleEndian>(0x26A7_270A).map_err(w)?;
    tx.write_u32::<LittleEndian>(consensus_branch_id).map_err(w)?;
    tx.write_u32::<LittleEndian>(0).map_err(w)?; // locktime
    tx.write_u32::<LittleEndian>(expiry_height).map_err(w)?;

    // transparent inputs
    write_compactsize(&mut tx, inputs.len() as u64)?;
    for (inp, script_sig) in inputs.iter().zip(script_sigs.iter()) {
        tx.write_all(&inp.prev_txid).map_err(w)?;
        tx.write_u32::<LittleEndian>(inp.vout).map_err(w)?;
        write_compactsize(&mut tx, script_sig.len() as u64)?;
        tx.write_all(script_sig).map_err(w)?;
        tx.write_u32::<LittleEndian>(SEQUENCE).map_err(w)?;
    }

    // transparent outputs
    write_compactsize(&mut tx, transparent_outputs.len() as u64)?;
    for out in transparent_outputs {
        tx.write_i64::<LittleEndian>(out.value as i64).map_err(w)?;
        write_compactsize(&mut tx, out.script_pubkey.len() as u64)?;
        tx.write_all(&out.script_pubkey).map_err(w)?;
    }

    // sapling spends (none)
    write_compactsize(&mut tx, 0)?;

    // sapling outputs
    write_compactsize(&mut tx, sapling_outputs.len() as u64)?;
    for output in sapling_outputs {
        tx.write_all(&output.cv.to_bytes()).map_err(w)?;
        tx.write_all(&output.cmu.to_bytes()).map_err(w)?;
        tx.write_all(output.ephemeral_key.as_ref()).map_err(w)?;
        tx.write_all(&output.enc_ciphertext).map_err(w)?;
        tx.write_all(&output.out_ciphertext).map_err(w)?;
    }

    // value_balance (always written when sapling outputs present)
    tx.write_i64::<LittleEndian>(value_balance).map_err(w)?;

    // no anchor (no spends)
    // no spend zkproofs
    // no spend auth sigs

    // output zkproofs
    for output in sapling_outputs {
        tx.write_all(&output.zkproof).map_err(w)?;
    }

    // binding signature
    let bsig_bytes: [u8; 64] = (*binding_sig).into();
    tx.write_all(&bsig_bytes).map_err(w)?;

    // orchard (none)
    write_compactsize(&mut tx, 0)?;

    Ok(tx)
}

fn write_compactsize_raw<W: Write>(w: &mut W, n: u64) {
    if n < 253 {
        let _ = w.write_all(&[n as u8]);
    } else if n <= 0xFFFF {
        let _ = w.write_all(&[253]);
        let _ = w.write_all(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        let _ = w.write_all(&[254]);
        let _ = w.write_all(&(n as u32).to_le_bytes());
    } else {
        let _ = w.write_all(&[255]);
        let _ = w.write_all(&n.to_le_bytes());
    }
}

fn parse_transparent_input(data: &[u8]) -> Result<TransparentInput, lib_error> {
    if data.len() < 46 {
        return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
    }
    let prev_txid: [u8; 32] = data[0..32].try_into().unwrap();
    let vout = u32::from_le_bytes(data[32..36].try_into().unwrap());
    let value = u64::from_le_bytes(data[36..44].try_into().unwrap());
    let spk_len = u16::from_le_bytes(data[44..46].try_into().unwrap()) as usize;
    if data.len() < 46 + spk_len {
        return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
    }
    let script_pubkey = data[46..46 + spk_len].to_vec();
    Ok(TransparentInput { prev_txid, vout, value, script_pubkey })
}

// --- FFI ---

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_shielding_tx_builder_new(
    pkp_bytes: Option<&go_slice>,
    extras_bytes: Option<&go_slice>,
    target_height: u32,
    out_handle: Option<&mut Handle>,
) -> lib_error {
    with_error_handler(|| {
        let _pkp = pkp_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let extras = extras_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_handle.ok_or(lib_error::LIB_NULL_PTR)?;

        let extras_data = extras.as_slice();
        if extras_data.len() < 96 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let mut ovk_bytes = [0u8; 32];
        ovk_bytes.copy_from_slice(&extras_data[32..64]);
        let ovk = OutgoingViewingKey(ovk_bytes);

        let zip212 = zip212_for_height(target_height as u64);

        let builder = ShieldingTxBuilder {
            ovk,
            target_height,
            zip212,
            inputs: Vec::new(),
            transparent_outputs: Vec::new(),
            sapling_outputs: Vec::new(),
            total_input: 0,
            total_sapling_output: 0,
            total_transparent_output: 0,
            finished: None,
        };

        *out = Handle::allocate(builder)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_shielding_tx_builder_add_input(
    builder_handle: Handle,
    input_data: Option<&go_slice>,
) -> lib_error {
    with_error_handler(|| {
        let data = input_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let inp = parse_transparent_input(data.as_slice())?;
        let mut builder = builder_handle.get::<ShieldingTxBuilder>()?;
        builder.total_input = builder
            .total_input
            .checked_add(inp.value)
            .ok_or(lib_error::LIB_SAPLING_ERROR)?;
        builder.inputs.push(inp);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_shielding_tx_builder_add_output(
    builder_handle: Handle,
    address: Option<&go_slice>,
    amount: u64,
) -> lib_error {
    with_error_handler(|| {
        let addr_slice = address.ok_or(lib_error::LIB_NULL_PTR)?;
        let addr_str =
            std::str::from_utf8(addr_slice.as_slice()).map_err(|_| lib_error::LIB_SAPLING_ERROR)?;
        let to = parse_payment_address(addr_str)?;
        let output_params = get_output_params()?;

        let mut builder = builder_handle.get::<ShieldingTxBuilder>()?;
        let value = NoteValue::from_raw(amount);
        let memo = [0u8; 512];

        let output = make_output(Some(builder.ovk), to, value, memo, builder.zip212, output_params)?;
        builder.total_sapling_output = builder
            .total_sapling_output
            .checked_add(amount)
            .ok_or(lib_error::LIB_SAPLING_ERROR)?;
        builder.sapling_outputs.push(output);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_shielding_tx_builder_add_transparent_output(
    builder_handle: Handle,
    address: Option<&go_slice>,
    amount: u64,
) -> lib_error {
    with_error_handler(|| {
        let addr_slice = address.ok_or(lib_error::LIB_NULL_PTR)?;
        let addr_str =
            std::str::from_utf8(addr_slice.as_slice()).map_err(|_| lib_error::LIB_ADDRESS_ERROR)?;
        let pubkey_hash = parse_transparent_address(addr_str)?;
        let script_pubkey = build_p2pkh_script_pubkey(&pubkey_hash);

        let mut builder = builder_handle.get::<ShieldingTxBuilder>()?;
        builder.total_transparent_output = builder
            .total_transparent_output
            .checked_add(amount)
            .ok_or(lib_error::LIB_SAPLING_ERROR)?;
        builder.transparent_outputs.push(TransparentOutput {
            value: amount,
            script_pubkey,
        });
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_shielding_tx_builder_build(
    builder_handle: Handle,
    out_sighashes: Option<&mut tss_buffer>,
    out_count: Option<&mut u32>,
) -> lib_error {
    with_error_handler(|| {
        let out_sh = out_sighashes.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_n = out_count.ok_or(lib_error::LIB_NULL_PTR)?;

        let mut builder = builder_handle.get::<ShieldingTxBuilder>()?;

        if builder.inputs.is_empty() || builder.sapling_outputs.is_empty() {
            return Err(lib_error::LIB_SAPLING_ERROR);
        }
        let total_out = builder
            .total_sapling_output
            .checked_add(builder.total_transparent_output)
            .ok_or(lib_error::LIB_SAPLING_ERROR)?;
        if builder.total_input <= total_out {
            return Err(lib_error::LIB_SAPLING_ERROR);
        }

        let value_balance = -(builder.total_sapling_output as i64);
        let consensus_branch_id = branch_id_for_height(builder.target_height);
        let expiry_height = builder.target_height + 40;

        let n = builder.inputs.len();
        let mut per_input_sighashes = Vec::with_capacity(n);
        for i in 0..n {
            let sh = compute_shielding_sighash(
                &builder.inputs,
                &builder.transparent_outputs,
                &builder.sapling_outputs,
                value_balance,
                consensus_branch_id,
                expiry_height,
                Some(i),
            );
            per_input_sighashes.push(sh);
        }

        let txid_sighash = compute_shielding_sighash(
            &builder.inputs,
            &builder.transparent_outputs,
            &builder.sapling_outputs,
            value_balance,
            consensus_branch_id,
            expiry_height,
            None,
        );

        let mut concat = Vec::with_capacity(n * 32);
        for sh in &per_input_sighashes {
            concat.extend_from_slice(sh);
        }

        *out_n = n as u32;
        *out_sh = tss_buffer::from_vec(concat);

        builder.finished = Some(ShieldingBuildState {
            inputs: std::mem::take(&mut builder.inputs),
            transparent_outputs: std::mem::take(&mut builder.transparent_outputs),
            sapling_outputs: std::mem::take(&mut builder.sapling_outputs),
            value_balance,
            consensus_branch_id,
            expiry_height,
            txid_sighash,
        });

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_shielding_tx_builder_complete(
    builder_handle: Handle,
    ecdsa_sigs: Option<&go_slice>,
    pubkeys: Option<&go_slice>,
    out_raw_tx: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sig_data = ecdsa_sigs.ok_or(lib_error::LIB_NULL_PTR)?;
        let pk_data = pubkeys.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_raw_tx.ok_or(lib_error::LIB_NULL_PTR)?;

        let mut builder: ShieldingTxBuilder = builder_handle.take::<ShieldingTxBuilder>()?;
        let state = builder
            .finished
            .take()
            .ok_or(lib_error::LIB_SAPLING_ERROR)?;

        let n = state.inputs.len();
        let pk_bytes = pk_data.as_slice();
        if pk_bytes.len() != n * 33 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let sig_bytes = sig_data.as_slice();
        let mut sigs: Vec<&[u8]> = Vec::with_capacity(n);
        let mut offset = 0;
        for _ in 0..n {
            if offset + 2 > sig_bytes.len() {
                return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
            }
            let sig_len =
                u16::from_le_bytes(sig_bytes[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            if offset + sig_len > sig_bytes.len() {
                return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
            }
            sigs.push(&sig_bytes[offset..offset + sig_len]);
            offset += sig_len;
        }

        let mut script_sigs = Vec::with_capacity(n);
        for i in 0..n {
            let pk = &pk_bytes[i * 33..(i + 1) * 33];
            let ss = build_p2pkh_script_sig(sigs[i], pk);
            script_sigs.push(ss);
        }

        let output_rcvs: Vec<&ValueCommitTrapdoor> =
            state.sapling_outputs.iter().map(|o| &o.rcv).collect();
        let bsk = compute_bsk(&[], &output_rcvs);

        let mut rng = thread_rng();
        let binding_sig = bsk.sign(&mut rng, &state.txid_sighash);

        let raw_tx = serialize_shielding_v5_tx(
            &state.inputs,
            &script_sigs,
            &state.transparent_outputs,
            &state.sapling_outputs,
            state.value_balance,
            &binding_sig,
            state.consensus_branch_id,
            state.expiry_height,
        )?;

        *out = tss_buffer::from_vec(raw_tx);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_input(txid_byte: u8, vout: u32, value: u64) -> TransparentInput {
        let mut prev_txid = [0u8; 32];
        prev_txid[0] = txid_byte;
        TransparentInput {
            prev_txid,
            vout,
            value,
            script_pubkey: vec![0x76, 0xa9, 0x14, /* 20 zero bytes */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac],
        }
    }

    #[test]
    fn test_hash_prevouts_deterministic() {
        let inputs = vec![mock_input(1, 0, 100_000)];
        let h1 = hash_prevouts(&inputs);
        let h2 = hash_prevouts(&inputs);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_per_input_sighashes_differ() {
        let inputs = vec![
            mock_input(1, 0, 100_000),
            mock_input(2, 1, 200_000),
        ];
        let t_out: Vec<TransparentOutput> = vec![];
        let h0 = hash_transparent_sig_digest(&inputs, &t_out, 0);
        let h1 = hash_transparent_sig_digest(&inputs, &t_out, 1);
        assert_ne!(h0, h1);
    }

    #[test]
    fn test_txid_digest_differs_from_sig_digest() {
        let inputs = vec![mock_input(1, 0, 100_000)];
        let t_out: Vec<TransparentOutput> = vec![];
        let txid = hash_transparent_txid_digest(&inputs, &t_out);
        let sig = hash_transparent_sig_digest(&inputs, &t_out, 0);
        assert_ne!(txid, sig);
    }

    #[test]
    fn test_transparent_output_changes_sighash() {
        let inputs = vec![mock_input(1, 0, 100_000)];
        let no_out: Vec<TransparentOutput> = vec![];
        let with_out = vec![TransparentOutput {
            value: 50_000,
            script_pubkey: build_p2pkh_script_pubkey(&[0u8; 20]),
        }];
        let h_without = hash_transparent_sig_digest(&inputs, &no_out, 0);
        let h_with = hash_transparent_sig_digest(&inputs, &with_out, 0);
        assert_ne!(h_without, h_with);
    }

    #[test]
    fn test_p2pkh_script_pubkey() {
        let hash = [0xAB; 20];
        let script = build_p2pkh_script_pubkey(&hash);
        assert_eq!(script.len(), 25);
        assert_eq!(script[0], 0x76); // OP_DUP
        assert_eq!(script[1], 0xa9); // OP_HASH160
        assert_eq!(script[2], 0x14); // push 20
        assert_eq!(&script[3..23], &hash);
        assert_eq!(script[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(script[24], 0xac); // OP_CHECKSIG
    }

    #[test]
    fn test_parse_transparent_address_valid() {
        let hash = parse_transparent_address("t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs");
        assert!(hash.is_ok());
        assert_eq!(hash.unwrap().len(), 20);
    }

    #[test]
    fn test_parse_transparent_address_invalid() {
        assert!(parse_transparent_address("zs1invalidaddr").is_err());
        assert!(parse_transparent_address("t3invalid").is_err());
        assert!(parse_transparent_address("").is_err());
    }

    #[test]
    fn test_p2pkh_script_sig() {
        let der_sig = vec![0x30, 0x44, 0x02, 0x20]; // truncated but valid for format test
        let pubkey = [0x02u8; 33];
        let ss = build_p2pkh_script_sig(&der_sig, &pubkey);
        assert_eq!(ss[0] as usize, der_sig.len() + 1); // push opcode for sig+hashtype
        assert_eq!(ss[1..1 + der_sig.len()], der_sig[..]);
        assert_eq!(ss[1 + der_sig.len()], 0x01); // SIGHASH_ALL
        assert_eq!(ss[2 + der_sig.len()], 33); // push opcode for pubkey
        assert_eq!(ss[3 + der_sig.len()..], pubkey[..]);
    }

    #[test]
    fn test_parse_transparent_input() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xAA; 32]); // prev_txid
        data.extend_from_slice(&3u32.to_le_bytes()); // vout
        data.extend_from_slice(&50000u64.to_le_bytes()); // value
        let spk = vec![0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac];
        data.extend_from_slice(&(spk.len() as u16).to_le_bytes());
        data.extend_from_slice(&spk);

        let inp = parse_transparent_input(&data).unwrap();
        assert_eq!(inp.prev_txid, [0xAA; 32]);
        assert_eq!(inp.vout, 3);
        assert_eq!(inp.value, 50000);
        assert_eq!(inp.script_pubkey, spk);
    }

    #[test]
    fn test_parse_transparent_input_too_short() {
        let data = vec![0u8; 30];
        assert!(parse_transparent_input(&data).is_err());
    }
}
