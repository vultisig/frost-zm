use std::collections::HashMap;

use crate::{
    bytes::*,
    codec,
    errors::*,
    handle::Handle,
    keyshare::bundle::KeyShareBundle,
    monero::spend,
};

use modular_frost::Participant;

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_test_create_signable_tx(
    key_share: Option<&go_slice>,
    out_signable_tx: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        use rand::rngs::OsRng;
        use rand::RngCore;
        use zeroize::Zeroizing;
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use monero_wallet::ed25519::{Scalar as MScalar, Commitment};
        use monero_wallet::ringct::RctType;
        use monero_wallet::send::{Change, SignableTransaction};

        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_signable_tx.ok_or(lib_error::LIB_NULL_PTR)?;

        let bundle = KeyShareBundle::deserialize(ks_data.as_slice())?;
        let view_pair = spend::view_pair_from_bundle(&bundle)?;
        let group_key_bytes = bundle.verifying_key_bytes()?;
        let mut gk_arr = [0u8; 32];
        gk_arr.copy_from_slice(&group_key_bytes);
        let group_key_point = curve25519_dalek::edwards::CompressedEdwardsY(gk_arr)
            .decompress()
            .ok_or(lib_error::LIB_UNKNOWN_ERROR)?;

        let amount = 1_000_000_000_000u64;
        let ring_len = 16u8;
        let real_index = 3u8;

        let commitment_mask: curve25519_dalek::Scalar = MScalar::random(&mut OsRng).into();

        let key_offset_scalar = MScalar::random(&mut OsRng);
        let key_offset_dalek: curve25519_dalek::Scalar = key_offset_scalar.into();
        let output_key = group_key_point + &key_offset_dalek * ED25519_BASEPOINT_TABLE;

        let mut ring_keys = Vec::new();
        let mut ring_commitments = Vec::new();
        let mut global_indices = Vec::new();

        for i in 0..ring_len {
            let (dest, mask, amt) = if i == real_index {
                (output_key, commitment_mask, amount)
            } else {
                let d = &MScalar::random(&mut OsRng).into() * ED25519_BASEPOINT_TABLE;
                let m: curve25519_dalek::Scalar = MScalar::random(&mut OsRng).into();
                let a = 500_000_000_000u64 + (OsRng.next_u64() % 1_000_000_000_000u64);
                (d, m, a)
            };

            ring_keys.push(
                monero_wallet::ed25519::CompressedPoint::from(dest.compress().to_bytes())
                    .decompress()
                    .ok_or(lib_error::LIB_UNKNOWN_ERROR)?,
            );
            ring_commitments.push(
                Commitment::new(MScalar::from(mask), amt).commit(),
            );
            global_indices.push(1000 + i as u64);
        }

        let mut owd_buf = Vec::with_capacity(2048);

        let output_key_bytes = output_key.compress().to_bytes();
        owd_buf.extend_from_slice(&output_key_bytes);
        let ko_bytes: [u8; 32] = key_offset_dalek.to_bytes();
        owd_buf.extend_from_slice(&ko_bytes);
        let cm_bytes: [u8; 32] = commitment_mask.to_bytes();
        owd_buf.extend_from_slice(&cm_bytes);
        owd_buf.extend_from_slice(&amount.to_le_bytes());

        fn write_varint(buf: &mut Vec<u8>, val: u64) {
            let mut v = val;
            loop {
                let byte = (v & 0x7F) as u8;
                v >>= 7;
                if v == 0 {
                    buf.push(byte);
                    break;
                } else {
                    buf.push(byte | 0x80);
                }
            }
        }

        let mut sorted: Vec<(u64, usize)> = global_indices
            .iter()
            .copied()
            .enumerate()
            .map(|(i, gi)| (gi, i))
            .collect();
        sorted.sort_by_key(|(gi, _)| *gi);

        let mut sorted_real_index = None;
        for (new_pos, (_, orig_idx)) in sorted.iter().enumerate() {
            if *orig_idx == real_index as usize {
                sorted_real_index = Some(new_pos as u8);
                break;
            }
        }
        let sorted_real_index = sorted_real_index.ok_or(lib_error::LIB_UNKNOWN_ERROR)?;

        let mut offsets = Vec::new();
        let mut prev = 0u64;
        for (gi, _) in &sorted {
            offsets.push(*gi - prev);
            prev = *gi;
        }

        write_varint(&mut owd_buf, sorted.len() as u64);
        for offset in &offsets {
            write_varint(&mut owd_buf, *offset);
        }
        owd_buf.push(sorted_real_index);

        for (_, orig_idx) in &sorted {
            let key_bytes: [u8; 32] = ring_keys[*orig_idx].compress().to_bytes();
            owd_buf.extend_from_slice(&key_bytes);
            let commit_bytes: [u8; 32] = ring_commitments[*orig_idx].compress().to_bytes();
            owd_buf.extend_from_slice(&commit_bytes);
        }

        let owd = monero_wallet::OutputWithDecoys::read(&mut owd_buf.as_slice())
            .map_err(|e| {
                eprintln!("[fromt_test] OutputWithDecoys::read failed: {:?}", e);
                lib_error::LIB_SERIALIZATION_ERROR
            })?;

        let recipient = monero_wallet::address::MoneroAddress::from_str(
            monero_wallet::address::Network::Mainnet,
            &view_pair.legacy_address(monero_wallet::address::Network::Mainnet).to_string(),
        )
        .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;

        let mut outgoing_view = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(outgoing_view.as_mut());

        let change = Change::new(view_pair, None);

        let fee_rate = monero_wallet::interface::FeeRate::new(20, 10000)
            .ok_or(lib_error::LIB_UNKNOWN_ERROR)?;

        let send_amount = 500_000_000_000u64;

        let signable = SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            outgoing_view,
            vec![owd],
            vec![(recipient, send_amount)],
            change,
            vec![],
            fee_rate,
        )
        .map_err(|e| {
            eprintln!("[fromt_test] SignableTransaction::new failed: {:?}", e);
            lib_error::LIB_SIGNING_ERROR
        })?;

        *out = tss_buffer::from_vec(signable.serialize());
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_spend_preprocess(
    key_share: Option<&go_slice>,
    signable_tx: Option<&go_slice>,
    out_handle: Option<&mut Handle>,
    out_preprocess: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let st_data = signable_tx.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_h = out_handle.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_pp = out_preprocess.ok_or(lib_error::LIB_NULL_PTR)?;

        let bundle = KeyShareBundle::deserialize(ks_data.as_slice())?;
        let keys = spend::convert_keyshare(&bundle)?;

        let signable = monero_wallet::send::SignableTransaction::read(
            &mut st_data.as_slice(),
        )
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let (sign_machine, preprocess_bytes) = spend::spend_preprocess(signable, keys)?;

        *out_h = Handle::allocate(sign_machine)?;
        *out_pp = tss_buffer::from_vec(preprocess_bytes);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_spend_sign(
    handle: Handle,
    preprocesses_map: Option<&go_slice>,
    out_handle: Option<&mut Handle>,
    out_share: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pp_data = preprocesses_map.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_h = out_handle.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_s = out_share.ok_or(lib_error::LIB_NULL_PTR)?;

        let sign_machine = handle.take::<monero_wallet::send::TransactionSignMachine>()?;

        let raw_map: std::collections::BTreeMap<u16, Vec<u8>> = codec::decode_u16_map(pp_data.as_slice())?;
        let mut preprocesses = HashMap::new();
        for (id, bytes) in raw_map {
            preprocesses.insert(Participant::new(id).unwrap(), bytes);
        }

        let (sig_machine, share_bytes) = spend::spend_sign(sign_machine, preprocesses)?;

        *out_h = Handle::allocate(sig_machine)?;
        *out_s = tss_buffer::from_vec(share_bytes);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_spend_complete(
    handle: Handle,
    shares_map: Option<&go_slice>,
    out_raw_tx: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sm_data = shares_map.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_raw_tx.ok_or(lib_error::LIB_NULL_PTR)?;

        let sig_machine = handle.take::<monero_wallet::send::TransactionSignatureMachine>()?;

        let raw_map: std::collections::BTreeMap<u16, Vec<u8>> = codec::decode_u16_map(sm_data.as_slice())?;
        let mut shares = HashMap::new();
        for (id, bytes) in raw_map {
            shares.insert(Participant::new(id).unwrap(), bytes);
        }

        let tx_bytes = spend::spend_complete(sig_machine, shares)?;

        *out = tss_buffer::from_vec(tx_bytes);
        Ok(())
    })
}
