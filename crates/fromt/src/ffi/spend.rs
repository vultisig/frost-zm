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
