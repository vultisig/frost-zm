use frost_ffi::bytes::*;
use frost_ffi::errors::*;

use fromtlib::keyshare::bundle::KeyShareBundle;
use fromtlib::monero::spend;

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_scan_balance(
    key_share: Option<&go_slice>,
    daemon_url: Option<&go_slice>,
    birthday: u64,
    spend_key: Option<&go_slice>,
    out_balance: Option<&mut u64>,
    out_num_outputs: Option<&mut u32>,
) -> lib_error {
    with_error_handler(|| {
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let url_data = daemon_url.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_bal = out_balance.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_num = out_num_outputs.ok_or(lib_error::LIB_NULL_PTR)?;

        let bundle = KeyShareBundle::deserialize(ks_data.as_slice())?;
        let url = std::str::from_utf8(url_data.as_slice())
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let view_pair = spend::view_pair_from_bundle(&bundle)?;

        let sk_opt: Option<[u8; 32]> = spend_key.and_then(|s| {
            let data = s.as_slice();
            if data.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(data);
                Some(arr)
            } else {
                None
            }
        });

        let rt = tokio::runtime::Runtime::new()
            .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;

        let (balance, count) = rt.block_on(async {
            let rpc = monero_simple_request_rpc::SimpleRequestTransport::new(url.to_string())
                .await
                .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;

            spend::scan_balance(&rpc, url, &view_pair, birthday, sk_opt.as_ref()).await
        })?;

        *out_bal = balance;
        *out_num = count;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn fromt_spend_prepare(
    key_share: Option<&go_slice>,
    daemon_url: Option<&go_slice>,
    recipient: Option<&go_slice>,
    amount: u64,
    birthday: u64,
    excluded_offsets: Option<&go_slice>,
    spend_key: Option<&go_slice>,
    out_signable_tx: Option<&mut tss_buffer>,
    out_spent_offsets: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ks_data = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let url_data = daemon_url.ok_or(lib_error::LIB_NULL_PTR)?;
        let rcpt_data = recipient.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_signable_tx.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_offsets = out_spent_offsets.ok_or(lib_error::LIB_NULL_PTR)?;

        let bundle = KeyShareBundle::deserialize(ks_data.as_slice())?;
        let url = std::str::from_utf8(url_data.as_slice())
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        let addr = std::str::from_utf8(rcpt_data.as_slice())
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let mut excluded: Vec<[u8; 32]> = Vec::new();
        if let Some(ex) = excluded_offsets {
            let data = ex.as_slice();
            if data.len() % 32 == 0 {
                for chunk in data.chunks_exact(32) {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(chunk);
                    excluded.push(arr);
                }
            }
        }

        let rt = tokio::runtime::Runtime::new()
            .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;

        let (signable, selected_offsets) = rt.block_on(async {
            let rpc = monero_simple_request_rpc::SimpleRequestTransport::new(url.to_string())
                .await
                .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;

            let sk_opt: Option<[u8; 32]> = spend_key.and_then(|s| {
                let data = s.as_slice();
                if data.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(data);
                    Some(arr)
                } else {
                    None
                }
            });
            let sk_ref = sk_opt.as_ref();

            spend::prepare_spend(&rpc, url, &bundle, addr, amount, birthday, &excluded, sk_ref).await
        })?;

        let input_offsets: Vec<u8> = selected_offsets.iter()
            .flat_map(|o| o.iter().copied())
            .collect();

        let signable_bytes = signable.serialize();
        *out = tss_buffer::from_vec(signable_bytes);
        *out_offsets = tss_buffer::from_vec(input_offsets);
        Ok(())
    })
}
