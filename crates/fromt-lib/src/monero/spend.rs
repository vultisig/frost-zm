use std::collections::HashMap;

macro_rules! debug_log {
	($($arg:tt)*) => {
		#[cfg(debug_assertions)]
		eprintln!($($arg)*);
	};
}

use zeroize::Zeroizing;

use rand::rngs::OsRng;
#[cfg(feature = "rpc")]
use rand::RngCore;

use modular_frost::dkg::{Interpolation, ThresholdKeys, ThresholdParams};
use modular_frost::sign::{PreprocessMachine, SignMachine, SignatureMachine, Writable};
use modular_frost::Participant;

use monero_wallet::ed25519::{Point, Scalar};
#[cfg(feature = "rpc")]
use monero_wallet::interface::{
    FeePriority, ProvidesBlockchain, ProvidesDecoys, ProvidesOutputs, ProvidesTransactions,
    ExpandToScannableBlock, ProvidesFeeRates,
};
#[cfg(feature = "rpc")]
use monero_wallet::ringct::RctType;
#[cfg(feature = "rpc")]
use monero_wallet::send::Change;
use monero_wallet::send::SignableTransaction;
#[cfg(feature = "rpc")]
use monero_wallet::{OutputWithDecoys, Scanner, ViewPair, WalletOutput};
#[cfg(not(feature = "rpc"))]
use monero_wallet::ViewPair;

use crate::errors::lib_error;
use crate::keyshare::bundle::KeyShareBundle;
use crate::keyshare::identifier::identifier_to_u16;

#[cfg(feature = "rpc")]
const RING_LEN: u8 = 16;

#[cfg(feature = "rpc")]
fn compute_key_image(
    output: &WalletOutput,
    spend_key: &curve25519_dalek::Scalar,
) -> [u8; 32] {
    use monero_wallet::ed25519::Point;

    let key_offset_bytes: [u8; 32] = <[u8; 32]>::from(output.key_offset());
    let key_offset_scalar = curve25519_dalek::Scalar::from_canonical_bytes(key_offset_bytes)
        .expect("invalid key offset scalar");
    let x = key_offset_scalar + spend_key;

    let output_key_bytes = output.key().compress().to_bytes();
    let hp = Point::biased_hash(output_key_bytes);
    let hp_dalek: curve25519_dalek::EdwardsPoint = hp.into();
    let ki = x * hp_dalek;
    ki.compress().to_bytes()
}

#[cfg(feature = "rpc")]
async fn check_key_images_spent(
    daemon_url: &str,
    key_images: &[[u8; 32]],
) -> Result<Vec<bool>, lib_error> {
    if key_images.is_empty() {
        return Ok(vec![]);
    }

    let ki_hex: Vec<String> = key_images.iter()
        .map(|ki| hex::encode(ki))
        .collect();
    let body = serde_json::json!({"key_images": ki_hex});

    let client = reqwest::Client::new();
    let resp = client.post(format!("{}/is_key_image_spent", daemon_url))
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            debug_log!("[fromt] is_key_image_spent request error: {:?}", e);
            lib_error::LIB_UNKNOWN_ERROR
        })?;

    let json: serde_json::Value = resp.json().await.map_err(|e| {
        debug_log!("[fromt] is_key_image_spent parse error: {:?}", e);
        lib_error::LIB_UNKNOWN_ERROR
    })?;

    let statuses = json["spent_status"].as_array().ok_or_else(|| {
        debug_log!("[fromt] is_key_image_spent: no 'spent_status' in response: {}", json);
        lib_error::LIB_UNKNOWN_ERROR
    })?;

    let flags: Vec<bool> = statuses.iter()
        .map(|s| s.as_u64().unwrap_or(0) != 0)
        .collect();

    Ok(flags)
}

pub fn filter_spent_outputs(
    outputs_data: &[u8],
    spent_flags: &[u8],
) -> Result<(u64, u32), lib_error> {
    if outputs_data.len() < 4 {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let count = u32::from_le_bytes(
        outputs_data[0..4].try_into().map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?,
    ) as usize;
    let expected_outputs_len = 4 + count * 72;
    if outputs_data.len() < expected_outputs_len {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    if spent_flags.len() < count {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }

    let mut balance = 0u64;
    let mut num_unspent = 0u32;
    for i in 0..count {
        if spent_flags[i] == 0 {
            let offset = 4 + i * 72 + 64;
            let amount = u64::from_le_bytes(
                outputs_data[offset..offset + 8]
                    .try_into()
                    .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?,
            );
            balance += amount;
            num_unspent += 1;
        }
    }

    Ok((balance, num_unspent))
}

pub fn convert_keyshare(
    bundle: &KeyShareBundle,
) -> Result<ThresholdKeys<dalek_ff_group::Ed25519>, lib_error> {
    let kp = &bundle.key_package;
    let pkp = &bundle.pub_key_package;

    let my_id = identifier_to_u16(kp.identifier())?;
    let min_signers = *kp.min_signers();
    let max_signers = pkp.verifying_shares().len() as u16;

    let params = ThresholdParams::new(min_signers, max_signers, Participant::new(my_id).unwrap())
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

    let secret_bytes: Vec<u8> = kp.signing_share().serialize();
    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(&secret_bytes);
    let dalek_scalar = curve25519_dalek::Scalar::from_canonical_bytes(secret_arr)
        .expect("invalid secret share scalar");
    let secret_scalar = dalek_ff_group::Scalar::from(dalek_scalar);

    let mut verification_shares = HashMap::new();
    for (ident, share) in pkp.verifying_shares() {
        let pid = identifier_to_u16(ident)?;
        let share_bytes: Vec<u8> = share
            .serialize()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        let mut share_arr = [0u8; 32];
        share_arr.copy_from_slice(&share_bytes);
        let compressed = curve25519_dalek::edwards::CompressedEdwardsY(share_arr);
        let point = compressed
            .decompress()
            .ok_or(lib_error::LIB_SERIALIZATION_ERROR)?;
        verification_shares
            .insert(Participant::new(pid).unwrap(), dalek_ff_group::EdwardsPoint(point));
    }

    ThresholdKeys::new(
        params,
        Interpolation::Lagrange,
        Zeroizing::new(secret_scalar),
        verification_shares,
    )
    .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)
}

pub fn view_pair_from_bundle(bundle: &KeyShareBundle) -> Result<ViewPair, lib_error> {
    let group_key_bytes = bundle.verifying_key_bytes()?;
    let mut gk_arr = [0u8; 32];
    gk_arr.copy_from_slice(&group_key_bytes);
    let spend_pub = curve25519_dalek::edwards::CompressedEdwardsY(gk_arr)
        .decompress()
        .ok_or(lib_error::LIB_SERIALIZATION_ERROR)?;

    let view_scalar =
        curve25519_dalek::Scalar::from_canonical_bytes(bundle.view_key)
            .expect("invalid view key");

    ViewPair::new(
        Point::from(spend_pub),
        Zeroizing::new(Scalar::from(view_scalar)),
    )
    .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)
}

#[cfg(feature = "rpc")]
pub async fn prepare_spend<R: ProvidesBlockchain + ProvidesTransactions + ProvidesOutputs + ProvidesDecoys + ProvidesFeeRates + ExpandToScannableBlock + Sync>(
    rpc: &R,
    daemon_url: &str,
    bundle: &KeyShareBundle,
    recipient_addr: &str,
    amount: u64,
    birthday: u64,
    excluded_key_offsets: &[[u8; 32]],
    spend_key: Option<&[u8; 32]>,
) -> Result<(SignableTransaction, Vec<[u8; 32]>), lib_error> {
    let view_pair = view_pair_from_bundle(bundle)?;

    let mut scanner = Scanner::new(view_pair.clone());

    let chain_height = rpc
        .latest_block_number()
        .await
        .map_err(|e| {
            debug_log!("[fromt] latest_block_number error: {:?}", e);
            lib_error::LIB_UNKNOWN_ERROR
        })?;

    let safe_height = if chain_height > 10 { chain_height - 10 } else { chain_height };
    debug_log!("[fromt] Chain height: {}, scanning {} to {} (10-block safety margin)", chain_height, birthday, safe_height);

    let start = birthday as usize;
    let end = safe_height;

    let mut owned_outputs: Vec<WalletOutput> = Vec::new();

    for height in start..=end {
        let block = rpc
            .block_by_number(height)
            .await
            .map_err(|e| {
                debug_log!("[fromt] block_by_number({}) error: {:?}", height, e);
                lib_error::LIB_UNKNOWN_ERROR
            })?;

        let scannable = rpc
            .expand_to_scannable_block(block)
            .await
            .map_err(|e| {
                debug_log!("[fromt] expand_to_scannable_block({}) error: {:?}", height, e);
                lib_error::LIB_UNKNOWN_ERROR
            })?;

        let scanned = scanner.scan(scannable).map_err(|e| {
            debug_log!("[fromt] scan block {} error: {:?}", height, e);
            lib_error::LIB_UNKNOWN_ERROR
        })?;
        let unlocked = scanned.not_additionally_locked();
        if !unlocked.is_empty() {
            debug_log!("[fromt] Found {} outputs at height {}", unlocked.len(), height);
        }
        owned_outputs.extend(unlocked);
    }

    debug_log!("[fromt] Scan complete. Found {} owned outputs", owned_outputs.len());
    for (i, output) in owned_outputs.iter().enumerate() {
        debug_log!(
            "[fromt]   Output {}: amount={} key_offset={} key={}",
            i,
            output.commitment().amount,
            hex::encode(<[u8; 32]>::from(output.key_offset())),
            hex::encode(output.key().compress().to_bytes()),
        );
    }

    if !excluded_key_offsets.is_empty() {
        let before = owned_outputs.len();
        owned_outputs.retain(|output| {
            let ko: [u8; 32] = <[u8; 32]>::from(output.key_offset());
            !excluded_key_offsets.contains(&ko)
        });
        let excluded = before - owned_outputs.len();
        if excluded > 0 {
            debug_log!("[fromt] Excluded {} locally-tracked spent outputs, {} remaining", excluded, owned_outputs.len());
        }
    }

    if let Some(sk_bytes) = spend_key {
        let sk = curve25519_dalek::Scalar::from_canonical_bytes(*sk_bytes)
            .expect("invalid spend key scalar");
        let key_images: Vec<[u8; 32]> = owned_outputs.iter()
            .map(|o| compute_key_image(o, &sk))
            .collect();
        debug_log!("[fromt] Checking {} key images against daemon...", key_images.len());
        let spent_flags = check_key_images_spent(daemon_url, &key_images).await?;
        let before_filter = owned_outputs.len();
        let mut filtered = Vec::new();
        for (output, spent) in owned_outputs.into_iter().zip(spent_flags.iter()) {
            if *spent {
                debug_log!("[fromt] Output at index {} is SPENT on-chain, skipping (amount={})",
                    output.index_on_blockchain(), output.commitment().amount);
            } else {
                filtered.push(output);
            }
        }
        owned_outputs = filtered;
        let removed = before_filter - owned_outputs.len();
        if removed > 0 {
            debug_log!("[fromt] Filtered {} on-chain spent outputs, {} unspent remaining", removed, owned_outputs.len());
        }
    }

    if owned_outputs.is_empty() {
        debug_log!("[fromt] No owned outputs found!");
        return Err(lib_error::LIB_UNKNOWN_ERROR);
    }

    owned_outputs.sort_by(|a, b| b.commitment().amount.cmp(&a.commitment().amount));
    let fee_estimate = 30_000_000u64;
    let needed = amount + fee_estimate;
    let mut selected: Vec<WalletOutput> = Vec::new();
    let mut total_selected = 0u64;
    for output in owned_outputs {
        let amt = output.commitment().amount;
        debug_log!("[fromt]   Output amount: {} piconero", amt);
        selected.push(output);
        total_selected += amt;
        if total_selected >= needed {
            break;
        }
    }
    if total_selected < needed {
        debug_log!("[fromt] Insufficient funds: have {}, need {}", total_selected, needed);
        return Err(lib_error::LIB_UNKNOWN_ERROR);
    }
    debug_log!("[fromt] Selected {} inputs totalling {} piconero", selected.len(), total_selected);
    let selected_offsets: Vec<[u8; 32]> = selected.iter()
        .map(|o| <[u8; 32]>::from(o.key_offset()))
        .collect();
    let owned_outputs = selected;

    let recipient = monero_wallet::address::MoneroAddress::from_str(
        monero_wallet::address::Network::Mainnet,
        recipient_addr,
    )
    .map_err(|e| {
        debug_log!("[fromt] parse recipient address error: {:?}", e);
        lib_error::LIB_UNKNOWN_ERROR
    })?;

    debug_log!("[fromt] Getting fee rate...");
    let fee_rate = rpc
        .fee_rate(FeePriority::Unimportant, u64::MAX)
        .await
        .map_err(|e| {
            debug_log!("[fromt] fee_rate error: {:?}", e);
            lib_error::LIB_UNKNOWN_ERROR
        })?;

    let mut outgoing_view = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(outgoing_view.as_mut());

    let change = Change::new(view_pair, None);

    debug_log!("[fromt] Selecting decoys for {} inputs...", owned_outputs.len());
    let mut inputs_with_decoys = Vec::new();
    for (i, output) in owned_outputs.into_iter().enumerate() {
        debug_log!("[fromt]   Selecting decoys for input {}...", i);
        let owd = OutputWithDecoys::fingerprintable_deterministic_new(
            &mut OsRng,
            rpc,
            RING_LEN,
            chain_height,
            output,
        )
        .await
        .map_err(|e| {
            debug_log!("[fromt] decoy selection error for input {}: {:?}", i, e);
            lib_error::LIB_UNKNOWN_ERROR
        })?;
        inputs_with_decoys.push(owd);
    }

    debug_log!("[fromt] Building signable transaction...");
    let signable = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        outgoing_view,
        inputs_with_decoys,
        vec![(recipient, amount)],
        change,
        vec![],
        fee_rate,
    )
    .map_err(|e| {
        debug_log!("[fromt] SignableTransaction::new error: {:?}", e);
        lib_error::LIB_UNKNOWN_ERROR
    })?;
    Ok((signable, selected_offsets))
}

#[cfg(feature = "rpc")]
pub async fn scan_balance<R: ProvidesBlockchain + ProvidesTransactions + ProvidesOutputs + ExpandToScannableBlock + Sync>(
    rpc: &R,
    daemon_url: &str,
    view_pair: &ViewPair,
    birthday: u64,
    spend_key: Option<&[u8; 32]>,
) -> Result<(u64, u32), lib_error> {
    let mut scanner = Scanner::new(view_pair.clone());

    let chain_height = rpc
        .latest_block_number()
        .await
        .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;

    let start = birthday as usize;
    let end = chain_height;

    let mut owned_outputs: Vec<WalletOutput> = Vec::new();

    debug_log!("[fromt] Scanning {} to {} ({} blocks)", start, end, end - start + 1);

    for height in start..=end {
        if height % 100 == 0 {
            debug_log!("[fromt] Scanning block {} / {}", height, end);
        }

        let block = rpc
            .block_by_number(height)
            .await
            .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;

        let scannable = rpc
            .expand_to_scannable_block(block)
            .await
            .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;

        let scanned = scanner.scan(scannable).map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;
        let unlocked = scanned.not_additionally_locked();
        for output in unlocked {
            let amount = output.commitment().amount;
            debug_log!(
                "[fromt] FOUND output at height {}: {} piconero ({:.12} XMR)",
                height,
                amount,
                amount as f64 / 1e12
            );
            owned_outputs.push(output);
        }
    }

    let total_received = owned_outputs.len() as u32;
    debug_log!("[fromt] Scan complete: {} outputs found", total_received);

    if let Some(sk_bytes) = spend_key {
        let sk = curve25519_dalek::Scalar::from_canonical_bytes(*sk_bytes)
            .expect("invalid spend key scalar");
        let key_images: Vec<[u8; 32]> = owned_outputs.iter()
            .map(|o| compute_key_image(o, &sk))
            .collect();
        debug_log!("[fromt] Checking {} key images against daemon...", key_images.len());
        let spent_flags = check_key_images_spent(daemon_url, &key_images).await?;
        let mut unspent = Vec::new();
        for (output, spent) in owned_outputs.into_iter().zip(spent_flags.iter()) {
            if *spent {
                debug_log!("[fromt] Output is SPENT on-chain (amount={})", output.commitment().amount);
            } else {
                unspent.push(output);
            }
        }
        owned_outputs = unspent;
        debug_log!("[fromt] {} unspent outputs remaining (filtered {} spent)",
            owned_outputs.len(), total_received as usize - owned_outputs.len());
    }

    let mut total_balance = 0u64;
    let num_outputs = owned_outputs.len() as u32;
    for output in &owned_outputs {
        total_balance += output.commitment().amount;
    }

    debug_log!("[fromt] Balance: {} piconero ({:.12} XMR), {} unspent outputs",
        total_balance, total_balance as f64 / 1e12, num_outputs);

    Ok((total_balance, num_outputs))
}

#[cfg(feature = "rpc")]
pub async fn scan_outputs<R: ProvidesBlockchain + ProvidesTransactions + ProvidesOutputs + ExpandToScannableBlock + Sync>(
    rpc: &R,
    view_pair: &ViewPair,
    birthday: u64,
) -> Result<Vec<u8>, lib_error> {
    let mut scanner = Scanner::new(view_pair.clone());

    let chain_height = rpc
        .latest_block_number()
        .await
        .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;

    let start = birthday as usize;
    let end = chain_height;

    let mut owned_outputs: Vec<WalletOutput> = Vec::new();

    for height in start..=end {
        let block = rpc
            .block_by_number(height)
            .await
            .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;

        let scannable = rpc
            .expand_to_scannable_block(block)
            .await
            .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;

        let scanned = scanner.scan(scannable).map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;
        let unlocked = scanned.not_additionally_locked();
        for output in unlocked {
            owned_outputs.push(output);
        }
    }

    let count = owned_outputs.len() as u32;
    let mut buf = Vec::with_capacity(4 + owned_outputs.len() * 72);
    buf.extend_from_slice(&count.to_le_bytes());
    for output in &owned_outputs {
        let output_key = output.key().compress().to_bytes();
        let key_offset: [u8; 32] = <[u8; 32]>::from(output.key_offset());
        let amount = output.commitment().amount;
        buf.extend_from_slice(&output_key);
        buf.extend_from_slice(&key_offset);
        buf.extend_from_slice(&amount.to_le_bytes());
    }

    Ok(buf)
}

pub fn spend_preprocess(
    signable: SignableTransaction,
    keys: ThresholdKeys<dalek_ff_group::Ed25519>,
) -> Result<
    (
        monero_wallet::send::TransactionSignMachine,
        Vec<u8>,
    ),
    lib_error,
> {
    let machine = signable
        .multisig(keys)
        .map_err(|e| {
            debug_log!("[fromt][spend_preprocess] multisig failed: {:?}", e);
            lib_error::LIB_SIGNING_ERROR
        })?;

    let (sign_machine, preprocess) = machine.preprocess(&mut OsRng);

    let mut preprocess_bytes = Vec::new();
    preprocess
        .write(&mut preprocess_bytes)
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

    Ok((sign_machine, preprocess_bytes))
}

pub fn spend_sign(
    sign_machine: monero_wallet::send::TransactionSignMachine,
    preprocesses: HashMap<Participant, Vec<u8>>,
) -> Result<
    (
        monero_wallet::send::TransactionSignatureMachine,
        Vec<u8>,
    ),
    lib_error,
> {
    let mut parsed_preprocesses = HashMap::new();
    for (participant, bytes) in &preprocesses {
        let preprocess = sign_machine
            .read_preprocess(&mut bytes.as_slice())
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        parsed_preprocesses.insert(*participant, preprocess);
    }

    let (sig_machine, share) = sign_machine
        .sign(parsed_preprocesses, &[])
        .map_err(|e| {
            debug_log!(
                "[fromt][spend_sign] sign failed: participants={}, error={:?}",
                preprocesses.len(),
                e
            );
            lib_error::LIB_SIGNING_ERROR
        })?;

    let mut share_bytes = Vec::new();
    share
        .write(&mut share_bytes)
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

    Ok((sig_machine, share_bytes))
}

pub fn spend_complete(
    sig_machine: monero_wallet::send::TransactionSignatureMachine,
    shares: HashMap<Participant, Vec<u8>>,
) -> Result<Vec<u8>, lib_error> {
    let mut parsed_shares = HashMap::new();
    for (participant, bytes) in &shares {
        let share = sig_machine
            .read_share(&mut bytes.as_slice())
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        parsed_shares.insert(*participant, share);
    }

    let tx = sig_machine
        .complete(parsed_shares)
        .map_err(|e| {
            debug_log!(
                "[fromt][spend_complete] complete failed: participants={}, error={:?}",
                shares.len(),
                e
            );
            lib_error::LIB_SIGNING_ERROR
        })?;

    let tx_bytes = tx.serialize();

    let tx2 = monero_wallet::transaction::Transaction::<monero_wallet::transaction::NotPruned>::read(&mut tx_bytes.as_slice())
        .map_err(|e| {
            debug_log!("[fromt] TX round-trip read failed: {:?}", e);
            lib_error::LIB_SERIALIZATION_ERROR
        })?;
    let tx2_bytes = tx2.serialize();

    if tx_bytes.len() != tx2_bytes.len() {
        debug_log!(
            "[fromt] TX round-trip size mismatch: wrote {} bytes, re-serialized {} bytes",
            tx_bytes.len(),
            tx2_bytes.len()
        );
    }
    if tx_bytes != tx2_bytes {
        debug_log!("[fromt] TX round-trip content mismatch!");
        for i in 0..tx_bytes.len().min(tx2_bytes.len()) {
            if tx_bytes[i] != tx2_bytes[i] {
                debug_log!("[fromt]   First diff at byte {}: 0x{:02x} vs 0x{:02x}", i, tx_bytes[i], tx2_bytes[i]);
                break;
            }
        }
    } else {
        debug_log!("[fromt] TX round-trip OK ({} bytes)", tx_bytes.len());
    }

    Ok(tx_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::dkg::tests::run_dkg;

    #[test]
    fn test_keyshare_conversion() {
        let results = run_dkg(3, 2);

        for bundle_bytes in &results {
            let bundle = KeyShareBundle::deserialize(bundle_bytes).unwrap();
            let keys = convert_keyshare(&bundle).unwrap();

            let group_key_bytes = bundle.verifying_key_bytes().unwrap();
            let gk_arr: [u8; 32] = group_key_bytes.as_slice().try_into().unwrap();
            let expected = curve25519_dalek::edwards::CompressedEdwardsY(gk_arr)
                .decompress()
                .unwrap();

            assert_eq!(
                keys.group_key().0,
                expected,
                "group keys must match after conversion"
            );
        }
    }

    #[test]
    fn test_view_pair_from_bundle() {
        let results = run_dkg(3, 2);
        let bundle = KeyShareBundle::deserialize(&results[0]).unwrap();
        let pair = view_pair_from_bundle(&bundle).unwrap();
        let addr = pair.legacy_address(monero_wallet::address::Network::Mainnet);
        let addr_str = addr.to_string();
        assert!(addr_str.starts_with("4"), "mainnet address should start with 4");
        assert_eq!(addr_str.len(), 95, "standard address should be 95 chars");
    }

    #[test]
    fn test_clsag_with_converted_keys() {
        use std::collections::HashMap;
        use rand::rngs::OsRng;
        use rand::RngCore;
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use monero_wallet::ed25519::{Scalar as MScalar, CompressedPoint, Commitment};
        use monero_clsag::{Decoys, ClsagContext, ClsagMultisig};
        use flexible_transcript::{Transcript as _, RecommendedTranscript};
        use modular_frost::sign::{
            PreprocessMachine, SignMachine, SignatureMachine, AlgorithmMachine,
        };

        let results = run_dkg(3, 2);

        let mut all_keys: HashMap<Participant, ThresholdKeys<dalek_ff_group::Ed25519>> =
            HashMap::new();
        for bundle_bytes in &results {
            let bundle = KeyShareBundle::deserialize(bundle_bytes).unwrap();
            let keys = convert_keyshare(&bundle).unwrap();
            let pid = keys.params().i();
            all_keys.insert(pid, keys);
        }

        let group_key = all_keys[&Participant::new(1).unwrap()].group_key().0;

        let amount = 1_000_000_000_000u64;
        let ring_len = 16u8;
        let ring_index = 3u8;
        let commitment_mask: curve25519_dalek::Scalar = MScalar::random(&mut OsRng).into();

        let mut ring = vec![];
        for i in 0..ring_len {
            let (dest, mask, amt) = if i == ring_index {
                (group_key, commitment_mask, amount)
            } else {
                let d = &MScalar::random(&mut OsRng).into() * ED25519_BASEPOINT_TABLE;
                let m: curve25519_dalek::Scalar = MScalar::random(&mut OsRng).into();
                let a = OsRng.next_u64();
                (d, m, a)
            };
            ring.push([
                CompressedPoint::from(dest.compress().to_bytes())
                    .decompress()
                    .unwrap(),
                Commitment::new(MScalar::from(mask), amt).commit(),
            ]);
        }

        let pseudo_mask: curve25519_dalek::Scalar = MScalar::random(&mut OsRng).into();

        let signers: Vec<Participant> = vec![
            Participant::new(1).unwrap(),
            Participant::new(2).unwrap(),
        ];

        let mut machines = HashMap::new();
        for &pid in &signers {
            let keys = all_keys[&pid].clone();
            let (algorithm, mask_send) = ClsagMultisig::new(
                RecommendedTranscript::new(b"fromt CLSAG test"),
                ClsagContext::new(
                    Decoys::new(
                        (1..=u64::from(ring_len)).collect(),
                        ring_index,
                        ring.clone(),
                    )
                    .unwrap(),
                    Commitment::new(MScalar::from(commitment_mask), amount),
                )
                .unwrap(),
            );
            mask_send.send(pseudo_mask);
            machines.insert(pid, AlgorithmMachine::new(algorithm, keys));
        }

        let mut msg = [0u8; 32];
        OsRng.fill_bytes(&mut msg);

        let mut sign_machines = HashMap::new();
        let mut preprocesses = HashMap::new();
        for (pid, machine) in machines {
            let (sm, pp) = machine.preprocess(&mut OsRng);
            let mut pp_bytes = Vec::new();
            pp.write(&mut pp_bytes).unwrap();
            sign_machines.insert(pid, sm);
            preprocesses.insert(pid, pp_bytes);
        }

        let mut sig_machines = HashMap::new();
        let mut shares = HashMap::new();
        for (pid, sm) in sign_machines {
            let mut other_pps = HashMap::new();
            for (&other_pid, pp_bytes) in &preprocesses {
                if other_pid != pid {
                    let pp = sm.read_preprocess(&mut pp_bytes.as_slice()).unwrap();
                    other_pps.insert(other_pid, pp);
                }
            }
            let (sigm, share) = sm.sign(other_pps, &msg).unwrap();
            let mut share_bytes = Vec::new();
            share.write(&mut share_bytes).unwrap();
            sig_machines.insert(pid, sigm);
            shares.insert(pid, share_bytes);
        }

        let first_pid = *sig_machines.keys().next().unwrap();
        let sigm = sig_machines.remove(&first_pid).unwrap();
        let mut other_shares = HashMap::new();
        for (&pid, share_bytes) in &shares {
            if pid != first_pid {
                let share = sigm.read_share(&mut share_bytes.as_slice()).unwrap();
                other_shares.insert(pid, share);
            }
        }
        let result = sigm.complete(other_shares);

        assert!(result.is_ok(), "CLSAG signing with converted keys should succeed: {:?}", result.err());
        debug_log!("CLSAG with converted frost-ed25519 keyshares: PASSED");
    }
}
