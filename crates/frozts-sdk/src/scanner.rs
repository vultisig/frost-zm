use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use sapling_crypto::zip32::DiversifiableFullViewingKey;
use tonic::transport::Channel;

use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::data_api::{
    AccountBirthday, AccountPurpose, WalletRead, WalletWrite,
};
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service;
use zcash_client_backend::sync::run as sync_run;
use zcash_client_memory::{MemBlockCache, MemoryWalletDb};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::MainNetwork;

use frost_ffi::errors::lib_error;

const BATCH_SIZE: usize = 10000;

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub spendable_balance: u64,
    pub chain_height: u64,
    pub scanned_height: u64,
}

pub fn ufvk_from_dfvk_bytes(dfvk_bytes: &[u8]) -> Result<UnifiedFullViewingKey, lib_error> {
    if dfvk_bytes.len() != 128 {
        return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
    }

    let arr: [u8; 128] = dfvk_bytes.try_into().unwrap();
    let dfvk = DiversifiableFullViewingKey::from_bytes(&arr)
        .ok_or(lib_error::LIB_SAPLING_ERROR)?;

    UnifiedFullViewingKey::new(None, Some(dfvk), None)
        .map_err(|_| lib_error::LIB_SAPLING_ERROR)
}

pub async fn scan_async(dfvk_bytes: &[u8], url: &str, birthday: u32) -> Result<ScanResult, lib_error> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let channel = Channel::from_shared(url.to_string())
        .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?
        .tls_config(tonic::transport::ClientTlsConfig::new().with_webpki_roots())
        .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?
        .connect()
        .await
        .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;

    let mut client = CompactTxStreamerClient::new(channel.clone());

    let network = MainNetwork;
    let mut db: MemoryWalletDb<MainNetwork> = MemoryWalletDb::new(network, BATCH_SIZE);
    let db_cache = MemBlockCache::new();

    let ufvk = ufvk_from_dfvk_bytes(dfvk_bytes)?;

    let treestate = client
        .get_tree_state(service::BlockId {
            height: (birthday - 1).into(),
            ..Default::default()
        })
        .await
        .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?
        .into_inner();

    let account_birthday = AccountBirthday::from_treestate(treestate, None)
        .map_err(|_| lib_error::LIB_SAPLING_ERROR)?;

    db.import_account_ufvk(
        "frost-account",
        &ufvk,
        &account_birthday,
        AccountPurpose::Spending { derivation: None },
        None,
    )
    .map_err(|_| lib_error::LIB_SAPLING_ERROR)?;

    let mut grpc_client = CompactTxStreamerClient::new(channel);
    sync_run(
        &mut grpc_client,
        &network,
        &db_cache,
        &mut db,
        BATCH_SIZE as u32,
    )
    .await
    .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;

    let chain_height = db
        .chain_height()
        .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?
        .map(|h| u64::from(u32::from(h)))
        .unwrap_or(0);

    let confirmations = ConfirmationsPolicy::new(
        NonZeroU32::new(1).unwrap(),
        NonZeroU32::new(1).unwrap(),
        false,
    )
    .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;

    let mut spendable: u64 = 0;
    let summary = db
        .get_wallet_summary(confirmations)
        .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;
    if let Some(summary) = &summary {
        for (_account_id, balance) in summary.account_balances() {
            spendable += balance.sapling_balance().spendable_value().into_u64();
            spendable += balance.orchard_balance().spendable_value().into_u64();
        }
    }

    let scanned_height = summary
        .as_ref()
        .map(|s| u64::from(u32::from(s.fully_scanned_height())))
        .unwrap_or(0);

    Ok(ScanResult {
        spendable_balance: spendable,
        chain_height,
        scanned_height,
    })
}

pub fn scan(dfvk_bytes: &[u8], url: &str, birthday: u32) -> Result<ScanResult, lib_error> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;
    rt.block_on(scan_async(dfvk_bytes, url, birthday))
}
