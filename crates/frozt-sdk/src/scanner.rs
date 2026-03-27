use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use orchard::keys::FullViewingKey as OrchardFvk;
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
const SAPLING_DFVK_LEN: usize = 128;
const ORCHARD_FVK_LEN: usize = 96;

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub spendable_balance: u64,
    pub sapling_balance: u64,
    pub orchard_balance: u64,
    pub chain_height: u64,
    pub scanned_height: u64,
}

pub fn ufvk_from_dfvk_bytes(dfvk_bytes: &[u8]) -> Result<UnifiedFullViewingKey, lib_error> {
    ufvk_from_components(Some(dfvk_bytes), None)
}

pub fn ufvk_from_components(
    sapling_dfvk_bytes: Option<&[u8]>,
    orchard_fvk_bytes: Option<&[u8]>,
) -> Result<UnifiedFullViewingKey, lib_error> {
    let sapling = match sapling_dfvk_bytes {
        Some(bytes) => {
            if bytes.len() != SAPLING_DFVK_LEN {
                return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
            }
            let arr: [u8; SAPLING_DFVK_LEN] = bytes.try_into().unwrap();
            Some(
                DiversifiableFullViewingKey::from_bytes(&arr)
                    .ok_or(lib_error::LIB_SAPLING_ERROR)?
            )
        }
        None => None,
    };

    let orchard = match orchard_fvk_bytes {
        Some(bytes) => {
            if bytes.len() != ORCHARD_FVK_LEN {
                return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
            }
            let arr: [u8; ORCHARD_FVK_LEN] = bytes.try_into().unwrap();
            Some(
                OrchardFvk::from_bytes(&arr)
                    .ok_or(lib_error::LIB_ORCHARD_ERROR)?
            )
        }
        None => None,
    };

    if sapling.is_none() && orchard.is_none() {
        return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
    }

    UnifiedFullViewingKey::new(None, sapling, orchard)
        .map_err(|_| lib_error::LIB_SAPLING_ERROR)
}

pub async fn scan_full_async(
    sapling_dfvk_bytes: Option<&[u8]>,
    orchard_fvk_bytes: Option<&[u8]>,
    url: &str,
    birthday: u32,
) -> Result<ScanResult, lib_error> {
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

    let ufvk = ufvk_from_components(sapling_dfvk_bytes, orchard_fvk_bytes)?;

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

    let mut sapling_total: u64 = 0;
    let mut orchard_total: u64 = 0;
    let summary = db
        .get_wallet_summary(confirmations)
        .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;
    if let Some(summary) = &summary {
        for (_account_id, balance) in summary.account_balances() {
            sapling_total += balance.sapling_balance().spendable_value().into_u64();
            orchard_total += balance.orchard_balance().spendable_value().into_u64();
        }
    }

    let scanned_height = summary
        .as_ref()
        .map(|s| u64::from(u32::from(s.fully_scanned_height())))
        .unwrap_or(0);

    Ok(ScanResult {
        spendable_balance: sapling_total + orchard_total,
        sapling_balance: sapling_total,
        orchard_balance: orchard_total,
        chain_height,
        scanned_height,
    })
}

pub async fn scan_async(dfvk_bytes: &[u8], url: &str, birthday: u32) -> Result<ScanResult, lib_error> {
    scan_full_async(Some(dfvk_bytes), None, url, birthday).await
}

pub fn scan(dfvk_bytes: &[u8], url: &str, birthday: u32) -> Result<ScanResult, lib_error> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;
    rt.block_on(scan_async(dfvk_bytes, url, birthday))
}

pub fn scan_full(
    sapling_dfvk_bytes: Option<&[u8]>,
    orchard_fvk_bytes: Option<&[u8]>,
    url: &str,
    birthday: u32,
) -> Result<ScanResult, lib_error> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;
    rt.block_on(scan_full_async(sapling_dfvk_bytes, orchard_fvk_bytes, url, birthday))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ufvk_from_dfvk_rejects_wrong_size() {
        let too_short = vec![0u8; 64];
        assert!(matches!(ufvk_from_dfvk_bytes(&too_short), Err(lib_error::LIB_INVALID_BUFFER_SIZE)));

        let too_long = vec![0u8; 256];
        assert!(matches!(ufvk_from_dfvk_bytes(&too_long), Err(lib_error::LIB_INVALID_BUFFER_SIZE)));
    }

    #[test]
    fn test_ufvk_from_components_rejects_both_none() {
        assert!(matches!(
            ufvk_from_components(None, None),
            Err(lib_error::LIB_INVALID_BUFFER_SIZE)
        ));
    }

    #[test]
    fn test_ufvk_from_components_rejects_wrong_sapling_size() {
        let bad = vec![0u8; 64];
        assert!(matches!(
            ufvk_from_components(Some(&bad), None),
            Err(lib_error::LIB_INVALID_BUFFER_SIZE)
        ));
    }

    #[test]
    fn test_ufvk_from_components_rejects_wrong_orchard_size() {
        let bad = vec![0u8; 32];
        assert!(matches!(
            ufvk_from_components(None, Some(&bad)),
            Err(lib_error::LIB_INVALID_BUFFER_SIZE)
        ));
    }

    #[test]
    fn test_ufvk_from_components_valid_orchard_fvk() {
        use orchard::keys::{FullViewingKey, SpendingKey};

        let seed = [42u8; 32];
        let sk = SpendingKey::from_zip32_seed(
            &seed, 133, zip32::AccountId::try_from(0u32).unwrap()
        ).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let fvk_bytes = fvk.to_bytes();
        assert_eq!(fvk_bytes.len(), ORCHARD_FVK_LEN);

        let result = ufvk_from_components(None, Some(&fvk_bytes));
        assert!(result.is_ok(), "valid orchard FVK should produce a UFVK");
    }

    #[test]
    fn test_ufvk_from_components_combined() {
        use orchard::keys::{FullViewingKey, SpendingKey};
        use sapling_crypto::zip32::ExtendedSpendingKey;

        let seed = [42u8; 32];

        let sk = SpendingKey::from_zip32_seed(
            &seed, 133, zip32::AccountId::try_from(0u32).unwrap()
        ).unwrap();
        let orchard_fvk = FullViewingKey::from(&sk);

        let sapling_xsk = ExtendedSpendingKey::master(&seed);
        let sapling_dfvk = sapling_xsk.to_diversifiable_full_viewing_key();
        let sapling_bytes = sapling_dfvk.to_bytes();

        let result = ufvk_from_components(Some(&sapling_bytes), Some(&orchard_fvk.to_bytes()));
        assert!(result.is_ok(), "combined sapling+orchard should produce a UFVK");
    }

    #[test]
    fn test_scan_result_serialization() {
        let result = ScanResult {
            spendable_balance: 12345,
            sapling_balance: 5000,
            orchard_balance: 7345,
            chain_height: 100,
            scanned_height: 99,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"sapling_balance\":5000"));
        assert!(json.contains("\"orchard_balance\":7345"));
        assert!(json.contains("\"spendable_balance\":12345"));

        let deserialized: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.sapling_balance, 5000);
        assert_eq!(deserialized.orchard_balance, 7345);
        assert_eq!(deserialized.spendable_balance, 12345);
    }
}
