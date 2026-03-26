pub mod dkg {
    pub use frosty::ceremony::dkg::*;
    pub type DkgRound1Secret = frosty::ceremony::dkg::DkgRound1Secret<crate::S>;
    pub type DkgRound2Secret = frosty::ceremony::dkg::DkgRound2Secret<crate::S>;
    pub const CC_LEN: usize = frosty::ceremony::dkg::EXTRA_LEN;

    pub fn dkg_part1(id: u16, max: u16, min: u16) -> Result<(DkgRound1Secret, Vec<u8>), frosty::lib_error> {
        frosty::ceremony::dkg::dkg_part1::<crate::S>(id, max, min)
    }

    pub fn dkg_part2(secret: DkgRound1Secret, r1_data: &[u8]) -> Result<(DkgRound2Secret, Vec<u8>), frosty::lib_error> {
        frosty::ceremony::dkg::dkg_part2::<crate::S>(secret, r1_data)
    }

    pub fn dkg_part3(
        secret: DkgRound2Secret, r1: &[u8], r2: &[u8], network: u8, birthday: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), frosty::lib_error> {
        frosty::ceremony::dkg::dkg_part3::<crate::S, frosty::bundle::ChainCodeMeta>(
            secret, r1, r2, |extra| frosty::bundle::ChainCodeMeta::from_dkg(extra, network, birthday),
        )
    }
}

pub mod sign {
    pub type SignNonces = frosty::ceremony::sign::SignNonces<crate::S>;

    pub fn sign_commit(key_share_data: &[u8]) -> Result<(SignNonces, Vec<u8>), frosty::lib_error> {
        frosty::ceremony::sign::sign_commit::<crate::S, frosty::bundle::ChainCodeMeta>(key_share_data)
    }

    pub fn sign_create_package(message: &[u8], commitments_data: &[u8]) -> Result<Vec<u8>, frosty::lib_error> {
        frosty::ceremony::sign::sign_create_package::<crate::S>(message, commitments_data)
    }

    pub fn sign(signing_package_data: &[u8], nonces: SignNonces, key_share_data: &[u8]) -> Result<Vec<u8>, frosty::lib_error> {
        frosty::ceremony::sign::sign::<crate::S, frosty::bundle::ChainCodeMeta>(signing_package_data, nonces, key_share_data)
    }

    pub fn sign_aggregate(signing_package_data: &[u8], shares_data: &[u8], key_share_data: &[u8]) -> Result<Vec<u8>, frosty::lib_error> {
        frosty::ceremony::sign::sign_aggregate::<crate::S, frosty::bundle::ChainCodeMeta>(signing_package_data, shares_data, key_share_data)
    }

    pub fn verify_signature(message: &[u8], signature_data: &[u8], key_share_data: &[u8]) -> Result<(), frosty::lib_error> {
        frosty::ceremony::sign::verify_signature::<crate::S, frosty::bundle::ChainCodeMeta>(message, signature_data, key_share_data)
    }
}

pub mod reshare {
    pub fn reshare_part1(id: u16, max: u16, min: u16, old_ks: Option<&[u8]>, old_ids: Option<&[u8]>) -> Result<(dkg::DkgRound1Secret, Vec<u8>), frosty::lib_error> {
        frosty::ceremony::reshare::reshare_part1::<crate::S, frosty::bundle::ChainCodeMeta>(id, max, min, old_ks, old_ids)
    }

    pub fn reshare_part3(
        secret: dkg::DkgRound2Secret, r1: &[u8], r2: &[u8], expected_vk: &[u8], network: u8, birthday: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), frosty::lib_error> {
        frosty::ceremony::reshare::reshare_part3::<crate::S, frosty::bundle::ChainCodeMeta>(
            secret, r1, r2, expected_vk, |extra| frosty::bundle::ChainCodeMeta::from_dkg(extra, network, birthday),
        )
    }

    use super::dkg;
}

pub mod key_import {
    pub fn derive_from_seed(seed: &[u8], account_index: u32) -> Result<([u8; 32], [u8; 32], Vec<u8>), frosty::lib_error> {
        frosty::ceremony::key_import::derive_from_seed::<crate::S>(seed, account_index, 44, 60)
    }

    pub fn key_import_part1(id: u16, max: u16, min: u16, sk: Option<&[u8; 32]>, cc: Option<&[u8; 32]>) -> Result<(dkg::DkgRound1Secret, Vec<u8>), frosty::lib_error> {
        frosty::ceremony::key_import::key_import_part1::<crate::S>(id, max, min, sk, cc)
    }

    pub fn key_import_part3(
        secret: dkg::DkgRound2Secret, r1: &[u8], r2: &[u8], expected_vk: &[u8], network: u8, birthday: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), frosty::lib_error> {
        frosty::ceremony::key_import::key_import_part3::<crate::S, frosty::bundle::ChainCodeMeta>(
            secret, r1, r2, expected_vk, |extra| frosty::bundle::ChainCodeMeta::from_dkg(extra, network, birthday),
        )
    }

    use super::dkg;
}

pub mod ckd {
    pub fn ckd_derive(key_share_data: &[u8], change: u32, index: u32) -> Result<Vec<u8>, frosty::lib_error> {
        frosty::ceremony::ckd::ckd_derive::<crate::S, frosty::bundle::ChainCodeMeta>(key_share_data, change, index)
    }

    pub fn derive_child_pubkey(key_share_data: &[u8], change: u32, index: u32) -> Result<Vec<u8>, frosty::lib_error> {
        frosty::ceremony::ckd::derive_child_pubkey::<crate::S, frosty::bundle::ChainCodeMeta>(key_share_data, change, index)
    }
}
