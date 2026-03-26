pub mod key_import;
pub mod ckd;
pub mod key_image;

pub mod dkg {
    pub use frosty::ceremony::dkg::{ser_err, EXTRA_LEN};
    pub type DkgRound1Secret = frosty::ceremony::dkg::DkgRound1Secret<crate::E>;
    pub type DkgRound2Secret = frosty::ceremony::dkg::DkgRound2Secret<crate::E>;
    pub const VK_SHARE_LEN: usize = frosty::ceremony::dkg::EXTRA_LEN;

    pub fn dkg_part1(id: u16, max: u16, min: u16) -> Result<(DkgRound1Secret, Vec<u8>), frosty::lib_error> {
        frosty::ceremony::dkg::dkg_part1::<crate::E>(id, max, min)
    }

    pub fn dkg_part2(secret: DkgRound1Secret, r1_data: &[u8]) -> Result<(DkgRound2Secret, Vec<u8>), frosty::lib_error> {
        frosty::ceremony::dkg::dkg_part2::<crate::E>(secret, r1_data)
    }

    pub fn dkg_part3(
        secret: DkgRound2Secret, r1: &[u8], r2: &[u8], network: u8, birthday: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), frosty::lib_error> {
        frosty::ceremony::dkg::dkg_part3::<crate::E, crate::keyshare::bundle::ViewKeyMeta>(
            secret, r1, r2, |extra| crate::keyshare::bundle::ViewKeyMeta::from_dkg(extra, network, birthday),
        )
    }

    pub fn decode_r1_map_with_vk(data: &[u8]) -> Result<(
        std::collections::BTreeMap<frost_core::Identifier<crate::E>, frost_core::keys::dkg::round1::Package<crate::E>>,
        std::collections::BTreeMap<frost_core::Identifier<crate::E>, [u8; 32]>,
    ), frosty::lib_error> {
        frosty::ceremony::dkg::decode_r1_map_with_extra::<crate::E>(data)
    }

    pub fn decode_r2_map(data: &[u8]) -> Result<
        std::collections::BTreeMap<frost_core::Identifier<crate::E>, frost_core::keys::dkg::round2::Package<crate::E>>,
        frosty::lib_error,
    > {
        frosty::ceremony::dkg::decode_r2_map::<crate::E>(data)
    }

    pub fn aggregate_view_key_shares(
        own_share: &[u8; 32],
        other_shares: &std::collections::BTreeMap<frost_core::Identifier<crate::E>, [u8; 32]>,
    ) -> Result<[u8; 32], frosty::errors::lib_error> {
        frosty::ceremony::dkg::aggregate_extra_shares::<crate::E>(own_share, other_shares)
    }
}

pub mod sign {
    pub type SignNonces = frosty::ceremony::sign::SignNonces<crate::E>;

    pub fn sign_commit(key_share_data: &[u8]) -> Result<(SignNonces, Vec<u8>), frosty::lib_error> {
        frosty::ceremony::sign::sign_commit::<crate::E, crate::keyshare::bundle::ViewKeyMeta>(key_share_data)
    }

    pub fn sign_create_package(message: &[u8], commitments_data: &[u8]) -> Result<Vec<u8>, frosty::lib_error> {
        frosty::ceremony::sign::sign_create_package::<crate::E>(message, commitments_data)
    }

    pub fn sign(signing_package_data: &[u8], nonces: SignNonces, key_share_data: &[u8]) -> Result<Vec<u8>, frosty::lib_error> {
        frosty::ceremony::sign::sign::<crate::E, crate::keyshare::bundle::ViewKeyMeta>(signing_package_data, nonces, key_share_data)
    }

    pub fn sign_aggregate(signing_package_data: &[u8], shares_data: &[u8], key_share_data: &[u8]) -> Result<Vec<u8>, frosty::lib_error> {
        frosty::ceremony::sign::sign_aggregate::<crate::E, crate::keyshare::bundle::ViewKeyMeta>(signing_package_data, shares_data, key_share_data)
    }

    pub fn verify_signature(message: &[u8], signature_data: &[u8], key_share_data: &[u8]) -> Result<(), frosty::lib_error> {
        frosty::ceremony::sign::verify_signature::<crate::E, crate::keyshare::bundle::ViewKeyMeta>(message, signature_data, key_share_data)
    }
}

pub mod reshare {
    pub fn reshare_part1(id: u16, max: u16, min: u16, old_ks: Option<&[u8]>, old_ids: Option<&[u8]>) -> Result<(dkg::DkgRound1Secret, Vec<u8>), frosty::lib_error> {
        frosty::ceremony::reshare::reshare_part1::<crate::E, crate::keyshare::bundle::ViewKeyMeta>(id, max, min, old_ks, old_ids)
    }

    pub fn reshare_part3(
        secret: dkg::DkgRound2Secret, r1: &[u8], r2: &[u8], expected_vk: &[u8], network: u8, birthday: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), frosty::lib_error> {
        frosty::ceremony::reshare::reshare_part3::<crate::E, crate::keyshare::bundle::ViewKeyMeta>(
            secret, r1, r2, expected_vk, |extra| crate::keyshare::bundle::ViewKeyMeta::from_dkg(extra, network, birthday),
        )
    }

    use super::dkg;
}
