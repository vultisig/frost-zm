use frost_core::{Ciphersuite, Field, Group};

use crate::bundle::{BundleMetadata, KeyShareBundle};
use crate::ceremony::dkg::{
    decode_r1_map_with_extra, decode_r2_map, ser_err,
    DkgRound1Secret, DkgRound2Secret, EXTRA_LEN,
};
use crate::errors::lib_error;

pub fn reshare_part1<C: Ciphersuite, M: BundleMetadata>(
    id: u16,
    max_signers: u16,
    min_signers: u16,
    old_key_share: Option<&[u8]>,
    old_ids_data: Option<&[u8]>,
) -> Result<(DkgRound1Secret<C>, Vec<u8>), lib_error> {
    if min_signers < 2 || max_signers < min_signers {
        return Err(lib_error::LIB_RESHARE_ERROR);
    }

    type F<C> = <<C as Ciphersuite>::Group as Group>::Field;

    let (additive_share, extra_bytes) = match old_key_share {
        Some(bundle_data) if !bundle_data.is_empty() => {
            let bundle = KeyShareBundle::<C, M>::deserialize(bundle_data)?;
            let old_ids_bytes = old_ids_data.ok_or(lib_error::LIB_NULL_PTR)?;
            let old_ids =
                frost_ceremony::reshare::decode_old_identifiers::<C>(old_ids_bytes)?;
            let additive_share = frost_ceremony::reshare::compute_additive_share::<C>(
                &bundle.key_package,
                &old_ids,
                max_signers,
            )?;
            let extra = *bundle.metadata.extra_bytes();
            (additive_share, extra)
        }
        _ => (F::<C>::one(), [0u8; 32]),
    };

    let (secret, mut pkg_bytes) =
        frost_ceremony::reshare::reshare_part1::<C>(id, max_signers, min_signers, additive_share)?;

    pkg_bytes.extend_from_slice(&extra_bytes);

    let out_secret = DkgRound1Secret {
        frost_secret: secret,
        extra_share: extra_bytes,
    };

    Ok((out_secret, pkg_bytes))
}

pub fn reshare_part3<C: Ciphersuite, M: BundleMetadata>(
    secret: DkgRound2Secret<C>,
    r1_data: &[u8],
    r2_data: &[u8],
    expected_vk: &[u8],
    build_meta: impl FnOnce([u8; EXTRA_LEN]) -> M,
) -> Result<(Vec<u8>, Vec<u8>), lib_error> {
    let (r1_pkgs, extra_shares) = decode_r1_map_with_extra::<C>(r1_data)?;
    let r2_pkgs = decode_r2_map::<C>(r2_data)?;

    let (key_package, pub_key_package) =
        frost_core::keys::dkg::part3(&secret.frost_secret, &r1_pkgs, &r2_pkgs)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    let vk_bytes = pub_key_package.verifying_key().serialize().map_err(ser_err)?;
    if <[u8]>::ne(vk_bytes.as_ref(), expected_vk) {
        return Err(lib_error::LIB_RESHARE_ERROR);
    }

    let extra = aggregate_reshare_extra(&secret.extra_share, &extra_shares)?;
    let metadata = build_meta(extra);

    let bundle = KeyShareBundle::new(key_package, pub_key_package, metadata);
    let bundle_bytes = bundle.serialize()?;

    Ok((bundle_bytes, vk_bytes))
}

fn aggregate_reshare_extra<C: Ciphersuite>(
    own_share: &[u8; EXTRA_LEN],
    other_shares: &std::collections::BTreeMap<frost_core::Identifier<C>, [u8; EXTRA_LEN]>,
) -> Result<[u8; EXTRA_LEN], lib_error> {
    let zero = [0u8; EXTRA_LEN];
    for share in other_shares.values() {
        if *share != zero {
            return Ok(*share);
        }
    }
    if *own_share != zero {
        return Ok(*own_share);
    }
    Err(lib_error::LIB_RESHARE_ERROR)
}
