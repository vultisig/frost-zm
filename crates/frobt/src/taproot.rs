use std::collections::BTreeMap;

use frost_core::keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare};
use frost_core::VerifyingKey;
use frost_secp256k1::Secp256K1Sha256;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::ops::Reduce;
use k256::ProjectivePoint;
use sha2::{Digest, Sha256};

use frosty::errors::lib_error;

type S = Secp256K1Sha256;

fn tagged_hash(tag: &str) -> Sha256 {
    let mut tag_hasher = Sha256::new();
    tag_hasher.update(tag.as_bytes());
    let tag_hash = tag_hasher.finalize();
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher
}

fn compute_tap_tweak(
    public_key: &ProjectivePoint,
    merkle_root: Option<&[u8]>,
) -> k256::Scalar {
    let mut hasher = tagged_hash("TapTweak");
    hasher.update(public_key.to_affine().x());
    if let Some(root) = merkle_root {
        hasher.update(root);
    }
    let hash = hasher.finalize();
    <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(&hash)
}

fn y_is_odd(point: &ProjectivePoint) -> bool {
    point.to_affine().y_is_odd().into()
}

pub fn tweak_key_package(
    kp: KeyPackage<S>,
    merkle_root: Option<&[u8]>,
) -> Result<KeyPackage<S>, lib_error> {
    let vk_element = kp.verifying_key().to_element();

    let (signing_scalar, vs_element, vk_even) = if y_is_odd(&vk_element) {
        (
            -kp.signing_share().to_scalar(),
            -kp.verifying_share().to_element(),
            -vk_element,
        )
    } else {
        (
            kp.signing_share().to_scalar(),
            kp.verifying_share().to_element(),
            vk_element,
        )
    };

    let t = compute_tap_tweak(&vk_even, merkle_root);
    let tp = ProjectivePoint::GENERATOR * t;

    Ok(KeyPackage::new(
        *kp.identifier(),
        SigningShare::new(signing_scalar + t),
        VerifyingShare::new(vs_element + tp),
        VerifyingKey::new(vk_even + tp),
        *kp.min_signers(),
    ))
}

pub fn tweak_public_key_package(
    pkp: PublicKeyPackage<S>,
    merkle_root: Option<&[u8]>,
) -> Result<PublicKeyPackage<S>, lib_error> {
    let vk_element = pkp.verifying_key().to_element();

    let (shares_map, vk_even) = if y_is_odd(&vk_element) {
        let negated: BTreeMap<_, _> = pkp
            .verifying_shares()
            .iter()
            .map(|(id, vs)| (*id, VerifyingShare::new(-vs.to_element())))
            .collect();
        (negated, -vk_element)
    } else {
        (pkp.verifying_shares().clone(), vk_element)
    };

    let t = compute_tap_tweak(&vk_even, merkle_root);
    let tp = ProjectivePoint::GENERATOR * t;

    let tweaked_shares: BTreeMap<_, _> = shares_map
        .iter()
        .map(|(id, vs)| (*id, VerifyingShare::new(vs.to_element() + tp)))
        .collect();

    Ok(PublicKeyPackage::new(
        tweaked_shares,
        VerifyingKey::new(vk_even + tp),
    ))
}

pub fn compute_taproot_output_key(
    verifying_key_bytes: &[u8],
    merkle_root: Option<&[u8]>,
) -> Result<Vec<u8>, lib_error> {
    use frost_core::{Ciphersuite, Group};

    let element = <<S as Ciphersuite>::Group as Group>::deserialize(
        verifying_key_bytes.try_into().map_err(|_| lib_error::LIB_SIGNING_ERROR)?,
    )
    .map_err(|_| lib_error::LIB_SIGNING_ERROR)?;

    let even_element = if y_is_odd(&element) { -element } else { element };

    let t = compute_tap_tweak(&even_element, merkle_root);
    let output = even_element + ProjectivePoint::GENERATOR * t;

    let serialized = <<S as Ciphersuite>::Group as Group>::serialize(&output)
        .map_err(|_| lib_error::LIB_SIGNING_ERROR)?;
    let sl: &[u8] = serialized.as_ref();
    Ok(sl.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Bundle;
    use crate::tests::run_dkg;

    #[test]
    fn test_tweak_consistency() {
        let bundles = run_dkg(3, 2);
        let b0 = Bundle::deserialize(&bundles[0]).unwrap();
        let b1 = Bundle::deserialize(&bundles[1]).unwrap();

        let tweaked_pkp0 = tweak_public_key_package(b0.pub_key_package.clone(), None).unwrap();
        let tweaked_pkp1 = tweak_public_key_package(b1.pub_key_package.clone(), None).unwrap();

        let vk0 = tweaked_pkp0.verifying_key().serialize().unwrap();
        let vk1 = tweaked_pkp1.verifying_key().serialize().unwrap();
        assert_eq!(vk0, vk1, "tweaked VKs should match across bundles");
    }

    #[test]
    fn test_tweak_changes_key() {
        let bundles = run_dkg(3, 2);
        let b0 = Bundle::deserialize(&bundles[0]).unwrap();

        let original_vk = b0.pub_key_package.verifying_key().serialize().unwrap();
        let tweaked_pkp = tweak_public_key_package(b0.pub_key_package.clone(), None).unwrap();
        let tweaked_vk = tweaked_pkp.verifying_key().serialize().unwrap();

        assert_ne!(original_vk, tweaked_vk, "tweak should change the key");
    }

    #[test]
    fn test_output_key_matches_tweak() {
        let bundles = run_dkg(3, 2);
        let b0 = Bundle::deserialize(&bundles[0]).unwrap();

        let vk_bytes = b0.verifying_key_bytes().unwrap();
        let output_key = compute_taproot_output_key(&vk_bytes, None).unwrap();

        let tweaked_pkp = tweak_public_key_package(b0.pub_key_package.clone(), None).unwrap();
        let tweaked_vk = tweaked_pkp.verifying_key().serialize().unwrap();
        let tweaked_sl: &[u8] = tweaked_vk.as_ref();

        assert_eq!(output_key, tweaked_sl, "output key should match tweaked VK");
    }

    #[test]
    fn test_tweak_matches_audited_frost_secp256k1_tr() {
        use frost_secp256k1_tr::keys::Tweak;

        let mut rng = rand::thread_rng();
        let (_, pkp_tr) = frost_secp256k1_tr::keys::generate_with_dealer(
            3,
            2,
            frost_secp256k1_tr::keys::IdentifierList::Default,
            &mut rng,
        )
        .unwrap();

        let raw_vk_tr = pkp_tr.verifying_key().serialize().unwrap();

        let tweaked_pkp_tr = pkp_tr.clone().tweak::<&[u8]>(None);
        let tweaked_vk_tr = tweaked_pkp_tr.verifying_key().serialize().unwrap();
        let tweaked_vk_tr_sl: &[u8] = tweaked_vk_tr.as_ref();

        let raw_vk_sl: &[u8] = raw_vk_tr.as_ref();
        let our_output = compute_taproot_output_key(raw_vk_sl, None).unwrap();

        assert_eq!(
            our_output.as_slice(),
            tweaked_vk_tr_sl,
            "our tweak must match the audited frost-secp256k1-tr crate's Tweak trait output"
        );
    }
}
