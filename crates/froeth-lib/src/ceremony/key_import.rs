use frost_core::{Ciphersuite, Field, Group};
use frost_secp256k1::Secp256K1Sha256;

use std::collections::BTreeMap;

use crate::{
    ceremony::dkg::{
        decode_r1_map_with_cc, decode_r2_map, ser_err,
        DkgRound1Secret, DkgRound2Secret, CC_LEN,
    },
    errors::lib_error,
};

type S = Secp256K1Sha256;
type Identifier = frost_core::Identifier<S>;
type Scalar = frost_core::Scalar<S>;
type F = <<S as Ciphersuite>::Group as Group>::Field;
type G = <S as Ciphersuite>::Group;

#[cfg(feature = "native")]
pub fn derive_from_seed(
    seed: &[u8],
    account_index: u32,
) -> Result<([u8; 32], [u8; 32], Vec<u8>), lib_error> {
    if seed.len() != 64 {
        return Err(lib_error::LIB_KEY_IMPORT_ERROR);
    }
    if account_index >= (1 << 31) {
        return Err(lib_error::LIB_KEY_IMPORT_ERROR);
    }

    use bitcoin::bip32::{ChildNumber, Xpriv};
    use bitcoin::Network;

    let master = Xpriv::new_master(Network::Bitcoin, seed)
        .map_err(|_| lib_error::LIB_KEY_IMPORT_ERROR)?;

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let path = [
        ChildNumber::from_hardened_idx(44).map_err(|_| lib_error::LIB_KEY_IMPORT_ERROR)?,
        ChildNumber::from_hardened_idx(60).map_err(|_| lib_error::LIB_KEY_IMPORT_ERROR)?,
        ChildNumber::from_hardened_idx(account_index).map_err(|_| lib_error::LIB_KEY_IMPORT_ERROR)?,
    ];

    let derived = master
        .derive_priv(&secp, &path)
        .map_err(|_| lib_error::LIB_KEY_IMPORT_ERROR)?;

    let private_key: [u8; 32] = derived.private_key.secret_bytes();
    let chain_code: [u8; 32] = derived.chain_code.to_bytes();

    let scalar: Scalar = F::deserialize(&private_key).map_err(ser_err)?;
    let point = <G as Group>::generator() * scalar;
    let vk = frost_core::VerifyingKey::<S>::new(point);
    let vk_ser = vk.serialize().map_err(ser_err)?;
    let sl: &[u8] = vk_ser.as_ref();
    let pub_key: Vec<u8> = sl.to_vec();

    Ok((private_key, chain_code, pub_key))
}

#[cfg(not(feature = "native"))]
pub fn derive_from_seed(
    seed: &[u8],
    account_index: u32,
) -> Result<([u8; 32], [u8; 32], Vec<u8>), lib_error> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    use k256::elliptic_curve::PrimeField;

    if seed.len() != 64 {
        return Err(lib_error::LIB_KEY_IMPORT_ERROR);
    }
    if account_index >= (1 << 31) {
        return Err(lib_error::LIB_KEY_IMPORT_ERROR);
    }

    type HmacSha512 = Hmac<Sha512>;

    fn derive_master(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), lib_error> {
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
            .map_err(|_| lib_error::LIB_KEY_IMPORT_ERROR)?;
        mac.update(seed);
        let result = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        cc.copy_from_slice(&result[32..]);
        Ok((key, cc))
    }

    fn derive_hardened_child(
        parent_key: &[u8; 32],
        parent_cc: &[u8; 32],
        index: u32,
    ) -> Result<([u8; 32], [u8; 32]), lib_error> {
        let mut mac = HmacSha512::new_from_slice(parent_cc)
            .map_err(|_| lib_error::LIB_KEY_IMPORT_ERROR)?;
        mac.update(&[0x00]);
        mac.update(parent_key);
        mac.update(&(0x80000000 | index).to_be_bytes());
        let result = mac.finalize().into_bytes();

        let mut child_key_il = [0u8; 32];
        child_key_il.copy_from_slice(&result[..32]);
        let mut child_cc = [0u8; 32];
        child_cc.copy_from_slice(&result[32..]);

        let il_scalar = k256::Scalar::from_repr(child_key_il.into())
            .into_option()
            .ok_or(lib_error::LIB_KEY_IMPORT_ERROR)?;
        let parent_scalar = k256::Scalar::from_repr((*parent_key).into())
            .into_option()
            .ok_or(lib_error::LIB_KEY_IMPORT_ERROR)?;
        let child_scalar = il_scalar + parent_scalar;
        let child_bytes: [u8; 32] = child_scalar.to_bytes().into();

        Ok((child_bytes, child_cc))
    }

    let (master_key, master_cc) = derive_master(seed)?;

    let (k1, cc1) = derive_hardened_child(&master_key, &master_cc, 44)?;
    let (k2, cc2) = derive_hardened_child(&k1, &cc1, 60)?;
    let (private_key, chain_code) = derive_hardened_child(&k2, &cc2, account_index)?;

    let scalar: Scalar = F::deserialize(&private_key).map_err(ser_err)?;
    let point = <G as Group>::generator() * scalar;
    let vk = frost_core::VerifyingKey::<S>::new(point);
    let vk_ser = vk.serialize().map_err(ser_err)?;
    let sl: &[u8] = vk_ser.as_ref();
    let pub_key: Vec<u8> = sl.to_vec();

    Ok((private_key, chain_code, pub_key))
}

pub fn private_key_to_public(private_key: &[u8; 32]) -> Result<Vec<u8>, lib_error> {
    let scalar: Scalar = F::deserialize(private_key).map_err(ser_err)?;
    let point = <G as Group>::generator() * scalar;
    let vk = frost_core::VerifyingKey::<S>::new(point);
    let vk_ser = vk.serialize().map_err(ser_err)?;
    let sl: &[u8] = vk_ser.as_ref();
    Ok(sl.to_vec())
}

pub fn key_import_part1(
    id: u16,
    max_signers: u16,
    min_signers: u16,
    private_key: Option<&[u8; 32]>,
    chain_code: Option<&[u8; 32]>,
) -> Result<(DkgRound1Secret, Vec<u8>), lib_error> {
    if min_signers < 2 || max_signers < min_signers {
        return Err(lib_error::LIB_KEY_IMPORT_ERROR);
    }

    let (constant_term, cc_bytes) = match private_key {
        Some(sk_bytes) => {
            let sk_scalar: Scalar = F::deserialize(sk_bytes).map_err(ser_err)?;
            let ct = frost_ceremony::key_import::derive_constant_term::<S>(sk_scalar, max_signers);
            let cc = chain_code
                .copied()
                .unwrap_or([0u8; 32]);
            (ct, cc)
        }
        None => (F::one(), [0u8; 32]),
    };

    let (secret, mut pkg_bytes) =
        frost_ceremony::key_import::key_import_part1::<S>(id, max_signers, min_signers, constant_term)?;

    pkg_bytes.extend_from_slice(&cc_bytes);

    let out_secret = DkgRound1Secret {
        frost_secret: secret,
        chain_code_share: cc_bytes,
    };

    Ok((out_secret, pkg_bytes))
}

pub fn key_import_part3(
    secret: DkgRound2Secret,
    r1_data: &[u8],
    r2_data: &[u8],
    expected_vk: &[u8],
    network: u8,
    birthday: u64,
) -> Result<(Vec<u8>, Vec<u8>), lib_error> {
    let (r1_pkgs, cc_shares) = decode_r1_map_with_cc(r1_data)?;
    let r2_pkgs = decode_r2_map(r2_data)?;

    let (key_package, pub_key_package) =
        frost_core::keys::dkg::part3(&secret.frost_secret, &r1_pkgs, &r2_pkgs)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    let vk_bytes = pub_key_package.verifying_key().serialize().map_err(ser_err)?;
    if <[u8]>::ne(vk_bytes.as_ref(), expected_vk) {
        return Err(lib_error::LIB_KEY_IMPORT_ERROR);
    }

    let chain_code = aggregate_import_chain_code(&secret.chain_code_share, &cc_shares)?;

    let bundle = crate::keyshare::bundle::KeyShareBundle::new(
        key_package,
        pub_key_package,
        chain_code,
        network,
        birthday,
    );

    let bundle_bytes = bundle.serialize()?;

    Ok((bundle_bytes, vk_bytes))
}

fn aggregate_import_chain_code(
    own_share: &[u8; CC_LEN],
    other_shares: &BTreeMap<Identifier, [u8; CC_LEN]>,
) -> Result<[u8; CC_LEN], lib_error> {
    let zero = [0u8; CC_LEN];
    if *own_share != zero {
        return Ok(*own_share);
    }
    for share in other_shares.values() {
        if *share != zero {
            return Ok(*share);
        }
    }
    Err(lib_error::LIB_KEY_IMPORT_ERROR)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ceremony::dkg;
    use crate::ceremony::dkg::tests::{decode_test_map, encode_test_map};
    use crate::keyshare::bundle::KeyShareBundle;

    fn derive_test_key() -> ([u8; 32], [u8; 32], Vec<u8>) {
        let seed = [0u8; 64];
        let (sk, cc, pub_key) = derive_from_seed(&seed, 0).unwrap();
        (sk, cc, pub_key)
    }

    pub fn run_key_import(
        n: u16,
        t: u16,
        private_key: &[u8; 32],
        chain_code: &[u8; 32],
        expected_pub: &[u8],
    ) -> Vec<Vec<u8>> {
        let mut secrets = Vec::new();
        let mut packages = Vec::new();

        for i in 1..=n {
            let (sk_opt, cc_opt) = if i == 1 {
                (Some(private_key), Some(chain_code))
            } else {
                (None, None)
            };
            let (secret, pkg) = key_import_part1(i, n, t, sk_opt, cc_opt).unwrap();
            secrets.push(secret);
            packages.push((i, pkg));
        }

        let mut secrets2 = Vec::new();
        let mut all_r2_packages: Vec<Vec<(u16, Vec<u8>)>> = Vec::new();

        for i in 0..n as usize {
            let others: Vec<_> = packages
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, (id, pkg))| (*id, pkg.clone()))
                .collect();

            let r1_map = encode_test_map(&others);
            let (secret2, r2_bytes) =
                dkg::dkg_part2(secrets.remove(0), &r1_map).unwrap();
            secrets2.push(secret2);
            all_r2_packages.push(decode_test_map(&r2_bytes));
        }

        let mut results = Vec::new();

        for i in 0..n as usize {
            let r1_others: Vec<_> = packages
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, (id, pkg))| (*id, pkg.clone()))
                .collect();

            let my_id = (i + 1) as u16;
            let mut r2_for_me = Vec::new();
            for (sender_idx, r2_pkgs) in all_r2_packages.iter().enumerate() {
                if sender_idx == i {
                    continue;
                }
                let sender_id = (sender_idx + 1) as u16;
                for (recipient_id, pkg_bytes) in r2_pkgs {
                    if *recipient_id == my_id {
                        r2_for_me.push((sender_id, pkg_bytes.clone()));
                    }
                }
            }

            let r1_map = encode_test_map(&r1_others);
            let r2_map = encode_test_map(&r2_for_me);

            let (bundle_bytes, _) = key_import_part3(
                secrets2.remove(0),
                &r1_map,
                &r2_map,
                expected_pub,
                0,
                0,
            )
            .unwrap();

            results.push(bundle_bytes);
        }

        results
    }

    #[test]
    fn test_key_import_2of3() {
        let (sk, cc, pub_key) = derive_test_key();
        let results = run_key_import(3, 2, &sk, &cc, &pub_key);
        assert_eq!(results.len(), 3);

        let b0 = KeyShareBundle::deserialize(&results[0]).unwrap();
        let b1 = KeyShareBundle::deserialize(&results[1]).unwrap();
        let b2 = KeyShareBundle::deserialize(&results[2]).unwrap();

        assert_eq!(b0.chain_code, b1.chain_code);
        assert_eq!(b1.chain_code, b2.chain_code);
        assert_eq!(b0.chain_code, cc);

        let vk0 = b0.pub_key_package.verifying_key().serialize().unwrap();
        assert_eq!(vk0, pub_key);
    }

    #[test]
    fn test_derive_from_seed() {
        let seed = [0xABu8; 64];
        let (sk1, cc1, pk1) = derive_from_seed(&seed, 0).unwrap();
        let (sk2, cc2, pk2) = derive_from_seed(&seed, 0).unwrap();
        assert_eq!(sk1, sk2);
        assert_eq!(cc1, cc2);
        assert_eq!(pk1, pk2);

        let seed2 = [0xCDu8; 64];
        let (sk3, _, _) = derive_from_seed(&seed2, 0).unwrap();
        assert_ne!(sk1, sk3);
    }

    #[test]
    fn test_derive_from_seed_eth_path() {
        let seed = [0x42u8; 64];
        let (sk_eth, _, _) = derive_from_seed(&seed, 0).unwrap();

        use bitcoin::bip32::{ChildNumber, Xpriv};
        use bitcoin::Network;

        let master = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let path = [
            ChildNumber::from_hardened_idx(44).unwrap(),
            ChildNumber::from_hardened_idx(60).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ];
        let derived = master.derive_priv(&secp, &path).unwrap();
        assert_eq!(sk_eth, derived.private_key.secret_bytes());
    }

    #[test]
    fn test_key_import_and_sign() {
        let (sk, cc, pub_key) = derive_test_key();
        let bundles = run_key_import(3, 2, &sk, &cc, &pub_key);

        use crate::ceremony::sign::tests::run_sign;
        let message = b"test message for froeth signing";

        let sig = run_sign(&bundles, &[0, 1]);
        crate::ceremony::sign::verify_signature(message.as_ref(), &sig, &bundles[0]).unwrap();
    }
}
