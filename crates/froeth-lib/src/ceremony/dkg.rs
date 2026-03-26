use std::collections::BTreeMap;

use frost_core::keys::dkg;
use frost_core::{Ciphersuite, Field, Group};
use frost_secp256k1::Secp256K1Sha256;

use crate::{codec, errors::lib_error};

type S = Secp256K1Sha256;
type Identifier = frost_core::Identifier<S>;
type Scalar = frost_core::Scalar<S>;
type F = <<S as Ciphersuite>::Group as Group>::Field;

pub(crate) const CC_LEN: usize = 32;

pub struct DkgRound1Secret {
    pub frost_secret: dkg::round1::SecretPackage<S>,
    pub chain_code_share: [u8; CC_LEN],
}

pub struct DkgRound2Secret {
    pub frost_secret: dkg::round2::SecretPackage<S>,
    pub chain_code_share: [u8; CC_LEN],
}

pub(crate) fn ser_err<Err: std::fmt::Debug>(e: Err) -> lib_error {
    #[cfg(debug_assertions)]
    eprintln!("froeth serialization error: {:?}", e);
    let _ = e;
    lib_error::LIB_SERIALIZATION_ERROR
}

fn split_froeth_package(data: &[u8]) -> Result<(&[u8], [u8; CC_LEN]), lib_error> {
    if data.len() < CC_LEN {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let frost_len = data.len() - CC_LEN;
    let frost_data = &data[..frost_len];
    let cc_data: [u8; CC_LEN] = data[frost_len..]
        .try_into()
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
    Ok((frost_data, cc_data))
}

pub fn decode_r1_map_with_cc(
    data: &[u8],
) -> Result<
    (
        BTreeMap<Identifier, dkg::round1::Package<S>>,
        BTreeMap<Identifier, [u8; CC_LEN]>,
    ),
    lib_error,
> {
    let raw_map: BTreeMap<Identifier, Vec<u8>> = codec::decode_map(
        data,
        |b| Identifier::deserialize(b).map_err(ser_err),
        |b| Ok(b.to_vec()),
    )?;

    let mut frost_map = BTreeMap::new();
    let mut cc_map = BTreeMap::new();

    for (id, bytes) in raw_map {
        let (frost_data, cc_bytes) = split_froeth_package(&bytes)?;
        let frost_pkg =
            dkg::round1::Package::<S>::deserialize(frost_data).map_err(ser_err)?;
        frost_map.insert(id, frost_pkg);
        cc_map.insert(id, cc_bytes);
    }

    Ok((frost_map, cc_map))
}

pub fn decode_r1_map(
    data: &[u8],
) -> Result<BTreeMap<Identifier, dkg::round1::Package<S>>, lib_error> {
    let (frost_map, _) = decode_r1_map_with_cc(data)?;
    Ok(frost_map)
}

pub fn encode_r2_map(
    map: &BTreeMap<Identifier, dkg::round2::Package<S>>,
) -> Result<Vec<u8>, lib_error> {
    frost_ceremony::dkg::encode_r2_map::<S>(map)
}

pub fn decode_r2_map(
    data: &[u8],
) -> Result<BTreeMap<Identifier, dkg::round2::Package<S>>, lib_error> {
    frost_ceremony::dkg::decode_r2_map::<S>(data)
}

pub fn dkg_part1(
    id: u16,
    max_signers: u16,
    min_signers: u16,
) -> Result<(DkgRound1Secret, Vec<u8>), lib_error> {
    if min_signers < 2 || max_signers < min_signers {
        return Err(lib_error::LIB_DKG_ERROR);
    }

    let mut rng = rand::thread_rng();

    let (secret, pkg_bytes) =
        frost_ceremony::dkg::dkg_part1::<S>(id, max_signers, min_signers)?;

    let cc_share: Scalar = F::random(&mut rng);
    let cc_share_bytes: [u8; 32] = {
            let s = F::serialize(&cc_share);
            let sl: &[u8] = s.as_ref();
            sl.try_into()
        }
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

    let mut out_bytes = pkg_bytes;
    out_bytes.extend_from_slice(&cc_share_bytes);

    let out_secret = DkgRound1Secret {
        frost_secret: secret,
        chain_code_share: cc_share_bytes,
    };

    Ok((out_secret, out_bytes))
}

pub fn dkg_part2(
    secret: DkgRound1Secret,
    r1_data: &[u8],
) -> Result<(DkgRound2Secret, Vec<u8>), lib_error> {
    let r1_pkgs = decode_r1_map(r1_data)?;

    let (secret2, r2_pkgs) =
        dkg::part2(secret.frost_secret, &r1_pkgs)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    let r2_bytes = encode_r2_map(&r2_pkgs)?;

    let out_secret = DkgRound2Secret {
        frost_secret: secret2,
        chain_code_share: secret.chain_code_share,
    };

    Ok((out_secret, r2_bytes))
}

pub fn dkg_part3(
    secret: DkgRound2Secret,
    r1_data: &[u8],
    r2_data: &[u8],
    network: u8,
    birthday: u64,
) -> Result<(Vec<u8>, Vec<u8>), lib_error> {
    let (r1_pkgs, cc_shares) = decode_r1_map_with_cc(r1_data)?;
    let r2_pkgs = decode_r2_map(r2_data)?;

    let (key_package, pub_key_package) =
        dkg::part3(&secret.frost_secret, &r1_pkgs, &r2_pkgs)
            .map_err(|_| lib_error::LIB_DKG_ERROR)?;

    let chain_code = aggregate_chain_code_shares(&secret.chain_code_share, &cc_shares)?;

    let bundle = crate::keyshare::bundle::KeyShareBundle::new(
        key_package,
        pub_key_package.clone(),
        chain_code,
        network,
        birthday,
    );

    let bundle_bytes = bundle.serialize()?;
    let vk_bytes = pub_key_package.verifying_key().serialize().map_err(ser_err)?;

    Ok((bundle_bytes, vk_bytes))
}

fn aggregate_chain_code_shares(
    own_share: &[u8; CC_LEN],
    other_shares: &BTreeMap<Identifier, [u8; CC_LEN]>,
) -> Result<[u8; CC_LEN], lib_error> {
    let own_arr: &[u8; 32] = own_share;
    let mut sum: Scalar = F::deserialize(own_arr).map_err(ser_err)?;

    for (_, share_bytes) in other_shares {
        let s: Scalar = F::deserialize(share_bytes).map_err(ser_err)?;
        sum = sum + s;
    }

    let result_serialized = F::serialize(&sum);
    let sl: &[u8] = result_serialized.as_ref();
    let result: [u8; 32] = sl
        .try_into()
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
    Ok(result)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keyshare::identifier::identifier_to_u16;

    pub fn run_dkg(n: u16, t: u16) -> Vec<Vec<u8>> {
        let mut secrets = Vec::new();
        let mut packages = Vec::new();

        for i in 1..=n {
            let (secret, pkg) = dkg_part1(i, n, t).unwrap();
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
                dkg_part2(secrets.remove(0), &r1_map).unwrap();

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

            let (bundle_bytes, _pub_key) =
                dkg_part3(secrets2.remove(0), &r1_map, &r2_map, 0, 0).unwrap();

            results.push(bundle_bytes);
        }

        results
    }

    pub(crate) fn encode_test_map(entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (id, v) in entries {
            let id_ident = Identifier::try_from(*id).unwrap();
            let id_bytes = id_ident.serialize();
            let id_slice: &[u8] = id_bytes.as_ref();
            buf.extend_from_slice(&(id_slice.len() as u32).to_le_bytes());
            buf.extend_from_slice(id_slice);
            buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
            buf.extend_from_slice(v);
        }
        buf
    }

    pub(crate) fn decode_test_map(data: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut pos = 0;
        let count =
            u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let mut entries = Vec::new();
        for _ in 0..count {
            let klen =
                u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let id = Identifier::deserialize(&data[pos..pos + klen]).unwrap();
            pos += klen;
            let vlen =
                u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let v = data[pos..pos + vlen].to_vec();
            pos += vlen;

            let id_u16 = identifier_to_u16(&id).unwrap();
            entries.push((id_u16, v));
        }
        entries
    }

    #[test]
    fn test_dkg_2x3() {
        let results = run_dkg(3, 2);
        assert_eq!(results.len(), 3);

        let bundle0 =
            crate::keyshare::bundle::KeyShareBundle::deserialize(&results[0])
                .unwrap();
        let bundle1 =
            crate::keyshare::bundle::KeyShareBundle::deserialize(&results[1])
                .unwrap();
        let bundle2 =
            crate::keyshare::bundle::KeyShareBundle::deserialize(&results[2])
                .unwrap();

        let vk0 = bundle0.pub_key_package.verifying_key().serialize().unwrap();
        let vk1 = bundle1.pub_key_package.verifying_key().serialize().unwrap();
        let vk2 = bundle2.pub_key_package.verifying_key().serialize().unwrap();

        assert_eq!(vk0, vk1);
        assert_eq!(vk1, vk2);

        assert_eq!(bundle0.chain_code, bundle1.chain_code);
        assert_eq!(bundle1.chain_code, bundle2.chain_code);
    }
}
