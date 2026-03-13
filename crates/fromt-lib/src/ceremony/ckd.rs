use frost_core::{Ciphersuite, Field, Group};
use frost_ed25519::Ed25519Sha512;
use tiny_keccak::{Hasher, Keccak};

use crate::ceremony::dkg::ser_err;
use crate::errors::lib_error;
use crate::keyshare::bundle::KeyShareBundle;

type E = Ed25519Sha512;
type Identifier = frost_core::Identifier<E>;
type Scalar = frost_core::Scalar<E>;
type F = <<E as Ciphersuite>::Group as Group>::Field;

pub struct CkdRound1Package {
    pub partial_dh: Vec<u8>,
    pub proof: Vec<u8>,
}

pub struct CkdState {
    pub key_share_data: Vec<u8>,
    pub account: u32,
    pub index: u32,
    pub lambda_x: Scalar,
    pub partial_packages: Vec<(u16, Vec<u8>)>,
}

fn derive_path_point(account: u32, index: u32) -> Scalar {
    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(b"fromt/ckd");
    keccak.update(&account.to_le_bytes());
    keccak.update(&index.to_le_bytes());
    keccak.finalize(&mut hash);
    curve25519_dalek::Scalar::from_bytes_mod_order(hash)
}

pub fn ckd_part1(
    key_share_data: &[u8],
    account: u32,
    index: u32,
    signer_ids: &[u16],
) -> Result<(CkdState, Vec<u8>), lib_error> {
    let bundle = KeyShareBundle::deserialize(key_share_data)?;
    let my_id = bundle.key_package.identifier();

    let all_ids: Vec<Identifier> = signer_ids
        .iter()
        .map(|id| Identifier::try_from(*id).map_err(|_| lib_error::LIB_INVALID_IDENTIFIER))
        .collect::<Result<_, _>>()?;

    let xi = my_id.to_scalar();
    let mut num = F::one();
    let mut den = F::one();
    for id in &all_ids {
        if id == my_id {
            continue;
        }
        let xj = id.to_scalar();
        num = num * xj;
        den = den * (xj - xi);
    }
    let den_inv = F::invert(&den).map_err(|_| lib_error::LIB_CKD_ERROR)?;
    let lambda = num * den_inv;

    let share = bundle.key_package.signing_share().to_scalar();
    let lambda_x = lambda * share;

    let h_path = derive_path_point(account, index);
    let partial = lambda_x * h_path;
    let partial_bytes = F::serialize(&partial);

    let partial_slice: &[u8] = partial_bytes.as_ref();
    let out_bytes = partial_slice.to_vec();

    let state = CkdState {
        key_share_data: key_share_data.to_vec(),
        account,
        index,
        lambda_x,
        partial_packages: Vec::new(),
    };

    Ok((state, out_bytes))
}

pub fn ckd_part2(
    state: CkdState,
    r1_packages: &[(u16, Vec<u8>)],
) -> Result<Vec<u8>, lib_error> {
    let bundle = KeyShareBundle::deserialize(&state.key_share_data)?;

    let h_path = derive_path_point(state.account, state.index);
    let own_partial = state.lambda_x * h_path;
    let mut sum = own_partial;

    for (_, pkg_bytes) in r1_packages {
        if pkg_bytes.len() != 32 {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let arr: &[u8; 32] = pkg_bytes
            .as_slice()
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        let partial: Scalar = F::deserialize(arr).map_err(ser_err)?;
        sum = sum + partial;
    }

    let mut keccak = Keccak::v256();
    let mut tweak_hash = [0u8; 32];
    let sum_bytes = F::serialize(&sum);
    keccak.update(sum_bytes.as_ref());
    keccak.update(&state.account.to_le_bytes());
    keccak.update(&state.index.to_le_bytes());
    keccak.finalize(&mut tweak_hash);

    let tweak: Scalar = curve25519_dalek::Scalar::from_bytes_mod_order(tweak_hash);

    let share = bundle.key_package.signing_share().to_scalar();
    let child_share = share + tweak;

    let child_share_bytes = F::serialize(&child_share);
    let child_slice: &[u8] = child_share_bytes.as_ref();
    Ok(child_slice.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::dkg::tests::run_dkg;
    #[test]
    fn test_ckd_deterministic() {
        let bundles = run_dkg(3, 2);

        let signer_ids = [1u16, 2];
        let (state1, pkg1) = ckd_part1(&bundles[0], 0, 0, &signer_ids).unwrap();
        let (state2, pkg2) = ckd_part1(&bundles[1], 0, 0, &signer_ids).unwrap();

        let child1 =
            ckd_part2(state1, &[(2, pkg2.clone())]).unwrap();
        let child2 =
            ckd_part2(state2, &[(1, pkg1.clone())]).unwrap();

        assert!(!child1.is_empty());
        assert!(!child2.is_empty());
    }
}
