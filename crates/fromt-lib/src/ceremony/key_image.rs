use curve25519_dalek::edwards::CompressedEdwardsY;
use frost_core::{Ciphersuite, Field, Group};
use frost_ed25519::Ed25519Sha512;
use monero_wallet::ed25519::Point;

use crate::errors::lib_error;
use crate::keyshare::bundle::KeyShareBundle;

type E = Ed25519Sha512;
type Identifier = frost_core::Identifier<E>;
type F = <<E as Ciphersuite>::Group as Group>::Field;

pub struct KeyImageOutput {
    pub output_key: [u8; 32],
    pub key_offset: [u8; 32],
}

pub struct KeyImageState {
    pub outputs: Vec<KeyImageOutput>,
    pub my_partials: Vec<[u8; 32]>,
}

fn decode_outputs(data: &[u8]) -> Result<Vec<KeyImageOutput>, lib_error> {
    if data.len() < 4 {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let count = u32::from_le_bytes(
        data[0..4].try_into().map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?,
    ) as usize;
    let expected = 4 + count * 64;
    if data.len() < expected {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let mut outputs = Vec::with_capacity(count);
    let mut pos = 4;
    for _ in 0..count {
        let mut output_key = [0u8; 32];
        let mut key_offset = [0u8; 32];
        output_key.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        key_offset.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        outputs.push(KeyImageOutput { output_key, key_offset });
    }
    Ok(outputs)
}

pub fn key_image_part1(
    key_share_data: &[u8],
    outputs_data: &[u8],
    signer_ids: &[u16],
) -> Result<(KeyImageState, Vec<u8>), lib_error> {
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
    let den_inv = F::invert(&den).map_err(|_| lib_error::LIB_UNKNOWN_ERROR)?;
    let lambda = num * den_inv;

    let share = bundle.key_package.signing_share().to_scalar();
    let lambda_x: curve25519_dalek::Scalar = lambda * share;

    let outputs = decode_outputs(outputs_data)?;
    if outputs.is_empty() {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }

    let mut partials_bytes = Vec::with_capacity(outputs.len() * 32);
    let mut my_partials = Vec::with_capacity(outputs.len());

    for out in &outputs {
        let hp = Point::biased_hash(out.output_key);
        let hp_dalek: curve25519_dalek::EdwardsPoint = hp.into();
        let partial = lambda_x * hp_dalek;
        let compressed = partial.compress().to_bytes();
        my_partials.push(compressed);
        partials_bytes.extend_from_slice(&compressed);
    }

    let state = KeyImageState {
        outputs,
        my_partials,
    };

    Ok((state, partials_bytes))
}

pub fn key_image_part2(
    state: KeyImageState,
    r1_packages: &[(u16, Vec<u8>)],
) -> Result<Vec<u8>, lib_error> {
    let n = state.outputs.len();
    let expected_len = n * 32;

    let mut sums: Vec<curve25519_dalek::EdwardsPoint> = state
        .my_partials
        .iter()
        .map(|p| {
            CompressedEdwardsY(*p)
                .decompress()
                .ok_or(lib_error::LIB_SERIALIZATION_ERROR)
        })
        .collect::<Result<_, _>>()?;

    for (_, pkg_bytes) in r1_packages {
        if pkg_bytes.len() != expected_len {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        for i in 0..n {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pkg_bytes[i * 32..(i + 1) * 32]);
            let point = CompressedEdwardsY(arr)
                .decompress()
                .ok_or(lib_error::LIB_SERIALIZATION_ERROR)?;
            sums[i] += point;
        }
    }

    let mut result = Vec::with_capacity(n * 32);
    for (i, sum) in sums.iter().enumerate() {
        let ko_scalar =
            curve25519_dalek::Scalar::from_canonical_bytes(state.outputs[i].key_offset);
        if bool::from(ko_scalar.is_none()) {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let ko_scalar = ko_scalar.unwrap();

        let hp = Point::biased_hash(state.outputs[i].output_key);
        let hp_dalek: curve25519_dalek::EdwardsPoint = hp.into();
        let offset_component = ko_scalar * hp_dalek;

        let ki = sum + offset_component;
        result.extend_from_slice(&ki.compress().to_bytes());
    }

    Ok(result)
}

pub fn encode_outputs(outputs: &[KeyImageOutput]) -> Vec<u8> {
    let count = outputs.len() as u32;
    let mut buf = Vec::with_capacity(4 + outputs.len() * 64);
    buf.extend_from_slice(&count.to_le_bytes());
    for out in outputs {
        buf.extend_from_slice(&out.output_key);
        buf.extend_from_slice(&out.key_offset);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::dkg::tests::run_dkg;

    fn reconstruct_secret(bundles: &[Vec<u8>], ids: &[u16]) -> curve25519_dalek::Scalar {
        let identifiers: Vec<Identifier> = ids
            .iter()
            .map(|id| Identifier::try_from(*id).unwrap())
            .collect();

        let mut secret = curve25519_dalek::Scalar::ZERO;
        for (idx, id) in ids.iter().enumerate() {
            let bundle = KeyShareBundle::deserialize(&bundles[*id as usize - 1]).unwrap();
            let xi = identifiers[idx].to_scalar();
            let mut num = F::one();
            let mut den = F::one();
            for ident in &identifiers {
                if ident == &identifiers[idx] {
                    continue;
                }
                let xj = ident.to_scalar();
                num = num * xj;
                den = den * (xj - xi);
            }
            let den_inv = F::invert(&den).unwrap();
            let lambda: curve25519_dalek::Scalar = num * den_inv;
            let share: curve25519_dalek::Scalar =
                bundle.key_package.signing_share().to_scalar();
            secret += lambda * share;
        }
        secret
    }

    fn single_party_key_image(
        spend_key: &curve25519_dalek::Scalar,
        output_key: &[u8; 32],
        key_offset: &[u8; 32],
    ) -> [u8; 32] {
        let ko = curve25519_dalek::Scalar::from_canonical_bytes(*key_offset).unwrap();
        let x = ko + spend_key;
        let hp = Point::biased_hash(*output_key);
        let hp_dalek: curve25519_dalek::EdwardsPoint = hp.into();
        let ki = x * hp_dalek;
        ki.compress().to_bytes()
    }

    fn make_test_output(seed: u8) -> KeyImageOutput {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        let scalar = curve25519_dalek::Scalar::from_bytes_mod_order([seed; 32]);
        let point = &scalar * ED25519_BASEPOINT_TABLE;
        let output_key = point.compress().to_bytes();

        let mut ko_bytes = [0u8; 32];
        ko_bytes[0] = seed.wrapping_add(42);
        let key_offset =
            curve25519_dalek::Scalar::from_bytes_mod_order(ko_bytes).to_bytes();

        KeyImageOutput { output_key, key_offset }
    }

    #[test]
    fn test_threshold_matches_single_party() {
        let bundles = run_dkg(3, 2);
        let signer_ids = [1u16, 2];
        let secret = reconstruct_secret(&bundles, &signer_ids);

        let out = make_test_output(7);
        let expected = single_party_key_image(&secret, &out.output_key, &out.key_offset);

        let outputs_data = encode_outputs(&[KeyImageOutput {
            output_key: out.output_key,
            key_offset: out.key_offset,
        }]);

        let (state1, pkg1) =
            key_image_part1(&bundles[0], &outputs_data, &signer_ids).unwrap();
        let (state2, pkg2) =
            key_image_part1(&bundles[1], &outputs_data, &signer_ids).unwrap();

        let ki1 = key_image_part2(state1, &[(2, pkg2.clone())]).unwrap();
        let ki2 = key_image_part2(state2, &[(1, pkg1.clone())]).unwrap();

        assert_eq!(ki1.len(), 32);
        assert_eq!(ki1, ki2);

        let mut got = [0u8; 32];
        got.copy_from_slice(&ki1);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_batch() {
        let bundles = run_dkg(3, 2);
        let signer_ids = [1u16, 2];
        let secret = reconstruct_secret(&bundles, &signer_ids);

        let test_outputs: Vec<KeyImageOutput> =
            (1u8..=5).map(|i| make_test_output(i)).collect();

        let expected: Vec<[u8; 32]> = test_outputs
            .iter()
            .map(|o| single_party_key_image(&secret, &o.output_key, &o.key_offset))
            .collect();

        let outputs_data = encode_outputs(&test_outputs);

        let (state1, pkg1) =
            key_image_part1(&bundles[0], &outputs_data, &signer_ids).unwrap();
        let (state2, pkg2) =
            key_image_part1(&bundles[1], &outputs_data, &signer_ids).unwrap();

        let kis = key_image_part2(state1, &[(2, pkg2)]).unwrap();
        assert_eq!(kis.len(), 5 * 32);

        for i in 0..5 {
            let mut got = [0u8; 32];
            got.copy_from_slice(&kis[i * 32..(i + 1) * 32]);
            assert_eq!(got, expected[i], "key image {} mismatch", i);
        }

        let kis2 = key_image_part2(state2, &[(1, pkg1)]).unwrap();
        assert_eq!(kis, kis2);
    }

    #[test]
    fn test_different_signer_sets() {
        let bundles = run_dkg(3, 2);
        let out = make_test_output(99);
        let outputs_data = encode_outputs(&[KeyImageOutput {
            output_key: out.output_key,
            key_offset: out.key_offset,
        }]);

        let sets: Vec<[u16; 2]> = vec![[1, 2], [1, 3], [2, 3]];
        let mut results = Vec::new();

        for ids in &sets {
            let (state_a, _pkg_a) =
                key_image_part1(&bundles[ids[0] as usize - 1], &outputs_data, ids)
                    .unwrap();
            let (_, pkg_b) =
                key_image_part1(&bundles[ids[1] as usize - 1], &outputs_data, ids)
                    .unwrap();
            let ki = key_image_part2(state_a, &[(ids[1], pkg_b)]).unwrap();
            results.push(ki);
        }

        assert_eq!(results[0], results[1]);
        assert_eq!(results[1], results[2]);
    }
}
