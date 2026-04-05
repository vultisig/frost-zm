use frost_core::keys::{KeyPackage, PublicKeyPackage};
use reddsa::frost::redpallas::PallasBlake2b512;

use crate::errors::lib_error;

type P = PallasBlake2b512;

const BUNDLE_VERSION: u8 = 1;

pub struct KeyShareBundle {
    pub key_package: KeyPackage<P>,
    pub pub_key_package: PublicKeyPackage<P>,
    pub orchard_extras: Vec<u8>,
    pub birthday: u64,
}

fn ser_err<E: std::fmt::Debug>(e: E) -> lib_error {
    #[cfg(debug_assertions)]
    eprintln!("frozto bundle serialization error: {:?}", e);
    let _ = e;
    lib_error::LIB_SERIALIZATION_ERROR
}

impl KeyShareBundle {
    pub fn new(
        key_package: KeyPackage<P>,
        pub_key_package: PublicKeyPackage<P>,
        orchard_extras: Vec<u8>,
        birthday: u64,
    ) -> Self {
        Self {
            key_package,
            pub_key_package,
            orchard_extras,
            birthday,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, lib_error> {
        let kp_bytes = self.key_package.serialize().map_err(ser_err)?;
        let pkp_bytes = self.pub_key_package.serialize().map_err(ser_err)?;

        let total = 1 + 8 + 4 + self.orchard_extras.len() + 4 + kp_bytes.len() + 4 + pkp_bytes.len();
        let mut buf = Vec::with_capacity(total);

        buf.push(BUNDLE_VERSION);
        buf.extend_from_slice(&self.birthday.to_le_bytes());
        buf.extend_from_slice(&(self.orchard_extras.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.orchard_extras);
        buf.extend_from_slice(&(kp_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&kp_bytes);
        buf.extend_from_slice(&(pkp_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&pkp_bytes);

        Ok(buf)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, lib_error> {
        let mut pos = 0;

        if data.len() < 1 + 8 + 4 {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }

        let version = data[pos];
        pos += 1;
        if version != BUNDLE_VERSION {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }

        let birthday = read_u64(data, &mut pos)?;

        let extras_len = read_u32(data, &mut pos)? as usize;
        if pos + extras_len > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let orchard_extras = data[pos..pos + extras_len].to_vec();
        pos += extras_len;

        let kp_len = read_u32(data, &mut pos)? as usize;
        if pos + kp_len > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let key_package =
            KeyPackage::<P>::deserialize(&data[pos..pos + kp_len]).map_err(ser_err)?;
        pos += kp_len;

        let pkp_len = read_u32(data, &mut pos)? as usize;
        if pos + pkp_len > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let pub_key_package =
            PublicKeyPackage::<P>::deserialize(&data[pos..pos + pkp_len]).map_err(ser_err)?;

        Ok(Self {
            key_package,
            pub_key_package,
            orchard_extras,
            birthday,
        })
    }

}

#[cfg(test)]
impl KeyShareBundle {
    pub fn verifying_key_bytes(&self) -> Result<Vec<u8>, lib_error> {
        let vk = self.pub_key_package.verifying_key().serialize().map_err(ser_err)?;
        Ok(vk)
    }
}

fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, lib_error> {
    if *pos + 8 > data.len() {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let val = u64::from_le_bytes(data[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(val)
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, lib_error> {
    if *pos + 4 > data.len() {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let val = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::tests::run_dkg;

    #[test]
    fn test_bundle_round_trip() {
        let results = run_dkg(3, 2);
        let extras = vec![0xABu8; 96];
        let birthday = 3256538u64;

        for (kp_bytes, pkp_bytes) in &results {
            let kp = KeyPackage::<P>::deserialize(kp_bytes).unwrap();
            let pkp = PublicKeyPackage::<P>::deserialize(pkp_bytes).unwrap();

            let bundle = KeyShareBundle::new(kp, pkp, extras.clone(), birthday);
            let serialized = bundle.serialize().unwrap();
            let deserialized = KeyShareBundle::deserialize(&serialized).unwrap();

            let reserialized = deserialized.serialize().unwrap();
            assert_eq!(serialized, reserialized);
            assert_eq!(deserialized.birthday, birthday);
            assert_eq!(deserialized.orchard_extras, extras);
        }
    }

    #[test]
    fn test_bundle_verifying_key() {
        let results = run_dkg(3, 2);
        let extras = vec![0u8; 96];

        let (kp_bytes, pkp_bytes) = &results[0];
        let kp = KeyPackage::<P>::deserialize(kp_bytes).unwrap();
        let pkp = PublicKeyPackage::<P>::deserialize(pkp_bytes).unwrap();

        let expected_vk = pkp.verifying_key().serialize().unwrap();

        let bundle = KeyShareBundle::new(kp, pkp, extras, 100);
        let vk = bundle.verifying_key_bytes().unwrap();
        assert_eq!(vk, expected_vk);
    }
}
