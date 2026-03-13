use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_ed25519::Ed25519Sha512;

use crate::ceremony::dkg::ser_err;
use crate::errors::lib_error;

type E = Ed25519Sha512;

const BUNDLE_VERSION: u8 = 2;

pub struct KeyShareBundle {
    pub key_package: KeyPackage<E>,
    pub pub_key_package: PublicKeyPackage<E>,
    pub view_key: [u8; 32],
    pub network: u8,
    pub birthday: u64,
}

impl KeyShareBundle {
    pub fn new(
        key_package: KeyPackage<E>,
        pub_key_package: PublicKeyPackage<E>,
        view_key: [u8; 32],
        network: u8,
        birthday: u64,
    ) -> Self {
        Self {
            key_package,
            pub_key_package,
            view_key,
            network,
            birthday,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, lib_error> {
        let kp_bytes = self.key_package.serialize().map_err(ser_err)?;
        let pkp_bytes = self.pub_key_package.serialize().map_err(ser_err)?;

        let total = 1 + 1 + 32 + 8 + 4 + kp_bytes.len() + 4 + pkp_bytes.len();
        let mut buf = Vec::with_capacity(total);

        buf.push(BUNDLE_VERSION);
        buf.push(self.network);
        buf.extend_from_slice(&self.view_key);
        buf.extend_from_slice(&self.birthday.to_le_bytes());
        buf.extend_from_slice(&(kp_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&kp_bytes);
        buf.extend_from_slice(&(pkp_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&pkp_bytes);

        Ok(buf)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, lib_error> {
        let mut pos = 0;

        if data.len() < 1 + 1 + 32 + 4 {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }

        let version = data[pos];
        pos += 1;
        if version != 1 && version != BUNDLE_VERSION {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }

        let network = data[pos];
        pos += 1;

        let view_key: [u8; 32] = data[pos..pos + 32]
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        pos += 32;

        let birthday = if version >= 2 {
            read_u64(data, &mut pos)?
        } else {
            0
        };

        let kp_len = read_u32(data, &mut pos)? as usize;
        if pos + kp_len > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let key_package =
            KeyPackage::<E>::deserialize(&data[pos..pos + kp_len]).map_err(ser_err)?;
        pos += kp_len;

        if pos + 4 > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let pkp_len = read_u32(data, &mut pos)? as usize;
        if pos + pkp_len > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let pub_key_package =
            PublicKeyPackage::<E>::deserialize(&data[pos..pos + pkp_len])
                .map_err(ser_err)?;

        Ok(Self {
            key_package,
            pub_key_package,
            view_key,
            network,
            birthday,
        })
    }

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
    use crate::ceremony::dkg::tests::run_dkg;

    #[test]
    fn test_bundle_round_trip() {
        let results = run_dkg(3, 2);
        for bundle_bytes in &results {
            let bundle = KeyShareBundle::deserialize(bundle_bytes).unwrap();
            let reserialized = bundle.serialize().unwrap();
            assert_eq!(bundle_bytes, &reserialized);
        }
    }
}
