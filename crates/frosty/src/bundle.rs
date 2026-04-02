use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::Ciphersuite;

use crate::errors::lib_error;

pub trait BundleMetadata: Sized + Send + 'static {
    const BUNDLE_VERSION: u8;

    fn serialize_meta(&self, buf: &mut Vec<u8>);
    fn deserialize_meta(data: &[u8], pos: &mut usize) -> Result<Self, lib_error>;
    fn extra_bytes(&self) -> &[u8; 32];
}

pub struct KeyShareBundle<C: Ciphersuite, M: BundleMetadata> {
    pub key_package: KeyPackage<C>,
    pub pub_key_package: PublicKeyPackage<C>,
    pub metadata: M,
}

fn ser_err<Err: std::fmt::Debug>(e: Err) -> lib_error {
    #[cfg(debug_assertions)]
    eprintln!("frosty bundle serialization error: {:?}", e);
    let _ = e;
    lib_error::LIB_SERIALIZATION_ERROR
}

impl<C: Ciphersuite, M: BundleMetadata> KeyShareBundle<C, M> {
    pub fn new(key_package: KeyPackage<C>, pub_key_package: PublicKeyPackage<C>, metadata: M) -> Self {
        Self {
            key_package,
            pub_key_package,
            metadata,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, lib_error> {
        let kp_bytes = self.key_package.serialize().map_err(ser_err)?;
        let pkp_bytes = self.pub_key_package.serialize().map_err(ser_err)?;

        let mut buf = Vec::new();
        self.metadata.serialize_meta(&mut buf);
        buf.extend_from_slice(&(kp_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&kp_bytes);
        buf.extend_from_slice(&(pkp_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&pkp_bytes);

        Ok(buf)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, lib_error> {
        let mut pos = 0;
        let metadata = M::deserialize_meta(data, &mut pos)?;

        let kp_len = read_u32(data, &mut pos)? as usize;
        if pos + kp_len > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let key_package =
            KeyPackage::<C>::deserialize(&data[pos..pos + kp_len]).map_err(ser_err)?;
        pos += kp_len;

        if pos + 4 > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let pkp_len = read_u32(data, &mut pos)? as usize;
        if pos + pkp_len > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let pub_key_package =
            PublicKeyPackage::<C>::deserialize(&data[pos..pos + pkp_len]).map_err(ser_err)?;

        Ok(Self {
            key_package,
            pub_key_package,
            metadata,
        })
    }

    pub fn verifying_key_bytes(&self) -> Result<Vec<u8>, lib_error> {
        let vk = self.pub_key_package.verifying_key().serialize().map_err(ser_err)?;
        Ok(vk)
    }
}

pub fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, lib_error> {
    if *pos + 8 > data.len() {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let val = u64::from_le_bytes(data[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(val)
}

pub fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, lib_error> {
    if *pos + 4 > data.len() {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let val = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(val)
}

pub struct ChainCodeMeta {
    pub chain_code: [u8; 32],
    pub network: u8,
    pub birthday: u64,
}

impl ChainCodeMeta {
    pub fn from_dkg(extra: [u8; 32], network: u8, birthday: u64) -> Self {
        Self {
            chain_code: extra,
            network,
            birthday,
        }
    }
}

impl BundleMetadata for ChainCodeMeta {
    const BUNDLE_VERSION: u8 = 1;

    fn serialize_meta(&self, buf: &mut Vec<u8>) {
        buf.push(Self::BUNDLE_VERSION);
        buf.push(self.network);
        buf.extend_from_slice(&self.chain_code);
        buf.extend_from_slice(&self.birthday.to_le_bytes());
    }

    fn deserialize_meta(data: &[u8], pos: &mut usize) -> Result<Self, lib_error> {
        if data.len() < *pos + 1 + 1 + 32 + 8 {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }

        let version = data[*pos];
        *pos += 1;
        if version != Self::BUNDLE_VERSION {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }

        let network = data[*pos];
        *pos += 1;

        let chain_code: [u8; 32] = data[*pos..*pos + 32]
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        *pos += 32;

        let birthday = read_u64(data, pos)?;

        Ok(Self {
            chain_code,
            network,
            birthday,
        })
    }

    fn extra_bytes(&self) -> &[u8; 32] {
        &self.chain_code
    }
}
