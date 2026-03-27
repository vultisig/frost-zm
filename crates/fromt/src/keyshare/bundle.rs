use frost_ed25519::Ed25519Sha512;

use frosty::bundle::{self, BundleMetadata, read_u64};
use frosty::errors::lib_error;

type E = Ed25519Sha512;

pub struct ViewKeyMeta {
    pub view_key: [u8; 32],
    pub network: u8,
    pub birthday: u64,
}

impl ViewKeyMeta {
    pub fn from_dkg(extra: [u8; 32], network: u8, birthday: u64) -> Self {
        Self {
            view_key: extra,
            network,
            birthday,
        }
    }
}

impl BundleMetadata for ViewKeyMeta {
    const BUNDLE_VERSION: u8 = 2;

    fn serialize_meta(&self, buf: &mut Vec<u8>) {
        buf.push(Self::BUNDLE_VERSION);
        buf.push(self.network);
        buf.extend_from_slice(&self.view_key);
        buf.extend_from_slice(&self.birthday.to_le_bytes());
    }

    fn deserialize_meta(data: &[u8], pos: &mut usize) -> Result<Self, lib_error> {
        if data.len() < *pos + 1 + 1 + 32 {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }

        let version = data[*pos];
        *pos += 1;
        if version != 1 && version != Self::BUNDLE_VERSION {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }

        let network = data[*pos];
        *pos += 1;

        let view_key: [u8; 32] = data[*pos..*pos + 32]
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        *pos += 32;

        let birthday = if version >= 2 {
            read_u64(data, pos)?
        } else {
            0
        };

        Ok(Self {
            view_key,
            network,
            birthday,
        })
    }

    fn extra_bytes(&self) -> &[u8; 32] {
        &self.view_key
    }
}

pub type KeyShareBundle = bundle::KeyShareBundle<E, ViewKeyMeta>;

pub fn new_bundle(
    key_package: frost_core::keys::KeyPackage<E>,
    pub_key_package: frost_core::keys::PublicKeyPackage<E>,
    view_key: [u8; 32],
    network: u8,
    birthday: u64,
) -> KeyShareBundle {
    KeyShareBundle::new(
        key_package,
        pub_key_package,
        ViewKeyMeta { view_key, network, birthday },
    )
}
