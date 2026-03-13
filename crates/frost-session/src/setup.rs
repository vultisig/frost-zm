use frost_ffi::errors::lib_error;

#[derive(Clone, Debug)]
pub struct PartyEntry {
    pub frost_id: u16,
    pub name: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SetupMsg {
    pub max_signers: u16,
    pub min_signers: u16,
    pub parties: Vec<PartyEntry>,
}

#[derive(Clone, Debug)]
pub struct SignSetup {
    pub base: SetupMsg,
    pub message: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ReshareSetup {
    pub base: SetupMsg,
    pub old_identifiers: Vec<u16>,
    pub expected_vk: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct KeyImportSetup {
    pub base: SetupMsg,
    pub seed_holder_id: u16,
    pub secret_data: Vec<u8>,
    pub account_index: u32,
}

#[derive(Clone, Debug)]
pub struct KeyImageSetup {
    pub base: SetupMsg,
    pub outputs_data: Vec<u8>,
}

impl SetupMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.max_signers.to_le_bytes());
        buf.extend_from_slice(&self.min_signers.to_le_bytes());
        buf.extend_from_slice(&(self.parties.len() as u16).to_le_bytes());
        for p in &self.parties {
            buf.extend_from_slice(&p.frost_id.to_le_bytes());
            buf.extend_from_slice(&(p.name.len() as u16).to_le_bytes());
            buf.extend_from_slice(&p.name);
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), lib_error> {
        if data.len() < 6 {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let mut pos = 0;
        let max_signers = read_u16(data, &mut pos)?;
        let min_signers = read_u16(data, &mut pos)?;
        let num_parties = read_u16(data, &mut pos)? as usize;

        let mut parties = Vec::with_capacity(num_parties);
        for _ in 0..num_parties {
            let frost_id = read_u16(data, &mut pos)?;
            let name_len = read_u16(data, &mut pos)? as usize;
            if pos + name_len > data.len() {
                return Err(lib_error::LIB_SERIALIZATION_ERROR);
            }
            let name = data[pos..pos + name_len].to_vec();
            pos += name_len;
            parties.push(PartyEntry { frost_id, name });
        }

        Ok((Self { max_signers, min_signers, parties }, pos))
    }

    pub fn party_name(&self, frost_id: u16) -> Option<&[u8]> {
        self.parties
            .iter()
            .find(|p| p.frost_id == frost_id)
            .map(|p| p.name.as_slice())
    }

    pub fn frost_id_by_name(&self, name: &[u8]) -> Option<u16> {
        self.parties
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.frost_id)
    }

    pub fn other_party_ids(&self, my_id: u16) -> Vec<u16> {
        self.parties
            .iter()
            .filter(|p| p.frost_id != my_id)
            .map(|p| p.frost_id)
            .collect()
    }

    pub fn coordinator_id(&self) -> u16 {
        self.parties[0].frost_id
    }
}

impl SignSetup {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = self.base.encode();
        buf.extend_from_slice(&(self.message.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.message);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, lib_error> {
        let (base, mut pos) = SetupMsg::decode(data)?;
        let msg_len = read_u32(data, &mut pos)? as usize;
        if pos + msg_len > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let message = data[pos..pos + msg_len].to_vec();
        Ok(Self { base, message })
    }
}

impl ReshareSetup {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = self.base.encode();
        buf.extend_from_slice(&(self.old_identifiers.len() as u16).to_le_bytes());
        for id in &self.old_identifiers {
            buf.extend_from_slice(&id.to_le_bytes());
        }
        buf.extend_from_slice(&(self.expected_vk.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.expected_vk);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, lib_error> {
        let (base, mut pos) = SetupMsg::decode(data)?;
        let num_old = read_u16(data, &mut pos)? as usize;
        let mut old_identifiers = Vec::with_capacity(num_old);
        for _ in 0..num_old {
            old_identifiers.push(read_u16(data, &mut pos)?);
        }
        let vk_len = read_u32(data, &mut pos)? as usize;
        if pos + vk_len > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let expected_vk = data[pos..pos + vk_len].to_vec();
        Ok(Self { base, old_identifiers, expected_vk })
    }
}

impl KeyImportSetup {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = self.base.encode();
        buf.extend_from_slice(&self.seed_holder_id.to_le_bytes());
        buf.extend_from_slice(&(self.secret_data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.secret_data);
        buf.extend_from_slice(&self.account_index.to_le_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, lib_error> {
        let (base, mut pos) = SetupMsg::decode(data)?;
        let seed_holder_id = read_u16(data, &mut pos)?;
        let secret_len = read_u32(data, &mut pos)? as usize;
        if pos + secret_len > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let secret_data = data[pos..pos + secret_len].to_vec();
        pos += secret_len;
        let account_index = read_u32(data, &mut pos)?;
        Ok(Self { base, seed_holder_id, secret_data, account_index })
    }
}

impl KeyImageSetup {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = self.base.encode();
        buf.extend_from_slice(&(self.outputs_data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.outputs_data);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, lib_error> {
        let (base, mut pos) = SetupMsg::decode(data)?;
        let outputs_len = read_u32(data, &mut pos)? as usize;
        if pos + outputs_len > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let outputs_data = data[pos..pos + outputs_len].to_vec();
        Ok(Self { base, outputs_data })
    }
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, lib_error> {
    if *pos + 2 > data.len() {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let val = u16::from_le_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
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

    #[test]
    fn roundtrip_setup_msg() {
        let setup = SetupMsg {
            max_signers: 3,
            min_signers: 2,
            parties: vec![
                PartyEntry { frost_id: 1, name: b"server".to_vec() },
                PartyEntry { frost_id: 2, name: b"client-a".to_vec() },
                PartyEntry { frost_id: 3, name: b"client-b".to_vec() },
            ],
        };

        let encoded = setup.encode();
        let (decoded, _) = SetupMsg::decode(&encoded).unwrap();

        assert_eq!(decoded.max_signers, 3);
        assert_eq!(decoded.min_signers, 2);
        assert_eq!(decoded.parties.len(), 3);
        assert_eq!(decoded.parties[0].frost_id, 1);
        assert_eq!(decoded.parties[0].name, b"server");
        assert_eq!(decoded.party_name(2), Some(b"client-a".as_slice()));
        assert_eq!(decoded.frost_id_by_name(b"client-b"), Some(3));
        assert_eq!(decoded.other_party_ids(1), vec![2, 3]);
    }

    #[test]
    fn roundtrip_sign_setup() {
        let setup = SignSetup {
            base: SetupMsg {
                max_signers: 2,
                min_signers: 2,
                parties: vec![
                    PartyEntry { frost_id: 1, name: b"s".to_vec() },
                    PartyEntry { frost_id: 2, name: b"c".to_vec() },
                ],
            },
            message: b"sign this".to_vec(),
        };

        let encoded = setup.encode();
        let decoded = SignSetup::decode(&encoded).unwrap();

        assert_eq!(decoded.message, b"sign this");
        assert_eq!(decoded.base.parties.len(), 2);
    }

    #[test]
    fn roundtrip_key_import_setup() {
        let setup = KeyImportSetup {
            base: SetupMsg {
                max_signers: 3,
                min_signers: 2,
                parties: vec![
                    PartyEntry { frost_id: 1, name: b"a".to_vec() },
                    PartyEntry { frost_id: 2, name: b"b".to_vec() },
                    PartyEntry { frost_id: 3, name: b"c".to_vec() },
                ],
            },
            seed_holder_id: 1,
            secret_data: vec![0xDE; 64],
            account_index: 7,
        };

        let encoded = setup.encode();
        let decoded = KeyImportSetup::decode(&encoded).unwrap();

        assert_eq!(decoded.base.max_signers, 3);
        assert_eq!(decoded.base.min_signers, 2);
        assert_eq!(decoded.seed_holder_id, 1);
        assert_eq!(decoded.secret_data, vec![0xDE; 64]);
        assert_eq!(decoded.account_index, 7);
    }

    #[test]
    fn roundtrip_key_import_setup_empty_secret() {
        let setup = KeyImportSetup {
            base: SetupMsg {
                max_signers: 2,
                min_signers: 2,
                parties: vec![
                    PartyEntry { frost_id: 1, name: b"s".to_vec() },
                    PartyEntry { frost_id: 2, name: b"c".to_vec() },
                ],
            },
            seed_holder_id: 1,
            secret_data: vec![],
            account_index: 0,
        };

        let encoded = setup.encode();
        let decoded = KeyImportSetup::decode(&encoded).unwrap();

        assert_eq!(decoded.secret_data.len(), 0);
        assert_eq!(decoded.account_index, 0);
    }

    #[test]
    fn roundtrip_reshare_setup() {
        let setup = ReshareSetup {
            base: SetupMsg {
                max_signers: 3,
                min_signers: 2,
                parties: vec![
                    PartyEntry { frost_id: 1, name: b"a".to_vec() },
                    PartyEntry { frost_id: 2, name: b"b".to_vec() },
                    PartyEntry { frost_id: 3, name: b"c".to_vec() },
                ],
            },
            old_identifiers: vec![1, 2],
            expected_vk: vec![0xAA; 32],
        };

        let encoded = setup.encode();
        let decoded = ReshareSetup::decode(&encoded).unwrap();

        assert_eq!(decoded.old_identifiers, vec![1, 2]);
        assert_eq!(decoded.expected_vk, vec![0xAA; 32]);
    }
}
