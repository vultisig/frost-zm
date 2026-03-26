use frosty::errors::lib_error;

pub struct UnsignedTxContext {
    pub tx_prefix_hash: [u8; 32],
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub fee: u64,
}

pub struct TxInput {
    pub amount: u64,
    pub key_offset_index: usize,
    pub ring: Vec<[u8; 32]>,
    pub pseudo_output_commitment: [u8; 32],
}

pub struct TxOutput {
    pub amount: u64,
    pub target_key: [u8; 32],
}

impl UnsignedTxContext {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.tx_prefix_hash);
        buf.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            buf.extend_from_slice(&input.amount.to_le_bytes());
            buf.extend_from_slice(&(input.key_offset_index as u32).to_le_bytes());
            buf.extend_from_slice(&(input.ring.len() as u32).to_le_bytes());
            for member in &input.ring {
                buf.extend_from_slice(member);
            }
            buf.extend_from_slice(&input.pseudo_output_commitment);
        }
        buf.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for output in &self.outputs {
            buf.extend_from_slice(&output.amount.to_le_bytes());
            buf.extend_from_slice(&output.target_key);
        }
        buf.extend_from_slice(&self.fee.to_le_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, lib_error> {
        let mut pos = 0;

        if data.len() < 32 + 4 {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }

        let tx_prefix_hash: [u8; 32] = data[pos..pos + 32]
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        pos += 32;

        let input_count = read_u32(data, &mut pos)? as usize;
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let amount = read_u64(data, &mut pos)?;
            let key_offset_index = read_u32(data, &mut pos)? as usize;
            let ring_len = read_u32(data, &mut pos)? as usize;
            let mut ring = Vec::with_capacity(ring_len);
            for _ in 0..ring_len {
                if pos + 32 > data.len() {
                    return Err(lib_error::LIB_SERIALIZATION_ERROR);
                }
                let member: [u8; 32] = data[pos..pos + 32]
                    .try_into()
                    .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
                pos += 32;
                ring.push(member);
            }
            if pos + 32 > data.len() {
                return Err(lib_error::LIB_SERIALIZATION_ERROR);
            }
            let pseudo_output_commitment: [u8; 32] = data[pos..pos + 32]
                .try_into()
                .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
            pos += 32;
            inputs.push(TxInput {
                amount,
                key_offset_index,
                ring,
                pseudo_output_commitment,
            });
        }

        let output_count = read_u32(data, &mut pos)? as usize;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let amount = read_u64(data, &mut pos)?;
            if pos + 32 > data.len() {
                return Err(lib_error::LIB_SERIALIZATION_ERROR);
            }
            let target_key: [u8; 32] = data[pos..pos + 32]
                .try_into()
                .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
            pos += 32;
            outputs.push(TxOutput { amount, target_key });
        }

        let fee = read_u64(data, &mut pos)?;

        Ok(Self {
            tx_prefix_hash,
            inputs,
            outputs,
            fee,
        })
    }
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, lib_error> {
    if *pos + 4 > data.len() {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let val = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(val)
}

fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, lib_error> {
    if *pos + 8 > data.len() {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let val = u64::from_le_bytes(data[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_context_round_trip() {
        let ctx = UnsignedTxContext {
            tx_prefix_hash: [0xAA; 32],
            inputs: vec![TxInput {
                amount: 1000000,
                key_offset_index: 5,
                ring: vec![[1u8; 32], [2u8; 32]],
                pseudo_output_commitment: [3u8; 32],
            }],
            outputs: vec![TxOutput {
                amount: 500000,
                target_key: [4u8; 32],
            }],
            fee: 10000,
        };

        let bytes = ctx.serialize();
        let ctx2 = UnsignedTxContext::deserialize(&bytes).unwrap();

        assert_eq!(ctx.tx_prefix_hash, ctx2.tx_prefix_hash);
        assert_eq!(ctx.inputs.len(), ctx2.inputs.len());
        assert_eq!(ctx.outputs.len(), ctx2.outputs.len());
        assert_eq!(ctx.fee, ctx2.fee);
    }
}
