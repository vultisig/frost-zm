use frosty::errors::lib_error;

pub fn attach_taproot_witness(
    raw_tx: &[u8],
    input_index: u32,
    signature: &[u8],
) -> Result<Vec<u8>, lib_error> {
    use bitcoin::consensus::{Decodable, Encodable};

    if signature.len() != 64 && signature.len() != 65 {
        return Err(lib_error::LIB_SIGNING_ERROR);
    }

    let mut tx: bitcoin::Transaction =
        bitcoin::Transaction::consensus_decode(&mut &raw_tx[..])
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

    let idx = input_index as usize;
    if idx >= tx.input.len() {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }

    tx.input[idx].witness = bitcoin::Witness::from_slice(&[signature]);

    let mut buf = Vec::new();
    tx.consensus_encode(&mut buf)
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

    Ok(buf)
}
