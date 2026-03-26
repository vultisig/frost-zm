use bitcoin::hashes::Hash;

use crate::errors::lib_error;

pub fn compute_taproot_sighash(
    raw_tx: &[u8],
    prevouts_data: &[u8],
    input_index: u32,
    sighash_type: u8,
) -> Result<[u8; 32], lib_error> {
    use bitcoin::consensus::Decodable;

    let tx: bitcoin::Transaction =
        bitcoin::Transaction::consensus_decode(&mut &raw_tx[..])
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

    let prevouts = decode_prevouts(prevouts_data)?;

    let sighash_ty = bitcoin::sighash::TapSighashType::from_consensus_u8(sighash_type)
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

    let mut cache = bitcoin::sighash::SighashCache::new(&tx);

    let sighash = cache
        .taproot_key_spend_signature_hash(
            input_index as usize,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            sighash_ty,
        )
        .map_err(|_| lib_error::LIB_SIGNING_ERROR)?;

    Ok(sighash.to_byte_array())
}

fn decode_prevouts(data: &[u8]) -> Result<Vec<bitcoin::TxOut>, lib_error> {
    use bitcoin::consensus::Decodable;
    let mut cursor = &data[..];

    let count = bitcoin::consensus::encode::VarInt::consensus_decode(&mut cursor)
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

    let mut prevouts = Vec::with_capacity(count.0 as usize);
    for _ in 0..count.0 {
        let txout = bitcoin::TxOut::consensus_decode(&mut cursor)
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        prevouts.push(txout);
    }

    Ok(prevouts)
}
