use std::rc::Rc;

use sapling_crypto::{
    circuit::OutputParameters,
    keys::OutgoingViewingKey,
    note_encryption::Zip212Enforcement,
    value::{NoteValue, ValueCommitTrapdoor},
};
use wasm_bindgen::prelude::*;

use froztslib::errors::lib_error;
use froztslib::shielding_tx;
use froztslib::tx::{self, OutputParts};

fn to_js(e: lib_error) -> JsError {
    JsError::new(&format!("{}", e))
}

#[wasm_bindgen]
pub struct WasmShieldingTxBuilder {
    ovk: OutgoingViewingKey,
    target_height: u32,
    zip212: Zip212Enforcement,
    output_params: Rc<OutputParameters>,
    inputs: Vec<shielding_tx::TransparentInput>,
    transparent_outputs: Vec<shielding_tx::TransparentOutput>,
    sapling_outputs: Vec<OutputParts>,
    total_input: u64,
    total_sapling_output: u64,
    total_transparent_output: u64,
    sighashes: Option<Vec<[u8; 32]>>,
    txid_sighash: Option<[u8; 32]>,
}

#[wasm_bindgen]
impl WasmShieldingTxBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(
        output_params_bytes: &[u8],
        extras_bytes: &[u8],
        target_height: u32,
    ) -> Result<WasmShieldingTxBuilder, JsError> {
        if extras_bytes.len() != 96 {
            return Err(JsError::new("extras must be 96 bytes"));
        }

        let output_params =
            OutputParameters::read(std::io::Cursor::new(output_params_bytes), true)
                .map_err(|e| JsError::new(&format!("read output params: {}", e)))?;

        let mut ovk_bytes = [0u8; 32];
        ovk_bytes.copy_from_slice(&extras_bytes[32..64]);
        let ovk = OutgoingViewingKey(ovk_bytes);
        let zip212 = froztslib::sapling::zip212_for_height(target_height as u64);

        Ok(WasmShieldingTxBuilder {
            ovk,
            target_height,
            zip212,
            output_params: Rc::new(output_params),
            inputs: Vec::new(),
            transparent_outputs: Vec::new(),
            sapling_outputs: Vec::new(),
            total_input: 0,
            total_sapling_output: 0,
            total_transparent_output: 0,
            sighashes: None,
            txid_sighash: None,
        })
    }

    #[wasm_bindgen(js_name = "addInput")]
    pub fn add_input(
        &mut self,
        prev_txid: &[u8],
        vout: u32,
        value: f64,
        script_pubkey: &[u8],
    ) -> Result<(), JsError> {
        if prev_txid.len() != 32 {
            return Err(JsError::new("prev_txid must be 32 bytes"));
        }
        let value = value as u64;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(prev_txid);

        self.total_input = self
            .total_input
            .checked_add(value)
            .ok_or_else(|| JsError::new("input overflow"))?;

        self.inputs.push(shielding_tx::TransparentInput {
            prev_txid: txid,
            vout,
            value,
            script_pubkey: script_pubkey.to_vec(),
        });
        Ok(())
    }

    #[wasm_bindgen(js_name = "addOutput")]
    pub fn add_output(&mut self, address: &str, amount: f64) -> Result<(), JsError> {
        let amount = amount as u64;
        let addr = tx::parse_payment_address(address).map_err(to_js)?;
        let memo = [0u8; 512];

        let output = tx::make_output(
            Some(self.ovk),
            addr,
            NoteValue::from_raw(amount),
            memo,
            self.zip212,
            &self.output_params,
        )
        .map_err(to_js)?;

        self.total_sapling_output = self
            .total_sapling_output
            .checked_add(amount)
            .ok_or_else(|| JsError::new("output overflow"))?;
        self.sapling_outputs.push(output);
        Ok(())
    }

    #[wasm_bindgen(js_name = "addTransparentOutput")]
    pub fn add_transparent_output(&mut self, address: &str, amount: f64) -> Result<(), JsError> {
        let amount = amount as u64;
        let pubkey_hash = shielding_tx::parse_transparent_address(address).map_err(to_js)?;
        let script_pubkey = shielding_tx::build_p2pkh_script_pubkey(&pubkey_hash);

        self.total_transparent_output = self
            .total_transparent_output
            .checked_add(amount)
            .ok_or_else(|| JsError::new("transparent output overflow"))?;
        self.transparent_outputs.push(shielding_tx::TransparentOutput {
            value: amount,
            script_pubkey,
        });
        Ok(())
    }

    pub fn build(&mut self) -> Result<(), JsError> {
        if self.inputs.is_empty() {
            return Err(JsError::new("no inputs added"));
        }
        if self.sapling_outputs.is_empty() {
            return Err(JsError::new("no sapling outputs added"));
        }
        let total_out = self
            .total_sapling_output
            .checked_add(self.total_transparent_output)
            .ok_or_else(|| JsError::new("output overflow"))?;
        if self.total_input <= total_out {
            return Err(JsError::new("inputs must exceed outputs (need fee)"));
        }

        let value_balance = -(self.total_sapling_output as i64);
        let consensus_branch_id = tx::branch_id_for_height(self.target_height);
        let expiry_height = self.target_height + 40;

        let n = self.inputs.len();
        let mut per_input_sighashes = Vec::with_capacity(n);
        for i in 0..n {
            let sh = shielding_tx::compute_shielding_sighash(
                &self.inputs,
                &self.transparent_outputs,
                &self.sapling_outputs,
                value_balance,
                consensus_branch_id,
                expiry_height,
                Some(i),
            );
            per_input_sighashes.push(sh);
        }

        let txid_sighash = shielding_tx::compute_shielding_sighash(
            &self.inputs,
            &self.transparent_outputs,
            &self.sapling_outputs,
            value_balance,
            consensus_branch_id,
            expiry_height,
            None,
        );

        self.sighashes = Some(per_input_sighashes);
        self.txid_sighash = Some(txid_sighash);
        Ok(())
    }

    #[wasm_bindgen(getter)]
    pub fn sighashes(&self) -> Vec<u8> {
        match &self.sighashes {
            Some(shs) => shs.iter().flat_map(|sh| sh.iter().copied()).collect(),
            None => Vec::new(),
        }
    }

    #[wasm_bindgen(getter, js_name = "numInputs")]
    pub fn num_inputs(&self) -> usize {
        self.inputs.len()
    }

    pub fn complete(
        &mut self,
        ecdsa_sigs: &[u8],
        pubkeys: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let sighashes = self
            .sighashes
            .as_ref()
            .ok_or_else(|| JsError::new("build() must be called before complete()"))?;
        let txid_sighash = self
            .txid_sighash
            .ok_or_else(|| JsError::new("build() must be called before complete()"))?;

        let n = sighashes.len();

        if pubkeys.len() != n * 33 {
            return Err(JsError::new(&format!(
                "expected {} pubkey bytes ({} * 33), got {}",
                n * 33,
                n,
                pubkeys.len()
            )));
        }

        let mut sigs: Vec<&[u8]> = Vec::with_capacity(n);
        let mut offset = 0;
        for _ in 0..n {
            if offset + 2 > ecdsa_sigs.len() {
                return Err(JsError::new("ecdsa_sigs too short"));
            }
            let sig_len =
                u16::from_le_bytes(ecdsa_sigs[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            if offset + sig_len > ecdsa_sigs.len() {
                return Err(JsError::new("ecdsa_sigs truncated"));
            }
            sigs.push(&ecdsa_sigs[offset..offset + sig_len]);
            offset += sig_len;
        }

        let mut script_sigs = Vec::with_capacity(n);
        for i in 0..n {
            let pk = &pubkeys[i * 33..(i + 1) * 33];
            let ss = shielding_tx::build_p2pkh_script_sig(sigs[i], pk);
            script_sigs.push(ss);
        }

        let output_rcvs: Vec<&ValueCommitTrapdoor> =
            self.sapling_outputs.iter().map(|o| &o.rcv).collect();
        let bsk = tx::compute_bsk(&[], &output_rcvs);

        let mut rng = rand::thread_rng();
        let binding_sig = bsk.sign(&mut rng, &txid_sighash);

        let value_balance = -(self.total_sapling_output as i64);
        let consensus_branch_id = tx::branch_id_for_height(self.target_height);
        let expiry_height = self.target_height + 40;

        let raw_tx = shielding_tx::serialize_shielding_v5_tx(
            &self.inputs,
            &script_sigs,
            &self.transparent_outputs,
            &self.sapling_outputs,
            value_balance,
            &binding_sig,
            consensus_branch_id,
            expiry_height,
        )
        .map_err(to_js)?;

        Ok(raw_tx)
    }
}
