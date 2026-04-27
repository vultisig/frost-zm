use froztolib::tree::{
    OrchardTree, OrchardWitness,
    read_commitment_tree_data, write_commitment_tree_data,
    serialize_witness, deserialize_witness,
};
use orchard::tree::MerkleHashOrchard;
use wasm_bindgen::prelude::*;

fn parse_node(cmx: &[u8]) -> Result<MerkleHashOrchard, JsError> {
    if cmx.len() != 32 {
        return Err(JsError::new("cmx must be 32 bytes"));
    }
    let bytes: [u8; 32] = cmx[..32].try_into().unwrap();
    let ct = MerkleHashOrchard::from_bytes(&bytes);
    if ct.is_none().into() {
        return Err(JsError::new("invalid orchard node"));
    }
    Ok(ct.unwrap())
}

#[wasm_bindgen]
pub struct WasmOrchardTree {
    inner: OrchardTree,
}

#[wasm_bindgen]
impl WasmOrchardTree {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmOrchardTree, JsError> {
        Ok(WasmOrchardTree {
            inner: OrchardTree::empty(),
        })
    }

    #[wasm_bindgen(js_name = "fromHexState")]
    pub fn from_hex_state(hex_state: &str) -> Result<WasmOrchardTree, JsError> {
        let bytes = hex::decode(hex_state)
            .map_err(|e| JsError::new(&format!("hex decode: {}", e)))?;
        let tree = read_commitment_tree_data(&bytes[..])
            .map_err(|e| JsError::new(&format!("parse tree: {}", e)))?;
        Ok(WasmOrchardTree { inner: tree })
    }

    pub fn append(&mut self, cmx: &[u8]) -> Result<(), JsError> {
        let node = parse_node(cmx)?;
        self.inner.append(node)
            .map_err(|_| JsError::new("tree append failed: tree is full"))
    }

    pub fn witness(&self) -> Result<WasmOrchardWitness, JsError> {
        let witness = OrchardWitness::from_tree(self.inner.clone())
            .ok_or_else(|| JsError::new("cannot create witness from empty tree"))?;
        Ok(WasmOrchardWitness { inner: witness })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        let mut buf = Vec::new();
        write_commitment_tree_data(&self.inner, &mut buf)
            .map_err(|e| JsError::new(&format!("serialize tree: {}", e)))?;
        Ok(buf)
    }
}

#[wasm_bindgen]
pub fn frozto_orchard_tree_size(hex_state: &str) -> Result<u64, JsError> {
    let bytes = hex::decode(hex_state)
        .map_err(|e| JsError::new(&format!("hex decode: {}", e)))?;
    let tree: OrchardTree = read_commitment_tree_data(&bytes[..])
        .map_err(|e| JsError::new(&format!("parse tree: {}", e)))?;
    Ok(tree.size() as u64)
}

#[wasm_bindgen]
pub struct WasmOrchardWitness {
    inner: OrchardWitness,
}

#[wasm_bindgen]
impl WasmOrchardWitness {
    pub fn append(&mut self, cmx: &[u8]) -> Result<(), JsError> {
        let node = parse_node(cmx)?;
        self.inner.append(node)
            .map_err(|_| JsError::new("witness append failed"))
    }

    pub fn root(&self) -> Result<Vec<u8>, JsError> {
        let root = self.inner.root();
        Ok(root.to_bytes().to_vec())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        serialize_witness(&self.inner)
            .map_err(|e| JsError::new(&format!("serialize witness: {}", e)))
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(data: &[u8]) -> Result<WasmOrchardWitness, JsError> {
        let witness = deserialize_witness(data)
            .map_err(|e| JsError::new(&format!("deserialize witness: {}", e)))?;
        Ok(WasmOrchardWitness { inner: witness })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::Hashable;
    use wasm_bindgen_test::*;

    #[test]
    fn test_tree_new_empty() {
        let tree = WasmOrchardTree::new().unwrap();
        assert!(tree.inner.left().is_none());
    }

    #[test]
    fn test_tree_append_and_witness() {
        let mut tree = WasmOrchardTree::new().unwrap();

        let mut cmx = [0u8; 32];
        cmx[0] = 1;
        tree.append(&cmx).unwrap();

        let witness = tree.witness().unwrap();
        let root = witness.root().unwrap();
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn test_witness_serialize_roundtrip() {
        let mut tree = WasmOrchardTree::new().unwrap();

        for i in 1u8..=5 {
            let mut cmx = [0u8; 32];
            cmx[0] = i;
            tree.append(&cmx).unwrap();
        }

        let witness = tree.witness().unwrap();
        let root1 = witness.root().unwrap();

        let serialized = witness.serialize().unwrap();
        assert!(!serialized.is_empty());

        let witness2 = WasmOrchardWitness::from_bytes(&serialized).unwrap();
        let root2 = witness2.root().unwrap();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_witness_append() {
        let mut tree = WasmOrchardTree::new().unwrap();

        let mut cmx1 = [0u8; 32];
        cmx1[0] = 1;
        tree.append(&cmx1).unwrap();

        let mut witness = tree.witness().unwrap();
        let root1 = witness.root().unwrap();
        assert!(!root1.is_empty());

        let mut cmx2 = [0u8; 32];
        cmx2[0] = 2;
        tree.append(&cmx2).unwrap();
        witness.append(&cmx2).unwrap();

        let root2 = witness.root().unwrap();
        assert!(!root2.is_empty());
    }

    #[wasm_bindgen_test]
    fn test_tree_new_empty_wasm() {
        test_tree_new_empty();
    }

    #[wasm_bindgen_test]
    fn test_tree_append_and_witness_wasm() {
        test_tree_append_and_witness();
    }

    #[wasm_bindgen_test]
    fn test_witness_serialize_roundtrip_wasm() {
        test_witness_serialize_roundtrip();
    }

    #[wasm_bindgen_test]
    fn test_witness_append_wasm() {
        test_witness_append();
    }
}
