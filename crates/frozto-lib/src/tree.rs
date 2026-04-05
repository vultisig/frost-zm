use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use incrementalmerkletree::frontier::CommitmentTree;
use incrementalmerkletree::witness::IncrementalWitness;
use orchard::tree::MerkleHashOrchard;
use std::io::{self, Read, Write};

use crate::{
    bytes::*,
    errors::*,
    handle::Handle,
};

const DEPTH: u8 = 32;

pub type OrchardTree = CommitmentTree<MerkleHashOrchard, DEPTH>;
pub type OrchardWitness = IncrementalWitness<MerkleHashOrchard, DEPTH>;

fn read_node<R: Read>(mut reader: R) -> io::Result<MerkleHashOrchard> {
    let mut buf = [0u8; 32];
    reader.read_exact(&mut buf)?;
    let ct = MerkleHashOrchard::from_bytes(&buf);
    if ct.is_none().into() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid node"));
    }
    Ok(ct.unwrap())
}

fn read_optional_node<R: Read>(mut reader: R) -> io::Result<Option<MerkleHashOrchard>> {
    let flag = reader.read_u8()?;
    if flag == 0 {
        Ok(None)
    } else {
        Ok(Some(read_node(&mut reader)?))
    }
}

fn write_optional_node<W: Write>(writer: &mut W, node: &Option<MerkleHashOrchard>) -> io::Result<()> {
    match node {
        Some(n) => {
            writer.write_all(&[1])?;
            writer.write_all(&n.to_bytes())?;
        }
        None => writer.write_all(&[0])?,
    }
    Ok(())
}

fn read_compact_size<R: Read>(mut reader: R) -> io::Result<usize> {
    let first = reader.read_u8()?;
    match first {
        0..=252 => Ok(first as usize),
        253 => Ok(reader.read_u16::<LittleEndian>()? as usize),
        254 => Ok(reader.read_u32::<LittleEndian>()? as usize),
        255 => Ok(reader.read_u64::<LittleEndian>()? as usize),
    }
}

fn write_compact_size<W: Write>(mut writer: W, val: usize) -> io::Result<()> {
    if val < 253 {
        writer.write_u8(val as u8)
    } else if val <= 0xFFFF {
        writer.write_u8(253)?;
        writer.write_u16::<LittleEndian>(val as u16)
    } else if val <= 0xFFFFFFFF {
        writer.write_u8(254)?;
        writer.write_u32::<LittleEndian>(val as u32)
    } else {
        writer.write_u8(255)?;
        writer.write_u64::<LittleEndian>(val as u64)
    }
}

pub fn read_commitment_tree_data<R: Read>(mut reader: R) -> io::Result<OrchardTree> {
    let left = read_optional_node(&mut reader)?;
    let right = read_optional_node(&mut reader)?;

    let parent_count = read_compact_size(&mut reader)?;
    if parent_count > DEPTH as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "parent_count exceeds tree depth"));
    }
    let mut parents = Vec::with_capacity(parent_count);
    for _ in 0..parent_count {
        parents.push(read_optional_node(&mut reader)?);
    }

    CommitmentTree::from_parts(left, right, parents)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid commitment tree"))
}

pub fn write_commitment_tree_data<W: Write>(tree: &OrchardTree, mut writer: W) -> io::Result<()> {
    write_optional_node(&mut writer, &tree.left())?;
    write_optional_node(&mut writer, &tree.right())?;

    let parents = tree.parents();
    write_compact_size(&mut writer, parents.len())?;
    for p in parents {
        write_optional_node(&mut writer, p)?;
    }

    Ok(())
}

pub fn deserialize_witness(data: &[u8]) -> io::Result<OrchardWitness> {
    let mut cursor = io::Cursor::new(data);

    let tree = read_commitment_tree_data(&mut cursor)?;

    let filled_count = read_compact_size(&mut cursor)?;
    let mut filled = Vec::with_capacity(filled_count);
    for _ in 0..filled_count {
        filled.push(read_node(&mut cursor)?);
    }

    let cursor_parents_count = read_compact_size(&mut cursor)?;
    let mut cursor_parents = Vec::with_capacity(cursor_parents_count);
    for _ in 0..cursor_parents_count {
        cursor_parents.push(read_optional_node(&mut cursor)?);
    }

    let cursor_tree = if cursor_parents.is_empty() {
        None
    } else {
        let ct = CommitmentTree::from_parts(
            cursor_parents.first().and_then(|n| *n),
            None,
            cursor_parents.get(1..).unwrap_or(&[]).to_vec(),
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid cursor tree"))?;
        Some(ct)
    };

    IncrementalWitness::from_parts(tree, filled, cursor_tree)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid witness parts"))
}

pub fn serialize_witness(witness: &OrchardWitness) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();

    write_commitment_tree_data(witness.tree(), &mut buf)?;

    let filled = witness.filled();
    write_compact_size(&mut buf, filled.len())?;
    for node in filled {
        buf.write_all(&node.to_bytes())?;
    }

    match witness.cursor() {
        Some(cursor) => {
            let cursor_parents = cursor.parents();
            write_compact_size(&mut buf, 1 + cursor_parents.len())?;
            write_optional_node(&mut buf, &cursor.left())?;
            for p in cursor_parents {
                write_optional_node(&mut buf, p)?;
            }
        }
        None => {
            write_compact_size(&mut buf, 0)?;
        }
    }

    Ok(buf)
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_tree_new(
    out_handle: Option<&mut Handle>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_handle.ok_or(lib_error::LIB_NULL_PTR)?;
        let tree = OrchardTree::empty();
        *out = Handle::allocate(tree)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_tree_append(
    tree_handle: Handle,
    cmx_bytes: Option<&go_slice>,
) -> lib_error {
    with_error_handler(|| {
        let cmx_data = cmx_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        if cmx_data.len() != 32 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let cmx_arr: [u8; 32] = cmx_data.as_slice()[..32].try_into().unwrap();
        let node = MerkleHashOrchard::from_bytes(&cmx_arr);
        if node.is_none().into() {
            return Err(lib_error::LIB_ORCHARD_ERROR);
        }
        let node = node.unwrap();

        let mut tree = tree_handle.get::<OrchardTree>()?;
        tree.append(node)
            .map_err(|_| lib_error::LIB_ORCHARD_ERROR)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_tree_serialize(
    tree_handle: Handle,
    out_data: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let tree = tree_handle.get::<OrchardTree>()?;
        let mut buf = Vec::new();
        write_commitment_tree_data(&tree, &mut buf)
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        *out = tss_buffer::from_vec(buf);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_tree_deserialize(
    data: Option<&go_slice>,
    out_handle: Option<&mut Handle>,
) -> lib_error {
    with_error_handler(|| {
        let tree_data = data.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_handle.ok_or(lib_error::LIB_NULL_PTR)?;
        let tree = read_commitment_tree_data(io::Cursor::new(tree_data.as_slice()))
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        *out = Handle::allocate(tree)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozto_tree_free(tree_handle: Handle) -> lib_error {
    with_error_handler(|| {
        let _ = tree_handle.take::<OrchardTree>()?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::Hashable;

    #[test]
    fn test_tree_new_and_append() {
        let mut handle = Handle::null();
        assert_eq!(frozto_tree_new(Some(&mut handle)), lib_error::LIB_OK);

        let node = MerkleHashOrchard::empty_leaf();
        let node_bytes = node.to_bytes();
        let node_slice = go_slice::from(node_bytes.as_ref());

        assert_eq!(
            frozto_tree_append(handle, Some(&node_slice)),
            lib_error::LIB_OK,
        );

        assert_eq!(frozto_tree_free(handle), lib_error::LIB_OK);
    }

    #[test]
    fn test_tree_serialize_roundtrip() {
        let mut tree = OrchardTree::empty();
        let node = MerkleHashOrchard::empty_leaf();
        tree.append(node).unwrap();

        let mut buf = Vec::new();
        write_commitment_tree_data(&tree, &mut buf).unwrap();

        let restored = read_commitment_tree_data(io::Cursor::new(&buf)).unwrap();

        let mut buf2 = Vec::new();
        write_commitment_tree_data(&restored, &mut buf2).unwrap();
        assert_eq!(buf, buf2);
    }
}
