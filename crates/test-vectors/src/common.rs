use frost_core::{Ciphersuite, Identifier};

pub fn encode_map<C: Ciphersuite>(entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (id, v) in entries {
        let id_ident = Identifier::<C>::try_from(*id).unwrap();
        let id_bytes = id_ident.serialize();
        let id_slice: &[u8] = id_bytes.as_ref();
        buf.extend_from_slice(&(id_slice.len() as u32).to_le_bytes());
        buf.extend_from_slice(id_slice);
        buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
        buf.extend_from_slice(v);
    }
    buf
}

pub fn decode_map<C: Ciphersuite>(data: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut pos = 0;
    let count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let mut entries = Vec::new();
    for _ in 0..count {
        let klen = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let id = Identifier::<C>::deserialize(&data[pos..pos + klen]).unwrap();
        pos += klen;
        let vlen = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let v = data[pos..pos + vlen].to_vec();
        pos += vlen;

        let id_u16 = id_to_u16::<C>(&id);
        entries.push((id_u16, v));
    }
    entries
}

fn id_to_u16<C: Ciphersuite>(id: &Identifier<C>) -> u16 {
    for i in 1u16..=256 {
        let candidate = Identifier::<C>::try_from(i).unwrap();
        if candidate == *id {
            return i;
        }
    }
    panic!("identifier not in range 1..=256");
}

pub fn run_dkg_3phase<C, S1, S2>(
    n: u16,
    t: u16,
    part1_fn: impl Fn(u16, u16, u16) -> (S1, Vec<u8>),
    part2_fn: impl Fn(S1, &[u8]) -> (S2, Vec<u8>),
    part3_fn: impl Fn(S2, &[u8], &[u8]) -> (Vec<u8>, Vec<u8>),
) -> (Vec<Vec<u8>>, Vec<u8>)
where
    C: Ciphersuite,
{
    let mut secrets1 = Vec::new();
    let mut packages1 = Vec::new();

    for i in 1..=n {
        let (secret, pkg) = part1_fn(i, n, t);
        secrets1.push(secret);
        packages1.push((i, pkg));
    }

    let mut secrets2 = Vec::new();
    let mut all_r2: Vec<Vec<(u16, Vec<u8>)>> = Vec::new();

    for i in 0..n as usize {
        let others: Vec<_> = packages1
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, (id, pkg))| (*id, pkg.clone()))
            .collect();
        let r1_map = encode_map::<C>(&others);
        let (s2, r2_bytes) = part2_fn(secrets1.remove(0), &r1_map);
        secrets2.push(s2);
        all_r2.push(decode_map::<C>(&r2_bytes));
    }

    let mut bundles = Vec::new();
    let mut vk = Vec::new();

    for i in 0..n as usize {
        let r1_others: Vec<_> = packages1
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, (id, pkg))| (*id, pkg.clone()))
            .collect();

        let my_id = (i + 1) as u16;
        let mut r2_for_me = Vec::new();
        for (sender_idx, r2_pkgs) in all_r2.iter().enumerate() {
            if sender_idx == i {
                continue;
            }
            let sender_id = (sender_idx + 1) as u16;
            for (recipient_id, pkg_bytes) in r2_pkgs {
                if *recipient_id == my_id {
                    r2_for_me.push((sender_id, pkg_bytes.clone()));
                }
            }
        }

        let r1_enc = encode_map::<C>(&r1_others);
        let r2_enc = encode_map::<C>(&r2_for_me);
        let (bundle_bytes, vk_bytes) = part3_fn(secrets2.remove(0), &r1_enc, &r2_enc);
        bundles.push(bundle_bytes);
        if vk.is_empty() {
            vk = vk_bytes;
        }
    }

    (bundles, vk)
}
