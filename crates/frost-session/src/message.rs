pub fn read_recipient(msg: &[u8]) -> u16 {
    if msg.len() < 2 {
        return 0;
    }
    u16::from_le_bytes([msg[0], msg[1]])
}

pub fn payload(msg: &[u8]) -> &[u8] {
    if msg.len() < 2 {
        return msg;
    }
    &msg[2..]
}

pub fn wrap_sender(sender_id: u16, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + data.len());
    buf.extend_from_slice(&sender_id.to_le_bytes());
    buf.extend_from_slice(data);
    buf
}
