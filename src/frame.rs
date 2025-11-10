pub fn split_frame(mut raw: &[u8]) -> Option<(usize,[u8;12],Vec<u8>)> {
    if raw.len() < 4+12 { return None; }
    let len = u32::from_le_bytes(raw[0..4].try_into().ok()?) as usize;
    let mut nonce = [0u8;12];
    nonce.copy_from_slice(&raw[4..16]);
    let ct = raw[16..16+len].to_vec();
    Some((len, nonce, ct))
}
