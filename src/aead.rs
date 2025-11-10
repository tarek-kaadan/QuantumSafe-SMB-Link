use anyhow::{Result, bail};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::NewAead;

pub struct AeadState {
    aead: ChaCha20Poly1305,
    nonce: u64,
}

impl AeadState {
    pub fn new(key: &[u8]) -> Self {
        Self { aead: ChaCha20Poly1305::new(Key::from_slice(key)), nonce: 0 }
    }
    fn next_nonce(&mut self) -> [u8;12] {
        let n = self.nonce;
        self.nonce = self.nonce.checked_add(1).expect("nonce overflow");
        let mut out = [0u8;12];
        out[4..12].copy_from_slice(&n.to_le_bytes());
        out
    }
    pub fn seal(&mut self, buf: &mut Vec<u8>) -> Result<Vec<u8>> {
        let n = self.next_nonce();
        let mut ct = buf.clone();
        self.aead.encrypt_in_place(Nonce::from_slice(&n), b"", &mut ct)
            .map_err(|_| anyhow::anyhow!("seal"))?;
        // frame: len | nonce | ct
        let mut out = Vec::with_capacity(4 + 12 + ct.len());
        out.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        out.extend_from_slice(&n);
        out.extend_from_slice(&ct);
        Ok(out)
    }
    pub fn open(&self, nonce: [u8;12], mut ct: Vec<u8>) -> Result<Vec<u8>> {
        let mut data = ct.clone();
        self.aead.decrypt_in_place(Nonce::from_slice(&nonce), b"", &mut data)
            .map_err(|_| anyhow::anyhow!("open"))?;
        Ok(data)
    }
}
