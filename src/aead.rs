// src/aead.rs
use anyhow::{anyhow, bail, Result};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Clone)]
pub struct SessionKeys {
    pub tx: [u8; 32],
    pub rx: [u8; 32],
}

impl SessionKeys {
    fn derive(preauth: &[u8], ikm: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(preauth), ikm);
        let mut tx = [0u8; 32];
        let mut rx = [0u8; 32];
        hk.expand(b"pq-smb tx v1", &mut tx).unwrap();
        hk.expand(b"pq-smb rx v1", &mut rx).unwrap();
        Self { tx, rx }
    }

    pub fn from_shared(
        transcript_salt: &[u8],
        classical: Option<&[u8]>,
        pq: &[u8],
        is_server: bool,
    ) -> Result<Self> {
        if classical.is_none() && pq.is_empty() {
            bail!("missing shared secret material");
        }
        let mut ikm = Vec::with_capacity(classical.map(|c| c.len()).unwrap_or(0) + pq.len());
        if let Some(bytes) = classical {
            ikm.extend_from_slice(bytes);
        }
        ikm.extend_from_slice(pq);
        let mut keys = Self::derive(transcript_salt, &ikm);
        if is_server {
            keys.swap_directions();
        }
        Ok(keys)
    }

    fn swap_directions(&mut self) {
        let tx = self.tx;
        self.tx = self.rx;
        self.rx = tx;
    }
}

#[derive(Default, Clone)]
pub struct NonceCounter(u64);

impl NonceCounter {
    pub fn next(&mut self) -> u64 {
        let n = self.0;
        self.0 = self.0.checked_add(1).expect("nonce overflow");
        n
    }
}

pub fn aead_seal(
    key: &[u8; 32],
    nonce12: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("invalid key length"))?;
    let nonce = Nonce::from(*nonce12);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("aead encrypt failed"))
}

pub fn aead_open(
    key: &[u8; 32],
    nonce12: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("invalid key length"))?;
    let nonce = Nonce::from(*nonce12);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("aead decrypt failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_keys_match_between_roles() -> Result<()> {
        let transcript = b"handshake transcript salt";
        let classical = [0xAAu8; 32];
        let pq = [0x42u8; 32];
        let client = SessionKeys::from_shared(transcript, Some(&classical), &pq, false)?;
        let server = SessionKeys::from_shared(transcript, Some(&classical), &pq, true)?;
        assert_eq!(client.tx, server.rx);
        assert_eq!(client.rx, server.tx);
        Ok(())
    }
}
