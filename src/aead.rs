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
    pub outgoing: [u8; 32],
    pub incoming: [u8; 32],
}

impl SessionKeys {
    fn derive(preauth: &[u8], ikm: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(preauth), ikm);
        let mut outgoing = [0u8; 32];
        let mut incoming = [0u8; 32];
        hk.expand(b"outgoing v1", &mut outgoing).unwrap();
        hk.expand(b"incoming v1", &mut incoming).unwrap();
        Self { outgoing, incoming }
    }

    pub fn from_shared(
        transcript_salt: &[u8],
        classical: Option<&[u8]>,
        post_quantum: &[u8],
        is_server: bool,
    ) -> Result<Self> {
        if classical.is_none() && post_quantum.is_empty() {
            bail!("missing shared secret material");
        }
        // concatenate whatever shared secret material we ended up with
        let mut ikm = Vec::with_capacity(classical.map(|c| c.len()).unwrap_or(0) + post_quantum.len());
        if let Some(bytes) = classical {
            ikm.extend_from_slice(bytes);
        }
        ikm.extend_from_slice(post_quantum);
        let mut keys = Self::derive(transcript_salt, &ikm);
        if is_server {
            keys.swap_directions();
        }
        Ok(keys)
    }

    fn swap_directions(&mut self) {
        let outgoing = self.outgoing;
        self.outgoing = self.incoming;
        self.outgoing = outgoing;
    }
}

#[derive(Default, Clone)]
pub struct NonceTicker(u64);

impl NonceTicker {
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
        assert_eq!(client.outgoing, server.incoming);
        assert_eq!(client.incoming, server.outgoing);
        Ok(())
    }
}
