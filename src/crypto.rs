use anyhow::{anyhow, Result};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

#[allow(dead_code)]
pub fn aead_encrypt(key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow!("bad key: {:?}", e))?;
    let nonce = Nonce::from(*nonce);
    cipher.encrypt(&nonce, plaintext)
        .map_err(|_| anyhow!("aead encrypt failed"))
}

#[allow(dead_code)]
pub fn aead_decrypt(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow!("bad key: {:?}", e))?;
    let nonce = Nonce::from(*nonce);
    cipher.decrypt(&nonce, ciphertext)
        .map_err(|_| anyhow!("aead decrypt failed"))
}

pub fn derive_keys(
    transcript_salt: &[u8],
    classical: Option<&[u8]>,
    pq: &[u8],
    is_server: bool,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if classical.is_none() && pq.is_empty() {
        return Err(anyhow!("missing shared secret material"));
    }

    let mut ikm = Vec::new();
    if let Some(bytes) = classical {
        ikm.extend_from_slice(bytes);
    }
    ikm.extend_from_slice(pq);

    let hk = Hkdf::<Sha256>::new(Some(transcript_salt), &ikm);
    let mut tx = [0u8; 32];
    let mut rx = [0u8; 32];
    hk.expand(b"QuantumSafe tx", &mut tx)
        .map_err(|_| anyhow!("hkdf tx expand failed"))?;
    hk.expand(b"QuantumSafe rx", &mut rx)
        .map_err(|_| anyhow!("hkdf rx expand failed"))?;
    if is_server {
        Ok((rx.to_vec(), tx.to_vec()))
    } else {
        Ok((tx.to_vec(), rx.to_vec()))
    }
}
