use anyhow::{anyhow, Result};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

pub fn generate_keys() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = dilithium2::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

pub fn sign_detached(msg: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>> {
    let sk = dilithium2::SecretKey::from_bytes(sk_bytes)
        .map_err(|e| anyhow!("invalid Dilithium secret key: {:?}", e))?;
    // correct name is `detached_sign`, not `sign_detached`
    let sig = dilithium2::detached_sign(msg, &sk);
    Ok(sig.as_bytes().to_vec())
}

pub fn verify_detached(msg: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> Result<()> {
    let pk = dilithium2::PublicKey::from_bytes(pk_bytes)
        .map_err(|e| anyhow!("invalid Dilithium public key: {:?}", e))?;
    let sig = dilithium2::DetachedSignature::from_bytes(sig_bytes)
        .map_err(|e| anyhow!("invalid Dilithium signature: {:?}", e))?;
    dilithium2::verify_detached_signature(&sig, msg, &pk)
        .map_err(|e| anyhow!("signature verification failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() -> Result<()> {
        let (pk, sk) = generate_keys();
        let msg = b"QuantumSafe-SMB-Link";
        let sig = sign_detached(msg, &sk)?;
        verify_detached(msg, &sig, &pk)
    }
}
