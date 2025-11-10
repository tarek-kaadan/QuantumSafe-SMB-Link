use anyhow::Result;
use pqcrypto_dilithium::dilithium2 as d2;

pub fn gen() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = d2::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

pub fn sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let sk = d2::SecretKey::from_bytes(sk).unwrap();
    Ok(d2::sign(msg, &sk).as_bytes().to_vec())
}

pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let pk = d2::PublicKey::from_bytes(pk).unwrap();
    d2::open(
        &d2::SignedMessage::from_bytes(sig).unwrap(),
        &pk
    ).map(|opened| opened.as_bytes() == msg).unwrap_or(false)
}
