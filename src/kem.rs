use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as XPub};

pub struct ClientHello {
    pub x_pub: [u8; 32],
    pub kyber_pk: Vec<u8>,
}

pub struct ServerReply {
    pub x_pub: [u8; 32],
    pub kyber_ct: Vec<u8>,
}

pub fn client_generate() -> (EphemeralSecret, [u8;32], Vec<u8>, Vec<u8>) {
    // X25519 ephemeral
    let x_sk = EphemeralSecret::random();
    let x_pub = XPub::from(&x_sk).to_bytes();

    // Kyber768 keypair
    let (ky_pk, ky_sk) = pqcrypto_kyber::kyber768::keypair();
    (x_sk, x_pub, ky_pk.as_bytes().to_vec(), ky_sk.as_bytes().to_vec())
}

pub fn server_reply(
    client_x_pub: [u8;32],
    client_ky_pk: &[u8],
) -> (EphemeralSecret, [u8;32], Vec<u8>, Vec<u8>) {
    let x_sk = EphemeralSecret::random();
    let x_pub = XPub::from(&x_sk).to_bytes();

    // Encapsulate to client's Kyber PK
    use pqcrypto_kyber::kyber768::{PublicKey, encapsulate};
    let ct_ss = encapsulate(&PublicKey::from_bytes(client_ky_pk).unwrap());
    let ky_ct = ct_ss.ciphertext.as_bytes().to_vec();
    let ss_pq = ct_ss.shared_secret.as_bytes().to_vec();

    // Classical shared secret
    let ss_x = x_sk.diffie_hellman(&XPub::from(client_x_pub)).to_bytes().to_vec();

    // Combined
    let mut ikm = Vec::new();
    ikm.extend_from_slice(&ss_x);
    ikm.extend_from_slice(&ss_pq);

    (x_sk, x_pub, ky_ct, ikm)
}

pub fn client_finish(
    client_x_sk: EphemeralSecret,
    server_x_pub: [u8;32],
    server_ky_ct: &[u8],
    client_ky_sk: &[u8],
) -> Vec<u8> {
    use pqcrypto_kyber::kyber768::{SecretKey, decapsulate};
    let ss_x = client_x_sk.diffie_hellman(&XPub::from(server_x_pub)).to_bytes().to_vec();

    let ss_pq = decapsulate(
        &pqcrypto_kyber::kyber768::Ciphertext::from_bytes(server_ky_ct).unwrap(),
        &SecretKey::from_bytes(client_ky_sk).unwrap(),
    ).as_bytes().to_vec();

    let mut ikm = Vec::new();
    ikm.extend_from_slice(&ss_x);
    ikm.extend_from_slice(&ss_pq);
    ikm
}

pub fn kdf(preauth: &[u8], ikm: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let hk = Hkdf::<Sha256>::new(Some(preauth), ikm);
    let mut k_tx = [0u8;32];
    let mut k_rx = [0u8;32];
    hk.expand(b"qssmb-tx-v1", &mut k_tx).unwrap();
    hk.expand(b"qssmb-rx-v1", &mut k_rx).unwrap();
    (k_tx.to_vec(), k_rx.to_vec())
}
