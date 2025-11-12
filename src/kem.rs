use anyhow::{anyhow, Result};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublic};

const CAP_HYBRID: u32 = 1 << 0;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientHello {
    pub x_pub: [u8; 32],
    pub kyber_pub: Vec<u8>,
    pub caps: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerHello {
    pub x_pub: [u8; 32],
    pub kyber_ct: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct SigMsg {
    pub sig: Vec<u8>,
}

pub struct ClientState {
    hybrid: bool,
    x_secret: Option<EphemeralSecret>,
    kyber_sk: kyber768::SecretKey,
}

#[derive(Debug, Clone)]
pub struct Shared {
    pub classical: Option<[u8; 32]>,
    pub pq: Vec<u8>,
}

pub fn client_make_hello(hybrid: bool) -> Result<(ClientHello, ClientState)> {
    let (x_secret, x_pub) = if hybrid {
        let sk = EphemeralSecret::random_from_rng(OsRng);
        let pk = XPublic::from(&sk).to_bytes();
        (Some(sk), pk)
    } else {
        (None, [0u8; 32])
    };

    let (ky_pk, ky_sk) = kyber768::keypair();
    let caps = if hybrid { CAP_HYBRID } else { 0 };
    let hello = ClientHello {
        x_pub,
        kyber_pub: ky_pk.as_bytes().to_vec(),
        caps,
    };
    let state = ClientState {
        hybrid,
        x_secret,
        kyber_sk: ky_sk,
    };
    Ok((hello, state))
}

pub fn server_reply(client_hello: &ClientHello, hybrid: bool) -> Result<(ServerHello, Shared)> {
    let use_hybrid = hybrid && (client_hello.caps & CAP_HYBRID != 0);
    let (x_pub, classical) = if use_hybrid {
        let x_sk = EphemeralSecret::random_from_rng(OsRng);
        let x_pub = XPublic::from(&x_sk).to_bytes();
        let ss_x = x_sk
            .diffie_hellman(&XPublic::from(client_hello.x_pub))
            .to_bytes();
        (x_pub, Some(ss_x))
    } else {
        ([0u8; 32], None)
    };

    let client_ky_pk = kyber768::PublicKey::from_bytes(&client_hello.kyber_pub)
        .map_err(|e| anyhow!("bad kyber pk: {:?}", e))?;
    let (ss_pq, ct) = kyber768::encapsulate(&client_ky_pk);
    let shared = Shared {
        classical,
        pq: ss_pq.as_bytes().to_vec(),
    };
    let reply = ServerHello {
        x_pub,
        kyber_ct: ct.as_bytes().to_vec(),
    };
    Ok((reply, shared))
}

pub fn client_finish(state: ClientState, server_hello: &ServerHello) -> Result<Shared> {
    let ClientState {
        hybrid,
        x_secret,
        kyber_sk,
    } = state;

    let classical = if hybrid {
        let sk = x_secret.ok_or_else(|| anyhow!("missing X25519 client secret"))?;
        Some(sk.diffie_hellman(&XPublic::from(server_hello.x_pub)).to_bytes())
    } else {
        None
    };

    let ct = kyber768::Ciphertext::from_bytes(&server_hello.kyber_ct)
        .map_err(|e| anyhow!("bad kyber ct: {:?}", e))?;
    let ss_pq = kyber768::decapsulate(&ct, &kyber_sk);
    Ok(Shared {
        classical,
        pq: ss_pq.as_bytes().to_vec(),
    })
}

pub fn transcript(client: &ClientHello, server: &ServerHello) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(
        client.x_pub.len() + client.kyber_pub.len() + server.x_pub.len() + server.kyber_ct.len() + 4,
    );
    transcript.extend_from_slice(&client.x_pub);
    transcript.extend_from_slice(&client.caps.to_le_bytes());
    transcript.extend_from_slice(&client.kyber_pub);
    transcript.extend_from_slice(&server.x_pub);
    transcript.extend_from_slice(&server.kyber_ct);
    transcript
}

pub fn preauth_hash(transcript: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(transcript);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn ikm_from_shared(shared: &Shared) -> Result<Vec<u8>> {
    if shared.classical.is_none() && shared.pq.is_empty() {
        return Err(anyhow!("missing shared secret material"));
    }
    let mut ikm = Vec::with_capacity(
        shared.classical.as_ref().map(|_| 32).unwrap_or(0) + shared.pq.len(),
    );
    if let Some(classical) = &shared.classical {
        ikm.extend_from_slice(classical);
    }
    ikm.extend_from_slice(&shared.pq);
    Ok(ikm)
}
