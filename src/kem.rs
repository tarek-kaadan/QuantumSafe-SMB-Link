use anyhow::{anyhow, bail, ensure, Result};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublic};

pub const CLIENT_HELLO_MAGIC: &[u8; 4] = b"QSLH";
pub const SERVER_HELLO_MAGIC: &[u8; 4] = b"QSLS";
pub const CLIENT_AUTH_MAGIC: &[u8; 4] = b"QSLA";
pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_HANDSHAKE_LEN: usize = 64 * 1024;

const TLV_KEM_LIST: u16 = 0x0001;
const TLV_SIG_LIST: u16 = 0x0002;
const TLV_HYBRID: u16 = 0x0003;
const TLV_PQ_REQUIRED: u16 = 0x0004;
const TLV_CHOSEN_SUITE: u16 = 0x0101;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KemAlgorithm {
    Kyber768 = 0x0001,
}

impl TryFrom<u16> for KemAlgorithm {
    type Error = anyhow::Error;
    fn try_from(value: u16) -> Result<Self> {
        match value {
            0x0001 => Ok(KemAlgorithm::Kyber768),
            other => Err(anyhow!("unknown KEM type {other:#x}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigAlgorithm {
    Dilithium2 = 0x0001,
}

impl TryFrom<u16> for SigAlgorithm {
    type Error = anyhow::Error;
    fn try_from(value: u16) -> Result<Self> {
        match value {
            0x0001 => Ok(SigAlgorithm::Dilithium2),
            other => Err(anyhow!("unknown signature type {other:#x}")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub kem_list: Vec<KemAlgorithm>,
    pub sig_list: Vec<SigAlgorithm>,
    pub hybrid: bool,
    pub pq_required: bool,
}

impl Capabilities {
    pub fn new(hybrid: bool, pq_required: bool) -> Self {
        Self {
            kem_list: vec![KemAlgorithm::Kyber768],
            sig_list: vec![SigAlgorithm::Dilithium2],
            hybrid,
            pq_required,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_tlv_u16_list(
            &mut out,
            TLV_KEM_LIST,
            self.kem_list.iter().map(|k| *k as u16),
        );
        push_tlv_u16_list(
            &mut out,
            TLV_SIG_LIST,
            self.sig_list.iter().map(|s| *s as u16),
        );
        push_tlv_bool(&mut out, TLV_HYBRID, self.hybrid);
        push_tlv_bool(&mut out, TLV_PQ_REQUIRED, self.pq_required);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut kem_list = Vec::new();
        let mut sig_list = Vec::new();
        let mut hybrid = false;
        let mut pq_required = true;
        let mut cursor = bytes;
        while !cursor.is_empty() {
            ensure!(cursor.len() >= 4, "malformed TLV header");
            let tag = u16::from_be_bytes([cursor[0], cursor[1]]);
            let len = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
            cursor = &cursor[4..];
            ensure!(cursor.len() >= len, "malformed TLV length");
            let value = &cursor[..len];
            cursor = &cursor[len..];
            match tag {
                TLV_KEM_LIST => {
                    ensure!(len % 2 == 0, "kem list must be u16 aligned");
                    for chunk in value.chunks_exact(2) {
                        kem_list.push(KemAlgorithm::try_from(u16::from_be_bytes([
                            chunk[0], chunk[1],
                        ]))?);
                    }
                }
                TLV_SIG_LIST => {
                    ensure!(len % 2 == 0, "sig list must be u16 aligned");
                    for chunk in value.chunks_exact(2) {
                        sig_list.push(SigAlgorithm::try_from(u16::from_be_bytes([
                            chunk[0], chunk[1],
                        ]))?);
                    }
                }
                TLV_HYBRID => {
                    ensure!(len == 1, "hybrid TLV must be 1 byte");
                    hybrid = value[0] != 0;
                }
                TLV_PQ_REQUIRED => {
                    ensure!(len == 1, "pq_required TLV must be 1 byte");
                    pq_required = value[0] != 0;
                }
                _ => {}
            }
        }
        if kem_list.is_empty() {
            bail!("kem list missing in capabilities");
        }
        if sig_list.is_empty() {
            bail!("sig list missing in capabilities");
        }
        Ok(Self {
            kem_list,
            sig_list,
            hybrid,
            pq_required,
        })
    }
}

pub struct ClientState {
    x_secret: EphemeralSecret,
    kyber_sk: kyber768::SecretKey,
}

#[derive(Clone, Debug)]
pub struct ClientHello {
    pub random: [u8; 32],
    pub x_pub: [u8; 32],
    pub kyber_pub: Vec<u8>,
    pub caps: Capabilities,
    pub caps_encoded: Vec<u8>,
}

impl ClientHello {
    pub fn new(caps: Capabilities) -> Result<(Self, ClientState)> {
        let mut client_random = [0u8; 32];
        OsRng.fill_bytes(&mut client_random);
        let x_secret = EphemeralSecret::random_from_rng(OsRng);
        let x_pub = XPublic::from(&x_secret).to_bytes();
        let (ky_pk, ky_sk) = kyber768::keypair();
        let kyber_pub = ky_pk.as_bytes().to_vec();
        let caps_encoded = caps.encode();
        let hello = Self {
            random: client_random,
            x_pub,
            kyber_pub: kyber_pub.clone(),
            caps: caps.clone(),
            caps_encoded: caps_encoded.clone(),
        };
        let state = ClientState {
            x_secret,
            kyber_sk: ky_sk,
        };
        Ok((hello, state))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.random);
        body.extend_from_slice(&self.x_pub);
        body.extend_from_slice(&(self.kyber_pub.len() as u16).to_be_bytes());
        body.extend_from_slice(&self.kyber_pub);
        body.extend_from_slice(&(self.caps_encoded.len() as u16).to_be_bytes());
        body.extend_from_slice(&self.caps_encoded);
        body
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        ensure!(payload.len() >= 32 + 32 + 2 + 2, "client hello too short");
        let mut cursor = payload;
        let mut random = [0u8; 32];
        random.copy_from_slice(&cursor[..32]);
        cursor = &cursor[32..];
        let mut x_pub = [0u8; 32];
        x_pub.copy_from_slice(&cursor[..32]);
        cursor = &cursor[32..];
        ensure!(cursor.len() >= 2, "missing kyber length");
        let ky_len = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
        cursor = &cursor[2..];
        ensure!(cursor.len() >= ky_len + 2, "kyber bytes truncated");
        let kyber_pub = cursor[..ky_len].to_vec();
        cursor = &cursor[ky_len..];
        let caps_len = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
        cursor = &cursor[2..];
        ensure!(cursor.len() == caps_len, "capabilities length mismatch");
        let caps_encoded = cursor.to_vec();
        let caps = Capabilities::decode(&caps_encoded)?;
        Ok(Self {
            random,
            x_pub,
            kyber_pub,
            caps,
            caps_encoded,
        })
    }
}

impl ClientState {
    pub fn shared_with(self, server: &ServerHello) -> Result<Shared> {
        let ct = kyber768::Ciphertext::from_bytes(&server.kyber_ct)
            .map_err(|e| anyhow!("invalid kyber ciphertext: {e:?}"))?;
        let ss_pq = kyber768::decapsulate(&ct, &self.kyber_sk);
        let classical = if server.chosen_suite.hybrid {
            let peer = XPublic::from(server.x_pub);
            Some(self.x_secret.diffie_hellman(&peer).to_bytes())
        } else {
            None
        };
        Ok(Shared {
            classical,
            pq: ss_pq.as_bytes().to_vec(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct ServerHello {
    pub random: [u8; 32],
    pub x_pub: [u8; 32],
    pub kyber_ct: Vec<u8>,
    pub chosen_suite: ChosenSuite,
    pub chosen_suite_encoded: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ServerHello {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.random);
        body.extend_from_slice(&self.x_pub);
        body.extend_from_slice(&(self.kyber_ct.len() as u16).to_be_bytes());
        body.extend_from_slice(&self.kyber_ct);
        body.extend_from_slice(&(self.chosen_suite_encoded.len() as u16).to_be_bytes());
        body.extend_from_slice(&self.chosen_suite_encoded);
        body.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        body.extend_from_slice(&self.signature);
        body
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        ensure!(
            payload.len() >= 32 + 32 + 2 + 2 + 2,
            "server hello too short"
        );
        let mut cursor = payload;
        let mut random = [0u8; 32];
        random.copy_from_slice(&cursor[..32]);
        cursor = &cursor[32..];
        let mut x_pub = [0u8; 32];
        x_pub.copy_from_slice(&cursor[..32]);
        cursor = &cursor[32..];
        ensure!(cursor.len() >= 2, "missing kyber ct length");
        let ct_len = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
        cursor = &cursor[2..];
        ensure!(cursor.len() >= ct_len + 2, "kyber ct truncated");
        let kyber_ct = cursor[..ct_len].to_vec();
        cursor = &cursor[ct_len..];
        let suite_len = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
        cursor = &cursor[2..];
        ensure!(cursor.len() >= suite_len + 2, "suite truncated");
        let chosen_suite_encoded = cursor[..suite_len].to_vec();
        cursor = &cursor[suite_len..];
        let chosen_suite = ChosenSuite::decode(&chosen_suite_encoded)?;
        let sig_len = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
        cursor = &cursor[2..];
        ensure!(cursor.len() == sig_len, "signature truncated");
        let signature = cursor.to_vec();
        Ok(Self {
            random,
            x_pub,
            kyber_ct,
            chosen_suite,
            chosen_suite_encoded,
            signature,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ChosenSuite {
    pub kem: KemAlgorithm,
    pub sig: SigAlgorithm,
    pub hybrid: bool,
}

impl ChosenSuite {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(7);
        out.extend_from_slice(&TLV_CHOSEN_SUITE.to_be_bytes());
        out.extend_from_slice(&(5u16).to_be_bytes());
        out.extend_from_slice(&(self.kem as u16).to_be_bytes());
        out.extend_from_slice(&(self.sig as u16).to_be_bytes());
        out.push(if self.hybrid { 1 } else { 0 });
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() >= 9, "chosen suite too short");
        ensure!(
            u16::from_be_bytes([bytes[0], bytes[1]]) == TLV_CHOSEN_SUITE,
            "bad suite tag"
        );
        let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        ensure!(len == 5 && bytes.len() == len + 4, "bad suite len");
        let kem = KemAlgorithm::try_from(u16::from_be_bytes([bytes[4], bytes[5]]))?;
        let sig = SigAlgorithm::try_from(u16::from_be_bytes([bytes[6], bytes[7]]))?;
        let hybrid = bytes[8] != 0;
        Ok(Self { kem, sig, hybrid })
    }
}

#[derive(Clone, Debug)]
pub struct ClientAuth {
    pub signature: Vec<u8>,
}

impl ClientAuth {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() >= 2, "client auth too short");
        let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        ensure!(bytes.len() - 2 == len, "client signature length mismatch");
        Ok(Self {
            signature: bytes[2..].to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Shared {
    pub classical: Option<[u8; 32]>,
    pub pq: Vec<u8>,
}

pub fn transcript_from_messages(client: &ClientHello, server: &ServerHello) -> Vec<u8> {
    build_transcript(
        &client.random,
        &server.random,
        &client.x_pub,
        &server.x_pub,
        &client.kyber_pub,
        &server.kyber_ct,
        &client.caps_encoded,
        &server.chosen_suite_encoded,
    )
}

pub fn build_transcript(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    client_x: &[u8; 32],
    server_x: &[u8; 32],
    client_kyber_pub: &[u8],
    server_kyber_ct: &[u8],
    caps_encoded: &[u8],
    suite_encoded: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        4 + 32
            + 32
            + 32
            + 32
            + client_kyber_pub.len()
            + server_kyber_ct.len()
            + caps_encoded.len()
            + suite_encoded.len(),
    );
    out.extend_from_slice(b"QSL1");
    out.extend_from_slice(client_random);
    out.extend_from_slice(server_random);
    out.extend_from_slice(client_x);
    out.extend_from_slice(server_x);
    out.extend_from_slice(client_kyber_pub);
    out.extend_from_slice(server_kyber_ct);
    out.extend_from_slice(caps_encoded);
    out.extend_from_slice(suite_encoded);
    out
}

pub fn preauth_hash(transcript: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(transcript);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn push_tlv_u16_list<I: Iterator<Item = u16>>(out: &mut Vec<u8>, tag: u16, values: I) {
    let mut tmp = Vec::new();
    for value in values {
        tmp.extend_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&(tmp.len() as u16).to_be_bytes());
    out.extend_from_slice(&tmp);
}

fn push_tlv_bool(out: &mut Vec<u8>, tag: u16, value: bool) {
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.push(if value { 1 } else { 0 });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_roundtrip() {
        let caps = Capabilities::new(true, true);
        let encoded = caps.encode();
        let decoded = Capabilities::decode(&encoded).expect("decode");
        assert_eq!(caps, decoded);
    }

    #[test]
    fn chosen_suite_roundtrip() {
        let suite = ChosenSuite {
            kem: KemAlgorithm::Kyber768,
            sig: SigAlgorithm::Dilithium2,
            hybrid: true,
        };
        let encoded = suite.encode();
        let decoded = ChosenSuite::decode(&encoded).expect("suite");
        assert_eq!(suite.kem, decoded.kem);
        assert_eq!(suite.sig, decoded.sig);
        assert_eq!(suite.hybrid, decoded.hybrid);
    }
}
