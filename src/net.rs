// src/net.rs
use std::{net::SocketAddr, sync::Arc};

use anyhow::{anyhow, bail, ensure, Context, Result};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
use rand_core::{OsRng, RngCore};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublic};

use crate::{
    aead::{self, NonceTicker},
    kem::{
        self, build_transcript, preauth_hash, Capabilities, ChosenSuite, ClientAuth, ClientHello,
        KemAlgorithm, ServerHello, Shared, SigAlgorithm, CLIENT_AUTH_MAGIC, CLIENT_HELLO_MAGIC,
        MAX_HANDSHAKE_LEN, PROTOCOL_VERSION, SERVER_HELLO_MAGIC,
    },
    sig,
};

const HANDSHAKE_HEADER_LEN: usize = 10;
const FRAME_AAD: [u8; 23] = *b"QuantumSafe-SMB-Link v1";

#[derive(Clone)]
pub struct ServerConfig {
    pub listen: String,
    pub forward: String,
    pub crypto: ServerCryptoConfig,
}

#[derive(Clone)]
pub struct ServerCryptoConfig {
    pub server_secret: Arc<[u8]>,
    pub client_public: Arc<[u8]>,
    pub hybrid: bool,
    pub pq_required: bool,
}

#[derive(Clone)]
pub struct ClientConfig {
    pub listen: String,
    pub dial: String,
    pub crypto: ClientCryptoConfig,
}

#[derive(Clone)]
pub struct ClientCryptoConfig {
    pub client_secret: Arc<[u8]>,
    pub server_public: Arc<[u8]>,
    pub hybrid: bool,
    pub pq_required: bool,
}

pub async fn run_server(cfg: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("failed to bind {}", cfg.listen))?;
    info!(listen = %cfg.listen, forward = %cfg.forward, "server waiting for tunnel peers");
    loop {
        let (socket, addr) = listener.accept().await?;
        let forward = cfg.forward.clone();
        let crypto = cfg.crypto.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_server_conn(socket, forward, crypto, addr).await {
                warn!(?err, peer = %addr, "server connection closed with error");
            }
        });
    }
}

pub async fn run_client(cfg: ClientConfig) -> Result<()> {
    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("failed to bind {}", cfg.listen))?;
    info!(listen = %cfg.listen, dial = %cfg.dial, "client shim listening for SMB apps");
    loop {
        let (socket, addr) = listener.accept().await?;
        let dial = cfg.dial.clone();
        let crypto = cfg.crypto.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client_conn(socket, dial, crypto, addr).await {
                warn!(?err, peer = %addr, "client connection closed with error");
            }
        });
    }
}

async fn handle_server_conn(
    mut tunnel: TcpStream,
    forward_to: String,
    crypto: ServerCryptoConfig,
    peer: SocketAddr,
) -> Result<()> {
    info!(%peer, "server running the PQ handshake dance");
    let keys = server_handshake(&mut tunnel, &crypto, Some(peer)).await?;
    let smb = TcpStream::connect(&forward_to)
        .await
        .with_context(|| format!("connect {forward_to}"))?;
    info!(%peer, "server handshake done, wiring tunnel into SMB backend");
    pump_streams(tunnel, smb, keys).await
}

async fn handle_client_conn(
    app: TcpStream,
    dial: String,
    crypto: ClientCryptoConfig,
    peer: SocketAddr,
) -> Result<()> {
    let mut tunnel = TcpStream::connect(&dial)
        .await
        .with_context(|| format!("dial tunnel {dial}"))?;
    info!(local = %peer, remote = %dial, "client dialing tunnel and starting handshake");
    let keys = client_handshake(&mut tunnel, &crypto).await?;
    info!(local = %peer, remote = %dial, "client handshake finished — piping traffic through");
    pump_streams(tunnel, app, keys).await
}

async fn pump_streams(tunnel: TcpStream, target: TcpStream, keys: aead::SessionKeys) -> Result<()> {
    let (mut tunnel_r, mut tunnel_w) = tunnel.into_split();
    let (mut dst_r, mut dst_w) = target.into_split();

    let rx_key = keys.incoming;
    let tx_key = keys.outgoing;
    let aad_rx = FRAME_AAD.as_slice();
    let inbound = tokio::spawn(async move {
        let mut last_nonce: Option<u64> = None;
        loop {
            let (nonce, ct) = read_frame(&mut tunnel_r).await?;
            if let Some(prev) = last_nonce {
                if nonce <= prev {
                    bail!("received out-of-order nonce {nonce} <= {prev}");
                }
            }
            last_nonce = Some(nonce);
            let pt = aead::aead_open(&rx_key, &nonce_to_12(nonce), &ct, aad_rx)?;
            dst_w.write_all(&pt).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    });

    let outbound = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        let mut counter = NonceTicker::default();
        let aad_tx = FRAME_AAD.as_slice();
        loop {
            let n = dst_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let nonce = counter.next();
            let ct = aead::aead_seal(&tx_key, &nonce_to_12(nonce), &buf[..n], aad_tx)?;
            write_frame(&mut tunnel_w, nonce, &ct).await?;
        }
        Ok::<_, anyhow::Error>(())
    });

    match tokio::try_join!(inbound, outbound) {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow!(e)),
    }
}

async fn client_handshake(
    stream: &mut TcpStream,
    crypto: &ClientCryptoConfig,
) -> Result<aead::SessionKeys> {
    let caps = Capabilities::new(crypto.hybrid, crypto.pq_required);
    let (hello, state) = ClientHello::new(caps)?;
    write_handshake_message(stream, HandshakeMessage::ClientHello, &hello.encode()).await?;

    let (kind, payload) = read_handshake_message(stream).await?;
    if !matches!(kind, HandshakeMessage::ServerHello) {
        bail!("expected ServerHello but got {:?}", kind);
    }
    let server_hello = ServerHello::decode(&payload)?;
    if server_hello.chosen_suite.kem != KemAlgorithm::Kyber768 {
        bail!("server replied with an unsupported KEM");
    }
    if server_hello.chosen_suite.sig != SigAlgorithm::Dilithium2 {
        bail!("server replied with an unsupported signature scheme");
    }
    if crypto.pq_required && !matches!(server_hello.chosen_suite.kem, KemAlgorithm::Kyber768) {
        bail!("pq_required but server did not offer PQ suite");
    }

    let transcript = kem::transcript_from_messages(&hello, &server_hello);
    sig::verify_detached(&transcript, &server_hello.signature, &crypto.server_public)?;
    let mode = if server_hello.chosen_suite.hybrid {
        "hybrid"
    } else {
        "pq-only"
    };
    info!(mode = mode, "client handshake: server picked its suite");
    debug!(?server_hello.chosen_suite, "client handshake: peer capabilities looked fine");

    let shared = state.shared_with(&server_hello)?;
    let preauth = kem::preauth_hash(&transcript);
    let classical = shared.classical.as_ref().map(|c| &c[..]);
    let keys = aead::SessionKeys::from_shared(&preauth, classical, &shared.pq, false)?;

    let auth = ClientAuth {
        signature: sig::sign_detached(&transcript, &crypto.client_secret)?,
    };
    write_handshake_message(stream, HandshakeMessage::ClientAuth, &auth.encode()).await?;
    Ok(keys)
}

async fn server_handshake(
    stream: &mut TcpStream,
    crypto: &ServerCryptoConfig,
    peer: Option<SocketAddr>,
) -> Result<aead::SessionKeys> {
    let (kind, payload) = read_handshake_message(stream).await?;
    if !matches!(kind, HandshakeMessage::ClientHello) {
        bail!("expected ClientHello, received {:?}", kind);
    }
    let client_hello = ClientHello::decode(&payload)?;
    if !client_hello
        .caps
        .kem_list
        .iter()
        .any(|k| *k == KemAlgorithm::Kyber768)
    {
        bail!("client didn't advertise Kyber768 support");
    }
    if !client_hello
        .caps
        .sig_list
        .iter()
        .any(|s| *s == SigAlgorithm::Dilithium2)
    {
        bail!("client didn't advertise Dilithium2 support");
    }
    if client_hello.caps.pq_required && !crypto.pq_required {
        bail!("client demands pq_required but server disabled it");
    }

    let mut server_random = [0u8; 32];
    OsRng.fill_bytes(&mut server_random);
    let x_secret = EphemeralSecret::random_from_rng(OsRng);
    let x_pub = XPublic::from(&x_secret).to_bytes();

    let client_pk = kyber768::PublicKey::from_bytes(&client_hello.kyber_pub)
        .map_err(|e| anyhow!("invalid client Kyber pk: {e:?}"))?;
    let (ss_pq, ct) = kyber768::encapsulate(&client_pk);
    let use_hybrid = crypto.hybrid && client_hello.caps.hybrid;
    let classical = if use_hybrid {
        Some(
            x_secret
                .diffie_hellman(&XPublic::from(client_hello.x_pub))
                .to_bytes(),
        )
    } else {
        None
    };
    let shared = Shared {
        classical,
        pq: ss_pq.as_bytes().to_vec(),
    };
    let chosen_suite = ChosenSuite {
        kem: KemAlgorithm::Kyber768,
        sig: SigAlgorithm::Dilithium2,
        hybrid: use_hybrid,
    };
    let suite_bytes = chosen_suite.encode();
    let ct_bytes = ct.as_bytes().to_vec();
    let transcript = build_transcript(
        &client_hello.random,
        &server_random,
        &client_hello.x_pub,
        &x_pub,
        &client_hello.kyber_pub,
        &ct_bytes,
        &client_hello.caps_encoded,
        &suite_bytes,
    );
    let signature = sig::sign_detached(&transcript, &crypto.server_secret)?;
    let server_hello = ServerHello {
        random: server_random,
        x_pub,
        kyber_ct: ct_bytes,
        chosen_suite,
        chosen_suite_encoded: suite_bytes.clone(),
        signature,
    };
    let mode = if use_hybrid { "hybrid" } else { "pq-only" };
    info!(?peer, mode = mode, "server handshake: sending ServerHello");
    debug!(?peer, "server handshake: client advertised caps {:?}", client_hello.caps);
    write_handshake_message(
        stream,
        HandshakeMessage::ServerHello,
        &server_hello.encode(),
    )
    .await?;
    debug!(?peer, "sent ServerHello");

    let (kind, payload) = read_handshake_message(stream).await?;
    if !matches!(kind, HandshakeMessage::ClientAuth) {
        bail!("expected ClientAuth, received {:?}", kind);
    }
    let client_auth = ClientAuth::decode(&payload)?;
    sig::verify_detached(&transcript, &client_auth.signature, &crypto.client_public)?;

    let preauth = preauth_hash(&transcript);
    let classical = shared.classical.as_ref().map(|c| &c[..]);
    let keys = aead::SessionKeys::from_shared(&preauth, classical, &shared.pq, true)?;
    Ok(keys)
}

pub async fn handshake_self_test(hybrid: bool) -> Result<()> {
    info!(hybrid = hybrid, "running in-memory handshake self-test");
    let (server_pk, server_sk) = sig::generate_keys();
    let (client_pk, client_sk) = sig::generate_keys();
    let server_cfg = ServerCryptoConfig {
        server_secret: Arc::from(server_sk),
        client_public: Arc::from(client_pk),
        hybrid,
        pq_required: true,
    };
    let client_cfg = ClientCryptoConfig {
        client_secret: Arc::from(client_sk),
        server_public: Arc::from(server_pk),
        hybrid,
        pq_required: true,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let server_task = tokio::spawn({
        let server_cfg = server_cfg.clone();
        async move {
            let (mut sock, peer) = listener.accept().await?;
            server_handshake(&mut sock, &server_cfg, Some(peer)).await
        }
    });

    let client_task = tokio::spawn({
        let client_cfg = client_cfg.clone();
        async move {
            let mut sock = TcpStream::connect(addr).await?;
            client_handshake(&mut sock, &client_cfg).await
        }
    });

    let (server_res, client_res) = tokio::join!(server_task, client_task);
    let server_keys = server_res??;
    let client_keys = client_res??;
    ensure!(
        server_keys.outgoing == client_keys.incoming && server_keys.incoming == client_keys.outgoing,
        "handshake self-test produced mismatched keys"
    );
    info!(hybrid = hybrid, "handshake self-test passed");
    Ok(())
}

#[derive(Debug)]
enum HandshakeMessage {
    ClientHello,
    ServerHello,
    ClientAuth,
}

impl HandshakeMessage {
    fn magic(self) -> &'static [u8; 4] {
        match self {
            HandshakeMessage::ClientHello => CLIENT_HELLO_MAGIC,
            HandshakeMessage::ServerHello => SERVER_HELLO_MAGIC,
            HandshakeMessage::ClientAuth => CLIENT_AUTH_MAGIC,
        }
    }

    fn from_magic(bytes: &[u8]) -> Result<Self> {
        match bytes {
            b if b == CLIENT_HELLO_MAGIC => Ok(HandshakeMessage::ClientHello),
            b if b == SERVER_HELLO_MAGIC => Ok(HandshakeMessage::ServerHello),
            b if b == CLIENT_AUTH_MAGIC => Ok(HandshakeMessage::ClientAuth),
            other => Err(anyhow!("unknown handshake magic {:?}", other)),
        }
    }
}

async fn read_handshake_message(stream: &mut TcpStream) -> Result<(HandshakeMessage, Vec<u8>)> {
    let mut header = [0u8; HANDSHAKE_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let kind = HandshakeMessage::from_magic(&header[..4])?;
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != PROTOCOL_VERSION {
        bail!("protocol version mismatch {version}");
    }
    let len = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
    if len > MAX_HANDSHAKE_LEN {
        bail!("handshake payload too large: {len}");
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok((kind, payload))
}

async fn write_handshake_message(
    stream: &mut TcpStream,
    kind: HandshakeMessage,
    payload: &[u8],
) -> Result<()> {
    if payload.len() > MAX_HANDSHAKE_LEN {
        bail!("handshake payload too large: {}", payload.len());
    }
    let mut header = [0u8; HANDSHAKE_HEADER_LEN];
    header[..4].copy_from_slice(kind.magic());
    header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    header[6..10].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    stream.write_all(&header).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

fn nonce_to_12(n: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[4..].copy_from_slice(&n.to_be_bytes());
    out
}

async fn write_frame<W: AsyncWriteExt + Unpin>(mut w: W, nonce: u64, ct: &[u8]) -> Result<()> {
    let len: u32 = (8 + ct.len()) as u32;
    w.write_u32_le(len).await?;
    w.write_u64_le(nonce).await?;
    w.write_all(ct).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncReadExt + Unpin>(mut r: R) -> Result<(u64, Vec<u8>)> {
    let len = r.read_u32_le().await?;
    if len < 8 {
        bail!("frame declared shorter than nonce field");
    }
    let nonce = r.read_u64_le().await?;
    let mut buf = vec![0u8; (len - 8) as usize];
    r.read_exact(&mut buf).await?;
    Ok((nonce, buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig;

    #[tokio::test]
    async fn handshake_roundtrip() -> Result<()> {
        let (server_pk, server_sk) = sig::generate_keys();
        let (client_pk, client_sk) = sig::generate_keys();
        let server_cfg = ServerCryptoConfig {
            server_secret: Arc::from(server_sk.clone()),
            client_public: Arc::from(client_pk.clone()),
            hybrid: true,
            pq_required: true,
        };
        let client_cfg = ClientCryptoConfig {
            client_secret: Arc::from(client_sk.clone()),
            server_public: Arc::from(server_pk.clone()),
            hybrid: true,
            pq_required: true,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let server_task = tokio::spawn({
            let server_cfg = server_cfg.clone();
            async move {
                let (mut sock, peer) = listener.accept().await?;
                server_handshake(&mut sock, &server_cfg, Some(peer)).await
            }
        });

        let client_task = tokio::spawn({
            let client_cfg = client_cfg.clone();
            async move {
                let mut sock = TcpStream::connect(addr).await?;
                client_handshake(&mut sock, &client_cfg).await
            }
        });

        let (server_res, client_res) = tokio::join!(server_task, client_task);
        let server_keys = server_res??;
        let client_keys = client_res??;
        assert_eq!(server_keys.outgoing, client_keys.incoming);
        assert_eq!(server_keys.incoming, client_keys.outgoing);
        Ok(())
    }
}
