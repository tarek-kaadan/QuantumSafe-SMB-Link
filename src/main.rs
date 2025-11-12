// src/main.rs
mod aead;
mod frame;
mod net;
mod kem;
mod sig; // adjust to your filenames
use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const HYBRID_MODE: bool = true;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Server { listen: String, forward: String, /* keys etc. */ },
    Client { listen: String, dial: String, /* keys etc. */ },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Server { listen, forward } => net::run_server(&listen, &forward).await?,
        Cmd::Client { listen, dial }    => net::run_client(&listen, &dial).await?,
    }
    Ok(())
}

/// Called by net.rs during handshake
pub async fn main_handshake_client(stream: &mut tokio::net::TcpStream) -> Result<(aead::SessionKeys, Vec<u8>)> {
    let (client_hello, client_state) = crate::kem::client_make_hello(HYBRID_MODE)?;
    let hello_bytes =
        bincode::serde::encode_to_vec(&client_hello, bincode::config::standard())?;
    stream.write_all(&hello_bytes).await?;

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let (server_hello, _) = bincode::serde::decode_from_slice::<crate::kem::ServerHello, _>(
        &buf[..n],
        bincode::config::standard(),
    )?;

    let shared = crate::kem::client_finish(client_state, &server_hello)?;
    let transcript = crate::kem::transcript(&client_hello, &server_hello);
    let preauth = crate::kem::preauth_hash(&transcript);
    let ikm = crate::kem::ikm_from_shared(&shared)?;
    let keys = aead::SessionKeys::derive(&preauth, &ikm);
    Ok((keys, preauth.to_vec()))
}

pub async fn main_handshake_server(stream: &mut tokio::net::TcpStream) -> Result<(aead::SessionKeys, Vec<u8>)> {
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let (client_hello, _) = bincode::serde::decode_from_slice::<crate::kem::ClientHello, _>(
        &buf[..n],
        bincode::config::standard(),
    )?;

    let (server_hello, shared) = crate::kem::server_reply(&client_hello, HYBRID_MODE)?;
    let reply =
        bincode::serde::encode_to_vec(&server_hello, bincode::config::standard())?;
    stream.write_all(&reply).await?;

    let transcript = crate::kem::transcript(&client_hello, &server_hello);
    let preauth = crate::kem::preauth_hash(&transcript);
    let ikm = crate::kem::ikm_from_shared(&shared)?;
    let keys = aead::SessionKeys::derive(&preauth, &ikm);
    Ok((keys, preauth.to_vec()))
}
