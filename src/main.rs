// src/main.rs
mod aead;
mod frame;
mod net;
mod kem;
mod sig;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::{fs, path::PathBuf, sync::Arc};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(name = "QuantumSafe-SMB-Link", version, about = "Post-quantum SMB tunnel")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Server(ServerCli),
    Client(ClientCli),
}

#[derive(Args)]
struct ServerCli {
    #[arg(long, default_value = "0.0.0.0:7445")]
    listen: String,
    #[arg(long, default_value = "127.0.0.1:445")]
    forward: String,
    #[arg(long)]
    server_sk: PathBuf,
    #[arg(long)]
    client_pk: PathBuf,
    #[arg(long, default_value_t = true)]
    hybrid: bool,
    #[arg(long, default_value_t = true)]
    pq_required: bool,
}

#[derive(Args)]
struct ClientCli {
    #[arg(long, default_value = "127.0.0.1:1445")]
    listen: String,
    #[arg(long, default_value = "127.0.0.1:7445")]
    dial: String,
    #[arg(long)]
    client_sk: PathBuf,
    #[arg(long)]
    server_pk: PathBuf,
    #[arg(long, default_value_t = true)]
    hybrid: bool,
    #[arg(long, default_value_t = true)]
    pq_required: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Server(args) => {
            let config = net::ServerConfig {
                listen: args.listen,
                forward: args.forward,
                crypto: net::ServerCryptoConfig {
                    server_secret: load_key(&args.server_sk)?,
                    client_public: load_key(&args.client_pk)?,
                    hybrid: args.hybrid,
                    pq_required: args.pq_required,
                },
            };
            net::run_server(config).await?;
        }
        Cmd::Client(args) => {
            let config = net::ClientConfig {
                listen: args.listen,
                dial: args.dial,
                crypto: net::ClientCryptoConfig {
                    client_secret: load_key(&args.client_sk)?,
                    server_public: load_key(&args.server_pk)?,
                    hybrid: args.hybrid,
                    pq_required: args.pq_required,
                },
            };
            net::run_client(config).await?;
        }
    }
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

fn load_key(path: &PathBuf) -> Result<Arc<[u8]>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read key {:?}", path))?;
    Ok(Arc::from(bytes))
}
