//! QuantumSafe-SMB-Link CLI quick reference:
//! - `quantumsafe-smb-link handshake-test --hybrid on`
//! - `quantumsafe-smb-link server --bind 0.0.0.0:7445 --forward 127.0.0.1:445 --hybrid on`
//! - `quantumsafe-smb-link client --bind 127.0.0.1:1445 --connect SERVER_IP:7445 --hybrid on`
//!
//! Point `--forward 127.0.0.1:445` at the SMB server you want to protect (Windows or Samba).
// src/main.rs
mod aead;
mod frame;
mod kem;
mod net;
mod sig;
mod gen_keys;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{fs, path::PathBuf, sync::Arc};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(
    name = "QuantumSafe-SMB-Link",
    version,
    about = "Post-quantum SMB tunnel"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    HandshakeTest(HandshakeCli),
    Server(ServerCli),
    Client(ClientCli),
    Keygen(KeygenCli),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Toggle {
    On,
    Off,
}

impl Toggle {
    fn as_bool(self) -> bool {
        matches!(self, Toggle::On)
    }
}

#[derive(Args)]
struct HandshakeCli {
    #[arg(long, value_enum, default_value_t = Toggle::On)]
    hybrid: Toggle,
}

#[derive(Args)]
struct ServerCli {
    #[arg(long = "bind", default_value = "0.0.0.0:7445")]
    bind: String,
    #[arg(long = "forward", default_value = "127.0.0.1:445")]
    forward: String,
    #[arg(long = "server-sk")]
    server_sk: PathBuf,
    #[arg(long = "client-pk")]
    client_pk: PathBuf,
    #[arg(long, value_enum, default_value_t = Toggle::On)]
    hybrid: Toggle,
}

#[derive(Args)]
struct ClientCli {
    #[arg(long = "bind", default_value = "127.0.0.1:1445")]
    bind: String,
    #[arg(long = "connect", default_value = "127.0.0.1:7445")]
    connect: String,
    #[arg(long = "client-sk")]
    client_sk: PathBuf,
    #[arg(long = "server-pk")]
    server_pk: PathBuf,
    #[arg(long, value_enum, default_value_t = Toggle::On)]
    hybrid: Toggle,
}

#[derive(Args)]
struct KeygenCli {
    #[arg(long)]
    secret_out: PathBuf,
    #[arg(long)]
    public_out: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::HandshakeTest(args) => {
            net::handshake_self_test(args.hybrid.as_bool()).await?;
        }
        Cmd::Server(args) => {
            let config = net::ServerConfig {
                listen: args.bind,
                forward: args.forward,
                crypto: net::ServerCryptoConfig {
                    server_secret: load_key(&args.server_sk)?,
                    client_public: load_key(&args.client_pk)?,
                    hybrid: args.hybrid.as_bool(),
                    pq_required: true,
                },
            };
            net::run_server(config).await?;
        }
        Cmd::Client(args) => {
            let config = net::ClientConfig {
                listen: args.bind,
                dial: args.connect,
                crypto: net::ClientCryptoConfig {
                    client_secret: load_key(&args.client_sk)?,
                    server_public: load_key(&args.server_pk)?,
                    hybrid: args.hybrid.as_bool(),
                    pq_required: true,
                },
            };
            net::run_client(config).await?;
        }
        Cmd::Keygen(args) => {
            let (pk, sk) = sig::generate_keys();
            fs::write(&args.secret_out, &sk)
                .with_context(|| format!("failed to write secret key {:?}", args.secret_out))?;
            fs::write(&args.public_out, &pk)
                .with_context(|| format!("failed to write public key {:?}", args.public_out))?;
            println!(
                "generated Dilithium2 keypair:\n  secret -> {}\n  public -> {}",
                args.secret_out.display(),
                args.public_out.display()
            );
        }
    }
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}

fn load_key(path: &PathBuf) -> Result<Arc<[u8]>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read key {:?}", path))?;
    Ok(Arc::from(bytes))
}
