use std::fs;
use std::path::Path;

use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};

fn main() -> anyhow::Result<()> {
    let out_dir = if cfg!(target_os = "windows") {
                            r"C:\QuantumSafeSMB\certs"
                        } else if cfg!(target_os = "linux") {
                            "/home/kali/QuantumSafeSMB/certs"
                        } else {
                            "certs"
                        };
    let dir = Path::new(out_dir);
    fs::create_dir_all(dir)?;
    let (pk, sk) = dilithium2::keypair();
    let pk_path = dir.join("server_dilithium.pk");
    let sk_path = dir.join("server_dilithium.sk");
    fs::write(&pk_path, pk.as_bytes())?;
    fs::write(&sk_path, sk.as_bytes())?;
    println!("  Secret key: {} ", sk_path.display());
    println!("  Public key: {} ", pk_path.display());
    println!();
    Ok(())
}   