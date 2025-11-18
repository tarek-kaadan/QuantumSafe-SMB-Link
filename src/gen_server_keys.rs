use std::fs;
use std::path::Path;

use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};

fn main() -> anyhow::Result<()> {
    let out_dir = "certs";
    let dir = Path::new(out_dir);
    fs::create_dir_all(dir)?;

    // Generate SERVER keypair only
    let (pk, sk) = dilithium2::keypair();

    let pk_path = dir.join("server_dilithium.pk");
    let sk_path = dir.join("server_dilithium.sk");

    fs::write(&pk_path, pk.as_bytes())?;
    fs::write(&sk_path, sk.as_bytes())?;

    println!("✓ Generated SERVER Dilithium2 keypair:");
    println!("  Secret key: {} (KEEP THIS SECRET!)", sk_path.display());
    println!("  Public key: {} (Share this with clients)", pk_path.display());
    println!();
    println!("Next steps:");
    println!("1. Copy {} to all client machines", pk_path.display());
    println!("2. NEVER share {}", sk_path.display());

    Ok(())
}   