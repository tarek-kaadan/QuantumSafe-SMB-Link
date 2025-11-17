use std::fs;
use std::path::Path;

use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};

fn write_keypair(base_path: &str, name: &str) -> anyhow::Result<()> {
    let (pk, sk) = dilithium2::keypair();

    let dir = Path::new(base_path);
    fs::create_dir_all(dir)?;

    let pk_path = dir.join(format!("{}_dilithium.pk", name));
    let sk_path = dir.join(format!("{}_dilithium.sk", name));

    fs::write(&pk_path, pk.as_bytes())?;
    fs::write(&sk_path, sk.as_bytes())?;

    println!("Wrote {} and {}",
             pk_path.display(),
             sk_path.display()
    );

    Ok(())
}

fn main() -> anyhow::Result<()> {
    // You can change "certs" to any directory you like.
    let out_dir = "certs";

    // Generate server keypair
    write_keypair(out_dir, "server")?;

    // Generate client keypair
    write_keypair(out_dir, "client")?;

    println!("Done generating Dilithium2 keypairs.");
    Ok(())
}
