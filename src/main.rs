mod kem; mod sig; mod aead; mod frame; mod net;

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.get(0).map(|s| s.as_str()) {
        Some("server") => server(&args[1..]).await,
        Some("client") => client(&args[1..]).await,
        _ => {
            eprintln!("Usage: server --listen 0.0.0.0:7445 --forward 127.0.0.1:445
   or: client --listen 127.0.0.1:1445 --dial <HOST:7445>");
            Ok(())
        }
    }
}

async fn server(args: &[String]) -> Result<()> {
    let listen = take_arg(args, "--listen").unwrap_or("0.0.0.0:7445".into());
    let forward = take_arg(args, "--forward").unwrap_or("127.0.0.1:445".into());
    let li = TcpListener::bind(&listen).await?;
    println!("Server listening on {}", listen);
    loop {
        let (mut sock, _) = li.accept().await?;
        let forward = forward.clone();
        tokio::spawn(async move {
            let (_x_sk, x_pub_s, ky_ct, ikm) = {
                // 1) recv client hello
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap();
                let client_x_pub = buf[0..32].try_into().unwrap();
                let ky_pk_len = u16::from_le_bytes(buf[32..34].try_into().unwrap()) as usize;
                let ky_pk = &buf[34..34+ky_pk_len];
                kem::server_reply(client_x_pub, ky_pk)
            };
            // 2) send reply
            let mut reply = Vec::new();
            reply.extend_from_slice(&x_pub_s);
            reply.extend_from_slice(&(ky_ct.len() as u16).to_le_bytes());
            reply.extend_from_slice(&ky_ct);
            sock.write_all(&reply).await.unwrap();

            let (k_tx, k_rx) = kem::kdf(b"preauth", &ikm);
            let mut tx = aead::AeadState::new(&k_tx);
            let rx  = aead::AeadState::new(&k_rx);

            // connect to real SMB
            if let Ok(up) = TcpStream::connect(&forward).await {
                // here you would wrap sock<->up with AEAD framing; omitted for brevity
                let _ = net::copy_bidirectional(sock, up).await;
            }
        });
    }
}

async fn client(args: &[String]) -> Result<()> {
    let listen = take_arg(args, "--listen").unwrap_or("127.0.0.1:1445".into());
    let dial   = take_arg(args, "--dial").unwrap_or("127.0.0.1:7445".into());
    let li = TcpListener::bind(&listen).await?;
    println!("Client listening on {}", listen);
    loop {
        let (mut local, _) = li.accept().await?;
        let dial = dial.clone();
        tokio::spawn(async move {
            let mut sock = TcpStream::connect(&dial).await.unwrap();

            // 1) build hello
            let (x_sk, x_pub_c, ky_pk, ky_sk) = kem::client_generate();
            let mut hello = Vec::new();
            hello.extend_from_slice(&x_pub_c);
            hello.extend_from_slice(&(ky_pk.len() as u16).to_le_bytes());
            hello.extend_from_slice(&ky_pk);
            sock.write_all(&hello).await.unwrap();

            // 2) read reply
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let x_pub_s = buf[0..32].try_into().unwrap();
            let ct_len = u16::from_le_bytes(buf[32..34].try_into().unwrap()) as usize;
            let ky_ct = &buf[34..34+ct_len];

            let ikm = kem::client_finish(x_sk, x_pub_s, ky_ct, &ky_sk);
            let (k_tx, k_rx) = kem::kdf(b"preauth", &ikm);
            let mut tx = aead::AeadState::new(&k_tx);
            let rx  = aead::AeadState::new(&k_rx);

            // connect local SMB app <-> tunnel
            let _ = net::copy_bidirectional(local, sock).await;
        });
    }
}

fn take_arg(args: &[String], key: &str) -> Option<String> {
    args.windows(2).find(|w| w[0]==key).map(|w| w[1].clone())
}
