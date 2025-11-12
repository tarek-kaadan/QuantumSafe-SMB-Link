// src/net.rs
use anyhow::Result;
use tokio::{net::{TcpListener, TcpStream}, io::{AsyncReadExt, AsyncWriteExt}};
use crate::aead::{NonceCounter, aead_seal, aead_open};
use crate::frame::{write_frame, read_frame};

pub async fn run_server(bind: &str, forward_to: &str) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    loop {
        let (tunnel_sock, _addr) = listener.accept().await?;
        let forward_to = forward_to.to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_server_conn(tunnel_sock, &forward_to).await {
                eprintln!("[server] conn error: {e:?}");
            }
        });
    }
}

async fn handle_server_conn(mut tunnel: TcpStream, forward_to: &str) -> Result<()> {
    // 1) handshake: receive ClientHello, send ServerHello, verify Dilithium, derive SessionKeys
    // let (keys, aad) = handshake_server(&mut tunnel).await?;
    let (keys, aad) = super::main_handshake_server(&mut tunnel).await?; // or wherever you put it

    // 2) connect to real SMB
    let smb = TcpStream::connect(forward_to).await?;

    // 3) start bidirectional pumps
    let mut n_tx = NonceCounter::default();
    let (mut tunnel_r, mut tunnel_w) = tunnel.into_split();
    let (mut smb_r, mut smb_w) = smb.into_split();

    // app -> server: decrypt from tunnel and write plaintext to SMB
    let rx_key = keys.rx;

    let aad_rx = aad.clone();
    let t1 = tokio::spawn(async move {
        let aad = aad_rx;
        loop {
            let (nonce, ct) = read_frame(&mut tunnel_r).await?;
            // (optional) track last nonce here if you need monotonic enforcement
            let pt = aead_open(&rx_key, &nonce_to_12(nonce), &ct, &aad)?;
            smb_w.write_all(&pt).await?;
        }
        #[allow(unreachable_code)] Ok::<(), anyhow::Error>(())
    });

    // client app -> tunnel: read plaintext from SMB, encrypt, send to tunnel
    let tx_key = keys.tx;

    let t2 = tokio::spawn(async move {
        let aad = aad;
        let mut buf = vec![0u8; 16*1024];
        loop {
            let n = smb_r.read(&mut buf).await?;
            if n == 0 { break; }
            let nonce = n_tx.next();
            let ct = aead_seal(&tx_key, &nonce_to_12(nonce), &buf[..n], &aad)?;
            write_frame(&mut tunnel_w, nonce, &ct).await?;
        }
        Ok::<_, anyhow::Error>(())
    });

    let _ = tokio::try_join!(t1, t2)?;
    Ok(())
}

pub async fn run_client(listen: &str, dial: &str) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    loop {
        let (app_sock, _addr) = listener.accept().await?;
        let dial = dial.to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_client_conn(app_sock, &dial).await {
                eprintln!("[client] conn error: {e:?}");
            }
        });
    }
}

async fn handle_client_conn(app: TcpStream, dial: &str) -> Result<()> {
    let mut tunnel = TcpStream::connect(dial).await?;

    // handshake: send ClientHello, receive ServerHello, verify Dilithium, derive SessionKeys
    let (keys, aad) = super::main_handshake_client(&mut tunnel).await?;

    let mut n_tx = NonceCounter::default();
    let (mut app_r, mut app_w) = app.into_split();
    let (mut tun_r, mut tun_w) = tunnel.into_split();

    // app -> tunnel
    let tx_key = keys.tx;

    let aad_tx = aad.clone();
    let t1 = tokio::spawn(async move {
        let aad = aad_tx;
        let mut buf = vec![0u8; 16*1024];
        loop {
            let n = app_r.read(&mut buf).await?;
            if n == 0 { break; }
            let nonce = n_tx.next();
            let ct = aead_seal(&tx_key, &nonce_to_12(nonce), &buf[..n], &aad)?;
            write_frame(&mut tun_w, nonce, &ct).await?;
        }
        Ok::<_, anyhow::Error>(())
    });

    // tunnel -> app
    let rx_key = keys.rx;

    let t2 = tokio::spawn(async move {
        let aad = aad;
        loop {
            let (nonce, ct) = read_frame(&mut tun_r).await?;
            let pt = aead_open(&rx_key, &nonce_to_12(nonce), &ct, &aad)?;
            app_w.write_all(&pt).await?;
        }
        #[allow(unreachable_code)] Ok::<(), anyhow::Error>(())
    });

    let _ = tokio::try_join!(t1, t2)?;
    Ok(())
}

fn nonce_to_12(n: u64) -> [u8;12] {
    let mut out = [0u8;12]; out[4..].copy_from_slice(&n.to_be_bytes()); out
}
