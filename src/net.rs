use anyhow::Result;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

pub async fn copy_bidirectional(mut a: TcpStream, mut b: TcpStream) -> Result<()> {
    let (mut ar, mut aw) = a.split();
    let (mut br, mut bw) = b.split();
    let t1 = tokio::io::copy(&mut ar, &mut bw);
    let t2 = tokio::io::copy(&mut br, &mut aw);
    let _ = tokio::try_join!(t1, t2)?;
    Ok(())
}
