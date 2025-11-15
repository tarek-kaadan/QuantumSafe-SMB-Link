// src/frame.rs
use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn write_frame<W: AsyncWriteExt + Unpin>(mut w: W, nonce: u64, ct: &[u8]) -> Result<()> {
    let len: u32 = (8 + ct.len()) as u32; // 8 for u64 nonce
    w.write_u32_le(len).await?;
    w.write_u64_le(nonce).await?;
    w.write_all(ct).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncReadExt + Unpin>(mut r: R) -> Result<(u64, Vec<u8>)> {
    let len = r.read_u32_le().await?;
    if len < 8 {
        bail!("frame too short");
    }
    let nonce = r.read_u64_le().await?;
    let mut buf = vec![0u8; (len - 8) as usize];
    r.read_exact(&mut buf).await?;
    Ok((nonce, buf))
}
