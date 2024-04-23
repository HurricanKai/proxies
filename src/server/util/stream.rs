use crate::server::{ReplyError, Result};
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::io::ErrorKind as IOErrorKind;
use tokio::net::{TcpSocket, TcpStream, ToSocketAddrs};
use tokio::time::timeout;

/// Easy to destructure bytes buffers by naming each fields:
///
/// # Examples (before)
///
/// ```ignore
/// let mut buf = [0u8; 2];
/// stream.read_exact(&mut buf).await?;
/// let [version, method_len] = buf;
///
/// assert_eq!(version, 0x05);
/// ```
///
/// # Examples (after)
///
/// ```ignore
/// let [version, method_len] = read_exact!(stream, [0u8; 2]);
///
/// assert_eq!(version, 0x05);
/// ```
#[macro_export]
macro_rules! read_exact {
    ($stream: expr, $array: expr) => {{
        let mut x = $array;
        //        $stream
        //            .read_exact(&mut x)
        //            .await
        //            .map_err(|_| io_err("lol"))?;
        $stream.read_exact(&mut x).await.map(|_| x)
    }};
}

#[macro_export]
macro_rules! ready {
    ($e:expr $(,)?) => {
        match $e {
            std::task::Poll::Ready(t) => t,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

pub async fn tcp_connect_with_timeout(
    addr: SocketAddr,
    request_timeout_s: u64,
    source_addr: IpAddr,
) -> Result<TcpStream> {
    let fut = tcp_connect(addr, source_addr);
    match timeout(Duration::from_secs(request_timeout_s), fut).await {
        Ok(result) => result,
        Err(_) => Err(ReplyError::ConnectionTimeout.into()),
    }
}

pub async fn tcp_connect(addr: SocketAddr, source_addr: IpAddr) -> Result<TcpStream> {
    let socket = match source_addr {
        IpAddr::V4(addr) => {
            let socket = TcpSocket::new_v4()?;
            socket.bind(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                addr, 0,
            )))?;
            socket
        }
        IpAddr::V6(addr) => {
            let socket = TcpSocket::new_v6()?;
            socket.bind(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                addr, 0, 0, 0,
            )))?;
            socket
        }
    };

    match socket.connect(addr).await {
        Ok(o) => Ok(o),
        Err(e) => match e.kind() {
            // Match other TCP errors with ReplyError
            IOErrorKind::ConnectionRefused => Err(ReplyError::ConnectionRefused.into()),
            IOErrorKind::ConnectionAborted => Err(ReplyError::ConnectionNotAllowed.into()),
            IOErrorKind::ConnectionReset => Err(ReplyError::ConnectionNotAllowed.into()),
            IOErrorKind::NotConnected => Err(ReplyError::NetworkUnreachable.into()),
            _ => Err(e.into()), // #[error("General failure")] ?
        },
    }
}
