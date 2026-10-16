//! The sockets the KDC client, DNS and kpasswd talk through.
//!
//! The exchanges are written once, as `async fn`s generic over [`Net`].
//! The blocking API runs them on [`Blocking`], whose operations are
//! plain `std::net` calls that finish before they return, so
//! [`block_on`] polls each future once; the `tokio` feature's API runs
//! them on tokio's (`Tokio`).

use std::future::{Future, ready};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

/// Connected UDP sockets and TCP streams, with a timeout on each wait.
pub(crate) trait Net: Sync {
    type Udp: Send + Sync;
    type Tcp: Send;

    /// The addresses `host:port` (or `[v6]:port`) names.
    fn resolve(&self, addr: &str) -> impl Future<Output = io::Result<Vec<SocketAddr>>> + Send;
    /// A UDP socket on an ephemeral port, connected to `peer`, so the
    /// kernel drops datagrams from anyone else.
    fn udp(&self, peer: SocketAddr) -> impl Future<Output = io::Result<Self::Udp>> + Send;
    fn send(&self, s: &Self::Udp, data: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
    fn recv(
        &self,
        s: &Self::Udp,
        buf: &mut [u8],
        timeout: Duration,
    ) -> impl Future<Output = io::Result<usize>> + Send;
    fn udp_local(&self, s: &Self::Udp) -> io::Result<SocketAddr>;
    fn connect(
        &self,
        peer: SocketAddr,
        timeout: Duration,
    ) -> impl Future<Output = io::Result<Self::Tcp>> + Send;
    fn write_all(
        &self,
        s: &mut Self::Tcp,
        data: &[u8],
        timeout: Duration,
    ) -> impl Future<Output = io::Result<()>> + Send;
    fn read_exact(
        &self,
        s: &mut Self::Tcp,
        buf: &mut [u8],
        timeout: Duration,
    ) -> impl Future<Output = io::Result<()>> + Send;
    fn tcp_local(&self, s: &Self::Tcp) -> io::Result<SocketAddr>;
}

/// Run a future whose every await is on [`Blocking`] to its end.
pub(crate) fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => unreachable!("blocking I/O does not wait"),
    }
}

fn unspecified(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
    }
}

/// `std::net`, blocking the calling thread.
pub(crate) struct Blocking;

impl Net for Blocking {
    type Udp = std::net::UdpSocket;
    type Tcp = std::net::TcpStream;

    fn resolve(&self, addr: &str) -> impl Future<Output = io::Result<Vec<SocketAddr>>> + Send {
        ready(addr.to_socket_addrs().map(Iterator::collect))
    }

    fn udp(&self, peer: SocketAddr) -> impl Future<Output = io::Result<Self::Udp>> + Send {
        ready(std::net::UdpSocket::bind(unspecified(peer)).and_then(|s| {
            s.connect(peer)?;
            Ok(s)
        }))
    }

    fn send(&self, s: &Self::Udp, data: &[u8]) -> impl Future<Output = io::Result<()>> + Send {
        ready(s.send(data).map(drop))
    }

    fn recv(
        &self,
        s: &Self::Udp,
        buf: &mut [u8],
        timeout: Duration,
    ) -> impl Future<Output = io::Result<usize>> + Send {
        ready(s.set_read_timeout(Some(timeout)).and_then(|()| s.recv(buf)))
    }

    fn udp_local(&self, s: &Self::Udp) -> io::Result<SocketAddr> {
        s.local_addr()
    }

    fn connect(
        &self,
        peer: SocketAddr,
        timeout: Duration,
    ) -> impl Future<Output = io::Result<Self::Tcp>> + Send {
        ready(std::net::TcpStream::connect_timeout(&peer, timeout))
    }

    fn write_all(
        &self,
        s: &mut Self::Tcp,
        data: &[u8],
        timeout: Duration,
    ) -> impl Future<Output = io::Result<()>> + Send {
        use std::io::Write;
        ready(
            s.set_write_timeout(Some(timeout))
                .and_then(|()| s.write_all(data)),
        )
    }

    fn read_exact(
        &self,
        s: &mut Self::Tcp,
        buf: &mut [u8],
        timeout: Duration,
    ) -> impl Future<Output = io::Result<()>> + Send {
        use std::io::Read;
        ready(
            s.set_read_timeout(Some(timeout))
                .and_then(|()| s.read_exact(buf)),
        )
    }

    fn tcp_local(&self, s: &Self::Tcp) -> io::Result<SocketAddr> {
        s.local_addr()
    }
}

/// tokio's sockets and timers, on the runtime the caller is in (which
/// needs its I/O and time drivers: `Runtime::new`, or `enable_all`).
#[cfg(feature = "tokio")]
pub(crate) struct Tokio;

#[cfg(feature = "tokio")]
async fn timed<T>(timeout: Duration, f: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(timeout, f)
        .await
        .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "timed out")))
}

#[cfg(feature = "tokio")]
impl Net for Tokio {
    type Udp = tokio::net::UdpSocket;
    type Tcp = tokio::net::TcpStream;

    async fn resolve(&self, addr: &str) -> io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host(addr).await?.collect())
    }

    async fn udp(&self, peer: SocketAddr) -> io::Result<Self::Udp> {
        let s = tokio::net::UdpSocket::bind(unspecified(peer)).await?;
        s.connect(peer).await?;
        Ok(s)
    }

    async fn send(&self, s: &Self::Udp, data: &[u8]) -> io::Result<()> {
        s.send(data).await.map(drop)
    }

    async fn recv(&self, s: &Self::Udp, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        timed(timeout, s.recv(buf)).await
    }

    fn udp_local(&self, s: &Self::Udp) -> io::Result<SocketAddr> {
        s.local_addr()
    }

    async fn connect(&self, peer: SocketAddr, timeout: Duration) -> io::Result<Self::Tcp> {
        timed(timeout, tokio::net::TcpStream::connect(peer)).await
    }

    async fn write_all(&self, s: &mut Self::Tcp, data: &[u8], timeout: Duration) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        timed(timeout, s.write_all(data)).await
    }

    async fn read_exact(
        &self,
        s: &mut Self::Tcp,
        buf: &mut [u8],
        timeout: Duration,
    ) -> io::Result<()> {
        use tokio::io::AsyncReadExt;
        timed(timeout, async { s.read_exact(buf).await.map(drop) }).await
    }

    fn tcp_local(&self, s: &Self::Tcp) -> io::Result<SocketAddr> {
        s.local_addr()
    }
}
