#![forbid(unsafe_code)]
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
};

use base64::Engine;
use clap::Parser;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::Bytes, client::conn::http1::Builder, server::conn::http1, service::Service,
    upgrade::Upgraded, Method, Request, Response,
};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use rusqlite::{Connection, OpenFlags};
use server::util::target_addr::TargetAddr;
use std::net::ToSocketAddrs;
use tokio::{net::TcpSocket, sync::Mutex};
use tokio_stream::StreamExt;

use crate::server::{DynamicUserPassword, IpSessionInfo, User};

pub mod server;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(short, long)]
    database: PathBuf,

    #[arg(short, long)]
    listen: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Cli::parse();

    let mut tasks = tokio::task::JoinSet::<()>::new();
    let db = Arc::new(Mutex::new(rusqlite::Connection::open_with_flags(
        args.database,
        OpenFlags::empty()
            .union(OpenFlags::SQLITE_OPEN_READ_ONLY)
            .union(OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .union(OpenFlags::SQLITE_OPEN_URI),
    )?));

    // CREATE TABLE IF NOT EXISTS proxies (
    //     id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    //     address TEXT NOT NULL,
    //     username TEXT NOT NULL,
    //     password TEXT NOT NULL
    // );

    for addr in args.listen.into_iter() {
        if let Ok(url) = url::Url::parse(&addr) {
            match url.scheme() {
                "socks5" => {
                    for addr in url.socket_addrs(|| Some(1080))? {
                        tasks.spawn(run_socks5(addr, db.clone()));
                    }
                }
                "http" => {
                    for addr in url.socket_addrs(|| Some(8118))? {
                        tasks.spawn(run_http(addr, db.clone()));
                    }
                }
                x => {
                    error!("Unknown schema {x}")
                }
            }
        }
    }
    info!("Waiting to exit...");
    while let Some(_) = tasks.join_next().await {}
    info!("All done! Bye");

    Ok(())
}

async fn run_socks5(listen_on: SocketAddr, db: Arc<Mutex<Connection>>) {
    let mut config = server::Config::default().with_authentication(DynamicUserPassword::new(db));

    config.set_dns_resolve(true);
    config.set_udp_support(true);
    config.set_execute_command(true);

    let config = config;

    info!("Listening on http://<user>:<password>@{listen_on}:1080");
    let server = server::Socks5Server::bind(listen_on)
        .await
        .unwrap()
        .with_config(config);

    let mut incoming = server.incoming();

    let mut tasks = tokio::task::JoinSet::<()>::new();

    // Standard TCP loop
    while let Some(socket_res) = incoming.next().await {
        match socket_res {
            Ok(socket) => {
                let socks = socket.upgrade_to_socks5();

                tasks.spawn(async move {
                    match socks.await {
                        Ok(mut socket) => {
                            if let Some(User {
                                username,
                                value: session_info,
                            }) = socket.take_credentials()
                            {
                                info!("Connected {username} for {:?}", session_info)
                            };
                        }
                        Err(err) => {
                            error!("{:#}", &err);
                        }
                    }
                });
            }
            Err(err) => {
                error!("accept error = {:?}", err);
            }
        }
    }

    info!("Exited listen loop?? Exiting...");
    while let Some(_) = tasks.join_next().await {}
}

async fn run_http(listen_on: SocketAddr, db: Arc<Mutex<Connection>>) {
    info!("Listening HTTP on {listen_on}");
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(listen_on).unwrap();

    let listener = socket.listen(16).unwrap();
    let service = ProxyService { db: db };

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);

        let service = service.clone();
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                warn!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

#[derive(Debug, Clone)]
struct ProxyService {
    db: Arc<Mutex<Connection>>,
}

impl Service<Request<hyper::body::Incoming>> for ProxyService {
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = http::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<hyper::body::Incoming>) -> Self::Future {
        let db = self.db.clone();
        Box::pin(async move {
            let auth = req
                .headers()
                .get("Proxy-Authorization")
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.split_once(' '))
                .and_then(|(method, value)| match method {
                    "Basic" => base64::prelude::BASE64_STANDARD
                        .decode(value)
                        .ok()
                        .and_then(|e| String::from_utf8(e).ok())
                        .and_then(|e| e.split_once(':').map(|(a, b)| (a.to_owned(), b.to_owned()))),
                    _ => None,
                });

            let auth = if let Some((username, password)) = auth {
                get_user(db.as_ref(), &username, &password)
                    .await
                    .unwrap_or_else(|_| None)
            } else {
                None
            };

            match auth {
                None => Response::builder()
                    .status(407)
                    .body(full("{ \"error\": \"Proxy Authorization Failed!\" }")),
                Some(session) => {
                    let source_addr = session.address;
                    if Method::CONNECT == req.method() {
                        info!("Running CONNECT based HTTP stream");
                        // Received an HTTP request like:
                        // ```
                        // CONNECT www.domain.com:443 HTTP/1.1
                        // Host: www.domain.com:443
                        // Proxy-Connection: Keep-Alive
                        // ```
                        //
                        // When HTTP method is CONNECT we should return an empty body
                        // then we can eventually upgrade the connection and talk a new protocol.
                        //
                        // Note: only after client received an empty body with STATUS_OK can the
                        // connection be upgraded, so we can't return a response inside
                        // `on_upgrade` future.
                        if let Some(host) = req.uri().host() {
                            let port = req.uri().port_u16().unwrap_or(80);
                            let target_addr = match host.parse::<IpAddr>() {
                                Ok(addr) => TargetAddr::Ip((addr, port).into()),
                                Err(_) => TargetAddr::Domain(host.to_owned(), port),
                            };

                            tokio::task::spawn(async move {
                                let target_addr = if target_addr.is_domain() {
                                    target_addr
                                        .resolve_dns(source_addr.is_ipv4())
                                        .await
                                        .unwrap()
                                } else {
                                    target_addr
                                };

                                let target_addr_socket =
                                    target_addr.to_socket_addrs().unwrap().next().unwrap();

                                match hyper::upgrade::on(req).await {
                                    Ok(upgraded) => {
                                        if let Err(e) =
                                            tunnel(upgraded, target_addr_socket, source_addr).await
                                        {
                                            error!("server io error: {}", e);
                                        };
                                    }
                                    Err(e) => error!("upgrade error: {}", e),
                                }
                            });

                            Ok(Response::new(empty()))
                        } else {
                            error!("CONNECT host is not socket addr: {:?}", req.uri());
                            let mut resp =
                                Response::new(full("CONNECT must be to a socket address"));
                            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

                            Ok(resp)
                        }
                    } else {
                        info!("Running direct HTTP request");
                        let host = req.uri().host().expect("uri has no host");
                        let port = req.uri().port_u16().unwrap_or(80);
                        let target_addr = match host.parse::<IpAddr>() {
                            Ok(addr) => TargetAddr::Ip((addr, port).into()),
                            Err(_) => TargetAddr::Domain(host.to_owned(), port),
                        };

                        let socket = match source_addr {
                            IpAddr::V4(addr) => {
                                let socket = TcpSocket::new_v4().unwrap();
                                socket
                                    .bind(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                                        addr, 0,
                                    )))
                                    .unwrap();
                                socket
                            }
                            IpAddr::V6(addr) => {
                                let socket = TcpSocket::new_v6().unwrap();
                                socket
                                    .bind(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                                        addr, 0, 0, 0,
                                    )))
                                    .unwrap();
                                socket
                            }
                        };

                        let target_addr = if target_addr.is_domain() {
                            target_addr
                                .resolve_dns(source_addr.is_ipv4())
                                .await
                                .unwrap()
                        } else {
                            target_addr
                        };

                        let target_addr_socket =
                            target_addr.to_socket_addrs().unwrap().next().unwrap();

                        let stream = socket.connect(target_addr_socket).await.unwrap();
                        let io = TokioIo::new(stream);

                        let (mut sender, conn) = Builder::new()
                            .preserve_header_case(true)
                            .title_case_headers(true)
                            .handshake(io)
                            .await
                            .unwrap();
                        tokio::task::spawn(async move {
                            if let Err(err) = conn.await {
                                error!("Connection failed: {:?}", err);
                            }
                        });

                        let resp = sender.send_request(req).await.unwrap();
                        Ok(resp.map(|b| b.boxed()))
                    }
                }
            }
        })
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

async fn tunnel(upgraded: Upgraded, addr: SocketAddr, source_addr: IpAddr) -> std::io::Result<()> {
    debug!("Tunneling {} to {}", addr, source_addr);
    let socket = match source_addr {
        IpAddr::V4(addr) => {
            let socket = TcpSocket::new_v4().unwrap();
            socket
                .bind(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                    addr, 0,
                )))
                .unwrap();
            socket
        }
        IpAddr::V6(addr) => {
            let socket = TcpSocket::new_v6().unwrap();
            socket
                .bind(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                    addr, 0, 0, 0,
                )))
                .unwrap();
            socket
        }
    };

    let mut server = socket.connect(addr).await?;
    let mut upgraded = TokioIo::new(upgraded);

    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    debug!(
        "client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
}

pub async fn get_user(
    db: &Mutex<Connection>,
    username: &str,
    password: &str,
) -> Result<Option<IpSessionInfo>, anyhow::Error> {
    let db = db.lock().await;

    let r = (match db
        .prepare_cached("SELECT address FROM proxies WHERE username = ?1 AND password = ?2")?
        .query_row([username, password], |r| {
            Ok(IpSessionInfo {
                address: r.get::<&str, String>("address")?.parse().unwrap(),
            })
        }) {
        Ok(x) => Ok(Some(x)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(x) => Err(x),
    })?;

    Ok(r)
}
