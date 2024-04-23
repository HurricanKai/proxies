#![forbid(unsafe_code)]
use std::{
    collections::HashMap,
    future::Future,
    hash::{DefaultHasher, Hasher},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
};

use base64::Engine;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::Bytes, client::conn::http1::Builder, server::conn::http1, service::Service,
    upgrade::Upgraded, Method, Request, Response,
};
use hyper_util::rt::TokioIo;
use log::{error, info};
use server::util::target_addr::TargetAddr;
use std::net::ToSocketAddrs;
use tokio::{fs::File, io::AsyncWriteExt, net::TcpSocket};
use tokio_stream::StreamExt;

use crate::server::{DynamicUserPassword, IpSessionInfo, User};

pub mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    info!("Calculating Users...");

    let mut csv_file = File::create("/tmp/users.csv").await.unwrap();

    csv_file
        .write_all("username,password,address,port\n".as_bytes())
        .await
        .unwrap();

    let cidr = cidr::Ipv4Cidr::new(Ipv4Addr::new(89, 36, 34, 128), 25).unwrap();

    let mut allowed_users = HashMap::new();
    let first_address = cidr.first_address();

    let mut hasher = DefaultHasher::new();
    for inet in cidr.iter().skip(1) {
        let address = inet.address();
        let num: u32 = address.into();
        hasher.write_u32(num);

        let username = format!("u_{num}");
        let password = base64::prelude::BASE64_STANDARD.encode(hasher.finish().to_le_bytes());
        info!("Generated User: http://{username}:{password}@{first_address}:1080");

        allowed_users.insert(
            username.clone(),
            (password.clone(), IpSessionInfo { address }),
        );
        csv_file
            .write_all(format!("{},\"{}\",{},1080\n", username, password, first_address).as_bytes())
            .await
            .unwrap();
    }

    let allowed_users = Arc::new(allowed_users);

    info!("Starting Servers...");

    let mut tasks = tokio::task::JoinSet::<()>::new();

    tasks.spawn(run_socks5(first_address, allowed_users.clone()));
    tasks.spawn(run_http(first_address, allowed_users.clone()));

    info!("Waiting to exit...");
    while let Some(_) = tasks.join_next().await {}
    info!("All done! Bye");

    Ok(())
}

async fn run_socks5(
    listen_on: Ipv4Addr,
    allowed_users: Arc<HashMap<String, (String, IpSessionInfo)>>,
) {
    let username = "user".to_string();
    let password = "password".to_string();

    let mut config =
        server::Config::default().with_authentication(DynamicUserPassword::new(allowed_users));

    config.set_dns_resolve(true);
    config.set_udp_support(true);
    config.set_execute_command(true);

    let config = config;

    info!("Listening on http://{username}:{password}@{listen_on}:1080");
    let server = server::Socks5Server::bind((listen_on, 1080))
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

async fn run_http(
    listen_on: Ipv4Addr,
    allowed_users: Arc<HashMap<String, (String, IpSessionInfo)>>,
) {
    info!("Listening HTTP on {listen_on}:8118");
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind((listen_on, 8118).into()).unwrap();

    let listener = socket.listen(16).unwrap();
    let service = ProxyService {
        allowed_users: allowed_users,
    };

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
                println!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

#[derive(Debug, Clone)]
struct ProxyService {
    allowed_users: Arc<HashMap<String, (String, IpSessionInfo)>>,
}

impl Service<Request<hyper::body::Incoming>> for ProxyService {
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = http::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<hyper::body::Incoming>) -> Self::Future {
        let allowed_users = self.allowed_users.clone();
        Box::pin(async move {
            let auth =
                req.headers()
                    .get("Proxy-Authorization")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|h| h.split_once(' '))
                    .and_then(|(method, value)| match method {
                        "Basic" => base64::prelude::BASE64_STANDARD
                            .decode(value)
                            .ok()
                            .and_then(|e| String::from_utf8(e).ok())
                            .and_then(|e| {
                                e.split_once(':').and_then(|(username, password)| {
                                    allowed_users.get(username).and_then(
                                        |(real_password, session)| match real_password == password {
                                            true => Some(session),
                                            false => None,
                                        },
                                    )
                                })
                            }),
                        _ => None,
                    });

            match auth {
                None => Response::builder()
                    .status(407)
                    .body(full("{ \"error\": \"Proxy Authorization Failed!\" }")),
                Some(session) => {
                    let source_addr = IpAddr::V4(session.address);
                    if Method::CONNECT == req.method() {
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
                                            eprintln!("server io error: {}", e);
                                        };
                                    }
                                    Err(e) => eprintln!("upgrade error: {}", e),
                                }
                            });

                            Ok(Response::new(empty()))
                        } else {
                            eprintln!("CONNECT host is not socket addr: {:?}", req.uri());
                            let mut resp =
                                Response::new(full("CONNECT must be to a socket address"));
                            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

                            Ok(resp)
                        }
                    } else {
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
                                println!("Connection failed: {:?}", err);
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

    println!(
        "client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
}
