use crate::read_exact;
use crate::server::util::target_addr::read_address;
use crate::server::util::target_addr::TargetAddr;
use crate::server::util::target_addr::ToTargetAddr;
use anyhow::Context;
use log::error;
use std::fmt;
use std::io;
use thiserror::Error;

use tokio::io::AsyncReadExt;

#[rustfmt::skip]
pub mod consts {
    pub const SOCKS5_VERSION:                          u8 = 0x05;

    pub const SOCKS5_AUTH_METHOD_NONE:                 u8 = 0x00;
    pub const SOCKS5_AUTH_METHOD_GSSAPI:               u8 = 0x01;
    pub const SOCKS5_AUTH_METHOD_PASSWORD:             u8 = 0x02;
    pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE:       u8 = 0xff;

    pub const SOCKS5_CMD_TCP_CONNECT:                  u8 = 0x01;
    pub const SOCKS5_CMD_TCP_BIND:                     u8 = 0x02;
    pub const SOCKS5_CMD_UDP_ASSOCIATE:                u8 = 0x03;

    pub const SOCKS5_ADDR_TYPE_IPV4:                   u8 = 0x01;
    pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME:            u8 = 0x03;
    pub const SOCKS5_ADDR_TYPE_IPV6:                   u8 = 0x04;

    pub const SOCKS5_REPLY_SUCCEEDED:                  u8 = 0x00;
    pub const SOCKS5_REPLY_GENERAL_FAILURE:            u8 = 0x01;
    pub const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED:     u8 = 0x02;
    pub const SOCKS5_REPLY_NETWORK_UNREACHABLE:        u8 = 0x03;
    pub const SOCKS5_REPLY_HOST_UNREACHABLE:           u8 = 0x04;
    pub const SOCKS5_REPLY_CONNECTION_REFUSED:         u8 = 0x05;
    pub const SOCKS5_REPLY_TTL_EXPIRED:                u8 = 0x06;
    pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED:      u8 = 0x07;
    pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

#[derive(Debug, PartialEq)]
pub enum Socks5Command {
    TCPConnect,
    TCPBind,
    UDPAssociate,
}

#[allow(dead_code)]
impl Socks5Command {
    #[inline]
    #[rustfmt::skip]
    fn as_u8(&self) -> u8 {
        match self {
            Socks5Command::TCPConnect   => consts::SOCKS5_CMD_TCP_CONNECT,
            Socks5Command::TCPBind      => consts::SOCKS5_CMD_TCP_BIND,
            Socks5Command::UDPAssociate => consts::SOCKS5_CMD_UDP_ASSOCIATE,
        }
    }

    #[inline]
    #[rustfmt::skip]
    pub fn from_u8(code: u8) -> Option<Socks5Command> {
        match code {
            consts::SOCKS5_CMD_TCP_CONNECT      => Some(Socks5Command::TCPConnect),
            consts::SOCKS5_CMD_TCP_BIND         => Some(Socks5Command::TCPBind),
            consts::SOCKS5_CMD_UDP_ASSOCIATE    => Some(Socks5Command::UDPAssociate),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum AuthenticationMethod {
    None,
    Password { username: String, password: String },
}

impl fmt::Display for AuthenticationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            AuthenticationMethod::None => f.write_str("AuthenticationMethod::None"),
            AuthenticationMethod::Password { .. } => f.write_str("AuthenticationMethod::Password"),
        }
    }
}

//impl Vec<AuthenticationMethod> {
//    pub fn as_bytes(&self) -> &[u8] {
//        self.iter().map(|l| l.as_u8()).collect()
//    }
//}
//
//impl From<&[AuthenticationMethod]> for &[u8] {
//    fn from(_: Vec<AuthenticationMethod>) -> Self {
//        &[0x00]
//    }
//}

#[derive(Error, Debug)]
pub enum SocksError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("the data for key `{0}` is not available")]
    Redaction(String),
    #[error("invalid header (expected {expected:?}, found {found:?})")]
    InvalidHeader { expected: String, found: String },

    #[error("Auth method unacceptable `{0:?}`.")]
    AuthMethodUnacceptable(Vec<u8>),
    #[error("Unsupported SOCKS version `{0}`.")]
    UnsupportedSocksVersion(u8),
    #[error("Domain exceeded max sequence length")]
    ExceededMaxDomainLen(usize),
    #[error("Authentication failed `{0}`")]
    AuthenticationFailed(String),
    #[error("Authentication rejected `{0}`")]
    AuthenticationRejected(String),

    #[error("Error with reply: {0}.")]
    ReplyError(#[from] ReplyError),

    #[cfg(feature = "socks4")]
    #[error("Error with reply: {0}.")]
    ReplySocks4Error(#[from] socks4::ReplyError),

    #[error("Argument input error: `{0}`.")]
    ArgumentInputError(&'static str),

    //    #[error("Other: `{0}`.")]
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T, E = SocksError> = core::result::Result<T, E>;

/// SOCKS5 reply code
#[derive(Error, Debug, Copy, Clone)]
pub enum ReplyError {
    #[error("Succeeded")]
    Succeeded,
    #[error("General failure")]
    GeneralFailure,
    #[error("Connection not allowed by ruleset")]
    ConnectionNotAllowed,
    #[error("Network unreachable")]
    NetworkUnreachable,
    #[error("Host unreachable")]
    HostUnreachable,
    #[error("Connection refused")]
    ConnectionRefused,
    #[error("Connection timeout")]
    ConnectionTimeout,
    #[error("TTL expired")]
    TtlExpired,
    #[error("Command not supported")]
    CommandNotSupported,
    #[error("Address type not supported")]
    AddressTypeNotSupported,
    //    OtherReply(u8),
}

impl ReplyError {
    #[inline]
    #[rustfmt::skip]
    pub fn as_u8(self) -> u8 {
        match self {
            ReplyError::Succeeded               => consts::SOCKS5_REPLY_SUCCEEDED,
            ReplyError::GeneralFailure          => consts::SOCKS5_REPLY_GENERAL_FAILURE,
            ReplyError::ConnectionNotAllowed    => consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
            ReplyError::NetworkUnreachable      => consts::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            ReplyError::HostUnreachable         => consts::SOCKS5_REPLY_HOST_UNREACHABLE,
            ReplyError::ConnectionRefused       => consts::SOCKS5_REPLY_CONNECTION_REFUSED,
            ReplyError::ConnectionTimeout       => consts::SOCKS5_REPLY_TTL_EXPIRED,
            ReplyError::TtlExpired              => consts::SOCKS5_REPLY_TTL_EXPIRED,
            ReplyError::CommandNotSupported     => consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            ReplyError::AddressTypeNotSupported => consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
//            ReplyError::OtherReply(c)           => c,
        }
    }

    #[inline]
    #[rustfmt::skip]
    pub fn from_u8(code: u8) -> ReplyError {
        match code {
            consts::SOCKS5_REPLY_SUCCEEDED                  => ReplyError::Succeeded,
            consts::SOCKS5_REPLY_GENERAL_FAILURE            => ReplyError::GeneralFailure,
            consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED     => ReplyError::ConnectionNotAllowed,
            consts::SOCKS5_REPLY_NETWORK_UNREACHABLE        => ReplyError::NetworkUnreachable,
            consts::SOCKS5_REPLY_HOST_UNREACHABLE           => ReplyError::HostUnreachable,
            consts::SOCKS5_REPLY_CONNECTION_REFUSED         => ReplyError::ConnectionRefused,
            consts::SOCKS5_REPLY_TTL_EXPIRED                => ReplyError::TtlExpired,
            consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED      => ReplyError::CommandNotSupported,
            consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => ReplyError::AddressTypeNotSupported,
//            _                                               => ReplyError::OtherReply(code),
            _                                               => unreachable!("ReplyError code unsupported."),
        }
    }
}

/// Generate UDP header
///
/// # UDP Request header structure.
/// ```text
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
///
/// The fields in the UDP request header are:
///
///     o  RSV  Reserved X'0000'
///     o  FRAG    Current fragment number
///     o  ATYP    address type of following addresses:
///        o  IP V4 address: X'01'
///        o  DOMAINNAME: X'03'
///        o  IP V6 address: X'04'
///     o  DST.ADDR       desired destination address
///     o  DST.PORT       desired destination port
///     o  DATA     user data
/// ```
pub fn new_udp_header<T: ToTargetAddr>(target_addr: T) -> Result<Vec<u8>> {
    let mut header = vec![
        0, 0, // RSV
        0, // FRAG
    ];
    header.append(&mut target_addr.to_target_addr()?.to_be_bytes()?);

    Ok(header)
}

/// Parse data from UDP client on raw buffer, return (frag, target_addr, payload).
pub async fn parse_udp_request<'a>(mut req: &'a [u8]) -> Result<(u8, TargetAddr, &'a [u8])> {
    let rsv = read_exact!(req, [0u8; 2]).context("Malformed request")?;

    if !rsv.eq(&[0u8; 2]) {
        return Err(ReplyError::GeneralFailure.into());
    }

    let [frag, atyp] = read_exact!(req, [0u8; 2]).context("Malformed request")?;

    let target_addr = read_address(&mut req, atyp).await.map_err(|e| {
        // print explicit error
        error!("{:#}", e);
        // then convert it to a reply
        ReplyError::AddressTypeNotSupported
    })?;

    Ok((frag, target_addr, req))
}
