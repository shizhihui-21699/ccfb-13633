//! Client for the privileged helper's Unix socket.
//!
//! This is the *only* way the agent can obtain privilege. It can send exactly
//! one fixed-size request frame and read exactly one fixed-size reply; there
//! is no "run this command" and no "read this file". If this whole process is
//! owned by an attacker, the worst it can do through this module is ask the
//! helper for the four operations the helper policy already permits.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use sync_wire::{Op, Params, Request, Response, RESPONSE_LEN};

/// Errors that can happen on the agent side of the channel.
#[derive(Debug)]
pub enum ChannelError {
    /// Could not connect to the helper.
    Connect(std::io::Error),
    /// Could not complete the exchange.
    Io(std::io::Error),
    /// The helper's reply was not a well-formed frame.
    BadReply,
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::Connect(e) => write!(f, "helper not reachable: {e}"),
            ChannelError::Io(e) => write!(f, "helper exchange failed: {e}"),
            ChannelError::BadReply => f.write_str("helper sent a malformed reply"),
        }
    }
}

impl std::error::Error for ChannelError {}

/// A thin, stateless client. Each call opens a fresh connection and sends one
/// request; the helper treats every connection as exactly one frame.
pub struct HelperClient {
    path: String,
    nonce: [u8; 32],
    next_seq: u64,
    timeout: Duration,
}

impl HelperClient {
    /// Create a client for the helper socket at `path`.
    pub fn new(path: impl Into<String>) -> Self {
        // A per-process nonce makes sequence numbers unique per client without
        // needing persistent state. It is derived from the process id, a
        // monotonic clock read and an address — none of it secret, which is
        // fine: replay protection is the helper's strictly-increasing counter
        // keyed on the audit token, not on the nonce's secrecy.
        let mut nonce = [0u8; 32];
        nonce[0..4].copy_from_slice(&std::process::id().to_le_bytes());
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        nonce[4..20].copy_from_slice(&nanos.to_le_bytes());
        let addr = &nonce as *const _ as usize as u64;
        nonce[20..28].copy_from_slice(&addr.to_le_bytes());
        // Bytes 28..32 stay zero; the helper does not interpret the nonce
        // beyond binding frames to a connection.
        HelperClient {
            path: path.into(),
            nonce,
            next_seq: 1,
            timeout: Duration::from_secs(3),
        }
    }

    /// Perform one request. The reply is returned as the wire type, so the
    /// agent has no way to smuggle additional meaning into it.
    pub fn call(&mut self, op: Op, params: Params) -> Result<Response, ChannelError> {
        let mut stream = UnixStream::connect(&self.path).map_err(ChannelError::Connect)?;
        stream.set_read_timeout(Some(self.timeout)).ok();
        stream.set_write_timeout(Some(self.timeout)).ok();

        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let req = Request {
            op,
            seq,
            nonce: self.nonce,
            params,
        };

        stream.write_all(&req.encode()).map_err(ChannelError::Io)?;
        stream.flush().map_err(ChannelError::Io)?;

        let mut buf = [0u8; RESPONSE_LEN];
        stream.read_exact(&mut buf).map_err(ChannelError::Io)?;
        Response::decode(&buf).map_err(|_| ChannelError::BadReply)
    }

    /// Health check; used by the agent at startup.
    pub fn health(&mut self) -> Result<Response, ChannelError> {
        self.call(Op::Health, Params::None)
    }
}
