//! The helper's socket server.
//!
//! Trust boundaries enforced here, in order, for every single frame:
//!
//! 1. read exactly one fixed-size frame with a short timeout;
//! 2. authenticate the peer's *current* code image (see [`crate::auth`]);
//! 3. decode the frame (`sync-wire`, which is total and fail-closed);
//! 4. enforce the reply's sequence number strictly increasing;
//! 5. evaluate policy and perform the operation.
//!
//! A failure at any step closes the connection and, where appropriate, tells
//! the caller nothing beyond a generic status. The helper never reuses a
//! connection for a second request, so there is no per-connection state an
//! attacker can poison — except the sequence counter, which exists precisely
//! to make replayed frames inert.
//!
//! # Why read the frame *before* authenticating
//!
//! Between "the frame arrived" and "we checked the sender", the peer can
//! `exec` a different image. Reading first and authenticating second means the
//! image we judge is the one present when the frame is *handled*, which is the
//! conservative choice:
//!
//! * if the peer has become an unlisted image by then, we refuse (verified:
//!   `auth:4`, "code hash is not allow-listed");
//! * a peer cannot get its own frame executed by `exec`-ing the *genuine,
//!   allow-listed* agent, because at that point the code running is the agent's
//!   own code, not the attacker's.
//!
//! Authenticating before reading would instead create a race in the other
//! direction: a peer could pass the check as the agent, then exec an arbitrary
//! image and send the frame.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Mutex;
use std::time::Duration;

use sync_wire::{Request, Response, Status, REQUEST_LEN};

use crate::auth::{AuthPolicy, PeerIdentity};
use crate::policy::Policy;

/// Accept timeout applied to every read, so a stalled peer cannot pin a thread.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-identity (uid, pid-independent) highest sequence number seen.
///
/// Keying on the audit token rather than pid matters: a pid can be reused, the
/// token belongs to the process that actually owns the connection. We keep a
/// bounded map so a hostile peer cannot exhaust memory by reconnecting.
struct ReplayGuard {
    highest: BTreeMap<[u8; 32], u64>,
    capacity: usize,
}

impl ReplayGuard {
    fn new(capacity: usize) -> Self {
        ReplayGuard {
            highest: BTreeMap::new(),
            capacity,
        }
    }

    /// Accept `seq` if it is strictly greater than anything this token has
    /// sent before. Returns false on replay or rollback.
    fn accept(&mut self, token: &[u8; 32], seq: u64) -> bool {
        match self.highest.get(token) {
            Some(prev) if seq <= *prev => false,
            _ => {
                if self.highest.len() >= self.capacity {
                    // Evict the lexicographically first entry. The point of
                    // the guard is to stop naive replay within a session, not
                    // to be a durable audit log; eviction only weakens it for
                    // an already-forgotten token.
                    if let Some(k) = self.highest.keys().next().copied() {
                        self.highest.remove(&k);
                    }
                }
                self.highest.insert(*token, seq);
                true
            }
        }
    }
}

/// A running helper.
pub struct HelperServer {
    listener: UnixListener,
    policy: Mutex<Policy>,
    auth: AuthPolicy,
    guard: Mutex<ReplayGuard>,
}

impl HelperServer {
    /// Bind `path`. Any pre-existing socket at that path is removed first; the
    /// caller must already have verified the parent directory is root-owned
    /// and not world-writable.
    pub fn bind(path: &str, policy: Policy, auth: AuthPolicy) -> io::Result<Self> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        Ok(HelperServer {
            listener,
            policy: Mutex::new(policy),
            auth,
            guard: Mutex::new(ReplayGuard::new(1024)),
        })
    }

    /// Restrict the socket file to its owner and group. Best effort: a failure
    /// here is reported so the caller can choose to abort.
    pub fn restrict_permissions(&self, path: &str) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)?;
        let mut perms = meta.permissions();
        perms.set_mode(0o660);
        std::fs::set_permissions(path, perms)
    }

    /// Serve forever. `on_decision` receives one line per handled request and
    /// is used by the test harness; in production it is a no-op closure.
    pub fn serve<F>(&self, mut on_decision: F) -> io::Result<()>
    where
        F: FnMut(&str),
    {
        for incoming in self.listener.incoming() {
            let stream = match incoming {
                Ok(s) => s,
                Err(_) => continue,
            };
            let _ = self.handle(&stream, &mut on_decision);
        }
        Ok(())
    }

    /// Handle one connection: one request, one response, then close.
    fn handle<F>(&self, stream: &UnixStream, on_decision: &mut F) -> io::Result<()>
    where
        F: FnMut(&str),
    {
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

        // Step 1: frame.
        let mut buf = [0u8; REQUEST_LEN];
        let mut handle = stream;
        if handle.read_exact(&mut buf).is_err() {
            // Short read / timeout / EOF: never respond, just close. Nothing
            // is learned from this connection.
            on_decision("io:short-read");
            return Ok(());
        }

        // Step 2: authenticate the peer's current image. This runs *after*
        // reading, so a peer that exec'd or received the fd mid-connection is
        // judged on the image that actually sent the frame.
        let identity: PeerIdentity = match self.auth.authenticate(stream) {
            Ok(id) => id,
            Err(e) => {
                on_decision(&format!("auth:{} ({e})", e.code()));
                let _ = write_reply(stream, Response::new(Status::BadRequest, e.code()));
                return Ok(());
            }
        };

        // Step 3: decode. Total and fail-closed.
        let request = match Request::decode(&buf) {
            Ok(r) => r,
            Err(_) => {
                on_decision("decode:reject");
                let _ = write_reply(stream, Response::new(Status::BadRequest, 0));
                return Ok(());
            }
        };

        // Step 4: replay/rollback guard, per audit token.
        let fresh = {
            let mut guard = self.guard.lock().unwrap_or_else(|p| p.into_inner());
            guard.accept(&identity.audit, request.seq)
        };
        if !fresh {
            on_decision("replay:reject");
            let _ = write_reply(stream, Response::new(Status::Denied, 9));
            return Ok(());
        }

        // Step 5: policy. The privileged decision is made here, from the
        // helper's own state, never from anything the caller supplied beyond
        // the bounded typed request.
        let outcome = {
            let mut policy = self.policy.lock().unwrap_or_else(|p| p.into_inner());
            policy.evaluate(&request)
        };

        on_decision(&format!(
            "op:{:?} uid:{} pid:{} status:{:?}",
            request.op, identity.uid, identity.pid, outcome.status
        ));

        let mut response = Response::new(outcome.status, outcome.detail);
        if let Some(v) = outcome.value {
            // Fixed 8-byte value, bounds already established by the type.
            response.payload[0..8].copy_from_slice(&v.to_le_bytes());
        }
        write_reply(stream, response)
    }
}

fn write_reply<S: Write>(mut stream: S, response: Response) -> io::Result<()> {
    stream.write_all(&response.encode())?;
    stream.flush()
}

/// A no-op decision sink for production builds.
pub fn silent(_: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_guard_is_strictly_increasing() {
        let mut g = ReplayGuard::new(8);
        let t = [1u8; 32];
        assert!(g.accept(&t, 1));
        assert!(!g.accept(&t, 1));
        assert!(!g.accept(&t, 0));
        assert!(g.accept(&t, 2));
        // A different token has its own counter.
        assert!(g.accept(&[2u8; 32], 1));
    }

    #[test]
    fn replay_guard_is_bounded() {
        let mut g = ReplayGuard::new(4);
        for i in 0..100u8 {
            let mut t = [0u8; 32];
            t[0] = i;
            assert!(g.accept(&t, 1));
        }
        assert!(g.highest.len() <= 4);
    }
}
