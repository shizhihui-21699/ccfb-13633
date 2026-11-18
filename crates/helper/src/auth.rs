//! Caller authentication for the privileged helper.
//!
//! # Threat model this module addresses
//!
//! The helper must answer one question — *may this connection perform this
//! operation?* — and it must answer it per request, not per connection setup,
//! because the answers are not equivalent on macOS:
//!
//! * A process can `exec` a different image while holding an open connection.
//!   Verified on macOS 26: the socket's peer audit token survives `exec`, and
//!   resolving it through the Security framework yields the **current** image.
//! * A process can hand its connected socket to a different process with
//!   `SCM_RIGHTS`. Verified on macOS 26: `LOCAL_PEERPID` then reports the
//!   *receiving* process, and the audit token follows it.
//!
//! So a check performed once at `accept()` time would authorise the wrong
//! program for every subsequent frame. This module is therefore called after
//! each frame is read, and it resolves the peer's image from the audit token
//! at that moment.
//!
//! # What the check is, and is not
//!
//! It identifies *which program* is on the other end: the kernel-supplied audit
//! token is resolved to a code object and validated against an allow-list of
//! code hashes. That stops unrelated malicious processes from using the helper
//! at all.
//!
//! It does **not** bound what an allow-listed program may ask for. A fully
//! compromised *agent* is still the genuine agent binary with the genuine hash;
//! what stops it is the protocol and the helper's own policy — four operations,
//! no paths, no commands. Both mechanisms are required; see `docs/design.md`.

use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;

// ---------------------------------------------------------------------------
// libc / framework bindings (no third-party dependencies)
// ---------------------------------------------------------------------------

type CFTypeRef = *const std::ffi::c_void;
type OSStatus = i32;

const SOL_LOCAL: i32 = 0;
const LOCAL_PEERPID: i32 = 0x002;
const LOCAL_PEERTOKEN: i32 = 0x006;

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

// `SecCSFlags`: validate the signature itself, do not just check presence.
const K_SEC_CSC_FLAGS_NONE: u32 = 0;

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFDataCreate(alloc: CFTypeRef, bytes: *const u8, length: isize) -> CFTypeRef;
    fn CFStringCreateWithCString(alloc: CFTypeRef, s: *const u8, enc: u32) -> CFTypeRef;
    fn CFDictionaryCreate(
        alloc: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        num: isize,
        key_cb: *const std::ffi::c_void,
        value_cb: *const std::ffi::c_void,
    ) -> CFTypeRef;
    fn CFRelease(r: CFTypeRef);
    static kCFTypeDictionaryKeyCallBacks: std::ffi::c_void;
    static kCFTypeDictionaryValueCallBacks: std::ffi::c_void;
    static kSecGuestAttributeAudit: CFTypeRef;
}

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecCodeCopyGuestWithAttributes(
        host: CFTypeRef,
        attrs: CFTypeRef,
        flags: u32,
        out: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecRequirementCreateWithString(s: CFTypeRef, flags: u32, out: *mut CFTypeRef) -> OSStatus;
    fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, req: CFTypeRef) -> OSStatus;
}

extern "C" {
    fn getpeereid(fd: i32, uid: *mut u32, gid: *mut u32) -> i32;
    fn getsockopt(fd: i32, level: i32, name: i32, val: *mut std::ffi::c_void, len: *mut u32)
        -> i32;
}

/// Releases a CoreFoundation object when dropped, including on early return.
struct CF(CFTypeRef);

impl CF {
    fn new(p: CFTypeRef) -> Option<CF> {
        if p.is_null() {
            None
        } else {
            Some(CF(p))
        }
    }
    fn raw(&self) -> CFTypeRef {
        self.0
    }
}

impl Drop for CF {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a CF create function and is released once.
        unsafe { CFRelease(self.0) }
    }
}

// ---------------------------------------------------------------------------
// Peer identification
// ---------------------------------------------------------------------------

/// Everything the helper knows about the process on the other end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Effective uid reported by the socket layer.
    pub uid: u32,
    /// Effective gid.
    pub gid: u32,
    /// Kernel pid; informational only (it is reusable, so never authorise on it).
    pub pid: i32,
    /// The 32-byte audit token. This is the authorisation input.
    pub audit: [u8; 32],
    /// Code hash of the *current* image, if it could be resolved.
    pub cdhash: Option<Vec<u8>>,
}

/// Why a peer could not be authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// The socket layer refused to describe the peer.
    NoPeerCredentials,
    /// The audit token was not the expected 32 bytes.
    BadToken,
    /// The peer's image could not be resolved to a code object.
    Unresolvable,
    /// The image did not match any allow-listed code hash.
    NotAllowListed,
    /// The caller's uid is not permitted to use the helper.
    UidNotPermitted,
}

impl AuthError {
    /// Stable, non-sensitive code for logging.
    pub fn code(self) -> u8 {
        match self {
            AuthError::NoPeerCredentials => 1,
            AuthError::BadToken => 2,
            AuthError::Unresolvable => 3,
            AuthError::NotAllowListed => 4,
            AuthError::UidNotPermitted => 5,
        }
    }
}

/// Strip an optional `sha256:`/`cdhash:` prefix and parse hex into raw bytes.
pub fn parse_cdhash_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    // Accept the spellings `codesign` and humans produce: `sha256:hex`,
    // `sha256=hex`, `cdhash:hex`, or bare hex.
    let s = s
        .strip_prefix("sha256:")
        .or_else(|| s.strip_prefix("sha256="))
        .or_else(|| s.strip_prefix("cdhash:"))
        .unwrap_or(s);
    if s.is_empty() || s.len() % 2 != 0 || s.len() > 64 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

unsafe fn code_for_audit(audit: &[u8; 32]) -> Option<CF> {
    let token = CF::new(CFDataCreate(std::ptr::null(), audit.as_ptr(), 32))?;
    let attrs = CF::new(CFDictionaryCreate(
        std::ptr::null(),
        &kSecGuestAttributeAudit as *const CFTypeRef,
        &token.raw(),
        1,
        &kCFTypeDictionaryKeyCallBacks as *const std::ffi::c_void,
        &kCFTypeDictionaryValueCallBacks as *const std::ffi::c_void,
    ))?;
    let mut code: CFTypeRef = std::ptr::null();
    if SecCodeCopyGuestWithAttributes(std::ptr::null(), attrs.raw(), 0, &mut code) != 0 {
        return None;
    }
    CF::new(code)
}

/// Does the peer's current image satisfy `cdhash H"<hex>"`?
///
/// `SecCodeCheckValidity` both checks the signature and evaluates the
/// requirement, so a tampered image that merely *looks* like an allow-listed
/// one fails here.
fn code_matches_cdhash(code: &CF, cdhash_hex: &str) -> bool {
    let req_str = format!("cdhash H\"{cdhash_hex}\"");
    let Ok(cstr) = std::ffi::CString::new(req_str) else {
        return false;
    };
    // SAFETY: CString guarantees a NUL-terminated buffer; CF and Security
    // objects are released by the `CF` wrappers.
    unsafe {
        let Some(s) = CF::new(CFStringCreateWithCString(
            std::ptr::null(),
            cstr.as_ptr() as *const u8,
            K_CF_STRING_ENCODING_UTF8,
        )) else {
            return false;
        };
        let mut req: CFTypeRef = std::ptr::null();
        if SecRequirementCreateWithString(s.raw(), 0, &mut req) != 0 {
            return false;
        }
        let Some(req) = CF::new(req) else {
            return false;
        };
        SecCodeCheckValidity(code.raw(), K_SEC_CSC_FLAGS_NONE, req.raw()) == 0
    }
}

/// Read the peer's credentials from a connected Unix socket.
pub fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity, AuthError> {
    let fd: RawFd = std::os::unix::io::AsRawFd::as_raw_fd(stream);
    let mut uid = 0u32;
    let mut gid = 0u32;
    // SAFETY: fd is a valid socket owned by `stream`; out-params are valid u32s.
    if unsafe { getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return Err(AuthError::NoPeerCredentials);
    }

    let mut pid: i32 = 0;
    let mut pid_len = std::mem::size_of::<i32>() as u32;
    // SAFETY: as above; buffer is exactly one i32.
    let pid_ok = unsafe {
        getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut i32 as *mut std::ffi::c_void,
            &mut pid_len,
        )
    } == 0
        && pid_len == std::mem::size_of::<i32>() as u32;

    let mut audit = [0u8; 32];
    let mut audit_len = 32u32;
    // SAFETY: buffer is exactly 32 bytes and the length is passed by pointer.
    let tok_ok = unsafe {
        getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            audit.as_mut_ptr() as *mut std::ffi::c_void,
            &mut audit_len,
        )
    } == 0;

    // On macOS the audit token is always available for a connected AF_UNIX
    // socket. Treat its absence as a failure rather than falling back to the
    // reusable pid.
    if !tok_ok || audit_len != 32 {
        return Err(AuthError::BadToken);
    }
    if !pid_ok {
        return Err(AuthError::NoPeerCredentials);
    }

    Ok(PeerIdentity {
        uid,
        gid,
        pid,
        audit,
        cdhash: None,
    })
}

/// A policy: which uids and which code hashes may use the helper.
#[derive(Clone, Debug, Default)]
pub struct AuthPolicy {
    /// Uids permitted to connect. Empty means "no uid check" (development
    /// mode only); combined with a cdhash allow-list this is still narrow.
    pub allowed_uids: Vec<u32>,
    /// Allow-listed code hashes, **already normalised to bare lowercase hex**.
    /// Never construct this field directly from user input; use
    /// [`AuthPolicy::new`] so a `sha256=` prefix cannot be spliced into a
    /// requirement string.
    allowed_cdhashes: Vec<String>,
}

impl AuthPolicy {
    /// Build a policy, normalising every hash. Invalid entries are rejected
    /// here, at load time, rather than silently never matching at request time.
    pub fn new(allowed_uids: Vec<u32>, allowed_cdhashes: &[String]) -> Result<Self, AuthError> {
        let mut normalised = Vec::with_capacity(allowed_cdhashes.len());
        for h in allowed_cdhashes {
            let raw = parse_cdhash_hex(h).ok_or(AuthError::NotAllowListed)?;
            normalised.push(raw.iter().map(|b| format!("{b:02x}")).collect::<String>());
        }
        Ok(AuthPolicy {
            allowed_uids,
            allowed_cdhashes: normalised,
        })
    }

    /// Authenticate a connected peer against this policy.
    ///
    /// Order matters: the cheap uid check runs first, but the code check is
    /// what decides. An empty allow-list is a configuration error and denies
    /// everything (fail closed) rather than allowing everything.
    pub fn authenticate(&self, stream: &UnixStream) -> Result<PeerIdentity, AuthError> {
        let mut id = peer_identity(stream)?;

        if !self.allowed_uids.is_empty() && !self.allowed_uids.contains(&id.uid) {
            return Err(AuthError::UidNotPermitted);
        }
        if self.allowed_cdhashes.is_empty() {
            return Err(AuthError::NotAllowListed);
        }

        // SAFETY: `code_for_audit` only reads `id.audit`, which is 32 bytes,
        // and returns a managed CF object.
        let code = unsafe { code_for_audit(&id.audit) }.ok_or(AuthError::Unresolvable)?;

        for candidate in &self.allowed_cdhashes {
            if code_matches_cdhash(&code, candidate) {
                // `candidate` is already normalised hex (see `AuthPolicy::new`),
                // so this cannot fail; keep it total anyway.
                id.cdhash = parse_cdhash_hex(candidate);
                return Ok(id);
            }
        }
        Err(AuthError::NotAllowListed)
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuthError::NoPeerCredentials => "peer credentials unavailable",
            AuthError::BadToken => "peer audit token unavailable",
            AuthError::Unresolvable => "peer image could not be resolved",
            AuthError::NotAllowListed => "peer code hash is not allow-listed",
            AuthError::UidNotPermitted => "peer uid is not permitted",
        };
        f.write_str(s)
    }
}

impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdhash_hex_parsing() {
        assert_eq!(parse_cdhash_hex("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert_eq!(parse_cdhash_hex("sha256:00ff").unwrap(), vec![0x00, 0xff]);
        assert_eq!(parse_cdhash_hex("sha256=00ff").unwrap(), vec![0x00, 0xff]);
        assert_eq!(parse_cdhash_hex("cdhash:00ff").unwrap(), vec![0x00, 0xff]);
        for bad in ["", "0", "0g", "00 ff", &"x".repeat(70)] {
            assert!(parse_cdhash_hex(bad).is_none(), "accepted {bad:?}");
        }
    }

    #[test]
    fn empty_allow_list_denies() {
        // A socketpair gives us a real connected handle to authenticate.
        let (a, _b) = UnixStream::pair().unwrap();
        let policy = AuthPolicy::default();
        let err = policy.authenticate(&a).unwrap_err();
        assert_eq!(err, AuthError::NotAllowListed);
    }

    #[test]
    fn uid_denial_happens_before_code_check() {
        let (a, _b) = UnixStream::pair().unwrap();
        let policy = AuthPolicy::new(vec![0], &["00".into()]).unwrap();
        let err = policy.authenticate(&a).unwrap_err();
        // The test process is not uid 0, so this must fail on uid.
        assert_eq!(err, AuthError::UidNotPermitted);
    }

    #[test]
    fn allow_list_is_normalised() {
        let p = AuthPolicy::new(
            vec![],
            &["sha256=AB12".into(), "cdhash:cd34".into(), "ef56".into()],
        )
        .unwrap();
        assert_eq!(p.allowed_cdhashes, vec!["ab12", "cd34", "ef56"]);
    }

    #[test]
    fn malformed_allow_list_entry_is_rejected_at_load_time() {
        for bad in ["", "zz", "sha256:"] {
            assert!(
                AuthPolicy::new(vec![], &[bad.into()]).is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn peer_credentials_are_available_for_socketpair() {
        let (a, _b) = UnixStream::pair().unwrap();
        let id = peer_identity(&a).unwrap();
        assert_eq!(id.audit.len(), 32);
        assert!(id.audit.iter().any(|b| *b != 0));
        assert_eq!(id.uid, unsafe { libc_geteuid() });
    }

    extern "C" {
        #[link_name = "geteuid"]
        fn libc_geteuid() -> u32;
    }
}
