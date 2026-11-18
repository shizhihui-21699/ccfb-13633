//! Integration tests against the *real* helper binary.
//!
//! These need macOS (audit tokens, `SecCodeCopyGuestWithAttributes`) and are
//! `#[ignore]`d so a plain `cargo test` stays portable. Run them with
//! `scripts/test-integration.sh`, which builds everything and sets the
//! environment variables documented below.
//!
//! Environment contract:
//!
//! * `RT_HELPER` — path to the built `syncd-helper`
//! * `RT_PROBE`  — path to the built `probe` (an allow-listed caller)
//! * `RT_WORKDIR`— writable directory for sockets and logs

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn env_path(key: &str) -> String {
    std::env::var(key)
        .unwrap_or_else(|_| panic!("{key} must be set by scripts/test-integration.sh"))
}

fn workdir() -> std::path::PathBuf {
    std::path::PathBuf::from(env_path("RT_WORKDIR"))
}

/// Code hash of a binary, in the form the helper accepts (`sha256:...`).
fn cdhash_of(path: &str) -> String {
    let out = Command::new("codesign")
        .args(["-dvvv", path])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stderr);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("CandidateCDHash ") {
            return rest.trim().to_string();
        }
    }
    panic!("no cdhash for {path}; codesign said:\n{text}");
}

struct Helper {
    child: Child,
    socket: String,
    decisions: std::path::PathBuf,
}

impl Helper {
    fn start(allowed: &[&str]) -> Helper {
        let n = std::process::id();
        let socket = workdir()
            .join(format!("h-{n}.sock"))
            .to_string_lossy()
            .into_owned();
        let decisions = workdir().join(format!("decisions-{n}.log"));
        let table = workdir().join(format!("volumes-{n}.txt"));
        std::fs::write(
            &table,
            "1b4e28ba-2fa1-11d2-883f-0016d3cca427 /Volumes/Data 1\n\
             2b4e28ba-2fa1-11d2-883f-0016d3cca427 /Volumes/Archive 0\n",
        )
        .unwrap();
        let mut cmd = Command::new(env_path("RT_HELPER"));
        cmd.arg("--socket")
            .arg(&socket)
            .arg("--table")
            .arg(&table)
            .arg("--simulate")
            .arg("--decisions");
        for h in allowed {
            cmd.arg("--allow-cdhash").arg(h);
        }
        let log = std::fs::File::create(&decisions).unwrap();
        cmd.stdout(Stdio::from(log)).stderr(Stdio::null());
        let child = cmd.spawn().unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while !std::path::Path::new(&socket).exists() {
            assert!(Instant::now() < deadline, "helper socket never appeared");
            std::thread::sleep(Duration::from_millis(20));
        }
        // Give the helper a moment to reach accept() after bind.
        std::thread::sleep(Duration::from_millis(50));
        Helper {
            child,
            socket,
            decisions,
        }
    }

    fn connect(&self) -> UnixStream {
        UnixStream::connect(&self.socket).unwrap()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.decisions).unwrap_or_default()
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn frame(op: u8, seq: u64, tail: [u8; 16]) -> [u8; 64] {
    let mut f = [0u8; 64];
    f[0..4].copy_from_slice(b"SYNC");
    f[4] = 1;
    f[5] = op;
    f[8..16].copy_from_slice(&seq.to_le_bytes());
    f[16..48].copy_from_slice(&[0xAB; 32]);
    f[48..64].copy_from_slice(&tail);
    f
}

fn exchange(s: &mut UnixStream, frame: &[u8; 64]) -> Option<[u8; 32]> {
    s.write_all(frame).ok()?;
    s.flush().ok()?;
    let mut buf = [0u8; 32];
    s.read_exact(&mut buf).ok()?;
    Some(buf)
}

// ---------------------------------------------------------------------------
// Startup and authentication
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs macOS + integration harness"]
fn helper_refuses_to_start_without_allow_list() {
    let socket = workdir().join("noallow.sock");
    let table = workdir().join("noallow-volumes.txt");
    std::fs::write(&table, "").unwrap();
    let out = Command::new(env_path("RT_HELPER"))
        .arg("--socket")
        .arg(&socket)
        .arg("--table")
        .arg(&table)
        .arg("--simulate")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "helper must refuse an empty allow-list"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("allow-list"), "stderr was: {err}");
    assert!(!socket.exists(), "helper must not have bound the socket");
}

/// A caller whose code hash is not allow-listed gets a uniform refusal, for
/// every frame shape. This is what stops an unrelated malicious local process
/// from using the helper at all.
#[test]
#[ignore = "needs macOS + integration harness"]
fn unlisted_caller_gets_uniform_refusal() {
    // Allow-list the helper itself: the test binary is then the only
    // unauthorised party.
    let helper_hash = cdhash_of(&env_path("RT_HELPER"));
    let helper = Helper::start(&[&helper_hash]);

    let mut statuses = Vec::new();
    for f in [
        frame(0, 1, [0u8; 16]),
        frame(1, 1, [0x1b; 16]),
        frame(99, 1, [0u8; 16]),
        frame(0, 1, [0xFF; 16]),
    ] {
        let mut s = helper.connect();
        statuses.push(exchange(&mut s, &f).expect("helper answers even refusals")[4]);
    }
    assert!(
        statuses.iter().all(|st| *st == 2),
        "unauthorised callers must get BadRequest for every shape, got {statuses:?}"
    );
    assert!(
        helper.log().contains("auth:"),
        "decisions:\n{}",
        helper.log()
    );
}

// ---------------------------------------------------------------------------
// Policy, against a live authorised caller
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs macOS + integration harness"]
fn authorised_caller_gets_exactly_the_allow_list() {
    let probe = env_path("RT_PROBE");
    let hash = cdhash_of(&probe);
    let helper = Helper::start(&[&hash]);

    let out = Command::new(&probe)
        .arg(&helper.socket)
        .arg("matrix")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    for expected in [
        "health=ok",
        "mount_allowed=ok",
        "mount_nonmountable=denied",
        "mount_unknown=denied",
        "setting_ok=ok",
        "setting_bad_value=bad",
        "unknown_op=bad",
    ] {
        assert!(
            stdout.contains(expected),
            "missing {expected} in probe output:\n{stdout}\nstderr:\n{}\ndecisions:\n{}",
            String::from_utf8_lossy(&out.stderr),
            helper.log()
        );
    }
}

#[test]
#[ignore = "needs macOS + integration harness"]
fn authorised_caller_cannot_replay() {
    let probe = env_path("RT_PROBE");
    let hash = cdhash_of(&probe);
    let helper = Helper::start(&[&hash]);

    let out = Command::new(&probe)
        .arg(&helper.socket)
        .arg("replay")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("first=ok") && stdout.contains("second=denied"),
        "probe output:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// The central claim: authentication follows the *current* image
// ---------------------------------------------------------------------------

/// An authorised caller connects, proves it is authorised, then `exec`s `/bin/sh`
/// with the socket still open. `sh` writes one valid frame. If the helper
/// trusted the connection, it would answer `ok`; because it re-authenticates
/// per frame it must refuse.
#[test]
#[ignore = "needs macOS + integration harness"]
fn exec_to_unlisted_image_is_refused() {
    let probe = env_path("RT_PROBE");
    let hash = cdhash_of(&probe);
    let helper = Helper::start(&[&hash]);

    let out = Command::new(&probe)
        .arg(&helper.socket)
        .arg("exec")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("before_exec=ok"),
        "the probe must be authorised before the exec; output:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The probe's `sh` reports whether its write actually reached the socket.
    // Without this the test could "pass" on a scenario where no attack frame
    // was ever sent.
    assert!(
        stdout.contains("post_exec=wrote:64"),
        "the post-exec frame never reached the socket; output:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The helper logs one decision per frame. The pre-exec frame must be
    // accepted; the post-exec frame must not be. `auth:` (image could not be
    // resolved — observed when resolving immediately after exec) and any
    // non-Ok status are both refusals, which is all the claim requires.
    let log = helper.log();
    let saw_ok = log
        .lines()
        .any(|l| l.contains("op:Health") && l.contains("status:Ok"));
    assert!(
        saw_ok,
        "expected the pre-exec frame to be authorised; decisions:\n{log}"
    );
    let refused = log.lines().any(|l| l.contains("auth:"))
        || log
            .lines()
            .any(|l| l.contains("op:Health") && !l.contains("status:Ok"));
    assert!(
        refused,
        "the post-exec frame was not refused; decisions:\n{log}"
    );
}

/// Same claim via a forked child (`fdpass` mode): the audit token survives
/// `exec`, the image does not, and the helper judges the latter.
#[test]
#[ignore = "needs macOS + integration harness"]
fn fd_pass_to_another_image_is_refused() {
    let probe = env_path("RT_PROBE");
    let hash = cdhash_of(&probe);
    let helper = Helper::start(&[&hash]);

    let out = Command::new(&probe)
        .arg(&helper.socket)
        .arg("fdpass")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("before_exec=ok"),
        "opener must be authorised; output:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("post_exec=wrote:64"),
        "the handed-over frame never reached the socket; output:\n{stdout}"
    );
    let log = helper.log();
    let refused = log.lines().any(|l| l.contains("auth:"))
        || log
            .lines()
            .any(|l| l.contains("op:Health") && !l.contains("status:Ok"));
    assert!(
        refused,
        "expected the handed-over frame to be re-authenticated and refused; decisions:\n{log}"
    );
}
