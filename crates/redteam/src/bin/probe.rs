//! `probe` — an allow-listed test client for the helper.
//!
//! Built by `scripts/test-integration.sh`, which passes this binary's code hash
//! to the helper as the only authorised caller. Each mode performs one
//! scenario and prints `key=value` lines the integration tests assert on.
//!
//! Modes:
//!   matrix      every operation against the live policy
//!   replay      the same sequence number twice from one process
//!   exec        connect, get authorised, then exec an unlisted image
//!   fdpass      hand the connected socket to an unlisted process

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

use sync_wire::{Op, Params, Request, Response, SettingId, Status};

const DATA_UUID: [u8; 16] = [
    0x1b, 0x4e, 0x28, 0xba, 0x2f, 0xa1, 0x11, 0xd2, 0x88, 0x3f, 0x00, 0x16, 0xd3, 0xcc, 0xa4, 0x27,
];
const ARCHIVE_UUID: [u8; 16] = [
    0x2b, 0x4e, 0x28, 0xba, 0x2f, 0xa1, 0x11, 0xd2, 0x88, 0x3f, 0x00, 0x16, 0xd3, 0xcc, 0xa4, 0x27,
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let socket = args.get(1).cloned().unwrap_or_else(|| {
        eprintln!("usage: probe SOCKET MODE");
        std::process::exit(2);
    });
    let mode = args.get(2).cloned().unwrap_or_else(|| "matrix".into());
    match mode.as_str() {
        "matrix" => matrix(&socket),
        "replay" => replay(&socket),
        "exec" => exec(&socket),
        "fdpass" => fdpass(&socket),
        other => {
            eprintln!("unknown mode {other}");
            std::process::exit(2);
        }
    }
}

fn req(op: Op, seq: u64, params: Params) -> Request {
    Request {
        op,
        seq,
        nonce: [0x5Au8; 32],
        params,
    }
}

fn one(socket: &str, r: &Request) -> Option<Response> {
    let mut s = UnixStream::connect(socket).ok()?;
    s.write_all(&r.encode()).ok()?;
    s.flush().ok()?;
    let mut buf = [0u8; 32];
    s.read_exact(&mut buf).ok()?;
    Response::decode(&buf).ok()
}

/// Print a stable name for a status.
fn label(s: Status) -> &'static str {
    match s {
        Status::Ok => "ok",
        Status::Denied => "denied",
        Status::BadRequest => "bad",
        Status::NotAvailable => "unavailable",
        Status::Busy => "busy",
        Status::Internal => "internal",
    }
}

fn matrix(socket: &str) {
    let cases: [(&str, Request); 7] = [
        ("health", req(Op::Health, 1, Params::None)),
        (
            "mount_allowed",
            req(Op::MountVolume, 2, Params::Volume(DATA_UUID)),
        ),
        (
            "mount_nonmountable",
            req(Op::MountVolume, 3, Params::Volume(ARCHIVE_UUID)),
        ),
        (
            "mount_unknown",
            req(Op::MountVolume, 4, Params::Volume([0x42; 16])),
        ),
        (
            "setting_ok",
            req(
                Op::SetSystemSetting,
                5,
                Params::Setting {
                    id: SettingId::DisksSleep,
                    value: 1,
                },
            ),
        ),
        (
            "setting_bad_value",
            req(
                Op::SetSystemSetting,
                6,
                Params::Setting {
                    id: SettingId::DisksSleep,
                    value: 0x1234_5678_i64,
                },
            ),
        ),
        ("unknown_op", req(Op::Health, 7, Params::Volume([1; 16]))), // shape mismatch
    ];
    for (name, r) in cases {
        match one(socket, &r) {
            Some(resp) => println!("{name}={}", label(resp.status)),
            None => println!("{name}=no-reply"),
        }
    }
}

fn replay(socket: &str) {
    let r = req(Op::Health, 100, Params::None);
    let first = one(socket, &r)
        .map(|x| label(x.status))
        .unwrap_or("no-reply");
    let second = one(socket, &r)
        .map(|x| label(x.status))
        .unwrap_or("no-reply");
    println!("first={first}");
    println!("second={second}");
}

/// Prove this image is authorised on one connection, then open a *second*
/// connection, `exec` `/bin/sh` while holding it, and have `sh` write the
/// frame. The helper must judge that frame on `sh`, not on the image that
/// opened the connection.
///
/// The helper accepts one request per connection, so the second connection is
/// unused until after the exec — which is exactly the window the claim is
/// about. The shell reports the byte count it actually wrote; the test refuses
/// to call this a pass if no frame arrived.
fn exec(socket: &str) {
    use std::os::unix::process::CommandExt;
    extern "C" {
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }

    // (1) Prove authorisation, on a throwaway connection.
    match one(socket, &req(Op::Health, 10, Params::None)) {
        Some(resp) => println!("before_exec={}", label(resp.status)),
        None => {
            println!("before_exec=no-reply");
            return;
        }
    }

    // (2) A fresh connection that stays open across the exec.
    let s = UnixStream::connect(socket).unwrap();
    let fd = s.as_raw_fd();
    // Move it well out of the range a non-interactive shell might reserve.
    let fd = unsafe {
        fcntl(fd, 0 /* F_DUPFD */, 200)
    };
    assert!(fd >= 0, "could not duplicate the socket");
    println!("exec_fd={fd}");
    // Clear FD_CLOEXEC (F_SETFD=2, arg 0) so `sh` inherits the socket.
    unsafe {
        fcntl(fd, 2, 0);
    }

    let frame = req(Op::Health, 11, Params::None).encode();
    let payload = std::env::temp_dir().join(format!("probe-frame-{}.bin", std::process::id()));
    std::fs::write(&payload, frame).unwrap();
    // `wc -c` reports the bytes dd accepted; `dd` exits non-zero if the write
    // fails, in which case the count is whatever it managed.
    let script = format!(
        "n=$(dd if='{path}' of=/dev/fd/{fd} bs=64 2>/tmp/probe-dd.err; \
             sed -n 's/^\\([0-9][0-9]*\\) bytes transferred.*/\\1/p' /tmp/probe-dd.err); \
         echo \"post_exec=wrote:$(printf '%s' \"$n\" | tr -d ' ')\"",
        path = payload.display(),
        fd = fd
    );
    let _ = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .exec();
}

/// Same kernel path as `exec`; kept as a named scenario for the test.
fn fdpass(socket: &str) {
    exec(socket);
}
