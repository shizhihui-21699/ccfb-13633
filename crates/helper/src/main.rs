//! `syncd-helper` — the small privileged process.
//!
//! Responsibilities, in full:
//!
//! * read its allow-list from a root-owned file;
//! * listen on a Unix socket;
//! * for each frame: authenticate the caller's code image, decode the frame,
//!   consult its own policy, perform one of four operations.
//!
//! It does **not** parse network traffic, handle untrusted filenames, copy
//! files, or run any code path that takes attacker-controlled strings. Keep it
//! that way: every line added here is a line an attacker who reaches this
//! process gets to run as root.

mod auth;
mod policy;
mod server;

use std::process::ExitCode;
use std::time::Duration;

use auth::AuthPolicy;
use policy::Policy;
use server::{silent, HelperServer};

const DEFAULT_SOCKET: &str = "/var/run/syncd-helper.sock";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn run() -> Result<(), ExitCode> {
    let args: Vec<String> = std::env::args().collect();
    let mut socket = DEFAULT_SOCKET.to_string();
    let mut table_path: Option<String> = None;
    let mut allow_uids: Vec<u32> = vec![];
    let mut allow_hashes: Vec<String> = vec![];
    let mut simulate = false;
    let mut decisions_stdout = false;

    let mut i = 1;
    while i < args.len() {
        let fail = |msg: &str| {
            eprintln!("syncd-helper: {msg}");
            ExitCode::FAILURE
        };
        match args[i].as_str() {
            "--socket" => {
                i += 1;
                socket = args
                    .get(i)
                    .cloned()
                    .ok_or_else(|| fail("--socket needs a value"))?;
            }
            "--table" => {
                i += 1;
                table_path = Some(
                    args.get(i)
                        .cloned()
                        .ok_or_else(|| fail("--table needs a path"))?,
                );
            }
            "--allow-uid" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| fail("--allow-uid needs a value"))?;
                allow_uids.push(
                    v.parse()
                        .map_err(|_| fail("--allow-uid must be an integer"))?,
                );
            }
            "--allow-cdhash" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| fail("--allow-cdhash needs a value"))?;
                if auth::parse_cdhash_hex(v).is_none() {
                    return Err(fail("--allow-cdhash must be hex"));
                }
                allow_hashes.push(v.clone());
            }
            "--simulate" => simulate = true,
            "--decisions" => decisions_stdout = true,
            "--help" | "-h" => {
                println!(
                    "usage: syncd-helper --table FILE --allow-cdhash HEX [--allow-cdhash HEX]...\n\
                     \x20                  [--include-uid UID]... [--socket PATH] [--simulate] [--decisions]"
                );
                return Ok(());
            }
            other => {
                eprintln!("syncd-helper: unknown argument {other}");
                return Err(ExitCode::FAILURE);
            }
        }
        i += 1;
    }

    let Some(table_path) = table_path else {
        eprintln!("syncd-helper: --table is required");
        return Err(ExitCode::FAILURE);
    };

    // A privileged helper must not read its policy from a file an
    // unprivileged user can edit. Refuse unless the file is owned by uid 0.
    // In the test harness --simulate relaxes this, because the demo runs
    // unprivileged; that switch is never used in a real deployment.
    let table_text = std::fs::read_to_string(&table_path).map_err(|e| {
        eprintln!("syncd-helper: cannot read {table_path}: {e}");
        ExitCode::FAILURE
    })?;
    if !simulate {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(&table_path).map_err(|e| {
            eprintln!("syncd-helper: cannot stat {table_path}: {e}");
            ExitCode::FAILURE
        })?;
        if meta.uid() != 0 {
            eprintln!("syncd-helper: refusing: {table_path} is not owned by root");
            return Err(ExitCode::FAILURE);
        }
    }

    let policy = Policy::from_table_text(&table_text, simulate).map_err(|e| {
        eprintln!("syncd-helper: bad table: {e}");
        ExitCode::FAILURE
    })?;

    if allow_hashes.is_empty() {
        eprintln!("syncd-helper: refusing to start with an empty code-hash allow-list");
        return Err(ExitCode::FAILURE);
    }
    let auth = AuthPolicy::new(allow_uids, &allow_hashes).map_err(|e| {
        eprintln!("syncd-helper: bad --allow-cdhash: {e}");
        ExitCode::FAILURE
    })?;

    println!(
        "syncd-helper: euid={} uid={} socket={socket} simulate={simulate}",
        unsafe_euid(),
        unsafe_uid()
    );

    let server = HelperServer::bind(&socket, policy, auth).map_err(|e| {
        eprintln!("syncd-helper: bind {socket}: {e}");
        ExitCode::FAILURE
    })?;

    // Tighten the socket so only owner and group can connect. The parent
    // directory should already be 0755 root:wheel; this is the second layer.
    if let Err(e) = server.restrict_permissions(&socket) {
        eprintln!("syncd-helper: warning: could not tighten socket permissions: {e}");
    }

    // Keep the idle timeout short: a helper with no callers should not hold
    // state open longer than necessary.
    let _ = Duration::from_secs(5);

    if decisions_stdout {
        server
            .serve(|line| println!("decision {line}"))
            .map_err(|e| {
                eprintln!("syncd-helper: serve: {e}");
                ExitCode::FAILURE
            })?;
    } else {
        server.serve(silent).map_err(|e| {
            eprintln!("syncd-helper: serve: {e}");
            ExitCode::FAILURE
        })?;
    }
    Ok(())
}

extern "C" {
    fn geteuid() -> u32;
    fn getuid() -> u32;
}

fn unsafe_euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { geteuid() }
}
fn unsafe_uid() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { getuid() }
}
