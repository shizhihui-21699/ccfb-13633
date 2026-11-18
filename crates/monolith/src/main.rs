//! `syncd-monolith` — the simplified "before" service.
//!
//! One process. It parses hostile network requests and, in the same address
//! space and at the same privilege level, mounts volumes and changes system
//! settings. It is a faithful sketch of the original design: convenient, and
//! entirely privileged.
//!
//! Run it as an ordinary user for the demo; the point is not that the demo
//! needs root, but that this binary is *designed* to run as root, and every
//! line of it — the parser, the path handling, the file store — would then be
//! root too.

use std::process::ExitCode;
use std::time::Duration;

use sync_core::net::{read_request, write_response, Reply, Server};
use sync_core::privops::{dispatch, DirectPrivOps};
use sync_core::volume::VolumeTable;
use sync_core::SyncStore;
use sync_wire::Status;

const DEFAULT_LISTEN: &str = "127.0.0.1:7788";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("syncd-monolith: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Config {
    listen: String,
    volumes: VolumeTable,
    store: SyncStore,
}

fn parse_args(args: &[String]) -> Result<Config, String> {
    let mut listen = DEFAULT_LISTEN.to_string();
    let mut volumes = VolumeTable::default();
    let mut store = SyncStore::new(std::env::temp_dir().join("syncd-monolith-store"));

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                i += 1;
                listen = args.get(i).ok_or("--listen needs a value")?.clone();
            }
            "--volumes" => {
                i += 1;
                let path = args.get(i).ok_or("--volumes needs a path")?;
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read {path}: {e}"))?;
                volumes = VolumeTable::parse(&text)?;
            }
            "--store" => {
                i += 1;
                store = SyncStore::new(args.get(i).ok_or("--store needs a path")?.clone());
            }
            "--help" | "-h" => {
                return Err(
                    "usage: syncd-monolith [--listen ADDR] [--volumes FILE] [--store DIR]".into(),
                )
            }
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }
    Ok(Config {
        listen,
        volumes,
        store,
    })
}

fn run(args: &[String]) -> Result<(), String> {
    let cfg = parse_args(args)?;
    let _ = cfg.store; // used by the real sync path; not needed for the demo

    // In the original design the process is started as root and stays root.
    println!(
        "syncd-monolith: euid={} uid={}",
        unsafe_euid(),
        unsafe_uid()
    );
    println!("syncd-monolith: listening on {}", cfg.listen);

    let mut ops = DirectPrivOps::new(cfg.volumes);
    let server = Server::bind(&cfg.listen, REQUEST_TIMEOUT)
        .map_err(|e| format!("bind {}: {e}", cfg.listen))?;

    server
        .serve(|request| -> Reply {
            match request {
                Ok(req) => {
                    // The privileged operation is executed in this process. A
                    // memory-safety bug anywhere in the paths above this line
                    // is a root bug.
                    let outcome = dispatch(&mut ops, &req);
                    Reply {
                        status: outcome.status,
                        detail: outcome.detail,
                    }
                }
                Err(_) => Reply {
                    status: Status::BadRequest,
                    detail: 0,
                },
            }
        })
        .map_err(|e| format!("serve: {e}"))
}

extern "C" {
    fn geteuid() -> u32;
    fn getuid() -> u32;
}

fn unsafe_euid() -> u32 {
    // SAFETY: geteuid is always safe to call and has no preconditions.
    unsafe { geteuid() }
}
fn unsafe_uid() -> u32 {
    // SAFETY: getuid is always safe to call and has no preconditions.
    unsafe { getuid() }
}

// Keep `read_request`/`write_response` in scope for readers who follow the
// module docs; they are used by the tests in sync-core.
#[allow(dead_code)]
fn _framing_is_shared() {
    let _ = read_request::<&[u8]>;
    let _ = write_response::<Vec<u8>>;
}
