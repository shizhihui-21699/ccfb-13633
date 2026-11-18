//! `syncd-agent` — the unprivileged main process.
//!
//! This is the process an attacker is expected to reach first: it speaks the
//! network protocol, parses filenames, copies files. After the split it runs
//! as the logged-in user. When it needs privilege it has exactly one option —
//! send a fixed-size frame to the helper and accept the helper's decision.
//!
//! Mapping from the old "do it here" code to the new channel:
//!
//! | old (monolith)            | new (agent)                                    |
//! |---------------------------|------------------------------------------------|
//! | `DirectPrivOps::mount`    | `send(MountVolume, volume_uuid)`               |
//! | `DirectPrivOps::unmount`  | `send(UnmountVolume, volume_uuid)`             |
//! | `DirectPrivOps::set_...`  | `send(SetSystemSetting, id, value)`            |
//!
//! Note what is *not* in that table: there is no mapping for "read a file as
//! root", "exec a program", "write a path", "change an ACL", or "load a
//! kernel extension", because none of those exist on the far side either.

mod channel;

use std::process::ExitCode;
use std::time::Duration;

use channel::HelperClient;
use sync_core::net::{Reply, Server};
use sync_core::privops::{dispatch, OpOutcome, PrivOps};
use sync_core::volume::VolumeId;
use sync_core::SyncStore;
use sync_wire::{Op, Params, SettingId, Status};

/// The privileged surface as seen from the agent: every method forwards one
/// frame to the helper. There is no method an attacker can reach that ends
/// anywhere other than helper policy.
struct HelperPrivOps {
    client: HelperClient,
}

impl HelperPrivOps {
    fn send(&mut self, op: Op, params: Params) -> OpOutcome {
        match self.client.call(op, params) {
            Ok(resp) => {
                // PAYLOAD_LEN is 24, so the first eight bytes always exist.
                let p = resp.payload;
                let value = Some(i64::from_le_bytes([
                    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                ]));
                OpOutcome {
                    status: resp.status,
                    detail: resp.detail,
                    value,
                }
            }
            // A helper that is unreachable or incoherent behaves like a refusal,
            // never like a success and never like unbounded privilege.
            Err(_) => OpOutcome {
                status: Status::Internal,
                detail: 0xFF,
                value: None,
            },
        }
    }
}

impl PrivOps for HelperPrivOps {
    fn mount(&mut self, volume: &VolumeId) -> OpOutcome {
        self.send(Op::MountVolume, Params::Volume(volume.0))
    }
    fn unmount(&mut self, volume: &VolumeId) -> OpOutcome {
        self.send(Op::UnmountVolume, Params::Volume(volume.0))
    }
    fn set_setting(&mut self, id: SettingId, value: i64) -> OpOutcome {
        self.send(Op::SetSystemSetting, Params::Setting { id, value })
    }
    fn health(&mut self) -> OpOutcome {
        self.send(Op::Health, Params::None)
    }
}

const DEFAULT_LISTEN: &str = "127.0.0.1:7789";
const DEFAULT_HELPER: &str = "/var/run/syncd-helper.sock";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("syncd-agent: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let mut listen = DEFAULT_LISTEN.to_string();
    let mut helper_path = DEFAULT_HELPER.to_string();
    let mut store_root = std::env::temp_dir().join("syncd-agent-store");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                i += 1;
                listen = args.get(i).ok_or("--listen needs a value")?.clone();
            }
            "--helper" => {
                i += 1;
                helper_path = args.get(i).ok_or("--helper needs a value")?.clone();
            }
            "--store" => {
                i += 1;
                store_root = args.get(i).ok_or("--store needs a path")?.into();
            }
            "--help" | "-h" => {
                return Err(
                    "usage: syncd-agent [--listen ADDR] [--helper SOCKET] [--store DIR]".into(),
                )
            }
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }

    // The unprivileged side refuses to start with elevated privileges. Static
    // privilege is what the split is designed to remove; if this binary is ever
    // started as root, refuse rather than silently become the monolith again.
    let euid = unsafe_euid();
    if euid == 0 {
        return Err("refusing to run as root: this process is the unprivileged side".into());
    }
    println!("syncd-agent: euid={} (unprivileged side)", euid);

    let _store = SyncStore::new(store_root);
    let mut ops = HelperPrivOps {
        client: HelperClient::new(helper_path.clone()),
    };

    match ops.client.health() {
        Ok(r) if r.status == Status::Ok => println!("syncd-agent: helper reachable at {helper_path}"),
        Ok(_) | Err(_) => println!(
            "syncd-agent: helper not answering at {helper_path}; privileged requests will fail closed"
        ),
    }

    let server =
        Server::bind(&listen, REQUEST_TIMEOUT).map_err(|e| format!("bind {listen}: {e}"))?;
    println!("syncd-agent: listening on {listen}");

    server
        .serve(|request| -> Reply {
            match request {
                Ok(req) => {
                    // The same dispatcher, and the same semantics, as the
                    // monolith — but the executor is now a remote, policy-
                    // enforcing process instead of this one's own syscalls.
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
}

fn unsafe_euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { geteuid() }
}
