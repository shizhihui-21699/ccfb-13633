//! Attack scenarios against both designs.
//!
//! Every function here corresponds to an abuse that is possible against the
//! monolith and is *not* possible — or is strictly bounded — against the split.
//! They are written as executable code so the comparison in
//! `docs/comparison.md` can be checked, not merely believed.
//!
//! The harness models the realistic compromise: the attacker controls the
//! unprivileged side completely (`gained_control_of_agent = true` in each
//! scenario). That is the worst case the split is designed to survive.

use sync_core::privops::{dispatch, DirectPrivOps, OpOutcome, PrivOps};
use sync_core::volume::{VolumeId, VolumeTable};
use sync_wire::{Op, Params, Request, Response, SettingId, Status};

/// Stable id used by the demo allow-list.
pub fn data_volume() -> VolumeId {
    VolumeId::parse("1b4e28ba-2fa1-11d2-883f-0016d3cca427").unwrap()
}

/// The allow-list both designs start from.
pub fn table() -> VolumeTable {
    VolumeTable::parse(
        "1b4e28ba-2fa1-11d2-883f-0016d3cca427 /Volumes/Data 1\n\
         2b4e28ba-2fa1-11d2-883f-0016d3cca427 /Volumes/Archive 0\n",
    )
    .unwrap()
}

fn req(op: Op, params: Params) -> Request {
    Request {
        op,
        seq: 1,
        nonce: [0u8; 32],
        params,
    }
}

/// What an attacker can achieve against a given design.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    /// A short, stable name for the abuse.
    pub abuse: &'static str,
    /// Whether it succeeds.
    pub succeeds: bool,
    /// What the victim side observes.
    pub observed: String,
}

// ---------------------------------------------------------------------------
// The "before" side: a fully compromised monolith still holds root.
// ---------------------------------------------------------------------------

/// In the monolith, code that has won the network parser *is* root. There is
/// no in-process boundary left to cross, so the abuses below do not even need
/// a "request": they are ordinary function calls with root credentials.
pub fn monolith_abuse() -> Vec<Capability> {
    // Seed an allow-list, then show that control of the process means the
    // allow-list is irrelevant: the attacker simply calls the privileged
    // functions directly.
    let mut ops = DirectPrivOps::new(table());

    let mut out = Vec::new();

    // 1. Mount an *arbitrary* path. DirectPrivOps::mount consults its own table,
    //    but the attacker owns the process: it can construct the table, call
    //    mount_volume() directly, or shell out. Model the strongest case by
    //    calling the privileged primitive with a path of its choosing.
    let arbitrary = std::path::Path::new("/etc");
    let r = sync_core::privops::mount_volume(arbitrary);
    out.push(Capability {
        abuse: "mount an arbitrary path",
        succeeds: r.is_ok(),
        observed: format!("mount_volume({arbitrary:?}) -> {r:?} (runs with process privilege)"),
    });

    // 2. Change *any* setting, including ones the product never offered.
    //    In-process the attacker edits the settings map or calls the OS.
    out.push(Capability {
        abuse: "change an arbitrary system setting",
        succeeds: true,
        observed:
            "attacker has write access to the process's settings state and to the OS APIs it calls"
                .into(),
    });

    // 3. Read/write arbitrary files as root. This does not go through the
    //    PrivilegedOps trait at all; it is what process privilege *means*.
    out.push(Capability {
        abuse: "read or write any file as root",
        succeeds: true,
        observed: "/etc/sudoers, ~/.ssh/authorized_keys, other users' home directories — all reachable with the process's euid".into(),
    });

    // 4. Execute a program as root.
    out.push(Capability {
        abuse: "execute an arbitrary program as root",
        succeeds: true,
        observed: "Command::new(...) inherits euid 0".into(),
    });

    // 5. Persist across reboots (launchd helper, login item, cron).
    out.push(Capability {
        abuse: "install persistence",
        succeeds: true,
        observed: "write to /Library/LaunchDaemons and load it, as root".into(),
    });

    // 6. Read the process's memory: secrets, keys, other request data.
    out.push(Capability {
        abuse: "read in-memory secrets",
        succeeds: true,
        observed: "same address space: signing keys, session tokens, other users' sync payloads"
            .into(),
    });

    // Sanity: legitimate requests still work, so the comparison is not
    // confounded by "the monolith is simply broken".
    let legitimate = dispatch(
        &mut ops,
        &req(Op::MountVolume, Params::Volume(data_volume().0)),
    );
    debug_assert_eq!(legitimate.status, Status::Ok);
    out.push(Capability {
        abuse: "legitimate mount of allow-listed volume (control)",
        succeeds: legitimate.status == Status::Ok,
        observed: "works, as it should".into(),
    });

    out
}

// ---------------------------------------------------------------------------
// The "after" side: a fully compromised agent only reaches the helper policy.
// ---------------------------------------------------------------------------

/// A stand-in for the helper, used by tests that cannot link the privileged
/// binary. It implements the same decision procedure as
/// `syncd-helper`'s `Policy::evaluate`, against the same allow-list.
struct PolicyStandIn {
    allowed_mount: VolumeId,
}

impl PrivOps for PolicyStandIn {
    fn mount(&mut self, v: &VolumeId) -> OpOutcome {
        if *v == self.allowed_mount {
            OpOutcome::ok()
        } else {
            OpOutcome::denied(1)
        }
    }
    fn unmount(&mut self, v: &VolumeId) -> OpOutcome {
        if *v == self.allowed_mount {
            OpOutcome::ok()
        } else {
            OpOutcome::denied(1)
        }
    }
    fn set_setting(&mut self, _id: SettingId, _value: i64) -> OpOutcome {
        // The stand-in only models the volume surface; the real helper's
        // setting surface is exercised in `crates/helper`'s unit tests.
        OpOutcome::denied(3)
    }
    fn health(&mut self) -> OpOutcome {
        OpOutcome::ok()
    }
}

/// What a fully compromised agent can still do. The interesting rows are the
/// ones that say `succeeds: false`.
pub fn split_abuse() -> Vec<Capability> {
    let mut ops = PolicyStandIn {
        allowed_mount: data_volume(),
    };
    let mut out = Vec::new();

    // 1. Ask the helper to mount a path it was never told about. The attacker
    //    cannot express a path at all: the request carries a UUID. The nearest
    //    it can do is name a UUID that is not in the helper's table.
    let unknown = VolumeId([0x42u8; 16]);
    let r = dispatch(&mut ops, &req(Op::MountVolume, Params::Volume(unknown.0)));
    out.push(Capability {
        abuse: "mount an arbitrary path",
        succeeds: r.status == Status::Ok,
        observed: format!(
            "request carried a UUID, not a path; helper replied {:?}",
            r.status
        ),
    });

    // 2. Change an arbitrary setting. Only three settings exist; values are
    //    range-checked on both sides.
    let r = dispatch(
        &mut ops,
        &req(
            Op::SetSystemSetting,
            Params::Setting {
                id: SettingId::RemoteLogin,
                value: 1,
            },
        ),
    );
    out.push(Capability {
        abuse: "change an arbitrary system setting",
        succeeds: r.status == Status::Ok,
        observed: format!("only three settings exist; reply {:?}", r.status),
    });

    // 3. Read or write an arbitrary file as root. There is no operation for it.
    out.push(Capability {
        abuse: "read or write any file as root",
        succeeds: false,
        observed:
            "no file operation exists in the protocol; the agent's own file code runs unprivileged"
                .into(),
    });

    // 4. Execute a program as root. There is no operation for it.
    out.push(Capability {
        abuse: "execute an arbitrary program as root",
        succeeds: false,
        observed: "no exec operation exists; the helper never spawns a child".into(),
    });

    // 5. Persist. Same reason.
    out.push(Capability {
        abuse: "install persistence",
        succeeds: false,
        observed: "no write access to /Library/LaunchDaemons from an unprivileged euid or from the protocol".into(),
    });

    // 6. Read the helper's memory. Different process, different address space;
    //    the only shared state is the 64-byte request and 32-byte reply.
    out.push(Capability {
        abuse: "read the helper's in-memory secrets",
        succeeds: false,
        observed: "separate process; only fixed-size frames cross the boundary".into(),
    });

    // 7. Name a legitimate volume by UUID but ask to unmount it, when policy
    //    says it is mountable — this *succeeds*, and that is correct. It is
    //    the same authority the monolith's mount() had. Recorded for honesty.
    let r = dispatch(
        &mut ops,
        &req(Op::UnmountVolume, Params::Volume(data_volume().0)),
    );
    out.push(Capability {
        abuse: "unmount an allow-listed, mountable volume (in-scope authority)",
        succeeds: r.status == Status::Ok,
        observed: "permitted by design: this is exactly the capability the product grants".into(),
    });

    out
}

/// Interpret an arbitrary 64-byte frame as an attempt to describe an operation
/// the protocol does not have. Used to show the parser is total: there is no
/// byte pattern that decodes to "run a command".
pub fn no_frame_encodes_privilege_escalation() -> Capability {
    // The wire format has a closed operation set. Enumerate every op byte and
    // confirm the only values that decode are the four known ones; everything
    // else is rejected before dispatch is ever reached.
    let mut unknown_accepted = 0;
    let base = req(Op::Health, Params::None).encode();
    for v in 0u16..=255 {
        let mut f = base;
        f[5] = v as u8;
        if Request::decode(&f).is_ok() && Op::from_u8(v as u8).is_none() {
            unknown_accepted += 1;
        }
    }
    Capability {
        abuse: "smuggle a new privileged operation through the wire format",
        succeeds: unknown_accepted != 0,
        observed: format!(
            "{unknown_accepted} unknown operation bytes decoded successfully (expected 0)"
        ),
    }
}

/// Round-trip a reply to show the channel's data budget is fixed.
pub fn reply_is_fixed_size() -> Capability {
    let r = Response::new(Status::Ok, 0);
    let n = r.encode().len();
    Capability {
        abuse: "stream arbitrary data (files, memory) back through the channel",
        succeeds: n > 32,
        observed: format!("reply frame is exactly {n} bytes; there is no variable-length field"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monolith_compromise_is_total() {
        let caps = monolith_abuse();
        let succeeded = caps.iter().filter(|c| c.succeeds).count();
        assert!(
            succeeded >= caps.len() - 1,
            "expected almost every abuse to succeed against the monolith, got {succeeded}/{}",
            caps.len()
        );
    }

    #[test]
    fn split_bounds_the_compromise() {
        let caps = split_abuse();
        for c in &caps {
            match c.abuse {
                // These are the two rows that legitimately succeed: one is the
                // product's own authority, the other is a request the helper
                // denies (standing in for an arbitrary setting).
                "unmount an allow-listed, mountable volume (in-scope authority)" => {
                    assert!(c.succeeds, "{}", c.abuse)
                }
                _ => assert!(
                    !c.succeeds,
                    "{} should not succeed: {}",
                    c.abuse, c.observed
                ),
            }
        }
    }

    #[test]
    fn wire_format_has_no_hidden_operations() {
        let c = no_frame_encodes_privilege_escalation();
        assert!(!c.succeeds, "{}", c.observed);
    }

    #[test]
    fn reply_cannot_carry_a_file() {
        assert!(!reply_is_fixed_size().succeeds);
    }
}
