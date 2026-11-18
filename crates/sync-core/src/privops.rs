//! The one interface across which privilege is granted.
//!
//! [`PrivOps`] is intentionally tiny and closed: four operations, no paths, no
//! commands, no arbitrary file access. Two deployments implement it:
//!
//! * the monolith implements it by calling the OS directly *inside the same
//!   privileged process that parses hostile network data*;
//! * the split implements it by sending one fixed-size frame to the helper,
//!   which re-validates everything before doing anything.
//!
//! The trait exists so the shared parsing code is byte-for-byte the same in
//! both deployments. The difference is not the code an attacker reaches; it is
//! what that code is allowed to do once it is reached.

use crate::volume::{VolumeId, VolumeTable};
use std::path::PathBuf;
use sync_wire::{Op, Request, SettingId, Status};

/// The result of a privileged operation, already stripped of OS detail.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpOutcome {
    /// Outcome class.
    pub status: Status,
    /// Small per-operation detail code.
    pub detail: u8,
    /// Current value, where meaningful (for example a setting's value).
    pub value: Option<i64>,
}

impl OpOutcome {
    /// Convenience: a successful outcome with no value.
    pub const fn ok() -> Self {
        OpOutcome {
            status: Status::Ok,
            detail: 0,
            value: None,
        }
    }

    /// Convenience: a refusal.
    pub const fn denied(detail: u8) -> Self {
        OpOutcome {
            status: Status::Denied,
            detail,
            value: None,
        }
    }
}

/// The complete privileged surface available to the unprivileged side.
pub trait PrivOps {
    /// Mount an allow-listed volume.
    fn mount(&mut self, volume: &VolumeId) -> OpOutcome;
    /// Unmount an allow-listed volume.
    fn unmount(&mut self, volume: &VolumeId) -> OpOutcome;
    /// Apply an allow-listed system setting.
    fn set_setting(&mut self, id: SettingId, value: i64) -> OpOutcome;
    /// Report whether the privileged side is reachable and healthy.
    fn health(&mut self) -> OpOutcome;
}

/// Monolith implementation: performs the operation in-process, with the
/// process's full (root) privilege.
///
/// This is the "before" side. Note that the only thing standing between a
/// hostile request and `/bin/sh` here is the correctness of this module and of
/// every module that can reach it. There is no second check, because there is
/// no second process.
pub struct DirectPrivOps {
    volumes: VolumeTable,
    settings: BTreeMapLite,
}

// A tiny ordered map avoids pulling in anything, and keeps the type readable.
type BTreeMapLite = std::collections::BTreeMap<SettingId, i64>;

/// Per-operation detail codes. Both deployments return these, so a caller sees
/// the same answer from the monolith and from the split when the *decision* is
/// the same. They are defined here, in the shared crate, so the two sides
/// cannot drift.
pub mod detail {
    /// The requested volume is not in the allow-list.
    pub const VOLUME_NOT_ALLOWED: u8 = 1;
    /// The volume exists in the list but is not marked mountable.
    pub const MOUNT_NOT_ALLOWED: u8 = 2;
    /// The requested setting value is outside the permitted range.
    pub const VALUE_OUT_OF_RANGE: u8 = 4;
    /// The OS refused the mount.
    pub const MOUNT_FAILED: u8 = 5;
    /// The OS refused the unmount.
    pub const UNMOUNT_FAILED: u8 = 6;
}

impl DirectPrivOps {
    /// Build from an allow-list table.
    pub fn new(volumes: VolumeTable) -> Self {
        DirectPrivOps {
            volumes,
            settings: BTreeMapLite::new(),
        }
    }

    /// Resolve a volume id to a path, distinguishing "unknown" from
    /// "known but not mountable" so the detail code matches the helper's.
    fn resolve(&self, id: &VolumeId) -> Result<PathBuf, u8> {
        match self.volumes.get(id) {
            None => Err(detail::VOLUME_NOT_ALLOWED),
            Some(v) if !v.allow_mount => Err(detail::MOUNT_NOT_ALLOWED),
            Some(v) => Ok(v.mount_point.clone()),
        }
    }
}

impl PrivOps for DirectPrivOps {
    fn mount(&mut self, volume: &VolumeId) -> OpOutcome {
        let path = match self.resolve(volume) {
            Ok(p) => p,
            Err(code) => return OpOutcome::denied(code),
        };
        match mount_volume(&path) {
            Ok(()) => OpOutcome::ok(),
            Err(code) => OpOutcome {
                status: Status::Internal,
                detail: detail::MOUNT_FAILED,
                value: Some(code as i64),
            },
        }
    }

    fn unmount(&mut self, volume: &VolumeId) -> OpOutcome {
        let path = match self.resolve(volume) {
            Ok(p) => p,
            Err(code) => return OpOutcome::denied(code),
        };
        match unmount_volume(&path) {
            Ok(()) => OpOutcome::ok(),
            Err(code) => OpOutcome {
                status: Status::Internal,
                detail: detail::UNMOUNT_FAILED,
                value: Some(code as i64),
            },
        }
    }

    fn set_setting(&mut self, id: SettingId, value: i64) -> OpOutcome {
        if value != 0 && value != 1 {
            return OpOutcome::denied(detail::VALUE_OUT_OF_RANGE);
        }
        self.settings.insert(id, value);
        OpOutcome {
            status: Status::Ok,
            detail: 0,
            value: Some(value),
        }
    }

    fn health(&mut self) -> OpOutcome {
        OpOutcome::ok()
    }
}

/// Actual mounting. In a real build these shell out to `diskutil`; the toy
/// implementation records the intent so the program runs unprivileged in
/// tests. The *shape* is what matters for the comparison: in the monolith this
/// is reachable from the same address space as the network parser.
pub fn mount_volume(path: &std::path::Path) -> Result<(), u8> {
    if !path.is_absolute() {
        return Err(2);
    }
    Ok(())
}

/// Actual unmounting; see [`mount_volume`].
pub fn unmount_volume(path: &std::path::Path) -> Result<(), u8> {
    if !path.is_absolute() {
        return Err(2);
    }
    Ok(())
}

/// Translate a decoded request into the trait calls that implement it.
///
/// Both deployments reuse this function, so the operation *semantics* cannot
/// drift between "before" and "after"; only the trust level of the executor
/// changes. A request carrying a parameter shape that does not match its
/// operation is a protocol error, never something this function guesses about.
pub fn dispatch<P: PrivOps>(ops: &mut P, req: &Request) -> OpOutcome {
    use sync_wire::Params;
    match (req.op, req.params) {
        (Op::Health, Params::None) => ops.health(),
        (Op::MountVolume, Params::Volume(raw)) => ops.mount(&VolumeId(raw)),
        (Op::UnmountVolume, Params::Volume(raw)) => ops.unmount(&VolumeId(raw)),
        (Op::SetSystemSetting, Params::Setting { id, value }) => ops.set_setting(id, value),
        // Any other combination is a malformed request. The wire decoder
        // already rejects these, so this arm is defence in depth.
        _ => OpOutcome {
            status: Status::BadRequest,
            detail: 0,
            value: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sync_wire::Params;

    struct Recorder {
        calls: Vec<String>,
    }
    impl PrivOps for Recorder {
        fn mount(&mut self, v: &VolumeId) -> OpOutcome {
            self.calls.push(format!("mount {}", v.to_string()));
            OpOutcome::ok()
        }
        fn unmount(&mut self, v: &VolumeId) -> OpOutcome {
            self.calls.push(format!("unmount {}", v.to_string()));
            OpOutcome::ok()
        }
        fn set_setting(&mut self, id: SettingId, value: i64) -> OpOutcome {
            self.calls.push(format!("setting {:?} {}", id, value));
            OpOutcome::ok()
        }
        fn health(&mut self) -> OpOutcome {
            self.calls.push("health".into());
            OpOutcome::ok()
        }
    }

    fn req(op: Op, params: Params) -> Request {
        Request {
            op,
            seq: 1,
            nonce: [7u8; 32],
            params,
        }
    }

    #[test]
    fn dispatch_routes_each_operation() {
        let mut r = Recorder { calls: vec![] };
        dispatch(&mut r, &req(Op::Health, Params::None));
        dispatch(&mut r, &req(Op::MountVolume, Params::Volume([1u8; 16])));
        dispatch(&mut r, &req(Op::UnmountVolume, Params::Volume([2u8; 16])));
        dispatch(
            &mut r,
            &req(
                Op::SetSystemSetting,
                Params::Setting {
                    id: SettingId::DisksSleep,
                    value: 1,
                },
            ),
        );
        assert_eq!(r.calls.len(), 4);
        assert_eq!(r.calls[0], "health");
        assert!(r.calls[1].starts_with("mount "));
        assert_eq!(r.calls[3], "setting DisksSleep 1");
    }

    #[test]
    fn mismatched_parameters_are_rejected_not_guessed() {
        let mut r = Recorder { calls: vec![] };
        let out = dispatch(&mut r, &req(Op::Health, Params::Volume([1u8; 16])));
        assert_eq!(out.status, Status::BadRequest);
        assert!(r.calls.is_empty());
    }

    #[test]
    fn direct_privops_denies_unknown_volume() {
        let mut ops = DirectPrivOps::new(VolumeTable::default());
        let out = ops.mount(&VolumeId([3u8; 16]));
        assert_eq!(out.status, Status::Denied);
    }
}
