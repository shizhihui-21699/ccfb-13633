//! The helper's own policy: what an *authenticated* caller may do.
//!
//! Authentication answers "which program is this?". Policy answers "is this
//! particular operation on this particular object permitted?" The two are
//! independent, and both are enforced here, in the privileged process:
//!
//! * the helper loads its volume allow-list from a root-owned file at startup;
//! * the caller can only name a volume by UUID, never by path;
//! * the matched volume must be flagged mountable in *that* file;
//! * settings are pinned to a fixed set with a fixed value range.
//!
//! Consequently a fully compromised agent — genuine binary, genuine hash,
//! arbitrary requests — can still only ask for what this file already
//! permits. That is the whole point of the split.

use std::collections::BTreeMap;

use sync_core::privops::OpOutcome;
use sync_core::privops::{mount_volume, unmount_volume};
use sync_core::volume::{VolumeId, VolumeTable};
use sync_wire::{Op, Params, Request, SettingId, Status};

/// Detail codes are shared with the monolith so an identical decision gets an
/// identical code from both designs. Re-exported here for call-site brevity.
pub use sync_core::privops::detail;

/// Runtime state of the helper's policy.
pub struct Policy {
    volumes: VolumeTable,
    /// Current values of settings this helper has applied.
    settings: BTreeMap<SettingId, i64>,
    /// If set, mounts and unmounts are simulated rather than performed. Used
    /// by the test harness so the demo never touches a real system.
    simulate: bool,
}

impl Policy {
    /// Build a policy from a parsed volume table.
    pub fn new(volumes: VolumeTable, simulate: bool) -> Self {
        Policy {
            volumes,
            settings: BTreeMap::new(),
            simulate,
        }
    }

    /// Load a policy from a table file. The caller (main) is responsible for
    /// refusing to run with a file that is not root-owned.
    pub fn from_table_text(text: &str, simulate: bool) -> Result<Self, String> {
        Ok(Policy::new(VolumeTable::parse(text)?, simulate))
    }

    /// Evaluate one already-decoded, already-authenticated request.
    ///
    /// Every branch re-derives what is allowed from `self`; nothing about the
    /// request is trusted except its typed contents, which the wire decoder
    /// has already bounded.
    pub fn evaluate(&mut self, req: &Request) -> OpOutcome {
        match (req.op, req.params) {
            (Op::Health, Params::None) => OpOutcome::ok(),

            (Op::MountVolume, Params::Volume(raw)) => {
                let id = VolumeId(raw);
                let Some(vol) = self.volumes.get(&id) else {
                    return OpOutcome::denied(detail::VOLUME_NOT_ALLOWED);
                };
                if !vol.allow_mount {
                    return OpOutcome::denied(detail::MOUNT_NOT_ALLOWED);
                }
                if self.simulate {
                    return OpOutcome::ok();
                }
                match mount_volume(&vol.mount_point) {
                    Ok(()) => OpOutcome::ok(),
                    Err(code) => OpOutcome {
                        status: Status::Internal,
                        detail: detail::MOUNT_FAILED,
                        value: Some(code as i64),
                    },
                }
            }

            (Op::UnmountVolume, Params::Volume(raw)) => {
                let id = VolumeId(raw);
                let Some(vol) = self.volumes.get(&id) else {
                    return OpOutcome::denied(detail::VOLUME_NOT_ALLOWED);
                };
                if !vol.allow_mount {
                    return OpOutcome::denied(detail::MOUNT_NOT_ALLOWED);
                }
                if self.simulate {
                    return OpOutcome::ok();
                }
                match unmount_volume(&vol.mount_point) {
                    Ok(()) => OpOutcome::ok(),
                    Err(code) => OpOutcome {
                        status: Status::Internal,
                        detail: detail::UNMOUNT_FAILED,
                        value: Some(code as i64),
                    },
                }
            }

            (Op::SetSystemSetting, Params::Setting { id, value }) => {
                // Defence in depth: the wire decoder enforces this range too,
                // but the privileged side must not rely on the client-side
                // representation alone.
                let permitted = match id {
                    SettingId::DisksSleep | SettingId::AutomaticLogin | SettingId::RemoteLogin => {
                        value == 0 || value == 1
                    }
                };
                if !permitted {
                    return OpOutcome::denied(detail::VALUE_OUT_OF_RANGE);
                }
                self.settings.insert(id, value);
                OpOutcome {
                    status: Status::Ok,
                    detail: 0,
                    value: Some(value),
                }
            }

            // A parameter shape that does not match its operation. The decoder
            // rejects these, so reaching here means a bug; refuse rather than
            // guess.
            _ => OpOutcome {
                status: Status::BadRequest,
                detail: 0,
                value: None,
            },
        }
    }

    /// Resolve a volume id to its configured path. Exposed for tests only.
    #[cfg(test)]
    fn path_for(&self, id: &VolumeId) -> Option<std::path::PathBuf> {
        self.volumes.get(id).map(|v| v.mount_point.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const U1: &str = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";
    const U2: &str = "2b4e28ba-2fa1-11d2-883f-0016d3cca427";

    fn policy() -> Policy {
        Policy::from_table_text(
            &format!("{U1} /Volumes/Data 1\n{U2} /Volumes/Archive 0\n"),
            true,
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

    fn uuid(s: &str) -> [u8; 16] {
        VolumeId::parse(s).unwrap().0
    }

    #[test]
    fn health_allowed() {
        let mut p = policy();
        assert_eq!(
            p.evaluate(&req(Op::Health, Params::None)).status,
            Status::Ok
        );
    }

    #[test]
    fn allow_listed_volume_mounts() {
        let mut p = policy();
        assert_eq!(
            p.path_for(&VolumeId(uuid(U1))),
            Some(std::path::PathBuf::from("/Volumes/Data"))
        );
        let out = p.evaluate(&req(Op::MountVolume, Params::Volume(uuid(U1))));
        assert_eq!(out.status, Status::Ok);
    }

    #[test]
    fn unknown_volume_denied() {
        let mut p = policy();
        let out = p.evaluate(&req(Op::MountVolume, Params::Volume([0x42u8; 16])));
        assert_eq!(out.status, Status::Denied);
        assert_eq!(out.detail, detail::VOLUME_NOT_ALLOWED);
    }

    #[test]
    fn non_mountable_volume_denied() {
        let mut p = policy();
        let out = p.evaluate(&req(Op::MountVolume, Params::Volume(uuid(U2))));
        assert_eq!(out.status, Status::Denied);
        assert_eq!(out.detail, detail::MOUNT_NOT_ALLOWED);
    }

    #[test]
    fn setting_values_are_rechecked_on_the_privileged_side() {
        let mut p = policy();
        for value in [0, 1] {
            let out = p.evaluate(&req(
                Op::SetSystemSetting,
                Params::Setting {
                    id: SettingId::DisksSleep,
                    value,
                },
            ));
            assert_eq!(out.status, Status::Ok);
        }
        for value in [-1, 2, 1000, i64::MAX] {
            let out = p.evaluate(&req(
                Op::SetSystemSetting,
                Params::Setting {
                    id: SettingId::DisksSleep,
                    value,
                },
            ));
            assert_eq!(out.status, Status::Denied, "value {value}");
            assert_eq!(out.detail, detail::VALUE_OUT_OF_RANGE);
        }
    }

    #[test]
    fn mismatched_shapes_are_bad_requests() {
        let mut p = policy();
        let out = p.evaluate(&req(Op::Health, Params::Volume([1u8; 16])));
        assert_eq!(out.status, Status::BadRequest);
        let out = p.evaluate(&req(Op::MountVolume, Params::None));
        assert_eq!(out.status, Status::BadRequest);
    }
}
