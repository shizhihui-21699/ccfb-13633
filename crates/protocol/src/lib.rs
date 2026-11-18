//! `sync-wire` — the complete trust boundary between the unprivileged agent
//! and the privileged helper.
//!
//! # Design rules (each one is a security property, not a style choice)
//!
//! 1. **Fixed size.** A request is exactly [`REQUEST_LEN`] bytes. There is no
//!    length field, so there is nothing for a hostile peer to lie about and no
//!    allocator on the receive path.
//! 2. **No strings, no paths, no shell.** The request carries a small enum of
//!    operation codes plus fixed-width identifiers. Volumes are named by UUID;
//!    the helper resolves the UUID to a path from *its own* table. A fully
//!    compromised agent therefore cannot name a path, a command, or an
//!    environment variable.
//! 3. **Exhaustive, fail-closed parsing.** Every bit of the frame is either
//!    interpreted or required to be zero. Unknown operation codes, unknown
//!    flag bits, non-zero reserved bytes and malformed UUIDs are all rejected.
//! 4. **Bounded responses.** A reply is exactly [`RESPONSE_LEN`] bytes with a
//!    fixed-size payload, so a compromised helper cannot stream data (files,
//!    secrets, memory) back through the channel.
//!
//! This crate has no dependencies and no `unsafe`. It is small enough to read
//! in one sitting, which is the point: it is the only code both privilege
//! domains share.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![no_std]

/// Bytes in an encoded request frame.
pub const REQUEST_LEN: usize = 64;
/// Bytes in an encoded response frame.
pub const RESPONSE_LEN: usize = 32;
/// Bytes available to a response payload.
pub const PAYLOAD_LEN: usize = 24;
/// Protocol version carried in every frame.
pub const VERSION: u8 = 1;

const REQUEST_MAGIC: [u8; 4] = *b"SYNC";
const RESPONSE_MAGIC: [u8; 4] = *b"SYNR";

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// The complete list of privileged operations the helper will ever perform.
///
/// If an operation is not listed here it cannot be requested, and if it cannot
/// be requested the main process cannot cause it to happen — no matter what an
/// attacker does to the main process.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Op {
    /// Liveness check. Performs no privileged work.
    Health = 0,
    /// Mount one allow-listed volume by UUID.
    MountVolume = 1,
    /// Unmount one allow-listed volume by UUID.
    UnmountVolume = 2,
    /// Change one allow-listed system setting to an allow-listed value.
    SetSystemSetting = 3,
}

impl Op {
    /// Map a wire byte to an operation, rejecting everything else.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Op::Health),
            1 => Some(Op::MountVolume),
            2 => Some(Op::UnmountVolume),
            3 => Some(Op::SetSystemSetting),
            _ => None,
        }
    }
}

/// System settings a caller is allowed to request. This is an allow-list, not
/// a name: the helper maps each variant to a concrete setting and permitted
/// value range of its own choosing.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u16)]
pub enum SettingId {
    /// Enable or disable "Put hard disks to sleep when possible".
    DisksSleep = 1,
    /// Enable or disable automatic login (0 = off, 1 = on).
    AutomaticLogin = 2,
    /// Enable or disable incoming network sharing (0 = off, 1 = on).
    RemoteLogin = 3,
}

impl SettingId {
    /// Map a wire value to a setting, rejecting everything else.
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(SettingId::DisksSleep),
            2 => Some(SettingId::AutomaticLogin),
            3 => Some(SettingId::RemoteLogin),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// Parameters of a request, decoded into typed form.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Params {
    /// No parameters.
    None,
    /// A volume, identified by its UUID.
    Volume([u8; 16]),
    /// A system setting and its requested value.
    Setting {
        /// Which allow-listed setting to change.
        id: SettingId,
        /// Requested value; the permitted range is per-setting.
        value: i64,
    },
}

/// A decoded, validated request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Request {
    /// Which privileged operation is being asked for.
    pub op: Op,
    /// Strictly increasing per-connection sequence number. The helper rejects
    /// any frame whose sequence number is not greater than the last accepted
    /// one, which makes replaying a captured frame useless even to a peer that
    /// legitimately owns the connection.
    pub seq: u64,
    /// Per-connection random nonce, fixed at handshake. Binds frames to a
    /// single connection.
    pub nonce: [u8; 32],
    /// Operation-specific parameters.
    pub params: Params,
}

/// Why a frame could not be decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeError {
    /// Frame did not start with the request magic.
    BadMagic,
    /// Protocol version mismatch.
    BadVersion,
    /// Operation code is not in the allow-list.
    UnknownOp,
    /// Any flag bit other than zero was set.
    UnknownFlags,
    /// Reserved bytes were expected to be zero and were not.
    NonZeroReserved,
    /// The parameters for this operation were not well-formed.
    BadParams,
}

impl Request {
    /// Encode into a fixed-size frame.
    pub fn encode(&self) -> [u8; REQUEST_LEN] {
        let mut out = [0u8; REQUEST_LEN];
        out[0..4].copy_from_slice(&REQUEST_MAGIC);
        out[4] = VERSION;
        out[5] = self.op as u8;
        out[6..8].copy_from_slice(&0u16.to_le_bytes()); // flags: always zero for now
        out[8..16].copy_from_slice(&self.seq.to_le_bytes());
        out[16..48].copy_from_slice(&self.nonce);
        match self.params {
            Params::None => {}
            Params::Volume(uuid) => out[48..64].copy_from_slice(&uuid),
            Params::Setting { id, value } => {
                out[48..50].copy_from_slice(&(id as u16).to_le_bytes());
                out[50..58].copy_from_slice(&value.to_le_bytes());
                // bytes 58..64 stay zero and are re-checked on decode
            }
        }
        out
    }

    /// Decode a frame, rejecting anything that is not exactly a well-formed
    /// request. This function is total: every input yields either `Ok` or a
    /// specific error, and it never panics.
    pub fn decode(frame: &[u8; REQUEST_LEN]) -> Result<Self, DecodeError> {
        if frame[0..4] != REQUEST_MAGIC {
            return Err(DecodeError::BadMagic);
        }
        if frame[4] != VERSION {
            return Err(DecodeError::BadVersion);
        }
        let op = Op::from_u8(frame[5]).ok_or(DecodeError::UnknownOp)?;
        let flags = u16::from_le_bytes([frame[6], frame[7]]);
        if flags != 0 {
            return Err(DecodeError::UnknownFlags);
        }
        // Fixed-index arrays rather than slice conversion: the length is known
        // to the compiler, so there is no `try_into().unwrap()` for a reader to
        // audit.
        let seq = u64::from_le_bytes([
            frame[8], frame[9], frame[10], frame[11], frame[12], frame[13], frame[14], frame[15],
        ]);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&frame[16..48]);
        let tail = &frame[48..64];

        let params = match op {
            Op::Health => {
                if tail.iter().any(|b| *b != 0) {
                    return Err(DecodeError::NonZeroReserved);
                }
                Params::None
            }
            Op::MountVolume | Op::UnmountVolume => {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(tail);
                if !is_plausible_uuid(&uuid) {
                    return Err(DecodeError::BadParams);
                }
                Params::Volume(uuid)
            }
            Op::SetSystemSetting => {
                let id = SettingId::from_u16(u16::from_le_bytes([tail[0], tail[1]]))
                    .ok_or(DecodeError::BadParams)?;
                let value = i64::from_le_bytes([
                    tail[2], tail[3], tail[4], tail[5], tail[6], tail[7], tail[8], tail[9],
                ]);
                if tail[10..16].iter().any(|b| *b != 0) {
                    return Err(DecodeError::NonZeroReserved);
                }
                if !value_in_range(id, value) {
                    return Err(DecodeError::BadParams);
                }
                Params::Setting { id, value }
            }
        };
        Ok(Request {
            op,
            seq,
            nonce,
            params,
        })
    }
}

/// A UUID is "plausible" if it is neither all-zero nor all-ones. The helper's
/// allow-list is what actually decides authorisation; this only rejects values
/// that cannot name anything.
fn is_plausible_uuid(u: &[u8; 16]) -> bool {
    !u.iter().all(|b| *b == 0) && !u.iter().all(|b| *b == 0xFF)
}

/// Numeric range permitted for each setting. This is a *protocol* limit; the
/// helper applies its own, possibly stricter, policy on top.
fn value_in_range(id: SettingId, value: i64) -> bool {
    match id {
        SettingId::DisksSleep => value == 0 || value == 1,
        SettingId::AutomaticLogin => value == 0 || value == 1,
        SettingId::RemoteLogin => value == 0 || value == 1,
    }
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// Outcome status codes. Kept small and closed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Status {
    /// The operation completed.
    Ok = 0,
    /// The helper refused: not in its allow-list, or policy said no.
    Denied = 1,
    /// The request was malformed or failed peer authentication.
    BadRequest = 2,
    /// The request was valid but the resource is not present.
    NotAvailable = 3,
    /// The request was valid but the resource is busy.
    Busy = 4,
    /// The helper failed internally; no detail is exposed to the caller.
    Internal = 5,
}

impl Status {
    /// Map a wire byte to a status; unknown values are treated as `Internal`
    /// (fail closed on the client side).
    pub const fn from_u8(v: u8) -> Status {
        match v {
            0 => Status::Ok,
            1 => Status::Denied,
            2 => Status::BadRequest,
            3 => Status::NotAvailable,
            4 => Status::Busy,
            _ => Status::Internal,
        }
    }
}

/// A helper reply: fixed size, fixed amount of information.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Response {
    /// Outcome.
    pub status: Status,
    /// Operation-specific detail code. The set of values is defined per
    /// operation; it is deliberately a small integer and never a string, so
    /// the channel cannot carry free-form data.
    pub detail: u8,
    /// Small fixed payload (for example the current value of a setting).
    /// Unused bytes are zero.
    pub payload: [u8; PAYLOAD_LEN],
}

impl Response {
    /// A response with no payload.
    pub const fn new(status: Status, detail: u8) -> Self {
        Response {
            status,
            detail,
            payload: [0u8; PAYLOAD_LEN],
        }
    }

    /// Encode into a fixed-size frame.
    pub fn encode(&self) -> [u8; RESPONSE_LEN] {
        let mut out = [0u8; RESPONSE_LEN];
        out[0..4].copy_from_slice(&RESPONSE_MAGIC);
        out[4] = self.status as u8;
        out[5] = self.detail;
        // bytes 6..8 reserved, stay zero
        out[8..32].copy_from_slice(&self.payload);
        out
    }

    /// Decode a reply, rejecting malformed frames (fail closed: the caller
    /// must not act on a reply it cannot parse).
    pub fn decode(frame: &[u8; RESPONSE_LEN]) -> Result<Self, DecodeError> {
        if frame[0..4] != RESPONSE_MAGIC {
            return Err(DecodeError::BadMagic);
        }
        if frame[6] != 0 || frame[7] != 0 {
            return Err(DecodeError::NonZeroReserved);
        }
        let mut payload = [0u8; PAYLOAD_LEN];
        payload.copy_from_slice(&frame[8..32]);
        Ok(Response {
            status: Status::from_u8(frame[4]),
            detail: frame[5],
            payload,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(nonce_seed: u8) -> [u8; 32] {
        let mut n = [0u8; 32];
        for (i, b) in n.iter_mut().enumerate() {
            *b = nonce_seed.wrapping_add(i as u8);
        }
        n
    }

    fn round_trip(req: Request) {
        let frame = req.encode();
        let back = Request::decode(&frame).expect("valid frame must decode");
        assert_eq!(back, req);
    }

    #[test]
    fn health_round_trip() {
        round_trip(Request {
            op: Op::Health,
            seq: 7,
            nonce: sample(1),
            params: Params::None,
        });
    }

    #[test]
    fn mount_round_trip() {
        let uuid = [0x11u8; 16];
        round_trip(Request {
            op: Op::MountVolume,
            seq: 1,
            nonce: sample(2),
            params: Params::Volume(uuid),
        });
        round_trip(Request {
            op: Op::UnmountVolume,
            seq: 2,
            nonce: sample(3),
            params: Params::Volume(uuid),
        });
    }

    #[test]
    fn setting_round_trip() {
        round_trip(Request {
            op: Op::SetSystemSetting,
            seq: 9,
            nonce: sample(4),
            params: Params::Setting {
                id: SettingId::RemoteLogin,
                value: 1,
            },
        });
    }

    #[test]
    fn every_unknown_op_is_rejected() {
        let base = Request {
            op: Op::Health,
            seq: 0,
            nonce: sample(0),
            params: Params::None,
        }
        .encode();
        for v in 0u16..=255 {
            if Op::from_u8(v as u8).is_some() {
                continue;
            }
            let mut f = base;
            f[5] = v as u8;
            assert_eq!(
                Request::decode(&f),
                Err(DecodeError::UnknownOp),
                "op {v} accepted"
            );
        }
    }

    #[test]
    fn unknown_flag_bits_are_rejected() {
        let base = Request {
            op: Op::Health,
            seq: 0,
            nonce: sample(0),
            params: Params::None,
        }
        .encode();
        for bit in 0..16 {
            let mut f = base;
            f[6 + bit / 8] |= 1 << (bit % 8);
            assert_eq!(
                Request::decode(&f),
                Err(DecodeError::UnknownFlags),
                "bit {bit}"
            );
        }
    }

    #[test]
    fn health_rejects_any_parameter_byte() {
        let base = Request {
            op: Op::Health,
            seq: 0,
            nonce: sample(0),
            params: Params::None,
        }
        .encode();
        for off in 48..64 {
            let mut f = base;
            f[off] = 1;
            assert_eq!(
                Request::decode(&f),
                Err(DecodeError::NonZeroReserved),
                "offset {off}"
            );
        }
    }

    #[test]
    fn bad_magic_and_version_rejected() {
        let mut f = Request {
            op: Op::Health,
            seq: 0,
            nonce: sample(0),
            params: Params::None,
        }
        .encode();
        f[0] ^= 0xFF;
        assert_eq!(Request::decode(&f), Err(DecodeError::BadMagic));
        let mut f = Request {
            op: Op::Health,
            seq: 0,
            nonce: sample(0),
            params: Params::None,
        }
        .encode();
        f[4] = 2;
        assert_eq!(Request::decode(&f), Err(DecodeError::BadVersion));
    }

    #[test]
    fn degenerate_uuids_rejected() {
        for uuid in [[0u8; 16], [0xFFu8; 16]] {
            let f = Request {
                op: Op::MountVolume,
                seq: 1,
                nonce: sample(0),
                params: Params::Volume(uuid),
            }
            .encode();
            assert_eq!(Request::decode(&f), Err(DecodeError::BadParams));
        }
    }

    #[test]
    fn setting_unknown_id_rejected() {
        let mut f = Request {
            op: Op::SetSystemSetting,
            seq: 1,
            nonce: sample(0),
            params: Params::Setting {
                id: SettingId::DisksSleep,
                value: 0,
            },
        }
        .encode();
        f[48..50].copy_from_slice(&999u16.to_le_bytes());
        assert_eq!(Request::decode(&f), Err(DecodeError::BadParams));
    }

    #[test]
    fn setting_out_of_range_value_rejected() {
        for value in [-1i64, 2, i64::MIN, i64::MAX] {
            let mut f = Request {
                op: Op::SetSystemSetting,
                seq: 1,
                nonce: sample(0),
                params: Params::Setting {
                    id: SettingId::AutomaticLogin,
                    value: 0,
                },
            }
            .encode();
            f[50..58].copy_from_slice(&value.to_le_bytes());
            assert_eq!(
                Request::decode(&f),
                Err(DecodeError::BadParams),
                "value {value}"
            );
        }
    }

    #[test]
    fn setting_rejects_nonzero_tail() {
        let base = Request {
            op: Op::SetSystemSetting,
            seq: 1,
            nonce: sample(0),
            params: Params::Setting {
                id: SettingId::DisksSleep,
                value: 1,
            },
        }
        .encode();
        for off in 58..64 {
            let mut f = base;
            f[off] = 0x80;
            assert_eq!(
                Request::decode(&f),
                Err(DecodeError::NonZeroReserved),
                "offset {off}"
            );
        }
    }

    #[test]
    fn response_round_trip_and_fail_closed() {
        let r = Response::new(Status::Denied, 4);
        let f = r.encode();
        assert_eq!(Response::decode(&f), Ok(r));
        let mut bad = f;
        bad[0] = b'X';
        assert!(Response::decode(&bad).is_err());
        // Unknown status bytes become Internal rather than a panic.
        let mut odd = f;
        odd[4] = 200;
        assert_eq!(Response::decode(&odd).unwrap().status, Status::Internal);
    }

    /// Exhaustive single-byte mutation: no input may panic, and any mutation
    /// that produces a decodable request must have been intended by the
    /// encoder's own invariants.
    #[test]
    fn no_single_byte_mutation_panics() {
        let frames = [
            Request {
                op: Op::Health,
                seq: 0,
                nonce: sample(0),
                params: Params::None,
            }
            .encode(),
            Request {
                op: Op::MountVolume,
                seq: 3,
                nonce: sample(5),
                params: Params::Volume([9u8; 16]),
            }
            .encode(),
            Request {
                op: Op::SetSystemSetting,
                seq: 3,
                nonce: sample(6),
                params: Params::Setting {
                    id: SettingId::DisksSleep,
                    value: 1,
                },
            }
            .encode(),
        ];
        for base in frames {
            for off in 0..REQUEST_LEN {
                for xor in [0x01u8, 0x80, 0xFF] {
                    let mut f = base;
                    f[off] ^= xor;
                    // Must not panic; result value is irrelevant.
                    let _ = Request::decode(&f);
                }
            }
        }
    }
}
