//! Volumes and the allow-list that maps a stable id to a mount point.
//!
//! The important property: a *caller* never supplies a path. It supplies a
//! [`VolumeId`], and the table decides whether that volume exists and where it
//! is allowed to be mounted. In the split, this table is loaded by the helper
//! from a root-owned file, so a compromised agent cannot add entries to it.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// A volume identifier: a 16-byte UUID.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct VolumeId(pub [u8; 16]);

impl VolumeId {
    /// Parse a canonical UUID string (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.len() != 36 {
            return None;
        }
        let bytes = s.as_bytes();
        let mut out = [0u8; 16];
        let mut oi = 0;
        let mut hi: Option<u8> = None;
        for (i, &c) in bytes.iter().enumerate() {
            // Hyphens are only valid at the canonical positions.
            let canonical_hyphen = matches!(i, 8 | 13 | 18 | 23);
            if canonical_hyphen {
                if c != b'-' {
                    return None;
                }
                continue;
            }
            if c == b'-' {
                return None;
            }
            let nibble = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return None,
            };
            match hi.take() {
                None => hi = Some(nibble),
                Some(h) => {
                    out[oi] = (h << 4) | nibble;
                    oi += 1;
                }
            }
        }
        if oi != 16 || hi.is_some() {
            return None;
        }
        Some(VolumeId(out))
    }

    /// Render as a canonical UUID string.
    #[allow(clippy::inherent_to_string)] // self is Copy and by-value on purpose
    pub fn to_string(self) -> String {
        let b = self.0;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

/// One allow-listed volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Volume {
    /// Stable id.
    pub id: VolumeId,
    /// Where the volume is mounted.
    pub mount_point: PathBuf,
    /// Whether the service may mount/unmount it.
    pub allow_mount: bool,
}

/// The set of volumes the service knows about.
#[derive(Clone, Debug, Default)]
pub struct VolumeTable {
    by_id: BTreeMap<VolumeId, Volume>,
}

impl VolumeTable {
    /// Build a table from an explicit list.
    pub fn new(volumes: Vec<Volume>) -> Self {
        let mut by_id = BTreeMap::new();
        for v in volumes {
            by_id.insert(v.id, v);
        }
        VolumeTable { by_id }
    }

    /// Parse a root-owned table file. Each non-empty, non-comment line is
    /// `<uuid> <mount-point> <allow_mount:0|1>`.
    ///
    /// A malformed line is a hard error: a configuration the helper cannot
    /// fully understand must not be silently narrowed (that could unmount the
    /// wrong thing) nor silently widened (that could authorise the wrong
    /// thing).
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut volumes = Vec::new();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let id_s = parts
                .next()
                .ok_or_else(|| format!("line {}: missing uuid", n + 1))?;
            let path_s = parts
                .next()
                .ok_or_else(|| format!("line {}: missing mount point", n + 1))?;
            let allow_s = parts
                .next()
                .ok_or_else(|| format!("line {}: missing allow flag", n + 1))?;
            if parts.next().is_some() {
                return Err(format!("line {}: trailing data", n + 1));
            }
            let id = VolumeId::parse(id_s).ok_or_else(|| format!("line {}: bad uuid", n + 1))?;
            if !path_s.starts_with('/') {
                return Err(format!("line {}: mount point must be absolute", n + 1));
            }
            let allow_mount = match allow_s {
                "0" => false,
                "1" => true,
                _ => return Err(format!("line {}: allow flag must be 0 or 1", n + 1)),
            };
            volumes.push(Volume {
                id,
                mount_point: PathBuf::from(path_s),
                allow_mount,
            });
        }
        Ok(VolumeTable::new(volumes))
    }

    /// Look up a volume.
    pub fn get(&self, id: &VolumeId) -> Option<&Volume> {
        self.by_id.get(id)
    }

    /// All volumes, in id order.
    pub fn iter(&self) -> impl Iterator<Item = &Volume> {
        self.by_id.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const U1: &str = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";

    #[test]
    fn uuid_round_trip() {
        let id = VolumeId::parse(U1).unwrap();
        assert_eq!(id.to_string(), U1);
    }

    #[test]
    fn uuid_rejects_malformed() {
        for s in [
            "",
            "1b4e28ba2fa111d2883f0016d3cca427",
            "1b4e28ba-2fa1-11d2-883f-0016d3cca42",
            "1b4e28ba-2fa1-11d2-883f-0016d3cca4277",
            "1b4e28bg-2fa1-11d2-883f-0016d3cca427",
            "1b4e28ba-2fa1-11d2-883-00016d3cca427",
            "-----------------------------------------------------------------",
        ] {
            assert!(VolumeId::parse(s).is_none(), "accepted {s:?}");
        }
    }

    #[test]
    fn table_parse() {
        let t = VolumeTable::parse(&format!("# comment\n{U1} /Volumes/Data 1\n")).unwrap();
        let v = t.get(&VolumeId::parse(U1).unwrap()).unwrap();
        assert_eq!(v.mount_point, PathBuf::from("/Volumes/Data"));
        assert!(v.allow_mount);
    }

    #[test]
    fn table_rejects_bad_lines() {
        for text in [
            "not-a-uuid /x 1",
            "1b4e28ba-2fa1-11d2-883f-0016d3cca427 relative 1",
            "1b4e28ba-2fa1-11d2-883f-0016d3cca427 /x yes",
            "1b4e28ba-2fa1-11d2-883f-0016d3cca427 /x 1 extra",
            "1b4e28ba-2fa1-11d2-883f-0016d3cca427 /x",
        ] {
            assert!(VolumeTable::parse(text).is_err(), "accepted {text:?}");
        }
    }
}
