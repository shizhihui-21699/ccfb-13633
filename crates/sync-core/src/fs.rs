//! Robust file and path handling for sync jobs.
//!
//! This module is deliberately full of realistic-looking code — path joining,
//! filename validation, conflict resolution — because this is the kind of code
//! a fuzzer or a crafted payload reaches first. The point of the exercise is
//! that after the split, a bug here yields *user* privileges and nothing more.

use std::io;
use std::path::{Component, Path, PathBuf};

/// Reject a sync-relative path that could escape the destination root.
///
/// This is the sort of routine that has historically been buggy: if it is
/// wrong, a crafted filename (`../../etc/sudoers`) writes outside the tree. In
/// the monolith "outside the tree" is still filesystem-root; after the split it
/// is still filesystem-root *for files*, but the process doing it is the
/// unprivileged agent, so the write is bounded by its own file permissions.
pub fn safe_join(root: &Path, relative: &str) -> Option<PathBuf> {
    if relative.is_empty() || relative.contains('\0') || relative.contains('\\') {
        return None;
    }
    if relative.starts_with('/') {
        return None;
    }
    let rel = Path::new(relative);
    let mut depth: i32 = 0;
    for comp in rel.components() {
        match comp {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            // `..` or a root/prefix component: refuse rather than normalise,
            // because normalising is where off-by-one bugs live.
            _ => return None,
        }
    }
    if depth == 0 {
        return None;
    }
    Some(root.join(rel))
}

/// Sanitise a proposed filename into something we are willing to create.
///
/// A NUL byte or a path separator is *rejected*, never silently stripped:
/// quietly rewriting a name changes which object the caller names, which is
/// its own class of bug.
pub fn sanitize_filename(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    if name.len() > 255 || name.contains('\0') || name.contains('/') {
        return None;
    }
    if name.starts_with('.') && name.contains("..") {
        return None;
    }
    // Trim surrounding whitespace and drop non-NUL control characters used to
    // make a name look like another one in a directory listing.
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." || cleaned.contains('/') {
        return None;
    }
    Some(cleaned)
}

/// A small, deliberately simple store used by the sync path. Writes are
/// copy-then-rename so a partial write never replaces a good file.
pub struct SyncStore {
    root: PathBuf,
}

impl SyncStore {
    /// Create a store rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        SyncStore { root: root.into() }
    }

    /// Root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Write `data` to `relative` under the root, atomically.
    ///
    /// Returns the final path, or `None` if the relative path was unsafe.
    pub fn put(&self, relative: &str, data: &[u8]) -> Option<io::Result<PathBuf>> {
        let dest = safe_join(&self.root, relative)?;
        if let Some(dir) = dest.parent() {
            if std::fs::create_dir_all(dir).is_err() {
                return Some(Err(io::Error::other("create dir")));
            }
        }
        let tmp = dest.with_extension("synctmp");
        // The cap is a hard product limit on a single object.
        if data.len() > 64 * 1024 * 1024 {
            return Some(Err(io::Error::other("object too large")));
        }
        Some(
            std::fs::write(&tmp, data)
                .and_then(|()| std::fs::rename(&tmp, &dest))
                .map(|()| dest),
        )
    }

    /// Read `relative` under the root.
    pub fn get(&self, relative: &str) -> Option<io::Result<Vec<u8>>> {
        let path = safe_join(&self.root, relative)?;
        Some(std::fs::read(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_rejects_escapes() {
        let root = Path::new("/tmp/root");
        for bad in ["../x", "a/../../b", "/etc/passwd", "", "a\\b", "a\0b", "."] {
            assert!(safe_join(root, bad).is_none(), "accepted {bad:?}");
        }
    }

    #[test]
    fn safe_join_accepts_ordinary() {
        let root = Path::new("/tmp/root");
        assert_eq!(
            safe_join(root, "a/b.txt").unwrap(),
            PathBuf::from("/tmp/root/a/b.txt")
        );
        assert_eq!(
            safe_join(root, "./a").unwrap(),
            PathBuf::from("/tmp/root/./a")
        );
    }

    #[test]
    fn filename_sanitising() {
        assert_eq!(sanitize_filename("  report.pdf ").unwrap(), "report.pdf");
        assert!(
            sanitize_filename("na\u{0}me").is_none(),
            "NUL must be rejected, not stripped"
        );
        assert_eq!(sanitize_filename("na\u{7}me").unwrap(), "name");
        for bad in ["", ".", "..", "a/b", "../../x"] {
            assert!(sanitize_filename(bad).is_none(), "accepted {bad:?}");
        }
        assert!(sanitize_filename(&"x".repeat(300)).is_none());
    }

    #[test]
    fn store_round_trip() {
        let dir = std::env::temp_dir().join(format!("sync-core-test-{}", std::process::id()));
        let store = SyncStore::new(&dir);
        let path = store.put("a/b.txt", b"hello").unwrap().unwrap();
        assert_eq!(store.get("a/b.txt").unwrap().unwrap(), b"hello");
        assert!(store.get("../escape").is_none());
        assert!(store.put("../escape", b"x").is_none());
        std::fs::remove_dir_all(&dir).ok();
        assert!(path.starts_with(&dir));
    }
}
