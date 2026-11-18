//! `sync-core` — the unprivileged bulk of the service.
//!
//! This is where an attacker who reaches the service lands: network framing,
//! command parsing, path resolution, file copying. In the monolith this code
//! runs as root; after the split it runs as the logged-in user in the agent
//! process. The *code is identical* in both deployments — the difference the
//! split makes is the privilege it runs with, and therefore the blast radius
//! of any bug in it.
//!
//! Privileged work is not performed here. It is expressed as the [`PrivOps`]
//! trait, which has exactly two implementations:
//!
//! * [`DirectPrivOps`] in the monolith — calls the operating system in-process,
//!   with whatever privilege the process happens to hold;
//! * a helper-client in the agent — forwards a fixed-size frame to a separate,
//!   minimal, privileged process.
//!
//! Everything else (parsing, file handling) is shared, so the comparison in
//! `docs/comparison.md` is about privilege, not about two different programs.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod fs;
pub mod net;
pub mod privops;
pub mod volume;

pub use fs::SyncStore;
pub use net::{Reply, Server};
pub use privops::{DirectPrivOps, OpOutcome, PrivOps};
pub use volume::{VolumeId, VolumeTable};
