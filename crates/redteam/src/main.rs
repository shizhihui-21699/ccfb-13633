//! Prints the before/after abuse comparison as a table.
//!
//! `cargo run -p syncd-redteam` — used by `scripts/demo.sh` and referenced by
//! `docs/comparison.md`. The same data is asserted by this crate's unit tests.

use syncd_redteam::{
    monolith_abuse, no_frame_encodes_privilege_escalation, reply_is_fixed_size, split_abuse,
    Capability,
};

fn print_table(title: &str, caps: &[Capability]) {
    println!("\n{title}");
    println!("{}", "-".repeat(title.len()));
    for c in caps {
        println!(
            "  {:<5} {:<52} {}",
            if c.succeeds { "YES" } else { "no" },
            c.abuse,
            c.observed
        );
    }
}

fn main() {
    let mono = monolith_abuse();
    let split = split_abuse();
    print_table(
        "BEFORE — one privileged process (attacker owns the network parser)",
        &mono,
    );
    print_table(
        "AFTER — unprivileged agent + privileged helper (attacker owns the agent)",
        &split,
    );
    print_table(
        "PROTOCOL — properties independent of compromise",
        &[
            no_frame_encodes_privilege_escalation(),
            reply_is_fixed_size(),
        ],
    );

    let mono_yes = mono.iter().filter(|c| c.succeeds).count();
    let split_yes = split.iter().filter(|c| c.succeeds).count();
    println!(
        "\nSummary: monolith {mono_yes}/{} abuses achievable; split {split_yes}/{} (the split's successes are the product's own intended authority).",
        mono.len(),
        split.len()
    );
}
