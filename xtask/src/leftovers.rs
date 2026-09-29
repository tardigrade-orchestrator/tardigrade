//! What a privileged run leaves behind in the system.
//!
//! These runs create real kernel resources: overlayfs mounts for bundles
//! (ADR-0003), tmpfs for secrets (ADR-0098), loop devices for volumes
//! (ADR-0027) and **cgroups** for containers (ADR-0006). Each holds its temp
//! directory as long as it exists — and a leftover costs a few hundred megabytes
//! nobody reaches any more.
//!
//! **A gate and not a note:** this session cleared such leftovers away **four
//! times** by hand, and twice only the full disk pointed at them.
//!
//! What is measured is the **difference**: what was already there before the run
//! does not belong to this run. What it does **not** see is a leftover
//! **outside** `/tmp`; the privileged tests work exclusively in `tempfile`
//! directories.

use std::collections::BTreeSet;
use std::fmt::Write as _;

/// A leftover as it appears in the report.
pub(crate) type Trace = String;

/// What currently hangs in the system.
///
/// Read are `/proc/mounts`, `/sys/block/loop*`, `/sys/block/dm-*` and
/// `/sys/fs/cgroup/tardigrade` — no foreign program, hence no output that
/// changes between versions.
///
/// **The mappers belong to it** since ADR-0113: an encrypted volume hangs on a
/// device-mapper device, and an open mapper holds its loop **with**
/// `AUTOCLEAR`, so it does not even appear indirectly.
///
/// **And the cgroups** for the same reason, with the finding from ADR-0118:
/// after a run an empty cgroup lay there without a process. The normal path
/// clears it away; what leaves it standing is the abnormal end.
#[must_use]
pub(crate) fn snapshot() -> BTreeSet<Trace> {
    let mut seen = BTreeSet::new();

    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let mut parts = line.split_whitespace();
            let (Some(_source), Some(target), Some(kind)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            if (kind == "overlay" || kind == "tmpfs") && target.starts_with("/tmp/") {
                seen.insert(format!("{kind} on {target}"));
            }
        }
    }

    if let Ok(entries) = std::fs::read_dir("/sys/block") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("loop") {
                let backing = entry.path().join("loop/backing_file");
                if let Ok(file) = std::fs::read_to_string(&backing) {
                    let file = file.trim();
                    if !file.is_empty() {
                        seen.insert(format!("/dev/{name} on {file}"));
                    }
                }
            } else if name.starts_with("dm-") {
                // **The name, not the node**: `dm-3` changes between runs,
                // `tgvol-…-daten` does not — and only the name tells an operator
                // which leftover it is.
                if let Ok(mapper) = std::fs::read_to_string(entry.path().join("dm/name")) {
                    let mapper = mapper.trim();
                    if !mapper.is_empty() {
                        // **The same shape as a loop trace**: what hangs where.
                        // Below it, with a crypt target, stands the loop device
                        // -- exactly the information an operator needs to
                        // detach it.
                        let under = std::fs::read_dir(entry.path().join("slaves"))
                            .map(|slaves| {
                                let mut names: Vec<String> = slaves
                                    .flatten()
                                    .map(|s| s.file_name().to_string_lossy().into_owned())
                                    .collect();
                                names.sort_unstable();
                                names.join(", ")
                            })
                            .unwrap_or_default();
                        let under = if under.is_empty() {
                            String::from("<unknown>")
                        } else {
                            under
                        };
                        seen.insert(format!("/dev/mapper/{mapper} on {under}"));
                    }
                }
            }
        }
    }

    // The roof of all container cgroups (`bundle::cgroups_path`, ADR-0006). It
    // stays out expressly: it arises with the first container and then belongs
    // to the node, not to a run.
    if let Ok(entries) = std::fs::read_dir("/sys/fs/cgroup/tardigrade") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            // Only directories: beside them lie the roof's own controller files
            // (`cpu.max`, `memory.current`, …).
            if !entry.path().is_dir() {
                continue;
            }
            // **With the number of processes in it**, and that is the actual
            // information: `0` means "left behind empty, `rmdir` suffices",
            // anything else means "something is still running there".
            let procs = std::fs::read_to_string(entry.path().join("cgroup.procs"))
                .map(|text| text.lines().count())
                .unwrap_or_default();
            seen.insert(format!(
                "cgroup /tardigrade/{name} with {procs} process(es)"
            ));
        }
    }

    seen
}

/// What this run left behind.
///
/// `before` is the snapshot from **before** the run.
#[must_use]
pub(crate) fn since(before: &BTreeSet<Trace>) -> Vec<Trace> {
    snapshot().difference(before).cloned().collect()
}

/// The report for a gate.
#[must_use]
pub(crate) fn report(task: &str, new: &[Trace]) -> String {
    let mut text = format!("{task} left {} kernel resource(s) behind:\n", new.len());
    for trace in new {
        let _ = writeln!(text, "  {trace}");
    }
    text.push_str(
        "\nEach holds its temp directory. A test's guard has to unmount **and** \
         detach the loop device, and it has to stand in `Drop` — at the end of \
         the function it does not run on a red test.\n\
         Clean up: `umount <path>`, `losetup -d <device>`, \
         `rmdir /sys/fs/cgroup/tardigrade/<id>`.",
    );
    text
}

#[cfg(test)]
mod tests {
    use super::{report, since, snapshot};
    use std::collections::BTreeSet;

    /// The snapshot reads the system and finds **something**.
    ///
    /// Every Linux has tmpfs mounts; that some of them lie under `/tmp` is not
    /// promised — what is checked is only that the reading itself works and that
    /// no empty trace arises.
    #[test]
    fn the_snapshot_reads_the_system() {
        for trace in snapshot() {
            assert!(!trace.is_empty(), "an empty trace says nothing");
            // **"What where" — and with a cgroup the where is its path.** The
            // condition once stood only on `" on "`, because back then there
            // were exactly two kinds of trace.
            assert!(
                trace.contains(" on ") || trace.starts_with("cgroup /"),
                "a trace has to say what hangs where: {trace}"
            );
        }
    }

    /// **The difference counts, not the stock.**
    ///
    /// Without it a leftover from an aborted earlier run would blame the next
    /// one — and that is exactly the situation in which a gate gets switched
    /// off.
    #[test]
    fn what_was_already_there_is_not_blamed() {
        let now = snapshot();
        assert!(
            since(&now).is_empty(),
            "against its own snapshot nothing may be left over"
        );

        // And the opposite direction: against an empty snapshot everything is
        // new. Without it a `since` that always returns empty would be green
        // too — and the gate mute.
        let all = since(&BTreeSet::new());
        assert_eq!(all.len(), now.len(), "against empty every entry is new");
    }

    /// The report names every leftover **and** what to do.
    #[test]
    fn the_report_names_every_leftover_and_the_way_out() {
        let text = report(
            "cargo xtask storage",
            &[
                String::from("overlay on /tmp/.tmpABC/bundles/tg-api/rootfs"),
                String::from("/dev/loop0 on /tmp/.tmpXYZ/volumes/daten/image"),
            ],
        );

        assert!(text.contains("cargo xtask storage"), "{text}");
        assert!(text.contains("/tmp/.tmpABC"), "{text}");
        assert!(text.contains("/dev/loop0"), "{text}");
        assert!(text.contains("losetup -d"), "{text}");
        assert!(text.contains('2'), "the number belongs to it: {text}");
    }

    /// **The snapshot sees mappers**, not only loops (ADR-0113).
    ///
    /// On a machine with a root file system on LVM at least one `dm-*` stands
    /// there. Without `dm-*` in the system the test says nothing and is skipped:
    /// an assertion that depends on the machine's equipment belongs named and
    /// not enforced.
    #[test]
    fn the_snapshot_sees_device_mapper() {
        let any_dm = std::fs::read_dir("/sys/block").is_ok_and(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with("dm-"))
        });
        if !any_dm {
            return;
        }

        assert!(
            super::snapshot()
                .iter()
                .any(|trace| trace.starts_with("/dev/mapper/")),
            "dm devices are present, the snapshot names none"
        );
    }

    /// **And it sees a leftover cgroup** (ADR-0118).
    ///
    /// Checked with a real cgroup, because only that substantiates the path and
    /// the counting of the processes. It is created and removed again; if it
    /// stayed, the test itself would be the leftover it looks for — hence the
    /// `rmdir` stands **before** the assertion.
    ///
    /// It stands **outside the normal suite** for two reasons: it demands root,
    /// and it changes the state its neighbours read. `cargo test` runs a file's
    /// tests concurrently — a cgroup arising between two snapshots makes
    /// `what_was_already_there_is_not_blamed` red, and that would look like a
    /// flaky test.
    #[test]
    #[ignore = "creates a real cgroup and thereby changes the snapshot; runs with `cargo xtask storage`"]
    fn the_snapshot_sees_a_leftover_cgroup() {
        let dir = std::path::Path::new("/sys/fs/cgroup/tardigrade/tg-leftover-probe");
        let dach_fehlte = !dir.parent().expect("parent").exists();
        std::fs::create_dir_all(dir).expect("create cgroup — demands root");

        let seen = super::snapshot();

        let _ = std::fs::remove_dir(dir);
        if dach_fehlte {
            // Clear away only what this test created: otherwise the roof belongs
            // to a running container.
            let _ = std::fs::remove_dir(dir.parent().expect("parent"));
        }

        assert!(
            seen.iter()
                .any(|trace| trace == "cgroup /tardigrade/tg-leftover-probe with 0 process(es)"),
            "an empty cgroup under our roof has to appear as a leftover: {seen:?}"
        );
    }
}
