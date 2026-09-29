//! Which device which instance gets (ADR-0143 determination 6, builds
//! ADR-0028).
//!
//! # Two levels, and only the lower one stands here
//!
//! **Cluster-wide** a device is a number: `device:<kind>` in the capacity
//! (ADR-0049) and the same resource in the demand. The planner compares them
//! like CPU and memory and sees nothing new — that is ADR-0028's promise, and
//! ADR-0034/0109 made it possible.
//!
//! **Node-locally** it is an assignment: which concrete CDI device goes to which
//! instance. That stands here.
//!
//! # Why it belongs on the disk
//!
//! It must survive the agent's restart. A derivation from the position in a
//! sorted list would be the finding from phase 9a in a new guise: if a device
//! fails or one is added, it would shift the assignment of **all the following**
//! instances — each would get a different one after a restart, and silently at
//! that.
//!
//! The ledger is **checked** on re-reading, like the address ledger from 9a: a
//! device the catalogue does not know, and a device assigned twice, are findings
//! and no state one carries on with. The second is at the same time the
//! enforcement of ADR-0028's ban on time-slicing — at any point in time a device
//! belongs to exactly one instance.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tg_defs::WorkloadExt as _;
use tg_defs::generated::WorkloadType;
use tg_runtime::cdi::{Catalogue, Edits};
use tg_runtime::network::Devices;

const FILE: &str = "devices/assigned";

type Ledger = BTreeMap<String, Vec<String>>;

pub(crate) struct Ledgers {
    catalogue: Catalogue,
    path: PathBuf,
    ledger: Mutex<Ledger>,
}

impl Ledgers {
    pub(crate) fn open(data_dir: &Path, dirs: &[PathBuf]) -> (Self, Vec<String>) {
        let (catalogue, findings) = Catalogue::read(dirs);
        let mut notes: Vec<String> = findings.iter().map(ToString::to_string).collect();

        let path = data_dir.join(FILE);
        let ledger = match read_ledger(&path, &catalogue) {
            Ok(ledger) => ledger,
            Err(reason) => {
                notes.push(format!("{}: {reason}", path.display()));
                Ledger::new()
            }
        };

        (
            Self {
                catalogue,
                path,
                ledger: Mutex::new(ledger),
            },
            notes,
        )
    }

    pub(crate) fn inventory(&self) -> BTreeMap<String, u64> {
        self.catalogue.inventory()
    }

    fn publish(&self, ledger: &Ledger) {
        let mut taken: BTreeMap<&str, u64> = BTreeMap::new();
        for name in ledger.values().flatten() {
            if let Some(kind) = name.split('=').next() {
                *taken.entry(kind).or_default() += 1;
            }
        }

        for name in self.catalogue.kinds() {
            #[expect(
                clippy::cast_precision_loss,
                reason = "a node's device count lies beyond any imprecision \
                          of f64"
            )]
            metrics::gauge!(
                tg_telemetry::names::NODE_DEVICES_ASSIGNED,
                "resource" => format!("{}{name}", tg_model::Resources::DEVICE_PREFIX),
            )
            .set(taken.get(name).copied().unwrap_or(0) as f64);
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.catalogue.len()
    }

    fn persist(&self, ledger: &Ledger) {
        let mut text = String::from(
            "# Which devices which instance holds (ADR-0143).\n\
             # Written by the agent, read at startup. Changing it by hand\n\
             # means giving two instances the same device.\n",
        );
        for (container, devices) in ledger {
            text.push_str(container);
            for device in devices {
                text.push(' ');
                text.push_str(device);
            }
            text.push('\n');
        }

        if let Some(parent) = self.path.parent()
            && let Err(err) = std::fs::create_dir_all(parent)
        {
            tracing::warn!(path = %parent.display(), %err, "device ledger cannot be created");
            return;
        }
        if let Err(err) = std::fs::write(&self.path, text) {
            tracing::warn!(
                path = %self.path.display(),
                %err,
                "device ledger not writable -- after a restart it is assigned anew"
            );
        }
    }
}

impl Devices for Ledgers {
    fn assign(&self, workload: &WorkloadType, instance: u32) -> Result<Option<Edits>, String> {
        let wanted = workload.devices();
        if wanted.is_empty() {
            return Ok(None);
        }

        let container = tg_runtime::bundle::container_id(workload.name(), instance);
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| "the ledger is poisoned".to_owned())?;

        // **Idempotent** (the trait's assurance): whoever is already assigned
        // gets the same again. Handing out anew would give a running instance a
        // different device at every pass.
        if let Some(held) = ledger.get(&container) {
            return self.edits_for(held);
        }

        let taken: BTreeSet<&str> = ledger.values().flatten().map(String::as_str).collect();

        let mut mine = Vec::new();
        for declared in wanted {
            let kind = declared.kind.0.as_str();
            let free: Vec<&str> = self
                .catalogue
                .names_of(kind)
                .into_iter()
                .filter(|name| !taken.contains(format!("{kind}={name}").as_str()))
                .filter(|name| !mine.contains(&format!("{kind}={name}")))
                .collect();

            let count = declared.count.0 as usize;
            if free.len() < count {
                return Err(format!(
                    "{container} demands {count}x `{kind}`, free are {} of {} \
                     on this node",
                    free.len(),
                    self.catalogue.names_of(kind).len()
                ));
            }
            for name in free.into_iter().take(count) {
                mine.push(format!("{kind}={name}"));
            }
        }

        let edits = self.edits_for(&mine)?;
        // **The line that answers "which GPU does inference-0 have?"**
        // (ADR-0145, determination 1). It stands in the log and not in a label:
        // the device name is a different one per node and one per instance.
        tracing::info!(
            container = %container,
            devices = %mine.join(" "),
            "devices assigned"
        );
        ledger.insert(container, mine);
        self.persist(&ledger);
        self.publish(&ledger);
        Ok(edits)
    }

    fn release(&self, container: &str) {
        let Ok(mut ledger) = self.ledger.lock() else {
            return;
        };
        if let Some(given) = ledger.remove(container) {
            tracing::info!(
                container = %container,
                devices = %given.join(" "),
                "devices released"
            );
            self.persist(&ledger);
            self.publish(&ledger);
        }
    }

    fn held(&self) -> Vec<String> {
        self.ledger
            .lock()
            .map(|ledger| ledger.keys().cloned().collect())
            .unwrap_or_default()
    }
}

impl Ledgers {
    fn edits_for(&self, names: &[String]) -> Result<Option<Edits>, String> {
        let mut edits = Edits::default();
        for name in names {
            let device = self
                .catalogue
                .get(name)
                .ok_or_else(|| format!("`{name}` stands in the ledger and in no spec"))?;
            for node in &device.edits.nodes {
                // **Is it still there?** (ADR-0145, determination 2) The
                // catalogue is read once at startup; between then and now the
                // card may have been pulled or the driver unloaded. Without this
                // line the instance would get a spec with a node that does not
                // exist, and the failure would come from the runtime -- without
                // saying what it was down to.
                if !node.host_path.exists() {
                    return Err(format!(
                        "`{name}` points at {}, and that no longer exists on \
                         this host",
                        node.host_path.display()
                    ));
                }
                edits.nodes.push(node.clone());
            }
            edits.mounts.extend(device.edits.mounts.iter().cloned());
            // **Duplicate environment variables fall away.** Two devices of the
            // same `kind` carry the same global `containerEdits` (ADR-0143), and
            // `PATH=x` twice in `process.env` is no valid OCI section.
            for variable in &device.edits.env {
                if !edits.env.contains(variable) {
                    edits.env.push(variable.clone());
                }
            }
        }
        Ok(Some(edits))
    }
}

fn read_ledger(path: &Path, catalogue: &Catalogue) -> Result<Ledger, String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        // No ledger is the normal case -- at the first start and on every node
        // without a device.
        return Ok(Ledger::new());
    };

    let mut ledger = Ledger::new();
    let mut taken: BTreeSet<String> = BTreeSet::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(container) = parts.next() else {
            continue;
        };
        let devices: Vec<String> = parts.map(ToOwned::to_owned).collect();
        if devices.is_empty() {
            return Err(format!("line {}: `{container}` holds nothing", number + 1));
        }

        for device in &devices {
            if catalogue.get(device).is_none() {
                return Err(format!(
                    "line {}: `{device}` stands in the ledger and in no spec",
                    number + 1
                ));
            }
            // **The same device twice is a finding** -- the enforcement of
            // ADR-0028's ban on time-slicing, and the same construction as the
            // doubly assigned address in 9a.
            if !taken.insert(device.clone()) {
                return Err(format!("line {}: `{device}` is assigned twice", number + 1));
            }
        }
        if ledger.insert(container.to_owned(), devices).is_some() {
            return Err(format!("line {}: `{container}` stands twice", number + 1));
        }
    }
    Ok(ledger)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    fn catalogue_with(dir: &Path, count: usize) -> Catalogue {
        let mut devices = String::new();
        for index in 0..count {
            if index > 0 {
                devices.push(',');
            }
            let node = if index % 2 == 0 {
                "/dev/null"
            } else {
                "/dev/zero"
            };
            let minor = if index % 2 == 0 { 3 } else { 5 };
            let _ = write!(
                devices,
                r#"{{ "name": "{index}", "containerEdits": {{ "deviceNodes": [
                     {{ "path": "{node}", "type": "c", "major": 1, "minor": {minor} }} ] }} }}"#
            );
        }
        std::fs::write(
            dir.join("probe.json"),
            format!(
                r#"{{ "cdiVersion": "0.6.0", "kind": "example.com/probe",
                      "devices": [ {devices} ] }}"#
            ),
        )
        .expect("write");
        let (catalogue, findings) = Catalogue::read(&[dir.to_path_buf()]);
        assert!(findings.is_empty(), "{findings:?}");
        catalogue
    }

    #[test]
    fn a_ledger_naming_an_unknown_device_is_a_finding() {
        let dir = tempfile::tempdir().expect("directory");
        let catalogue = catalogue_with(dir.path(), 2);
        let ledger = dir.path().join("ledger");
        std::fs::write(&ledger, "tg-api-0 example.com/probe=9\n").expect("write");

        let err = read_ledger(&ledger, &catalogue).expect_err("must be a finding");
        assert!(err.contains("in no spec"), "{err}");
    }

    #[test]
    fn the_same_device_twice_is_a_finding() {
        let dir = tempfile::tempdir().expect("directory");
        let catalogue = catalogue_with(dir.path(), 2);
        let ledger = dir.path().join("ledger");
        std::fs::write(
            &ledger,
            "tg-api-0 example.com/probe=0\ntg-api-1 example.com/probe=0\n",
        )
        .expect("write");

        let err = read_ledger(&ledger, &catalogue).expect_err("must be a finding");
        assert!(err.contains("assigned twice"), "{err}");
    }

    #[test]
    fn a_sound_ledger_survives_a_restart() {
        let dir = tempfile::tempdir().expect("directory");
        let catalogue = catalogue_with(dir.path(), 3);
        let ledger = dir.path().join("ledger");
        std::fs::write(
            &ledger,
            "# comment\n\ntg-api-0 example.com/probe=0 example.com/probe=1\n\
             tg-batch-0 example.com/probe=2\n",
        )
        .expect("write");

        let read = read_ledger(&ledger, &catalogue).expect("valid");
        assert_eq!(read.len(), 2);
        assert_eq!(
            read.get("tg-api-0").map(Vec::as_slice),
            Some(
                &[
                    "example.com/probe=0".to_owned(),
                    "example.com/probe=1".to_owned()
                ][..]
            )
        );
    }

    #[test]
    fn a_device_that_vanished_from_the_host_is_refused() {
        use tg_runtime::network::Devices as _;

        let dir = tempfile::tempdir().expect("tempdir");
        // **Under `/dev/shm`**, and that for two reasons: the path bolt from
        // ADR-0143 admits a device node only under `/dev/` (otherwise it would
        // cover a file of the rootfs), and `/dev/shm` is `1777` -- this witness
        // needs no permissions. `/dev/null` would not do: it never disappears,
        // and precisely that is what shall happen here.
        let node =
            std::path::PathBuf::from(format!("/dev/shm/tg-probe-vanish-{}", std::process::id()));
        std::fs::write(&node, b"").expect("create");
        std::fs::write(
            dir.path().join("probe.json"),
            format!(
                r#"{{ "cdiVersion": "0.6.0", "kind": "example.com/probe",
                      "devices": [ {{ "name": "0", "containerEdits": {{
                        "deviceNodes": [ {{ "path": "/dev/probe",
                          "hostPath": "{}", "type": "c",
                          "major": 1, "minor": 3 }} ] }} }} ] }}"#,
                node.display()
            ),
        )
        .expect("write");

        let (ledgers, notes) = Ledgers::open(dir.path(), &[dir.path().to_path_buf()]);
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(ledgers.len(), 1, "the setup must know one device");

        let set = tg_defs::from_str(DECLARES_A_DEVICE).expect("definition");
        let workload = &set.workloads()[0];

        // **The counter-check first**: as long as the node is there, it works.
        assert!(
            ledgers.assign(workload, 0).is_ok(),
            "with an existing node the assignment must succeed"
        );
        ledgers.release(&tg_runtime::bundle::container_id(workload.name(), 0));

        // **And then it is gone.**
        std::fs::remove_file(&node).expect("remove");
        let err = ledgers
            .assign(workload, 0)
            .expect_err("a vanished node must cost the start");
        assert!(
            err.contains("no longer exists on this host"),
            "the message must name the reason: {err}"
        );
    }

    const DECLARES_A_DEVICE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="inference" kind="service">
    <image reference="example.com/inference:1"/>
    <devices>
      <device kind="example.com/probe" count="1"/>
    </devices>
  </workload>
</workloads>"#;

    #[test]
    fn the_number_of_assigned_devices_is_reported() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use tg_runtime::network::Devices as _;

        let dir = tempfile::tempdir().expect("tempdir");
        catalogue_with(dir.path(), 2);
        let (ledgers, notes) = Ledgers::open(dir.path(), &[dir.path().to_path_buf()]);
        assert!(notes.is_empty(), "{notes:?}");

        let set = tg_defs::from_str(DECLARES_A_DEVICE).expect("definition");
        let workload = &set.workloads()[0];

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let assigned = |name: &str| -> Option<f64> {
            snapshotter
                .snapshot()
                .into_vec()
                .into_iter()
                .find_map(|(key, _, _, value)| {
                    let mine = key.key().name() == tg_telemetry::names::NODE_DEVICES_ASSIGNED
                        && key
                            .key()
                            .labels()
                            .any(|l| l.key() == "resource" && l.value() == name);
                    match value {
                        DebugValue::Gauge(seen) if mine => Some(seen.into_inner()),
                        _ => None,
                    }
                })
        };

        metrics::with_local_recorder(&recorder, || {
            ledgers.assign(workload, 0).expect("assignment");
        });
        assert_eq!(
            assigned("device:example.com/probe"),
            Some(1.0),
            "one assignment must be reported as one"
        );

        // **And down again.** A number that does not come back would report a
        // device as permanently occupied that has long been free.
        metrics::with_local_recorder(&recorder, || {
            ledgers.release(&tg_runtime::bundle::container_id(workload.name(), 0));
        });
        assert_eq!(
            assigned("device:example.com/probe"),
            Some(0.0),
            "after the release the number must come back, and the series must \
             stay: otherwise the absence reads like `no devices`"
        );
    }

    #[test]
    fn a_missing_ledger_is_empty_not_broken() {
        let dir = tempfile::tempdir().expect("directory");
        let catalogue = catalogue_with(dir.path(), 1);
        let read = read_ledger(&dir.path().join("doesnotexist"), &catalogue).expect("empty");
        assert!(read.is_empty());
    }
}
