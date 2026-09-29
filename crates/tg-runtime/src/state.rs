//! The durable local desired-state cache.
//!
//! The agent reconciles **exclusively** against this cache, without
//! control-plane reachability. It must therefore survive a restart of the
//! agent and an outage of the control plane unharmed.
//!
//! What is stored is the **XML definition itself**, not a derived form. That
//! has three reasons:
//!
//! - No second format and no second parser that can deviate from the XSD.
//! - The cache stays readable and diffable -- in operation it is traceable
//!   what the node holds to be wanted.
//! - The desired/actual separation stays clean: here lies **only** desired.
//!   Actual is asked of the runtime, not written along, and can therefore not
//!   go stale either.

use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use tg_defs::{WorkloadExt as _, generated::WorkloadType};

use crate::error::RuntimeError;

const SUFFIX: &str = ".xml";

#[derive(Debug, Clone)]
pub struct DesiredState {
    dir: PathBuf,
}

impl DesiredState {
    pub fn open(data_dir: &Path) -> Result<Self, RuntimeError> {
        let dir = data_dir.join("desired");
        fs::create_dir_all(&dir)
            .map_err(|source| RuntimeError::io("laying out the cache", &dir, source))?;
        // **The permissions do not belong to the umask.** The cache is this
        // node's truth; whoever can write it writes the truth, and whoever
        // can read it knows the cluster's wanted state. Measured, before
        // this line it stood at `0755` -- the store beside it already stood
        // at `0700`.
        //
        // It is set for an **existing** directory too: a node that ran before
        // would otherwise stay in exactly the state at issue.
        crate::content::seal_soft(&dir, "closing the desired state");

        Ok(Self { dir })
    }

    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn put(&self, workload: &WorkloadType) -> Result<PathBuf, RuntimeError> {
        let name = workload.name();
        let xml = tg_defs::workload_to_xml(workload).map_err(|err| RuntimeError::Unmappable {
            workload: name.to_owned(),
            reason: err.to_string(),
        })?;

        let target = self.path_for(name);
        let temp = target.with_extension("tmp");

        let mut file = File::create(&temp)
            .map_err(|source| RuntimeError::io("writing the cache", &temp, source))?;
        file.write_all(xml.as_bytes())
            .map_err(|source| RuntimeError::io("writing the cache", &temp, source))?;
        file.sync_all()
            .map_err(|source| RuntimeError::io("the cache fsync", &temp, source))?;
        drop(file);

        fs::rename(&temp, &target)
            .map_err(|source| RuntimeError::io("renaming the cache", &target, source))?;

        self.sync_dir("the definition");

        Ok(target)
    }

    pub fn remove(&self, name: &str) -> Result<(), RuntimeError> {
        // The assignment goes along: an instance list without a definition
        // would be a remnant that applied again at the next `put` of the same
        // name.
        let _ = fs::remove_file(self.instances_path(name));
        // And the generations (ADR-0071): a left-behind counter would be a
        // restart that hits a later workload of the same name.
        let _ = fs::remove_file(self.generations_path(name));

        let target = self.path_for(name);
        match fs::remove_file(&target) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(RuntimeError::io("deleting the cache", &target, source)),
        }
    }

    pub fn load_all(&self) -> Result<Vec<WorkloadType>, RuntimeError> {
        let mut files: Vec<PathBuf> = fs::read_dir(&self.dir)
            .map_err(|source| RuntimeError::io("reading the cache", &self.dir, source))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && path.to_string_lossy().ends_with(SUFFIX))
            .collect();
        files.sort();

        let mut workloads = Vec::new();
        for path in files {
            let set = tg_defs::from_path(&path).map_err(|err| RuntimeError::Unmappable {
                workload: path.display().to_string(),
                reason: format!("an entry in the desired-state cache is unreadable: {err}"),
            })?;
            workloads.extend(set.workloads().iter().cloned());
        }

        workloads.sort_by(|a, b| a.name().cmp(b.name()));
        Ok(workloads)
    }

    pub fn assign(&self, name: &str, instances: &[u32]) -> Result<(), RuntimeError> {
        let mut sorted: Vec<u32> = instances.to_vec();
        sorted.sort_unstable();
        sorted.dedup();

        let mut text = String::new();
        for instance in sorted {
            use std::fmt::Write as _;
            let _ = writeln!(text, "{instance}");
        }

        let target = self.instances_path(name);
        let temp = target.with_extension("instances.tmp");
        let mut file = File::create(&temp)
            .map_err(|source| RuntimeError::io("writing the assignment", &temp, source))?;
        file.write_all(text.as_bytes())
            .map_err(|source| RuntimeError::io("writing the assignment", &temp, source))?;
        file.sync_all()
            .map_err(|source| RuntimeError::io("the assignment fsync", &temp, source))?;
        drop(file);
        fs::rename(&temp, &target)
            .map_err(|source| RuntimeError::io("renaming the assignment", &target, source))?;
        self.sync_dir("the assignment");

        Ok(())
    }

    #[must_use]
    pub fn instances(&self, name: &str) -> Vec<u32> {
        let path = self.instances_path(name);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            // **Missing and unreadable are two statements.** Both gave the
            // same answer and the same silence; an I/O error thereby meant
            // "instance 0" -- a container nobody put here. The answer stays
            // (an empty list would mean "not wanted" for the clearer,
            // ADR-0058, and a file error must not cost a running workload,
            // ADR-0062 determination 4); what is added is the information.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return vec![0],
            Err(err) => {
                tracing::warn!(
                    workload = name,
                    path = %path.display(),
                    %err,
                    "the assignment is unreadable, instance 0 applies"
                );
                return vec![0];
            }
        };

        text.lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect()
    }

    pub fn set_lease(&self, name: &str, lease: Option<(u64, u64)>) -> Result<(), RuntimeError> {
        let path = self.lease_path(name);
        let Some((epoch, expires_at)) = lease else {
            return match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(RuntimeError::io("removing the lease", &path, source)),
            };
        };

        // The same construction as the assignment beside it: first write
        // beside, then rename. A half-written lease would be a deadline
        // nobody can read -- and the workload would not start up.
        let temp = path.with_extension("lease.tmp");
        let mut file = File::create(&temp)
            .map_err(|source| RuntimeError::io("writing the lease", &temp, source))?;
        file.write_all(format!("{epoch} {expires_at}\n").as_bytes())
            .map_err(|source| RuntimeError::io("writing the lease", &temp, source))?;
        file.sync_all()
            .map_err(|source| RuntimeError::io("the lease fsync", &temp, source))?;
        drop(file);
        fs::rename(&temp, &path)
            .map_err(|source| RuntimeError::io("renaming the lease", &path, source))?;
        self.sync_dir("the lease");

        Ok(())
    }

    pub fn set_generations(
        &self,
        name: &str,
        generations: &[(u32, u64)],
    ) -> Result<(), RuntimeError> {
        let path = self.generations_path(name);
        if generations.iter().all(|(_, generation)| *generation == 0) {
            // Nothing decreed means no file -- the same statement, and a
            // cache that carries only what there is.
            return match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(RuntimeError::io("removing the generations", &path, source)),
            };
        }

        let mut sorted: Vec<(u32, u64)> = generations.to_vec();
        sorted.sort_unstable();
        let mut body = String::new();
        for (instance, generation) in &sorted {
            use std::fmt::Write as _;
            let _ = writeln!(body, "{instance} {generation}");
        }

        // The same construction as the lease beside it: first write beside,
        // then rename. A half-written generation would be a number nobody can
        // read -- and then the node would restart or not, depending on where
        // the write broke off.
        let temp = path.with_extension("generations.tmp");
        let mut file = File::create(&temp)
            .map_err(|source| RuntimeError::io("writing the generations", &temp, source))?;
        file.write_all(body.as_bytes())
            .map_err(|source| RuntimeError::io("writing the generations", &temp, source))?;
        file.sync_all()
            .map_err(|source| RuntimeError::io("the generations fsync", &temp, source))?;
        drop(file);
        fs::rename(&temp, &path)
            .map_err(|source| RuntimeError::io("renaming the generations", &path, source))?;
        self.sync_dir("the generations");

        Ok(())
    }

    #[must_use]
    pub fn generation(&self, name: &str, instance: u32) -> u64 {
        let path = self.generations_path(name);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return 0,
            // Zero stays the answer -- an unreadable generation must not
            // trigger a restart. But it belongs named: an operator reads the
            // decreed generation in `tgctl cluster show`, and the container
            // runs with the old one.
            Err(err) => {
                tracing::warn!(
                    workload = name,
                    path = %path.display(),
                    %err,
                    "the generations are unreadable, no restart"
                );
                return 0;
            }
        };

        text.lines()
            .find_map(|line| {
                let (left, right) = line.split_once(' ')?;
                (left.trim().parse::<u32>().ok()? == instance).then(|| right.trim().parse().ok())?
            })
            .unwrap_or(0)
    }

    pub fn set_active_instance(&self, name: &str, instance: u32) -> Result<(), RuntimeError> {
        let path = self.active_path(name);
        if instance == 0 {
            return match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(RuntimeError::io(
                    "removing the active instance",
                    &path,
                    source,
                )),
            };
        }

        // First write beside, then rename -- like the lease and the
        // generations. A half-written number would be an active instance
        // nobody can read, and then **none** would start up.
        let temp = path.with_extension("active.tmp");
        let mut file = File::create(&temp)
            .map_err(|source| RuntimeError::io("writing the active instance", &temp, source))?;
        file.write_all(format!("{instance}\n").as_bytes())
            .map_err(|source| RuntimeError::io("writing the active instance", &temp, source))?;
        file.sync_all()
            .map_err(|source| RuntimeError::io("the active-instance fsync", &temp, source))?;
        drop(file);
        fs::rename(&temp, &path)
            .map_err(|source| RuntimeError::io("renaming the active instance", &path, source))?;
        self.sync_dir("the active instance");

        Ok(())
    }

    #[must_use]
    pub fn active_instance(&self, name: &str) -> u32 {
        let path = self.active_path(name);
        match fs::read_to_string(&path) {
            Ok(text) => text.trim().parse().unwrap_or_else(|_| {
                tracing::warn!(
                    workload = name,
                    path = %path.display(),
                    "the active instance is unreadable, instance 0 applies"
                );
                0
            }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
            Err(err) => {
                tracing::warn!(
                    workload = name,
                    path = %path.display(),
                    %err,
                    "the active instance is unreadable, instance 0 applies"
                );
                0
            }
        }
    }

    #[must_use]
    pub fn lease(&self, name: &str) -> Option<tg_model::lease::Held> {
        let text = fs::read_to_string(self.lease_path(name)).ok()?;
        let mut parts = text.split_whitespace();
        let epoch = parts.next()?.parse().ok()?;
        let expires_at = parts.next()?.parse().ok()?;

        Some(tg_model::lease::Held { epoch, expires_at })
    }

    pub fn load_assigned(&self) -> Result<Cached<(WorkloadType, Vec<u32>)>, RuntimeError> {
        let readable = self.load_readable()?;

        Ok(Cached {
            workloads: readable
                .workloads
                .into_iter()
                .map(|workload| {
                    let instances = self.instances(workload.name());
                    (workload, instances)
                })
                .filter(|(_, instances)| !instances.is_empty())
                .collect(),
            unreadable: readable.unreadable,
        })
    }

    pub fn load_readable(&self) -> Result<Cached<WorkloadType>, RuntimeError> {
        let mut workloads = Vec::new();
        let mut unreadable = Vec::new();

        for path in self.documents()? {
            match tg_defs::from_path(&path) {
                Ok(set) => workloads.extend(set.workloads().iter().cloned()),
                Err(err) => {
                    tracing::error!(
                        entry = %path.display(),
                        error = %err,
                        "an entry in the desired-state cache is unreadable -- it is passed over"
                    );
                    unreadable.push(stem_of(&path));
                }
            }
        }

        workloads.sort_by(|a, b| a.name().cmp(b.name()));
        unreadable.sort();

        Ok(Cached {
            workloads,
            unreadable,
        })
    }

    fn documents(&self) -> Result<Vec<PathBuf>, RuntimeError> {
        let mut files: Vec<PathBuf> = fs::read_dir(&self.dir)
            .map_err(|source| RuntimeError::io("reading the cache", &self.dir, source))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && path.to_string_lossy().ends_with(SUFFIX))
            .collect();
        files.sort();

        Ok(files)
    }

    pub fn names(&self) -> Result<Vec<String>, RuntimeError> {
        Ok(self.documents()?.iter().map(|path| stem_of(path)).collect())
    }

    fn sync_dir(&self, what: &str) {
        match File::open(&self.dir) {
            Ok(dir) => {
                if let Err(source) = dir.sync_all() {
                    tracing::warn!(
                        what,
                        dir = %self.dir.display(),
                        error = %source,
                        "the directory is not durable -- this write may \
                         possibly not survive a power failure"
                    );
                }
            }
            Err(source) => tracing::warn!(
                what,
                dir = %self.dir.display(),
                error = %source,
                "the directory cannot be opened -- this write may possibly \
                 not survive a power failure"
            ),
        }
    }

    fn path_for(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}{SUFFIX}"))
    }

    fn generations_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.generations"))
    }

    fn active_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.active"))
    }

    fn instances_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.instances"))
    }

    fn lease_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.lease"))
    }
}

#[derive(Debug, Clone)]
pub struct Cached<T> {
    pub workloads: Vec<T>,
    pub unreadable: Vec<String>,
}

fn stem_of(path: &std::path::Path) -> String {
    path.file_stem().map_or_else(
        || path.display().to_string(),
        |stem| stem.to_string_lossy().into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(xml: &str) -> WorkloadType {
        tg_defs::from_str(xml).expect("parses").workloads()[0].clone()
    }

    const ONE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.example.com/api:1"/>
  </workload>
</workloads>"#;

    const TWO: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="db" kind="service">
    <image reference="registry.example.com/db:16"/>
  </workload>
</workloads>"#;

    #[test]
    fn state_survives_a_fresh_open_of_the_same_directory() {
        let dir = tempfile::tempdir().expect("tempdir");

        let first = DesiredState::open(dir.path()).expect("open");
        first.put(&parse(ONE)).expect("put api");
        first.put(&parse(TWO)).expect("put db");
        drop(first);

        // A new agent process, the same disk, no network.
        let second = DesiredState::open(dir.path()).expect("open again");
        let workloads = second.load_all().expect("load");

        let names: Vec<&str> = workloads.iter().map(tg_defs::WorkloadExt::name).collect();
        assert_eq!(names, vec!["api", "db"]);
    }

    #[test]
    fn without_a_file_instance_zero_is_active() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");

        assert_eq!(state.active_instance("api"), 0);
    }

    #[test]
    fn the_active_instance_survives_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir");

        let first = DesiredState::open(dir.path()).expect("open");
        first.set_active_instance("api", 2).expect("set");
        drop(first);

        let second = DesiredState::open(dir.path()).expect("open again");
        assert_eq!(second.active_instance("api"), 2);
    }

    #[test]
    fn returning_to_zero_removes_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");

        state.set_active_instance("api", 1).expect("set");
        state.set_active_instance("api", 0).expect("withdraw");

        assert_eq!(state.active_instance("api"), 0);
        assert!(
            !dir.path().join("api.active").exists(),
            "the file must be gone, not contain a zero"
        );
    }

    #[test]
    fn an_unreadable_decree_falls_back_to_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");

        std::fs::write(dir.path().join("api.active"), b"broken\n").expect("write");

        assert_eq!(state.active_instance("api"), 0);
    }

    #[test]
    fn load_is_sorted_by_name_regardless_of_write_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");

        state.put(&parse(TWO)).expect("put db");
        state.put(&parse(ONE)).expect("put api");

        let names: Vec<String> = state
            .load_all()
            .expect("load")
            .iter()
            .map(|w| w.name().to_owned())
            .collect();
        assert_eq!(names, vec!["api", "db"]);
    }

    #[test]
    fn put_overwrites_an_existing_definition() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");

        state.put(&parse(ONE)).expect("first");
        state.put(&parse(ONE)).expect("again");

        assert_eq!(state.load_all().expect("load").len(), 1);
    }

    #[test]
    fn remove_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");

        state.put(&parse(ONE)).expect("put");
        state.remove("api").expect("first remove");
        state
            .remove("api")
            .expect("the second remove must not fail");

        assert!(state.load_all().expect("load").is_empty());
    }

    #[test]
    fn empty_cache_loads_as_empty_not_as_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");

        assert!(state.load_all().expect("load").is_empty());
    }

    #[test]
    fn corrupt_entry_is_reported_not_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");
        state.put(&parse(ONE)).expect("put");
        fs::write(state.dir().join("broken.xml"), "<workloads>").expect("lay a broken entry");

        let err = state.load_all().unwrap_err();

        assert!(matches!(err, RuntimeError::Unmappable { .. }));
    }

    #[test]
    fn temp_files_are_ignored_by_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");
        state.put(&parse(ONE)).expect("put");
        fs::write(state.dir().join("half.tmp"), "<broken").expect("lay out a temp file");

        assert_eq!(state.load_all().expect("load").len(), 1);
    }

    // --- The assignment (ADR-0034, ADR-0040) --------------------------------

    #[test]
    fn a_workload_without_an_assignment_runs_instance_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");
        state.put(&parse(ONE)).expect("put");

        assert_eq!(state.instances("api"), vec![0]);
        let assigned = state.load_assigned().expect("load");
        assert_eq!(assigned.workloads.len(), 1);
        assert_eq!(assigned.workloads[0].1, vec![0]);
        assert!(assigned.unreadable.is_empty());
    }

    #[test]
    fn an_assignment_survives_a_fresh_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = DesiredState::open(dir.path()).expect("open");
        first.put(&parse(ONE)).expect("put");
        first.assign("api", &[0, 2]).expect("assign");
        drop(first);

        let second = DesiredState::open(dir.path()).expect("open again");
        assert_eq!(second.instances("api"), vec![0, 2]);
    }

    #[test]
    fn an_empty_assignment_is_not_the_same_as_a_missing_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");
        state.put(&parse(ONE)).expect("put");

        state.assign("api", &[]).expect("assign");

        assert!(state.instances("api").is_empty());
        assert!(
            state.load_assigned().expect("load").workloads.is_empty(),
            "a workload without an instance has nothing to reconcile here"
        );
    }

    fn collector(
        sink: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> impl tracing::Subscriber + Send + Sync {
        use tracing_subscriber::layer::SubscriberExt as _;

        struct Collect(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Collect {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                struct Grab<'a>(&'a mut String);

                impl tracing::field::Visit for Grab<'_> {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        use std::fmt::Write as _;
                        let _ = write!(self.0, " {}={value:?}", field.name());
                    }
                }

                let mut line = String::new();
                event.record(&mut Grab(&mut line));
                if let Ok(mut all) = self.0.lock() {
                    all.push(line);
                }
            }
        }

        tracing_subscriber::registry().with(Collect(sink))
    }

    #[test]
    fn every_rename_syncs_its_directory() {
        let source = include_str!("state.rs");
        let prod = source
            .split("#[cfg(test)]")
            .next()
            .expect("production part");
        let lines: Vec<&str> = prod.lines().collect();

        let mut renames = 0;
        let mut missing = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            if !line.contains("fs::rename(") {
                continue;
            }
            renames += 1;
            // The `rename` carries its `map_err` arm on the following lines;
            // the search therefore runs in a window and not on the next one.
            let follows = lines[index..]
                .iter()
                .take(6)
                .any(|l| l.contains("sync_dir("));
            if !follows {
                missing.push(index + 1);
            }
        }

        assert!(
            renames >= 4,
            "only {renames} `rename` found -- the haystack has fallen away, \
             and without it this guard confirms everything"
        );
        assert!(
            missing.is_empty(),
            "these `rename` do not make their directory entry durable, so \
             they do not survive a power failure -- lines {missing:?}"
        );
    }

    #[test]
    fn a_directory_that_cannot_be_synced_is_named() {
        use std::sync::{Arc, Mutex};
        use tracing::subscriber::with_default;

        let dir = tempfile::tempdir().expect("temp");
        let store = DesiredState::open(dir.path()).expect("open");

        // Remove the directory under the store: `File::open` fails
        // afterwards, and exactly that arm was quiet.
        std::fs::remove_dir_all(store.dir()).expect("gone");

        let sink = Arc::new(Mutex::new(Vec::new()));
        with_default(collector(Arc::clone(&sink)), || store.sync_dir("witness"));

        let said = sink.lock().expect("sink").join("\n");
        assert!(
            said.contains("witness") && said.contains("power failure"),
            "the failure was swallowed: {said:?}"
        );
    }

    #[test]
    fn an_unreadable_assignment_is_a_finding_not_a_missing_one() {
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");
        state.put(&parse(ONE)).expect("put");
        state.assign("api", &[1, 2]).expect("assign");

        // A **directory** at the file's place: that fails on reading as
        // `root` too, and it is not `NotFound` -- a permission bit passes
        // `root` over.
        let path = state.instances_path("api");
        fs::remove_file(&path).expect("file gone");
        fs::create_dir(&path).expect("directory there");

        let said = Arc::new(Mutex::new(Vec::new()));
        let lines = Arc::clone(&said);
        let got = tracing::subscriber::with_default(collector(lines), || state.instances("api"));

        assert_eq!(got, vec![0], "the behaviour stays");
        let said = said.lock().expect("not poisoned").join("\n");
        assert!(
            said.contains("the assignment is unreadable") && said.contains("api"),
            "a read error belongs named: {said}"
        );
    }

    #[test]
    fn a_missing_assignment_stays_quiet() {
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");
        state.put(&parse(ONE)).expect("put");

        let said = Arc::new(Mutex::new(Vec::new()));
        let lines = Arc::clone(&said);
        let got = tracing::subscriber::with_default(collector(lines), || state.instances("api"));

        assert_eq!(got, vec![0]);
        assert!(
            said.lock().expect("not poisoned").is_empty(),
            "the normal case does not belong in the log"
        );
    }

    #[test]
    fn an_unreadable_generation_is_a_finding() {
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");
        state.put(&parse(ONE)).expect("put");
        state.set_generations("api", &[(0, 7)]).expect("set");

        let path = state.generations_path("api");
        fs::remove_file(&path).expect("file gone");
        fs::create_dir(&path).expect("directory there");

        let said = Arc::new(Mutex::new(Vec::new()));
        let lines = Arc::clone(&said);
        let got =
            tracing::subscriber::with_default(collector(lines), || state.generation("api", 0));

        assert_eq!(got, 0, "no restart on an unreadable generation");
        let said = said.lock().expect("not poisoned").join("\n");
        assert!(
            said.contains("the generations are unreadable") && said.contains("api"),
            "a read error belongs named: {said}"
        );
    }

    #[test]
    fn duplicate_instances_are_collapsed_and_sorted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");
        state.put(&parse(ONE)).expect("put");

        state.assign("api", &[3, 1, 3, 1, 0]).expect("assign");

        assert_eq!(state.instances("api"), vec![0, 1, 3]);
    }

    #[test]
    fn removing_a_workload_removes_its_assignment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");
        state.put(&parse(ONE)).expect("put");
        state.assign("api", &[1, 2]).expect("assign");

        state.remove("api").expect("remove");
        state.put(&parse(ONE)).expect("put again");

        assert_eq!(
            state.instances("api"),
            vec![0],
            "the old assignment has come back"
        );
    }

    #[test]
    fn rubbish_in_an_assignment_is_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = DesiredState::open(dir.path()).expect("open");
        state.put(&parse(ONE)).expect("put");

        std::fs::write(
            dir.path().join("desired").join("api.instances"),
            "0\nx\n\n2\n",
        )
        .expect("write");

        assert_eq!(state.instances("api"), vec![0, 2]);
    }
}
