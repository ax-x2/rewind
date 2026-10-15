//! Sequential, bounded historical exports. All work here is on the coordinator's cold path.
use crate::{
    Result,
    archive::{self, Archive, Manifest},
    cli,
    coverage::hash,
    ensure, output, reconstruct,
    types::*,
};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Write},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};

pub const HISTORY_FORMAT: u32 = 3;
pub const MAX_VERSIONS: usize = 1024;
pub const MAX_OUTPUT: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    MissingBaseline,
    MissingSource,
    InvalidElf,
    Fatal,
}

#[derive(Debug)]
pub struct VersionIssue {
    pub kind: FailureKind,
    detail: &'static str,
}
impl VersionIssue {
    pub fn source(detail: &'static str) -> Self {
        Self {
            kind: FailureKind::MissingSource,
            detail,
        }
    }
}
impl std::fmt::Display for VersionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.detail)
    }
}
impl std::error::Error for VersionIssue {}
pub(crate) fn missing_baseline(detail: &'static str) -> anyhow::Error {
    VersionIssue {
        kind: FailureKind::MissingBaseline,
        detail,
    }
    .into()
}
pub(crate) fn missing_source(detail: &'static str) -> anyhow::Error {
    VersionIssue::source(detail).into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub kind: FailureKind,
    pub detail: String,
}
impl Failure {
    fn from_error(error: &anyhow::Error) -> Self {
        let kind = error
            .downcast_ref::<VersionIssue>()
            .map_or(FailureKind::Fatal, |issue| issue.kind);
        let mut detail = format!("{error:#}");
        let mut end = detail.len().min(1024);
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        detail.truncate(end);
        Self { kind, detail }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Pending,
    Ready,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub selection: Selection,
    pub filename: String,
    pub state: EvidenceState,
    pub payload_bytes: Option<u64>,
    pub sha256: Option<String>,
    pub error: Option<Failure>,
}
impl Version {
    fn new(selection: Selection) -> Self {
        Self {
            filename: filename(&selection),
            selection,
            state: EvidenceState::Pending,
            payload_bytes: None,
            sha256: None,
            error: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct History {
    pub max_versions: usize,
    pub discovery_complete: bool,
    pub versions: Vec<Version>,
}
impl History {
    pub fn new(max_versions: usize) -> Self {
        Self {
            max_versions,
            discovery_complete: false,
            versions: Vec::new(),
        }
    }
}

pub fn filename(selection: &Selection) -> String {
    let p = selection.position;
    format!(
        "{}-{}-{}-{}-{}.so",
        p.slot, p.transaction, p.outer, p.ordinal, selection.signature
    )
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn validate_history(manifest: &Manifest) -> Result<()> {
    let Some(history) = &manifest.history else {
        ensure!(
            manifest.format != HISTORY_FORMAT,
            "CorruptArchive: bulk history missing"
        );
        return Ok(());
    };
    ensure!(
        manifest.format == HISTORY_FORMAT
            && manifest.selection.is_none()
            && manifest.config.deployment.is_none()
            && manifest.config.genesis == GENESIS
            && manifest.config.range.start < manifest.config.range.end
            && manifest.config.range.chunks().take(16385).count() <= 16384,
        "CorruptArchive: bulk mode/selection"
    );
    let Target::Program(program) = manifest.config.target else {
        anyhow::bail!("CorruptArchive: bulk target must be a program");
    };
    ensure!(
        (1..=MAX_VERSIONS).contains(&history.max_versions)
            && history.versions.len() <= history.max_versions,
        "CorruptArchive: version bound"
    );
    ensure!(
        if history.discovery_complete {
            !history.versions.is_empty()
        } else {
            history.versions.is_empty() && !manifest.complete
        },
        "CorruptArchive: discovery state"
    );
    let mut previous = None;
    for version in &history.versions {
        let selection = &version.selection;
        ensure!(
            selection.program == program
                && manifest.config.loader.accepts(selection.loader)
                && selection.position.slot >= manifest.config.range.start
                && selection.position.slot < manifest.config.range.end
                && selection.position.transaction < MAX_TX as u32
                && previous.is_none_or(|position| position < selection.position)
                && version.filename == filename(selection),
            "CorruptArchive: version identity/order/path"
        );
        ensure!(
            match selection.loader {
                LoaderKind::V3 => selection.programdata == Some(programdata(&program)),
                LoaderKind::V4 => selection.programdata.is_none() && selection.capacity.is_none(),
            },
            "CorruptArchive: loader selection"
        );
        previous = Some(selection.position);
        ensure!(
            match version.state {
                EvidenceState::Ready =>
                    version.error.is_none()
                        && version
                            .payload_bytes
                            .is_some_and(|n| n > 0 && n <= MAX_PAYLOAD as u64)
                        && version.sha256.as_deref().is_some_and(valid_hash),
                EvidenceState::Pending =>
                    version.error.is_none()
                        && version.payload_bytes.is_none()
                        && version.sha256.is_none(),
                EvidenceState::Failed =>
                    version
                        .error
                        .as_ref()
                        .is_some_and(|error| error.detail.len() <= 1024)
                        && version.payload_bytes.is_none()
                        && version.sha256.is_none(),
            },
            "CorruptArchive: version evidence state"
        );
    }
    ensure!(
        !manifest.complete
            || history.discovery_complete
                && history
                    .versions
                    .iter()
                    .all(|version| version.state == EvidenceState::Ready),
        "CorruptArchive: bulk completion"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Publication {
    Pending,
    Published,
    Failed,
}
#[derive(Debug, Serialize, Deserialize)]
struct Artifact {
    selection: Selection,
    filename: String,
    status: Publication,
    payload_bytes: Option<u64>,
    sha256: Option<String>,
    error: Option<Failure>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Index {
    format: u32,
    config: RecoveryConfig,
    discovery_complete: bool,
    complete: bool,
    versions: Vec<Artifact>,
}

struct Outputs {
    root: PathBuf,
    lock: PathBuf,
    index: Index,
}

fn directory_destination(path: &Path) -> Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_dir(),
                "InvalidConfig: expected a directory, not a symlink/file: {}",
                path.display()
            );
            Ok(fs::canonicalize(path)?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            Ok(fs::canonicalize(parent)?.join(
                path.file_name()
                    .context("InvalidConfig: directory name missing")?,
            ))
        }
        Err(error) => Err(error.into()),
    }
}

fn separate_directories(evidence: &Path, outputs: &Path) -> Result<()> {
    let evidence = directory_destination(evidence)?;
    let outputs = directory_destination(outputs)?;
    ensure!(
        !outputs.starts_with(&evidence) && !evidence.starts_with(&outputs),
        "InvalidConfig: evidence/output directories must be separate"
    );
    Ok(())
}
impl Drop for Outputs {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock);
    }
}
impl Outputs {
    fn open(root: &Path, config: &RecoveryConfig, archive_root: &Path) -> Result<Self> {
        separate_directories(archive_root, root)?;
        if !root.try_exists()? {
            fs::create_dir(root)?;
        }
        ensure!(
            fs::symlink_metadata(root)?.is_dir(),
            "OutputConflict: output must be a directory"
        );
        let root = fs::canonicalize(root)?;
        let lock = root.join(".rewind.lock");
        OpenOptions::new().write(true).create_new(true).open(&lock).context("OutputBusy: output lock exists; confirm no export is running before removing a stale lock")?;
        let mut outputs = Self {
            root,
            lock,
            index: Index {
                format: 1,
                config: config.clone(),
                discovery_complete: false,
                complete: false,
                versions: Vec::new(),
            },
        };
        let path = outputs.root.join("versions.json");
        let existing_index = output::regular_exists(&path)?;
        if existing_index {
            ensure!(
                fs::metadata(&path)?.len() <= archive::MAX_MANIFEST as u64,
                "OutputConflict: index size"
            );
            outputs.index = serde_json::from_reader(File::open(&path)?)?;
            ensure!(
                outputs.index.format == 1
                    && outputs.index.config == *config
                    && outputs.index.versions.len() <= MAX_VERSIONS,
                "OutputConflict: incompatible batch index"
            );
            ensure!(
                outputs.index.discovery_complete
                    || outputs.index.versions.is_empty() && !outputs.index.complete,
                "OutputConflict: index discovery"
            );
        }
        // An index is the ownership marker. Unexpected files are never adopted.
        let mut partials = Vec::new();
        for (count, entry) in fs::read_dir(&outputs.root)?.enumerate() {
            ensure!(
                count < MAX_VERSIONS * 2 + 18,
                "OutputConflict: directory entry bound"
            );
            let entry = entry?;
            let name = entry.file_name();
            let owned_partial = name
                .to_str()
                .and_then(|name| name.strip_prefix(".rewind-tmp-"))
                .is_some_and(|suffix| {
                    suffix.len() == 6 && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
                });
            if owned_partial {
                ensure!(
                    entry.file_type()?.is_file() && entry.metadata()?.len() <= MAX_PAYLOAD as u64,
                    "OutputConflict: invalid publication temporary"
                );
                ensure!(
                    partials.len() < 16,
                    "SourceResourceLimit: publication temporaries"
                );
                partials.push(entry.path());
                continue;
            }
            let expected = name == "versions.json"
                || name == ".rewind.lock"
                || outputs.index.versions.iter().any(|version| {
                    name == version.filename.as_str()
                        || name == format!("{}.json", version.filename).as_str()
                });
            ensure!(
                expected && entry.file_type()?.is_file(),
                "OutputConflict: unexpected file/type"
            );
        }
        // Reserved temporary names are owned by this publisher. Remove only
        // validated regular files after checking the directory under its lock.
        for partial in partials {
            fs::remove_file(partial)?;
        }
        if !existing_index {
            outputs.save()?;
        }
        Ok(outputs)
    }

    fn bind(&mut self, history: &History) -> Result<()> {
        ensure!(
            history.discovery_complete,
            "IncompleteArchive: bulk discovery is incomplete"
        );
        if self.index.discovery_complete {
            ensure!(
                self.index.versions.len() == history.versions.len()
                    && self
                        .index
                        .versions
                        .iter()
                        .zip(&history.versions)
                        .all(|(a, b)| a.selection == b.selection && a.filename == b.filename),
                "OutputConflict: version list differs"
            );
        } else {
            self.index.versions = history
                .versions
                .iter()
                .map(|version| Artifact {
                    selection: version.selection.clone(),
                    filename: version.filename.clone(),
                    status: Publication::Pending,
                    payload_bytes: None,
                    sha256: None,
                    error: None,
                })
                .collect();
            self.index.discovery_complete = true;
        }
        for artifact in &self.index.versions {
            let identity = artifact.payload_bytes.zip(artifact.sha256.as_deref());
            let known = identity.is_some_and(|(size, digest)| {
                size > 0 && size <= MAX_PAYLOAD as u64 && valid_hash(digest)
            });
            let absent = artifact.payload_bytes.is_none() && artifact.sha256.is_none();
            ensure!(
                match artifact.status {
                    Publication::Published => known && artifact.error.is_none(),
                    Publication::Pending => (known || absent) && artifact.error.is_none(),
                    Publication::Failed =>
                        absent
                            && artifact
                                .error
                                .as_ref()
                                .is_some_and(|error| error.detail.len() <= 1024),
                },
                "OutputConflict: artifact journal state"
            );
        }
        ensure!(
            !self.index.complete
                || self
                    .index
                    .versions
                    .iter()
                    .all(|v| v.status == Publication::Published),
            "OutputConflict: index completion"
        );
        self.index.complete = false;
        self.save()
    }

    fn existing_bytes(&self, limit: u64) -> Result<u64> {
        let mut total = 0u64;
        for artifact in &self.index.versions {
            let path = self.root.join(&artifact.filename);
            let binary = output::regular_exists(&path)?;
            let sidecar = output::regular_exists(&output::manifest_path(&path))?;
            ensure!(!sidecar || binary, "OutputConflict: sidecar has no binary");
            if binary {
                let size = fs::metadata(&path)?.len();
                ensure!(
                    size <= MAX_PAYLOAD as u64,
                    "OutputConflict: oversized binary"
                );
                total = total
                    .checked_add(size)
                    .context("SourceResourceLimit: output size overflow")?;
                if artifact.status == Publication::Published {
                    ensure!(
                        sidecar
                            && artifact.payload_bytes == Some(size)
                            && artifact.sha256.as_deref()
                                == Some(archive::file_hash(&path)?.0.as_str()),
                        "OutputConflict: published binary changed"
                    );
                    let metadata = output::manifest_path(&path);
                    ensure!(
                        fs::metadata(&metadata)?.len() <= archive::MAX_MANIFEST as u64,
                        "OutputConflict: provenance size"
                    );
                    let provenance: serde_json::Value =
                        serde_json::from_reader(File::open(metadata)?)?;
                    ensure!(
                        provenance["selection"] == serde_json::to_value(&artifact.selection)?
                            && provenance["sha256"].as_str() == artifact.sha256.as_deref()
                            && provenance["config"] == serde_json::to_value(&self.index.config)?
                            && provenance["complete"] == true,
                        "OutputConflict: published provenance changed"
                    );
                }
            } else {
                // Missing artifacts can be regenerated from their verified evidence.
                ensure!(!sidecar, "OutputConflict: orphan sidecar");
            }
        }
        ensure!(
            total <= limit,
            "SourceResourceLimit: total exported payload exceeds output quota"
        );
        Ok(total)
    }

    fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.index)?;
        ensure!(
            bytes.len() <= archive::MAX_MANIFEST,
            "SourceResourceLimit: output index"
        );
        let mut temporary = output::publication_temporary(&self.root, true)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary.persist(self.root.join("versions.json"))?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

fn limits(versions: Option<usize>, bytes: Option<u64>) -> Result<(usize, u64)> {
    let versions = versions.unwrap_or(MAX_VERSIONS);
    let bytes = bytes.unwrap_or(MAX_OUTPUT);
    ensure!(
        (1..=MAX_VERSIONS).contains(&versions) && (1..=MAX_OUTPUT).contains(&bytes),
        "InvalidConfig: bulk limits must be positive and at most 1024 versions / 1 GiB output"
    );
    Ok((versions, bytes))
}

pub fn recover(args: &cli::Recover, config: RecoveryConfig) -> Result<()> {
    let (limit, quota) = limits(args.max_versions, args.max_output_bytes)?;
    let root = args
        .resume
        .as_ref()
        .or(args.archive.as_ref())
        .context("InvalidConfig: --all-versions requires --archive or --resume")?;
    let directory = args
        .out_dir
        .as_deref()
        .context("InvalidConfig: --all-versions requires --out-dir")?;
    separate_directories(root, directory)?;
    let mut archive = Archive::open_history(root, config, args.resume.is_some(), limit)?;
    let mut outputs = Outputs::open(directory, &archive.manifest.config, root)?;
    let runtime = cli::runtime()?;
    if !archive
        .manifest
        .history
        .as_ref()
        .expect("bulk mode")
        .discovery_complete
    {
        archive.manifest.rpc_hint = runtime.block_on(crate::history::rpc::probe(
            args.rpc_url.as_deref(),
            &archive.manifest.config,
            matches!(args.history_source, cli::Source::Jetstreamer),
        ))?;
        archive.save()?;
        let target = archive.manifest.config.target;
        let range = archive.manifest.config.range;
        crate::history::supervisor::collect(&mut archive, &runtime, target, range)?;
    }
    discover(&mut archive)?;
    export(
        &mut archive,
        &mut outputs,
        Some(&runtime),
        quota,
        args.keep_going,
    )
}

pub fn replay(args: &cli::Replay) -> Result<()> {
    let (_, quota) = limits(None, args.max_output_bytes)?;
    let manifest = archive::load_manifest(&args.archive)?;
    let history = manifest
        .history
        .as_ref()
        .context("InvalidConfig: --all-versions requires a bulk archive")?;
    ensure!(
        history.discovery_complete,
        "IncompleteArchive: bulk discovery is incomplete"
    );
    let mut archive = Archive::open_history(
        &args.archive,
        manifest.config.clone(),
        true,
        history.max_versions,
    )?;
    let mut outputs = Outputs::open(
        args.out_dir
            .as_deref()
            .context("InvalidConfig: --out-dir required")?,
        &archive.manifest.config,
        &args.archive,
    )?;
    discover(&mut archive)?;
    export(&mut archive, &mut outputs, None, quota, args.keep_going)
}

fn discover(archive: &mut Archive) -> Result<()> {
    let config = &archive.manifest.config;
    let Target::Program(program) = config.target else {
        anyhow::bail!("InvalidConfig: bulk requires a program");
    };
    let paths = cli::required_paths(archive, config.target, config.range)?;
    let sorted = archive.sorted(&paths)?;
    let result = reconstruct::discover_all_with_policy(
        BufReader::new(sorted.reopen()?),
        program,
        archive.manifest.config.loader,
        archive
            .manifest
            .history
            .as_ref()
            .expect("bulk mode")
            .max_versions,
    );
    archive.discard_temporary(sorted)?;
    let selections = result?;
    let history = archive.manifest.history.as_mut().expect("bulk mode");
    if history.discovery_complete {
        ensure!(
            selections.len() == history.versions.len()
                && selections
                    .iter()
                    .zip(&history.versions)
                    .all(|(selection, version)| selection == &version.selection),
            "CorruptArchive: frozen deployment list differs from evidence"
        );
    } else {
        history.versions = selections.into_iter().map(Version::new).collect();
        history.discovery_complete = true;
        archive.save()?;
    }
    Ok(())
}

pub(crate) fn selection_payload(
    archive: &mut Archive,
    runtime: Option<&tokio::runtime::Runtime>,
    selection: &Selection,
) -> Result<reconstruct::Reconstruction> {
    let result = match selection.loader {
        LoaderKind::V3 => {
            let range = SearchRange {
                start: archive.manifest.config.range.start,
                end: selection.position.slot + 1,
            };
            let target = Target::Buffer(selection.buffer);
            let paths = match runtime {
                Some(runtime) => {
                    crate::history::supervisor::collect(archive, runtime, target, range)?
                }
                None => cli::required_paths(archive, target, range)?,
            };
            let sorted = archive.sorted(&paths)?;
            let result = reconstruct::reconstruct(
                BufReader::new(sorted.reopen()?),
                selection.buffer,
                Some(selection),
            );
            archive.discard_temporary(sorted)?;
            result?
        }
        LoaderKind::V4 => {
            crate::v4::Resolver::new(archive, runtime).reconstruct_selection(selection)?
        }
    };
    output::validate_elf(&result.bytes).map_err(|error| {
        error.context(VersionIssue {
            kind: FailureKind::InvalidElf,
            detail: "InvalidElf: recovered version failed ELF validation",
        })
    })?;
    Ok(result)
}

fn export(
    archive: &mut Archive,
    outputs: &mut Outputs,
    runtime: Option<&tokio::runtime::Runtime>,
    quota: u64,
    keep_going: bool,
) -> Result<()> {
    outputs.bind(archive.manifest.history.as_ref().expect("bulk mode"))?;
    let mut used = outputs.existing_bytes(quota)?;
    let count = outputs.index.versions.len();
    for index in 0..count {
        ensure!(
            !crate::history::supervisor::CANCELLED.load(Ordering::Relaxed),
            "Interrupted: recovery cancelled"
        );
        let selection = outputs.index.versions[index].selection.clone();
        eprintln!(
            "Version {}/{}: slot {} ({})",
            index + 1,
            count,
            selection.position.slot,
            selection.signature
        );
        let result = match selection_payload(archive, runtime, &selection) {
            Ok(result) => result,
            Err(error) => {
                let failure = Failure::from_error(&error);
                let version = &mut archive
                    .manifest
                    .history
                    .as_mut()
                    .expect("bulk mode")
                    .versions[index];
                version.state = EvidenceState::Failed;
                version.payload_bytes = None;
                version.sha256 = None;
                version.error = Some(failure.clone());
                archive.manifest.complete = false;
                archive.save()?;
                let artifact = &mut outputs.index.versions[index];
                artifact.status = Publication::Failed;
                artifact.payload_bytes = None;
                artifact.sha256 = None;
                artifact.error = Some(failure.clone());
                outputs.save()?;
                if !keep_going || failure.kind == FailureKind::Fatal {
                    return Err(error);
                }
                continue;
            }
        };
        let size = result.bytes.len() as u64;
        let digest = hash(&result.bytes);
        let version = &mut archive
            .manifest
            .history
            .as_mut()
            .expect("bulk mode")
            .versions[index];
        if version.state == EvidenceState::Ready {
            ensure!(
                version.payload_bytes == Some(size) && version.sha256.as_ref() == Some(&digest),
                "CorruptArchive: recovered payload differs from ready evidence"
            );
        }
        let path = outputs.root.join(&version.filename);
        if !output::regular_exists(&path)? {
            used = used
                .checked_add(size)
                .context("SourceResourceLimit: output size overflow")?;
        }
        ensure!(
            used <= quota,
            "SourceResourceLimit: total exported payload exceeds output quota"
        );
        version.state = EvidenceState::Ready;
        version.payload_bytes = Some(size);
        version.sha256 = Some(digest.clone());
        version.error = None;
        archive.manifest.complete = archive
            .manifest
            .history
            .as_ref()
            .expect("bulk mode")
            .versions
            .iter()
            .all(|v| v.state == EvidenceState::Ready);
        archive.save()?;
        // This independently verifies existing binaries and sidecars, or completes
        // the sidecar for a matching orphan binary. It never replaces a binary.
        if let Err(error) =
            output::publish_resumable(&path, &result, &archive.manifest.config, &selection)
        {
            let artifact = &mut outputs.index.versions[index];
            artifact.status = Publication::Failed;
            artifact.payload_bytes = None;
            artifact.sha256 = None;
            artifact.error = Some(Failure::from_error(&error));
            outputs.save()?;
            return Err(error);
        }
        let artifact = &mut outputs.index.versions[index];
        artifact.status = Publication::Published;
        artifact.payload_bytes = Some(size);
        artifact.sha256 = Some(digest);
        artifact.error = None;
        outputs.save()?;
        // result owns the only root payload and is dropped at the iteration boundary.
    }
    let published = outputs
        .index
        .versions
        .iter()
        .filter(|artifact| artifact.status == Publication::Published)
        .count();
    outputs.index.complete = published == count;
    outputs.save()?;
    println!(
        "Exported {published}/{count} versions; index: {}",
        outputs.root.join("versions.json").display()
    );
    ensure!(
        published == count,
        "BatchIncomplete: {} historical versions failed",
        count - published
    );
    Ok(())
}
