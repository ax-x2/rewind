use crate::{
    Result,
    archive::{Archive, load_manifest},
    ensure, history, output, reconstruct,
    types::*,
};
use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    version,
    about = "Recover Solana loader-v3 and CoreBPF loader-v4 programs from Jetstreamer history"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Action,
}

#[derive(Subcommand)]
// Parsed once on the cold CLI path; inline storage avoids an unnecessary allocation.
#[allow(clippy::large_enum_variant)]
pub enum Action {
    Recover(Recover),
    Replay(Replay),
    #[command(name = "__scan-worker", hide = true)]
    Worker {
        #[arg(long)]
        socket: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Source {
    Auto,
    Jetstreamer,
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("output").required(true).args(["out", "out_dir"])))]
pub struct Replay {
    #[arg(long)]
    pub archive: PathBuf,
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Replay every discovered version from a bulk archive.
    #[arg(long, requires = "out_dir", conflicts_with = "out")]
    pub all_versions: bool,
    /// Directory for bulk binaries, provenance and versions.json.
    #[arg(long, requires = "all_versions")]
    pub out_dir: Option<PathBuf>,
    /// Continue after version-local failures; any failure still exits nonzero.
    #[arg(long, requires = "all_versions", conflicts_with = "out")]
    pub keep_going: bool,
    /// Maximum total binary bytes, including existing exports (default/max: 1073741824).
    #[arg(long, requires = "all_versions", conflicts_with = "out")]
    pub max_output_bytes: Option<u64>,
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("target").required(true).args(["program", "buffer"])), group(clap::ArgGroup::new("range").required(true).args(["slots", "epochs"])), group(clap::ArgGroup::new("output").required(true).args(["out", "out_dir"])))]
pub struct Recover {
    /// Select a loader, or infer it from successful historical instructions.
    #[arg(long, value_enum, default_value = "auto")]
    pub loader: LoaderPolicy,
    #[arg(long)]
    pub program: Option<solana_address::Address>,
    #[arg(long)]
    pub buffer: Option<solana_address::Address>,
    /// Inclusive FIRST:LAST slot bounds, including upload creation/initialization.
    #[arg(long)]
    pub slots: Option<String>,
    /// Inclusive FIRST:LAST mainnet epoch bounds (432000 slots per epoch).
    #[arg(long)]
    pub epochs: Option<String>,
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Export every supported deployment in the range instead of one version.
    #[arg(long, requires_all = ["program", "out_dir"], conflicts_with_all = ["out", "buffer", "deployment_signature"])]
    pub all_versions: bool,
    /// Directory for bulk binaries, provenance and versions.json.
    #[arg(long, requires = "all_versions")]
    pub out_dir: Option<PathBuf>,
    /// Maximum discovered versions before exporting any binary (default/max: 1024).
    #[arg(long, requires = "all_versions", conflicts_with = "out")]
    pub max_versions: Option<usize>,
    /// Maximum total binary bytes, including existing exports (default/max: 1073741824).
    #[arg(long, requires = "all_versions", conflicts_with = "out")]
    pub max_output_bytes: Option<u64>,
    /// Continue after version-local failures; any failure still exits nonzero.
    #[arg(long, requires = "all_versions", conflicts_with = "out")]
    pub keep_going: bool,
    #[arg(long, conflicts_with = "resume")]
    pub archive: Option<PathBuf>,
    #[arg(long)]
    pub resume: Option<PathBuf>,
    #[arg(long)]
    pub rpc_url: Option<String>,
    #[arg(long, value_enum, default_value = "auto")]
    pub history_source: Source,
    #[arg(long, requires = "program")]
    pub deployment_signature: Option<solana_signature::Signature>,
    #[arg(long)]
    pub index_base: Option<String>,
    #[arg(long)]
    pub car_base: Option<String>,
}

pub fn parse_range(input: &str) -> Result<SearchRange> {
    let (first, last) = input
        .split_once(':')
        .context("InvalidRange: expected FIRST:LAST (inclusive)")?;
    SearchRange::inclusive(first.parse()?, last.parse()?)
}

fn base(explicit: &Option<String>, variable: &str) -> Result<String> {
    let value = explicit
        .clone()
        .or_else(|| std::env::var(variable).ok())
        .or_else(|| std::env::var("JETSTREAMER_ARCHIVE_BASE").ok())
        .unwrap_or_else(|| "https://files.old-faithful.net".into());
    let parsed = reqwest::Url::parse(&value)?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https")
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "InvalidConfig: archive base must be an HTTP(S) directory URL without query/fragment"
    );
    Ok(value.trim_end_matches('/').to_owned())
}

fn configuration(args: &Recover) -> Result<RecoveryConfig> {
    let range = if let Some(slots) = &args.slots {
        parse_range(slots)?
    } else {
        let epochs = parse_range(args.epochs.as_deref().context("missing range")?)?;
        SearchRange {
            start: epochs
                .start
                .checked_mul(SLOTS_PER_EPOCH)
                .context("InvalidRange: epoch overflow")?,
            end: epochs
                .end
                .checked_mul(SLOTS_PER_EPOCH)
                .context("InvalidRange: epoch overflow")?,
        }
    };
    // Mainnet has no warmup epochs. Other cluster schedules are not accepted.
    ensure!(
        range.start < range.end && range.chunks().take(16385).count() <= 16384,
        "SourceResourceLimit: search exceeds 16384 chunks; split the search range"
    );
    let target = args
        .program
        .map(Target::Program)
        .or_else(|| args.buffer.map(Target::Buffer))
        .context("missing target")?;
    Ok(RecoveryConfig {
        loader: args.loader,
        target,
        range,
        deployment: args.deployment_signature,
        index_base: base(&args.index_base, "JETSTREAMER_COMPACT_INDEX_BASE_URL")?,
        car_base: base(&args.car_base, "JETSTREAMER_HTTP_BASE_URL")?,
        genesis: GENESIS.into(),
    })
}

pub(crate) fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()?)
}

fn check_output(out: &Path) -> Result<()> {
    ensure!(
        !out.try_exists()? && !output::manifest_path(out).try_exists()?,
        "OutputExists: output/provenance already exists"
    );
    ensure!(
        out.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .is_dir(),
        "InvalidConfig: output directory does not exist"
    );
    Ok(())
}

pub fn recover(args: Recover) -> Result<()> {
    let config = configuration(&args)?;
    if args.all_versions {
        return crate::bulk::recover(&args, config);
    }
    check_output(
        args.out
            .as_deref()
            .context("InvalidConfig: --out required")?,
    )?;
    let temporary = if args.archive.is_none() && args.resume.is_none() {
        Some(
            tempfile::Builder::new()
                .prefix("rewind-evidence-")
                .tempdir()?,
        )
    } else {
        None
    };
    let root = args
        .resume
        .clone()
        .or_else(|| args.archive.clone())
        .unwrap_or_else(|| {
            temporary
                .as_ref()
                .expect("temporary archive")
                .path()
                .join("evidence")
        });
    eprintln!("Evidence archive: {}", root.display());
    let result = recover_at(&args, &root, config);
    if result.is_err()
        && let Some(temporary) = temporary
    {
        let _ = temporary.keep();
        eprintln!("Partial evidence retained at {}", root.display());
    }
    result
}

fn recover_at(args: &Recover, root: &Path, config: RecoveryConfig) -> Result<()> {
    let mut archive = Archive::open(root, config.clone(), args.resume.is_some())?;
    let runtime = runtime()?;
    if !archive.manifest.complete {
        archive.manifest.rpc_hint = runtime.block_on(history::rpc::probe(
            args.rpc_url.as_deref(),
            &config,
            matches!(args.history_source, Source::Jetstreamer),
        ))?;
        eprintln!("RPC: {}", archive.manifest.rpc_hint);
        archive.save()?;
        let selection = if let Target::Program(program) = config.target {
            let paths =
                history::supervisor::collect(&mut archive, &runtime, config.target, config.range)?;
            let sorted = archive.sorted(&paths)?;
            let selection = reconstruct::discover_with_policy(
                BufReader::new(File::open(sorted.path())?),
                program,
                config.deployment,
                config.loader,
            )?;
            archive.discard_temporary(sorted)?;
            eprintln!(
                "Selected buffer {} at slot {}",
                selection.buffer, selection.position.slot
            );
            Some(selection)
        } else {
            None
        };
        ensure!(
            archive
                .manifest
                .selection
                .as_ref()
                .is_none_or(|old| Some(old) == selection.as_ref()),
            "ResumeMismatch: selected deployment changed"
        );
        archive.manifest.selection = selection;
        archive.save()?;
        if archive
            .manifest
            .selection
            .as_ref()
            .is_none_or(|s| s.loader == LoaderKind::V3)
        {
            let (buffer, range) = buffer_request(&archive.manifest)?;
            history::supervisor::collect(&mut archive, &runtime, Target::Buffer(buffer), range)?;
        }
    }
    export(
        &mut archive,
        args.out
            .as_deref()
            .context("InvalidConfig: --out required")?,
        Some(&runtime),
    )
}

fn buffer_request(
    manifest: &crate::archive::Manifest,
) -> Result<(solana_address::Address, SearchRange)> {
    match manifest.config.target {
        Target::Buffer(buffer) => {
            ensure!(
                manifest.selection.is_none(),
                "CorruptArchive: buffer archive has program selection"
            );
            Ok((buffer, manifest.config.range))
        }
        Target::Program(program) => {
            let selection = manifest
                .selection
                .as_ref()
                .context("IncompleteArchive: no deployment selected")?;
            ensure!(
                selection.program == program
                    && selection.position.slot >= manifest.config.range.start
                    && selection.position.slot < manifest.config.range.end,
                "CorruptArchive: selected program/range"
            );
            Ok((
                selection.buffer,
                SearchRange {
                    start: manifest.config.range.start,
                    end: selection.position.slot + 1,
                },
            ))
        }
    }
}

pub fn replay(root: &Path, out: &Path) -> Result<()> {
    check_output(out)?;
    let manifest = load_manifest(root)?;
    ensure!(
        manifest.history.is_none(),
        "InvalidConfig: bulk archive requires replay --all-versions --out-dir"
    );
    ensure!(
        manifest.complete,
        "IncompleteArchive: recovery did not finish all required chunks"
    );
    let mut archive = Archive::open(root, manifest.config.clone(), true)?;
    export(&mut archive, out, None)
}

pub fn replay_args(args: Replay) -> Result<()> {
    if args.all_versions {
        crate::bulk::replay(&args)
    } else {
        replay(
            &args.archive,
            args.out
                .as_deref()
                .context("InvalidConfig: --out required")?,
        )
    }
}

pub(crate) fn required_paths(
    archive: &Archive,
    target: Target,
    range: SearchRange,
) -> Result<Vec<PathBuf>> {
    range
        .chunks()
        .map(|range| {
            archive.verified_covering(target, range)?.ok_or_else(|| {
                crate::bulk::missing_source("IncompleteArchive: required chunk missing")
            })
        })
        .collect()
}

fn export(
    archive: &mut Archive,
    out: &Path,
    runtime: Option<&tokio::runtime::Runtime>,
) -> Result<()> {
    ensure!(
        archive.manifest.config.genesis == GENESIS,
        "IncompleteArchive: source identity"
    );
    if let Target::Program(program) = archive.manifest.config.target {
        let paths = required_paths(
            archive,
            Target::Program(program),
            archive.manifest.config.range,
        )?;
        let sorted = archive.sorted(&paths)?;
        let selection = reconstruct::discover_with_policy(
            BufReader::new(File::open(sorted.path())?),
            program,
            archive.manifest.config.deployment,
            archive.manifest.config.loader,
        )?;
        archive.discard_temporary(sorted)?;
        ensure!(
            Some(&selection) == archive.manifest.selection.as_ref(),
            "CorruptArchive: saved selection does not match evidence"
        );
    }
    let selected = archive.manifest.selection.clone();
    let result = if let Some(selection) = selected.as_ref() {
        crate::bulk::selection_payload(archive, runtime, selection)?
    } else {
        let (buffer, range) = buffer_request(&archive.manifest)?;
        let kind = {
            let paths = required_paths(archive, Target::Buffer(buffer), range)?;
            let sorted = archive.sorted(&paths)?;
            let result = crate::v4::detect(BufReader::new(File::open(sorted.path())?), buffer)?;
            archive.discard_temporary(sorted)?;
            ensure!(
                archive.manifest.config.loader.accepts(result),
                "LoaderMismatch: archive history does not match --loader"
            );
            result
        };
        match kind {
            LoaderKind::V3 => {
                let paths = required_paths(archive, Target::Buffer(buffer), range)?;
                let sorted = archive.sorted(&paths)?;
                let result = reconstruct::reconstruct(
                    BufReader::new(File::open(sorted.path())?),
                    buffer,
                    None,
                )?;
                archive.discard_temporary(sorted)?;
                result
            }
            LoaderKind::V4 => crate::v4::Resolver::new(archive, runtime).reconstruct()?,
        }
    };
    output::validate_elf(&result.bytes)?;
    if !archive.manifest.complete {
        archive.manifest.complete = true;
        archive.save()?;
    }
    let digest = output::publish(
        out,
        &result,
        &archive.manifest.config,
        archive.manifest.selection.as_ref(),
    )?;
    println!(
        "Recovered {} bytes to {}\nSHA-256: {digest}",
        result.bytes.len(),
        out.display()
    );
    Ok(())
}
