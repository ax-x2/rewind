use crate::{Result, coverage::hash, ensure, reconstruct::Reconstruction, types::*};
use serde::Serialize;
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

pub fn validate_elf(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= MAX_PAYLOAD, "InvalidElf: payload limit");
    let elf = goblin::elf::Elf::parse(bytes)?;
    ensure!(
        elf.is_64 && elf.little_endian,
        "InvalidElf: expected little-endian ELF64"
    );
    ensure!(
        matches!(elf.header.e_machine, 247 | 263),
        "InvalidElf: unsupported SBF machine"
    );
    ensure!(
        elf.header.e_type == goblin::elf::header::ET_DYN,
        "InvalidElf: expected shared object"
    );
    ensure!(
        !elf.program_headers.is_empty() && !elf.section_headers.is_empty(),
        "InvalidElf: missing headers"
    );
    for header in &elf.program_headers {
        ensure!(
            header.p_filesz <= header.p_memsz,
            "InvalidElf: segment file size exceeds memory size"
        );
        ensure!(
            header
                .p_offset
                .checked_add(header.p_filesz)
                .is_some_and(|end| end <= bytes.len() as u64),
            "InvalidElf: segment outside payload"
        );
    }
    for section in &elf.section_headers {
        if section.sh_type != goblin::elf::section_header::SHT_NOBITS {
            ensure!(
                section
                    .sh_offset
                    .checked_add(section.sh_size)
                    .is_some_and(|end| end <= bytes.len() as u64),
                "InvalidElf: section outside payload"
            );
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct Provenance<'a> {
    loader: LoaderKind,
    loader_id: String,
    loader_client_revision: Option<&'a str>,
    baseline_account: solana_address::Address,
    format: u32,
    sdk_revision: &'a str,
    config: &'a RecoveryConfig,
    selection: Option<&'a Selection>,
    buffer: solana_address::Address,
    created: OrderKey,
    initialized: OrderKey,
    consumed: Option<OrderKey>,
    payload_bytes: usize,
    explicitly_written_bytes: usize,
    known_zero_bytes: usize,
    sha256: String,
    complete: bool,
    payload_semantics: &'static str,
}

pub fn manifest_path(out: &Path) -> PathBuf {
    let mut name = out.as_os_str().to_owned();
    name.push(".json");
    PathBuf::from(name)
}

pub fn publish(
    out: &Path,
    result: &Reconstruction,
    config: &RecoveryConfig,
    selection: Option<&Selection>,
) -> Result<String> {
    publish_inner(out, result, config, selection, false)
}

pub(crate) fn publish_resumable(
    out: &Path,
    result: &Reconstruction,
    config: &RecoveryConfig,
    selection: &Selection,
) -> Result<String> {
    publish_inner(out, result, config, Some(selection), true)
}

pub(crate) fn regular_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(
                meta.is_file(),
                "OutputConflict: expected a regular file: {}",
                path.display()
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn publication_temporary(
    parent: &Path,
    resumable: bool,
) -> Result<tempfile::NamedTempFile> {
    let mut builder = tempfile::Builder::new();
    builder.rand_bytes(6);
    if resumable {
        builder.prefix(".rewind-tmp-");
    }
    Ok(builder.tempfile_in(parent)?)
}

fn publish_inner(
    out: &Path,
    result: &Reconstruction,
    config: &RecoveryConfig,
    selection: Option<&Selection>,
    resume: bool,
) -> Result<String> {
    validate_elf(&result.bytes)?;
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let manifest = manifest_path(out);
    let binary_exists = regular_exists(out)?;
    let metadata_exists = regular_exists(&manifest)?;
    ensure!(
        resume || (!binary_exists && !metadata_exists),
        "OutputExists: output or provenance already exists"
    );
    ensure!(
        !metadata_exists || binary_exists,
        "OutputConflict: provenance has no binary"
    );
    let digest = hash(&result.bytes);
    let provenance = Provenance {
        loader: result.loader,
        loader_id: result.loader.id().to_string(),
        loader_client_revision: (result.loader == LoaderKind::V4).then_some(V4_CLIENT_REVISION),
        baseline_account: result.baseline_account,
        format: FORMAT,
        sdk_revision: SDK_REVISION,
        config,
        selection,
        buffer: result.buffer,
        created: result.created,
        initialized: result.initialized,
        consumed: result.consumed,
        payload_bytes: result.bytes.len(),
        explicitly_written_bytes: result.explicitly_written,
        known_zero_bytes: result.bytes.len() - result.explicitly_written,
        sha256: digest.clone(),
        complete: true,
        payload_semantics: match result.loader {
            LoaderKind::V3 => {
                "loader-v3 buffer payload, including uploader padding; excludes loader metadata and ProgramData spare capacity"
            }
            LoaderKind::V4 => {
                "CoreBPF loader-v4 ELF payload immediately before the selected deployment or buffer close; excludes account metadata"
            }
        },
    };
    if binary_exists {
        ensure!(
            std::fs::metadata(out)?.len() == result.bytes.len() as u64,
            "OutputConflict: binary length differs"
        );
        ensure!(
            crate::archive::file_hash(out)?.0 == digest,
            "OutputConflict: binary hash differs"
        );
    }
    if metadata_exists {
        ensure!(
            std::fs::metadata(&manifest)?.len() <= crate::archive::MAX_MANIFEST as u64,
            "OutputConflict: provenance size"
        );
        let existing: serde_json::Value = serde_json::from_reader(File::open(&manifest)?)?;
        ensure!(
            existing == serde_json::to_value(&provenance)?,
            "OutputConflict: provenance differs"
        );
        return Ok(digest);
    }
    let mut metadata = publication_temporary(parent, resume)?;
    serde_json::to_writer_pretty(&mut metadata, &provenance)?;
    metadata.as_file().sync_all()?;
    // The sidecar is the completion marker and is published last. A crash between
    // files leaves a binary without a success marker; both paths use no-clobber.
    if !binary_exists {
        let mut binary = publication_temporary(parent, resume)?;
        binary.write_all(&result.bytes)?;
        binary.as_file().sync_all()?;
        binary.persist_noclobber(out)?;
    }
    metadata.persist_noclobber(&manifest).map_err(|e| {
        anyhow::anyhow!(
            "PublicationInterrupted: binary is at {}; no complete sidecar was published: {e}",
            out.display()
        )
    })?;
    File::open(parent)?.sync_all()?;
    Ok(digest)
}
