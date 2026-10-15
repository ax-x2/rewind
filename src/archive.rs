//! Versioned evidence, bounded sorting, and crash-safe chunk journals.
use crate::{Result, coverage::hash, ensure, types::*};
use anyhow::Context;
use bincode::Options;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

pub const MAX_MANIFEST: usize = 8 * 1024 * 1024;
const SORT_MEMORY: usize = 32 * 1024 * 1024;

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let options = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_FRAME as u64);
    ensure!(
        options.serialized_size(value)? <= MAX_FRAME as u64,
        "SourceResourceLimit: encoded frame"
    );
    Ok(options.serialize(value)?)
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ensure!(bytes.len() <= MAX_FRAME, "SourceResourceLimit: frame");
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_FRAME as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)?)
}

pub fn write_record<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<u64> {
    let bytes = encode(value)?;
    writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&bytes)?;
    Ok(4 + bytes.len() as u64)
}

pub fn read_record<T: DeserializeOwned>(reader: &mut impl Read) -> Result<Option<T>> {
    let mut header = [0; 4];
    let first = reader.read(&mut header[..1])?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..])?;
    let len = u32::from_le_bytes(header) as usize;
    ensure!(len > 0 && len <= MAX_FRAME, "CorruptArchive: frame length");
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes)?;
    Ok(Some(decode(&bytes)?))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    pub target: Target,
    pub range: SearchRange,
    pub stem: String,
    pub proof_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    pub coverage: Coverage,
    pub raw_hash: String,
    pub raw_size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub sdk_revision: String,
    pub config: RecoveryConfig,
    pub selection: Option<Selection>,
    pub chunks: Vec<Chunk>,
    pub complete: bool,
    pub rpc_hint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<crate::bulk::History>,
}

pub struct Archive {
    pub root: PathBuf,
    pub manifest: Manifest,
    used: u64,
    lock: PathBuf,
    pub(crate) failed_sources: Vec<(Target, SearchRange)>,
}

impl Drop for Archive {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock);
    }
}

impl Archive {
    pub fn open(root: &Path, config: RecoveryConfig, resume: bool) -> Result<Self> {
        Self::open_mode(root, config, resume, None)
    }

    pub fn open_history(
        root: &Path,
        config: RecoveryConfig,
        resume: bool,
        limit: usize,
    ) -> Result<Self> {
        ensure!(
            (1..=crate::bulk::MAX_VERSIONS).contains(&limit),
            "InvalidConfig: version limit"
        );
        Self::open_mode(root, config, resume, Some(limit))
    }

    fn open_mode(
        root: &Path,
        config: RecoveryConfig,
        resume: bool,
        limit: Option<usize>,
    ) -> Result<Self> {
        if !resume {
            fs::create_dir(root)
                .with_context(|| format!("archive directory must be new: {}", root.display()))?;
        }
        ensure!(
            fs::symlink_metadata(root)?.is_dir(),
            "CorruptArchive: archive must be a directory"
        );
        let lock = root.join(".lock");
        let _lock = OpenOptions::new().write(true).create_new(true).open(&lock).context("ArchiveBusy: archive lock exists; confirm no recovery is running before removing a stale lock")?;
        let result = (|| {
            let manifest = if resume {
                load_manifest(root)?
            } else {
                Manifest {
                    format: if limit.is_some() {
                        crate::bulk::HISTORY_FORMAT
                    } else {
                        FORMAT
                    },
                    sdk_revision: SDK_REVISION.to_owned(),
                    config: config.clone(),
                    selection: None,
                    chunks: Vec::new(),
                    complete: false,
                    rpc_hint: "disabled".into(),
                    history: limit.map(crate::bulk::History::new),
                }
            };
            ensure!(
                manifest.config == config,
                "ResumeMismatch: recovery configuration differs"
            );
            ensure!(
                manifest.sdk_revision == SDK_REVISION,
                "ResumeMismatch: SDK revision differs"
            );
            ensure!(
                manifest
                    .history
                    .as_ref()
                    .map(|history| history.max_versions)
                    == limit,
                "ResumeMismatch: --all-versions mode or version limit differs"
            );
            ensure!(
                manifest.format != 1 || manifest.complete,
                "ResumeMismatch: incomplete v1 archive omitted v4 history; start a new archive"
            );
            let mut used = 0u64;
            let mut entries = 0usize;
            for entry in fs::read_dir(root)? {
                entries += 1;
                ensure!(
                    entries <= 65536,
                    "SourceResourceLimit: archive directory entries"
                );
                let meta = entry?.path().symlink_metadata()?;
                ensure!(
                    meta.is_file(),
                    "CorruptArchive: unexpected non-file in archive"
                );
                used = used
                    .checked_add(meta.len())
                    .context("archive size overflow")?;
            }
            ensure!(used <= MAX_SPOOL, "SourceResourceLimit: archive quota");
            Ok((manifest, used))
        })();
        match result {
            Ok((manifest, used)) => Ok(Self {
                root: root.to_owned(),
                manifest,
                used,
                lock,
                failed_sources: Vec::new(),
            }),
            Err(error) => {
                fs::remove_file(lock)?;
                Err(error)
            }
        }
    }

    pub fn reserve(&mut self, bytes: u64) -> Result<()> {
        ensure!(
            self.used.saturating_add(bytes) <= MAX_SPOOL,
            "SourceResourceLimit: 1 GiB archive quota (includes sorting)"
        );
        self.used += bytes;
        Ok(())
    }

    pub fn discard_temporary(&mut self, file: tempfile::NamedTempFile) -> Result<()> {
        self.used = self.used.saturating_sub(file.as_file().metadata()?.len());
        file.close()?;
        Ok(())
    }

    pub fn reset_partial_accounting(&mut self, path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                ensure!(
                    meta.is_file(),
                    "CorruptArchive: partial path is not a regular file"
                );
                self.used = self.used.saturating_sub(meta.len());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    pub fn save(&mut self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.manifest)?;
        ensure!(bytes.len() <= MAX_MANIFEST, "SourceResourceLimit: manifest");
        self.reserve(bytes.len() as u64)?;
        let mut file = tempfile::NamedTempFile::new_in(&self.root)?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        let path = self.root.join("archive.json");
        let old = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        file.persist(path)?;
        self.used = self.used.saturating_sub(old);
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    pub fn commit(
        &mut self,
        target: Target,
        range: SearchRange,
        partial: &Path,
        coverage: Coverage,
    ) -> Result<()> {
        let stem = chunk_stem(target, range);
        let (raw_hash, raw_size) = file_hash(partial)?;
        let proof = encode(&Proof {
            coverage,
            raw_hash,
            raw_size,
        })?;
        let raw = self.root.join(format!("{stem}.raw"));
        let proof_path = self.root.join(format!("{stem}.proof"));
        // Unjournaled files can remain after a crash. They have deterministic names,
        // are owned by this run, and are replaced only while holding the archive lock.
        self.reset_partial_accounting(&raw)?;
        fs::rename(partial, &raw)?;
        self.reset_partial_accounting(&proof_path)?;
        self.reserve(proof.len() as u64)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(proof_path)?;
        file.write_all(&proof)?;
        file.sync_all()?;
        ensure!(
            self.manifest.chunks.len() < 16384,
            "SourceResourceLimit: committed chunks"
        );
        self.manifest.chunks.push(Chunk {
            target,
            range,
            stem,
            proof_hash: hash(&proof),
        });
        self.save()
    }

    pub fn verified(&self, target: Target, range: SearchRange) -> Result<Option<PathBuf>> {
        if let Some(chunk) = self
            .manifest
            .chunks
            .iter()
            .find(|c| c.target == target && c.range == range)
        {
            return Ok(Some(verify_chunk(&self.root, chunk)?));
        }
        Ok(None)
    }

    pub fn verified_covering(&self, target: Target, range: SearchRange) -> Result<Option<PathBuf>> {
        self.manifest
            .chunks
            .iter()
            .filter(|chunk| {
                chunk.target == target
                    && chunk.range.start <= range.start
                    && chunk.range.end >= range.end
            })
            .min_by_key(|chunk| chunk.range.end - chunk.range.start)
            .map(|chunk| verify_chunk(&self.root, chunk))
            .transpose()
    }

    pub fn sorted(&mut self, paths: &[PathBuf]) -> Result<tempfile::NamedTempFile> {
        // Signature pass detects the same transaction reported at different positions.
        let signature = self.sort_pass(paths, true)?;
        let result = self.sort_pass(&[signature.path().to_owned()], false)?;
        self.used = self
            .used
            .saturating_sub(signature.as_file().metadata()?.len());
        Ok(result)
    }

    fn sort_pass(&mut self, paths: &[PathBuf], signature: bool) -> Result<tempfile::NamedTempFile> {
        let mut runs = Vec::new();
        let mut records = Vec::with_capacity(16384);
        let metadata_memory = records.capacity() * std::mem::size_of::<TransactionRecord>();
        let mut memory = metadata_memory;
        for path in paths {
            let mut reader = BufReader::new(File::open(path)?);
            while let Some(record) = read_record::<TransactionRecord>(&mut reader)? {
                validate_record(&record)?;
                let size = record_memory(&record) - std::mem::size_of::<TransactionRecord>();
                if (memory + size > SORT_MEMORY || records.len() == records.capacity())
                    && !records.is_empty()
                {
                    runs.push(self.make_run(&mut records, signature)?);
                    memory = metadata_memory;
                }
                records.push(record);
                memory += size;
            }
        }
        if !records.is_empty() || runs.is_empty() {
            runs.push(self.make_run(&mut records, signature)?);
        }
        while runs.len() > 1 {
            let mut next = Vec::new();
            for group in runs.chunks(16) {
                next.push(self.merge(group, signature)?);
            }
            for run in &runs {
                self.used = self.used.saturating_sub(run.as_file().metadata()?.len());
            }
            runs = next;
        }
        Ok(runs.pop().expect("at least one run"))
    }

    fn make_run(
        &mut self,
        records: &mut Vec<TransactionRecord>,
        signature: bool,
    ) -> Result<tempfile::NamedTempFile> {
        records.sort_unstable_by(|a, b| compare(a, b, signature));
        let mut run = tempfile::NamedTempFile::new_in(&self.root)?;
        {
            let mut writer = BufWriter::new(&mut run);
            let mut previous: Option<TransactionRecord> = None;
            for record in records.drain(..) {
                if duplicate(previous.as_ref(), &record, signature)? {
                    continue;
                }
                self.reserve(encode(&record)?.len() as u64 + 4)?;
                write_record(&mut writer, &record)?;
                previous = Some(record);
            }
            writer.flush()?;
        }
        Ok(run)
    }

    fn merge(
        &mut self,
        runs: &[tempfile::NamedTempFile],
        signature: bool,
    ) -> Result<tempfile::NamedTempFile> {
        let mut readers = runs
            .iter()
            .map(|r| r.reopen().map(BufReader::new))
            .collect::<std::io::Result<Vec<_>>>()?;
        let mut heads = readers
            .iter_mut()
            .map(read_record::<TransactionRecord>)
            .collect::<Result<Vec<_>>>()?;
        let mut output = tempfile::NamedTempFile::new_in(&self.root)?;
        {
            let mut writer = BufWriter::new(&mut output);
            let mut previous = None;
            loop {
                let index = heads
                    .iter()
                    .enumerate()
                    .filter_map(|(i, h)| h.as_ref().map(|r| (i, r)))
                    .min_by(|(_, a), (_, b)| compare(a, b, signature))
                    .map(|(i, _)| i);
                let Some(index) = index else {
                    break;
                };
                let record = heads[index].take().expect("selected nonempty head");
                if !duplicate(previous.as_ref(), &record, signature)? {
                    self.reserve(encode(&record)?.len() as u64 + 4)?;
                    write_record(&mut writer, &record)?;
                    previous = Some(record);
                }
                heads[index] = read_record(&mut readers[index])?;
            }
            writer.flush()?;
        }
        Ok(output)
    }
}

fn compare(a: &TransactionRecord, b: &TransactionRecord, signature: bool) -> std::cmp::Ordering {
    if signature {
        a.signature.as_ref().cmp(b.signature.as_ref())
    } else {
        (a.slot, a.index).cmp(&(b.slot, b.index))
    }
}

fn duplicate(
    previous: Option<&TransactionRecord>,
    record: &TransactionRecord,
    signature: bool,
) -> Result<bool> {
    if let Some(previous) = previous.filter(|p| compare(p, record, signature).is_eq()) {
        ensure!(
            previous == record,
            "CorruptArchive: conflicting duplicate transaction"
        );
        return Ok(true);
    }
    Ok(false)
}

pub fn record_memory(record: &TransactionRecord) -> usize {
    std::mem::size_of::<TransactionRecord>()
        + record.keys.capacity() * 32
        + record.instructions.capacity() * std::mem::size_of::<RawInstruction>()
        + record
            .instructions
            .iter()
            .map(|i| i.data.capacity() + i.accounts.capacity())
            .sum::<usize>()
        + record.logs.as_ref().map_or(0, |logs| {
            logs.capacity() * std::mem::size_of::<String>()
                + logs.iter().map(String::capacity).sum::<usize>()
        })
}

pub fn validate_record(record: &TransactionRecord) -> Result<()> {
    ensure!(
        record.keys.len() <= 256
            && record.instructions.len() <= 8448
            && record.index < MAX_TX as u32
            && record_memory(record) <= 1024 * 1024,
        "CorruptArchive: transaction resource bounds"
    );
    let mut previous = None;
    for ix in &record.instructions {
        record.program(ix)?;
        for index in &ix.accounts {
            ensure!(
                (*index as usize) < record.keys.len(),
                "CorruptArchive: account index"
            );
        }
        let position = (ix.outer, ix.ordinal);
        let canonical = match previous {
            None => position == (0, 0),
            Some((outer, ordinal)) => {
                (ix.outer == outer && ix.ordinal == ordinal + 1)
                    || (ix.outer == outer + 1 && ix.ordinal == 0)
            }
        };
        ensure!(
            canonical && (ix.ordinal != 0 || ix.depth == Some(1)),
            "CorruptArchive: noncanonical instruction order"
        );
        previous = Some(position);
    }
    Ok(())
}

pub fn file_hash(path: &Path) -> Result<(String, u64)> {
    ensure!(
        fs::symlink_metadata(path)?.is_file(),
        "CorruptArchive: expected a regular file"
    );
    let mut reader = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];
    let mut size = 0u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        ensure!(size <= MAX_SPOOL, "SourceResourceLimit: evidence file");
        hasher.update(&buffer[..count]);
    }
    Ok((crate::coverage::hex(&hasher.finalize()), size))
}

pub fn load_manifest(root: &Path) -> Result<Manifest> {
    let path = root.join("archive.json");
    ensure!(
        fs::symlink_metadata(&path)?.is_file() && fs::metadata(&path)?.len() <= MAX_MANIFEST as u64,
        "CorruptArchive: manifest type/size"
    );
    let manifest: Manifest = serde_json::from_reader(File::open(path)?)?;
    ensure!(
        matches!(manifest.format, 1 | FORMAT | crate::bulk::HISTORY_FORMAT)
            && manifest.chunks.len() <= 16384,
        "CorruptArchive: unsupported manifest"
    );
    crate::bulk::validate_history(&manifest)?;
    if manifest.format == 1 {
        ensure!(
            manifest.config.loader == LoaderPolicy::V3
                && manifest
                    .selection
                    .as_ref()
                    .is_none_or(|s| s.loader == LoaderKind::V3),
            "CorruptArchive: v1 archive cannot certify v4 history"
        );
    }
    Ok(manifest)
}

pub fn verify_chunk(root: &Path, chunk: &Chunk) -> Result<PathBuf> {
    let label = match chunk.target {
        Target::Program(_) => "program",
        Target::Buffer(_) => "buffer",
    };
    ensure!(
        chunk.stem == format!("{label}-{}-{}", chunk.range.start, chunk.range.end)
            || chunk.stem == chunk_stem(chunk.target, chunk.range),
        "CorruptArchive: chunk path"
    );
    let proof_path = root.join(format!("{}.proof", chunk.stem));
    ensure!(
        fs::symlink_metadata(&proof_path)?.is_file()
            && fs::metadata(&proof_path)?.len() <= MAX_FRAME as u64,
        "CorruptArchive: proof size/type"
    );
    let proof_bytes = fs::read(proof_path)?;
    ensure!(
        hash(&proof_bytes) == chunk.proof_hash,
        "CorruptArchive: proof hash mismatch"
    );
    let proof: Proof = decode(&proof_bytes)?;
    ensure!(
        proof.coverage.range == chunk.range,
        "CorruptArchive: coverage bounds"
    );
    ensure!(
        chunk.range.start < chunk.range.end
            && chunk.range.end - chunk.range.start <= CHUNK_SLOTS
            && (chunk.range.end - 1) / SLOTS_PER_EPOCH == chunk.range.start / SLOTS_PER_EPOCH,
        "CorruptArchive: coverage range limits"
    );
    ensure!(
        proof.coverage.index_hash.len() == 64
            && proof
                .coverage
                .index_hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit()),
        "CorruptArchive: index identity"
    );
    let mut previous = None;
    for slot in &proof.coverage.slots {
        ensure!(
            slot.slot >= chunk.range.start
                && slot.slot < chunk.range.end
                && slot.transactions <= MAX_TX as u64
                && previous.is_none_or(|previous| slot.slot > previous),
            "CorruptArchive: coverage slot ordering/count"
        );
        previous = Some(slot.slot);
    }
    let raw = root.join(format!("{}.raw", chunk.stem));
    let (digest, size) = file_hash(&raw)?;
    ensure!(
        digest == proof.raw_hash && size == proof.raw_size,
        "CorruptArchive: raw evidence hash mismatch"
    );
    Ok(raw)
}

pub fn chunk_stem(target: Target, range: SearchRange) -> String {
    let label = match target {
        Target::Program(_) => "program",
        Target::Buffer(_) => "buffer",
    };
    format!("{label}-{}-{}-{}", target.address(), range.start, range.end)
}
