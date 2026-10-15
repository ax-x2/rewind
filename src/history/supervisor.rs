//! Blocking IPC and disk I/O live exclusively on the coordinator's cold path.
use super::worker::Request;
use crate::{
    Result,
    archive::{self, Archive},
    coverage, ensure,
    types::*,
};
use anyhow::Context;
use std::{
    fs::OpenOptions,
    io::{BufWriter, Read, Write},
    os::fd::AsRawFd,
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub static CANCELLED: AtomicBool = AtomicBool::new(false);

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

pub fn collect(
    archive: &mut Archive,
    runtime: &tokio::runtime::Runtime,
    target: Target,
    range: SearchRange,
) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let full = archive.manifest.config.range;
    ensure!(
        range.start >= full.start && range.end <= full.end,
        "InvalidRange: collection outside search bounds"
    );
    let ranges: Vec<_> = if archive.manifest.history.is_some() {
        full.chunks()
            .filter(|chunk| chunk.start < range.end && chunk.end > range.start)
            .collect()
    } else {
        range.chunks().collect()
    };
    for chunk in ranges {
        ensure!(
            !CANCELLED.load(Ordering::Relaxed),
            "Interrupted: recovery cancelled"
        );
        if let Some(path) = archive.verified_covering(target, chunk)? {
            paths.push(path);
            continue;
        }
        ensure!(
            archive.manifest.chunks.len() < 16384,
            "SourceResourceLimit: committed chunks"
        );
        if archive.failed_sources.contains(&(target, chunk)) {
            return Err(crate::bulk::missing_source(
                "SourceUnavailable: chunk already failed during this run",
            ));
        }
        eprintln!(
            "Jetstreamer: {} through {} ({})",
            chunk.start,
            chunk.end - 1,
            target.address()
        );
        let fetched = runtime.block_on(coverage::fetch_index(
            &archive.manifest.config.index_base,
            chunk,
        ));
        let (present, index_hash) = match fetched {
            Ok(index) => index,
            Err(error)
                if archive.manifest.history.is_some()
                    && error.downcast_ref::<reqwest::Error>().is_some() =>
            {
                ensure!(
                    archive.failed_sources.len() < 16384,
                    "SourceResourceLimit: failed source chunks"
                );
                archive.failed_sources.push((target, chunk));
                return Err(error.context(crate::bulk::VersionIssue::source(
                    "SourceUnavailable: cannot load independent archive index",
                )));
            }
            Err(error) => {
                return Err(error.context("UnknownCoverage: cannot load independent archive index"));
            }
        };
        let request = Request {
            target,
            range: chunk,
            present,
            index_hash,
        };
        scan_chunk(archive, request)?;
        paths.push(
            archive
                .verified(target, chunk)?
                .context("chunk was not committed")?,
        );
    }
    Ok(paths)
}

fn scan_chunk(archive: &mut Archive, request: Request) -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("rewind-ipc-")
        .tempdir_in("/tmp")?;
    let socket_path = temp.path().join("scan.sock");
    let listener = UnixListener::bind(&socket_path)?;
    listener.set_nonblocking(true)?;
    let config = &archive.manifest.config;
    let mut child = ChildGuard(
        Command::new(std::env::current_exe()?)
            .arg("__scan-worker")
            .arg("--socket")
            .arg(&socket_path)
            .env("JETSTREAMER_HTTP_BASE_URL", &config.car_base)
            .env("JETSTREAMER_COMPACT_INDEX_BASE_URL", &config.index_base)
            .env("JETSTREAMER_NETWORK", "mainnet")
            .env_remove("JETSTREAMER_ARCHIVE_BACKEND")
            .env_remove("JETSTREAMER_FORCE_LEGACY_INDEX")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    let start = Instant::now();
    let mut socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                ensure!(
                    child.0.try_wait()?.is_none(),
                    "WorkerFailed: archive reader exited before connecting"
                );
                ensure!(
                    start.elapsed() < Duration::from_secs(30),
                    "SourceTimeout: child startup"
                );
                ensure!(
                    !CANCELLED.load(Ordering::Relaxed),
                    "Interrupted: recovery cancelled"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    };
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    super::socket_buffers(socket.as_raw_fd())?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request_bytes = archive::encode(&request)?;
    socket.write_all(&(request_bytes.len() as u32).to_le_bytes())?;
    socket.write_all(&request_bytes)?;
    let partial = archive.root.join(format!(
        "{}.partial",
        archive::chunk_stem(request.target, request.range)
    ));
    archive.reset_partial_accounting(&partial)?;
    // A prior interrupted attempt is not a committed chunk. Truncate only this
    // deterministic partial owned by the locked archive.
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&partial)?;
    let mut writer = BufWriter::with_capacity(64 * 1024, file);
    let mut last_progress = Instant::now();
    let mut high_water = None;
    let result: Result<Coverage> = (|| {
        loop {
            let mut header = [0; 4];
            read_interruptible(&mut socket, &mut header, start, last_progress)?;
            let length = u32::from_le_bytes(header) as usize;
            ensure!(
                length > 0 && length <= MAX_FRAME,
                "WorkerProtocol: frame limit"
            );
            let mut bytes = vec![0; length];
            read_interruptible(&mut socket, &mut bytes, start, last_progress)?;
            match archive::decode::<Frame>(&bytes)? {
                Frame::Transaction(record) => {
                    ensure!(
                        record.slot >= request.range.start
                            && record.slot < request.range.end
                            && (record.index as usize) < MAX_TX,
                        "WorkerProtocol: transaction bounds"
                    );
                    let key = (record.slot, record.index);
                    if high_water.is_none_or(|p| key > p) {
                        high_water = Some(key);
                        last_progress = Instant::now();
                    }
                    let size = archive::encode(&record)?.len() as u64 + 4;
                    archive.reserve(size)?;
                    archive::write_record(&mut writer, &record)?;
                }
                Frame::Progress(slot) => {
                    ensure!(
                        slot >= request.range.start && slot < request.range.end,
                        "WorkerProtocol: progress bounds"
                    );
                    let key = (slot, u32::MAX);
                    if high_water.is_none_or(|p| key > p) {
                        high_water = Some(key);
                        last_progress = Instant::now();
                    }
                }
                Frame::Complete(report) => {
                    ensure!(
                        report.range == request.range && report.index_hash == request.index_hash,
                        "UnknownCoverage: worker report identity"
                    );
                    let expected: Vec<_> = request
                        .present
                        .iter()
                        .enumerate()
                        .filter(|(_, present)| **present)
                        .map(|(i, _)| request.range.start + i as u64)
                        .collect();
                    ensure!(
                        report.slots.len() == expected.len()
                            && report
                                .slots
                                .iter()
                                .zip(expected)
                                .all(|(slot, expected)| slot.slot == expected
                                    && slot.transactions <= MAX_TX as u64),
                        "UnknownCoverage: worker present slots"
                    );
                    break Ok(report);
                }
                Frame::Error(error) => anyhow::bail!("ArchiveSource: {error}"),
            }
        }
    })();
    if result.is_err() {
        let _ = socket.write_all(&[1]);
        let shutdown = Instant::now();
        while child.0.try_wait()?.is_none() && shutdown.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    let report = result?;
    let exit_deadline = Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        ensure!(
            exit_deadline.elapsed() < Duration::from_secs(5),
            "WorkerFailed: did not exit after completion"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    ensure!(status.success(), "WorkerFailed: archive process {status}");
    drop(writer);
    archive.commit(request.target, request.range, &partial, report)
}

fn read_interruptible(
    socket: &mut UnixStream,
    bytes: &mut [u8],
    start: Instant,
    progress: Instant,
) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        ensure!(
            !CANCELLED.load(Ordering::Relaxed),
            "Interrupted: recovery cancelled"
        );
        ensure!(
            start.elapsed() < Duration::from_secs(1800),
            "SourceTimeout: chunk deadline"
        );
        ensure!(
            progress.elapsed() < Duration::from_secs(120),
            "SourceTimeout: no archive progress"
        );
        match socket.read(&mut bytes[offset..]) {
            Ok(0) => anyhow::bail!("WorkerFailed: premature end of evidence stream"),
            Ok(count) => offset += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
