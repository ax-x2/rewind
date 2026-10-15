use crate::{Result, archive, coverage::Audit, ensure, types::*};
use futures_util::future::BoxFuture;
use jetstreamer_firehose::{
    SharedError,
    firehose::{self, BlockData, TransactionData},
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_message::{VersionedMessage, compiled_instruction::CompiledInstruction};
use std::{
    os::fd::AsRawFd,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::{broadcast, mpsc},
};

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub target: Target,
    pub range: SearchRange,
    pub present: Vec<bool>,
    pub index_hash: String,
}

// Eight queue entries have a fixed small footprint; boxing candidates would add
// an allocation to ownership transfer solely to shrink progress messages.
#[allow(clippy::large_enum_variant)]
enum Event {
    Candidate(TransactionData),
    Progress(u64),
    Fatal(String),
}
type HandlerFuture = BoxFuture<'static, std::result::Result<(), SharedError>>;

/// Three borrowed key slices avoid allocating a concatenated lookup-table key list.
pub struct Accounts<'a> {
    pub static_keys: &'a [Address],
    pub writable: &'a [Address],
    pub readonly: &'a [Address],
}

impl Accounts<'_> {
    pub fn get(&self, index: u8) -> Result<&Address> {
        let mut index = index as usize;
        for slice in [self.static_keys, self.writable, self.readonly] {
            if index < slice.len() {
                return Ok(&slice[index]);
            }
            index -= slice.len();
        }
        anyhow::bail!("MalformedInstruction: historical account index");
    }

    pub fn candidate(
        &self,
        ix: &CompiledInstruction,
        target: Address,
        data: Option<Address>,
    ) -> Result<bool> {
        let id = *self.get(ix.program_id_index)?;
        // Validate indexes even for rejected instructions. A malformed message must
        // not make a target operation disappear from a supposedly complete scan.
        let mut matched = false;
        for account in &ix.accounts {
            let key = self.get(*account)?;
            matched |= *key == target || data == Some(*key);
        }
        Ok(matched && (managed_loader(id) || id == SYSTEM))
    }
}

pub fn is_candidate(tx: &TransactionData, target: Address, data: Option<Address>) -> Result<bool> {
    let message = &tx.transaction.message;
    let meta = &tx.transaction_status_meta;
    let keys = Accounts {
        static_keys: message.static_account_keys(),
        writable: &meta.loaded_addresses.writable,
        readonly: &meta.loaded_addresses.readonly,
    };
    ensure!(
        keys.static_keys.len() + keys.writable.len() + keys.readonly.len() <= 256,
        "SourceResourceLimit: account keys"
    );
    ensure!(
        message.instructions().len() <= 256,
        "SourceResourceLimit: outer instructions"
    );
    let mut candidate = false;
    for ix in message.instructions() {
        if meta.inner_instructions.is_none() {
            let id = *keys.get(ix.program_id_index)?;
            let mentions_target = ix.accounts.iter().any(|index| {
                keys.get(*index)
                    .is_ok_and(|key| *key == target || data == Some(*key))
            });
            ensure!(
                !mentions_target || managed_loader(id) || id == SYSTEM,
                "AmbiguousExecution: target referenced by a program without inner-instruction metadata"
            );
        }
        candidate |= keys.candidate(ix, target, data)?;
    }
    let mut count = 0usize;
    if let Some(groups) = &meta.inner_instructions {
        for group in groups {
            ensure!(
                (group.index as usize) < message.instructions().len(),
                "MalformedInstruction: inner group index"
            );
            count += group.instructions.len();
            ensure!(count <= 8192, "SourceResourceLimit: inner instructions");
            for inner in &group.instructions {
                candidate |= keys.candidate(&inner.instruction, target, data)?;
            }
        }
    }
    Ok(candidate)
}

fn retained_bytes(tx: &TransactionData) -> usize {
    let instruction_bytes = |instructions: &[CompiledInstruction]| {
        std::mem::size_of_val(instructions)
            + instructions
                .iter()
                .map(|i| i.data.capacity() + i.accounts.capacity())
                .sum::<usize>()
    };
    let (keys, instructions, lookups) = match &tx.transaction.message {
        VersionedMessage::Legacy(m) => (m.account_keys.capacity(), m.instructions.capacity(), 0),
        VersionedMessage::V0(m) => (
            m.account_keys.capacity(),
            m.instructions.capacity(),
            m.address_table_lookups.capacity()
                * std::mem::size_of::<solana_message::v0::MessageAddressTableLookup>()
                + m.address_table_lookups
                    .iter()
                    .map(|l| l.writable_indexes.capacity() + l.readonly_indexes.capacity())
                    .sum::<usize>(),
        ),
        VersionedMessage::V1(m) => (m.account_keys.capacity(), m.instructions.capacity(), 0),
    };
    let meta = &tx.transaction_status_meta;
    let mut size = std::mem::size_of::<TransactionData>()
        + keys * 32
        + instructions * std::mem::size_of::<CompiledInstruction>()
        + lookups
        + tx.transaction.signatures.capacity() * 64;
    size += instruction_bytes(tx.transaction.message.instructions());
    size += (meta.loaded_addresses.writable.capacity() + meta.loaded_addresses.readonly.capacity())
        * 32;
    if let Some(groups) = &meta.inner_instructions {
        size +=
            groups.capacity() * std::mem::size_of::<solana_transaction_status::InnerInstructions>();
        for group in groups {
            size += group.instructions.capacity()
                * std::mem::size_of::<solana_transaction_status::InnerInstruction>();
            size += group
                .instructions
                .iter()
                .map(|i| i.instruction.data.capacity() + i.instruction.accounts.capacity())
                .sum::<usize>();
        }
    }
    if let Some(logs) = &meta.log_messages {
        size += logs.capacity() * std::mem::size_of::<String>()
            + logs.iter().map(String::capacity).sum::<usize>();
    }
    size
}

fn strip_unused(tx: &mut TransactionData) {
    let old = std::mem::take(&mut tx.transaction_status_meta);
    tx.transaction_status_meta = solana_transaction_status::TransactionStatusMeta {
        status: old.status,
        inner_instructions: old.inner_instructions,
        log_messages: old.log_messages,
        loaded_addresses: old.loaded_addresses,
        ..Default::default()
    };
}

pub fn snapshot(tx: TransactionData) -> Result<TransactionRecord> {
    let mut keys = tx.transaction.message.static_account_keys().to_vec();
    keys.extend_from_slice(&tx.transaction_status_meta.loaded_addresses.writable);
    keys.extend_from_slice(&tx.transaction_status_meta.loaded_addresses.readonly);
    let mut instructions = Vec::new();
    for (outer, ix) in tx.transaction.message.instructions().iter().enumerate() {
        instructions.push(RawInstruction {
            program: ix.program_id_index,
            accounts: ix.accounts.clone(),
            data: ix.data.clone(),
            outer: outer as u16,
            ordinal: 0,
            depth: Some(1),
        });
        if let Some(groups) = &tx.transaction_status_meta.inner_instructions {
            let mut matching = groups.iter().filter(|g| g.index as usize == outer);
            if let Some(group) = matching.next() {
                ensure!(
                    matching.next().is_none(),
                    "MalformedInstruction: duplicate inner group"
                );
                for (ordinal, inner) in group.instructions.iter().enumerate() {
                    instructions.push(RawInstruction {
                        program: inner.instruction.program_id_index,
                        accounts: inner.instruction.accounts.clone(),
                        data: inner.instruction.data.clone(),
                        outer: outer as u16,
                        ordinal: (ordinal + 1) as u16,
                        depth: inner.stack_height,
                    });
                }
            }
        }
    }
    let record = TransactionRecord {
        slot: tx.slot,
        index: tx.transaction_slot_index as u32,
        signature: tx.signature,
        keys,
        instructions,
        logs: tx.transaction_status_meta.log_messages,
    };
    ensure!(
        archive::record_memory(&record) <= 1024 * 1024,
        "SourceResourceLimit: raw transaction memory"
    );
    Ok(record)
}

async fn send(socket: &mut UnixStream, frame: &Frame) -> Result<()> {
    let bytes = archive::encode(frame)?;
    socket.write_u32_le(bytes.len() as u32).await?;
    socket.write_all(&bytes).await?;
    Ok(())
}

pub fn run(socket: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let limit = libc::rlimit {
            rlim_cur: 4 * 1024 * 1024 * 1024,
            rlim_max: 4 * 1024 * 1024 * 1024,
        };
        // SAFETY: this single-threaded child sets its own resource limit before Tokio starts.
        ensure!(
            unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) } == 0,
            "SourceResourceLimit: cannot establish child address-space limit"
        );
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .thread_stack_size(2 * 1024 * 1024)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut stream = UnixStream::connect(socket).await?;
        super::socket_buffers(stream.as_raw_fd())?;
        let length = stream.read_u32_le().await? as usize;
        ensure!(length <= MAX_FRAME, "WorkerProtocol: request too large");
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await?;
        let request: Request = archive::decode(&bytes)?;
        let result = scan(request, &mut stream).await;
        if let Err(error) = &result {
            let _ = send(&mut stream, &Frame::Error(format!("{error:#}"))).await;
        }
        result
    })
}

async fn scan(request: Request, socket: &mut UnixStream) -> Result<()> {
    let audit = Arc::new(Audit::new(request.range)?);
    {
        let (sender, mut receiver) = mpsc::channel::<Event>(8);
        let (shutdown, shutdown_rx) = broadcast::channel(1);
        let (mut reader, writer) = socket.split();
        // Independent cancellation listener survives SDK retry sleeps.
        let shutdown_on_cancel = shutdown.clone();
        let cancel = async move {
            let mut byte = [0];
            let _ = reader.read(&mut byte).await;
            let _ = shutdown_on_cancel.send(());
        };
        tokio::pin!(cancel);
        let target = request.target.address();
        let data = match request.target {
            Target::Program(p) => Some(programdata(&p)),
            Target::Buffer(_) => None,
        };
        let tx_audit = audit.clone();
        let tx_sender = sender.clone();
        let tx_shutdown = shutdown.clone();
        let on_tx = move |_: usize, mut tx: TransactionData| -> HandlerFuture {
            let audit = tx_audit.clone();
            let sender = tx_sender.clone();
            let shutdown = tx_shutdown.clone();
            Box::pin(async move {
                let result: Result<()> = async {
                    audit.transaction(tx.slot, tx.transaction_slot_index)?;
                    if tx.transaction_status_meta.status.is_err() {
                        return Ok(());
                    }
                    if !is_candidate(&tx, target, data)? {
                        return Ok(());
                    }
                    ensure!(!tx.transaction_status_meta.pre_balances.is_empty() && tx.transaction_status_meta.pre_balances.len() == tx.transaction_status_meta.post_balances.len(), "AmbiguousExecution: candidate execution metadata missing (SDK defaults cannot prove success)");
                    strip_unused(&mut tx);
                    ensure!(
                        retained_bytes(&tx) <= 1024 * 1024,
                        "SourceResourceLimit: retained SDK transaction"
                    );
                    sender
                        .send(Event::Candidate(tx))
                        .await
                        .map_err(|_| anyhow::anyhow!("WorkerProtocol: transport closed"))?;
                    Ok(())
                }
                .await;
                if let Err(error) = &result {
                    audit.fail();
                    let _ = sender.send(Event::Fatal(format!("{error:#}"))).await;
                    let _ = shutdown.send(());
                }
                result.map_err(|e| e.into_boxed_dyn_error())
            })
        };
        let block_audit = audit.clone();
        let block_sender = sender.clone();
        let block_shutdown = shutdown.clone();
        let completed_slots = Arc::new(AtomicU64::new(0));
        let progress_count = completed_slots.clone();
        let on_block = move |_: usize, block: BlockData| -> HandlerFuture {
            let audit = block_audit.clone();
            let sender = block_sender.clone();
            let shutdown = block_shutdown.clone();
            let completed = progress_count.clone();
            Box::pin(async move {
                let result: Result<()> = async {
                    if let BlockData::Block {
                        slot,
                        executed_transaction_count,
                        ..
                    } = block
                    {
                        audit.block(slot, executed_transaction_count)?;
                        completed.fetch_add(1, Ordering::Relaxed);
                        sender
                            .send(Event::Progress(slot))
                            .await
                            .map_err(|_| anyhow::anyhow!("WorkerProtocol: transport closed"))?;
                    }
                    Ok(())
                }
                .await;
                if let Err(error) = &result {
                    audit.fail();
                    let _ = sender.send(Event::Fatal(format!("{error:#}"))).await;
                    let _ = shutdown.send(());
                }
                result.map_err(|e| e.into_boxed_dyn_error())
            })
        };
        let error_audit = audit.clone();
        let error_shutdown = shutdown.clone();
        let errors = Arc::new(AtomicU64::new(0));
        let stalled = Arc::new(AtomicU64::new(0));
        let last_progress = Arc::new(AtomicU64::new(0));
        let error_sender = sender.clone();
        let on_error = move |_: usize, context: firehose::FirehoseErrorContext| -> HandlerFuture {
            let audit = error_audit.clone();
            let shutdown = error_shutdown.clone();
            let errors = errors.clone();
            let stalled = stalled.clone();
            let last_progress = last_progress.clone();
            let completed = completed_slots.clone();
            let sender = error_sender.clone();
            Box::pin(async move {
                let current = completed.load(Ordering::Relaxed);
                let old = last_progress.swap(current, Ordering::Relaxed);
                let without_progress = if old == current {
                    stalled.fetch_add(1, Ordering::Relaxed) + 1
                } else {
                    stalled.store(1, Ordering::Relaxed);
                    1
                };
                if errors.fetch_add(1, Ordering::Relaxed) + 1 >= 16 || without_progress >= 3 {
                    audit.fail();
                    let reason: String = context.error_message.chars().take(4096).collect();
                    let _ = sender
                        .send(Event::Fatal(format!(
                            "SourceRetryLimit at slot {}: {reason}",
                            context.slot
                        )))
                        .await;
                    let _ = shutdown.send(());
                }
                Ok(())
            })
        };
        drop(sender);
        let firehose = firehose::firehose(
            2,
            true,
            false,
            Some(64 * 1024 * 1024),
            request.range.start..request.range.end,
            Some(on_block),
            Some(on_tx),
            None::<firehose::OnEntryFn>,
            None::<firehose::OnRewardFn>,
            Some(on_error),
            None::<firehose::OnStatsTrackingFn>,
            Some(shutdown_rx),
        );
        let transport = async move {
            let mut writer = writer;
            while let Some(event) = receiver.recv().await {
                let frame = match event {
                    Event::Candidate(tx) => Frame::Transaction(snapshot(tx)?),
                    Event::Progress(slot) => Frame::Progress(slot),
                    Event::Fatal(error) => anyhow::bail!("{error}"),
                };
                let bytes = archive::encode(&frame)?;
                writer.write_u32_le(bytes.len() as u32).await?;
                writer.write_all(&bytes).await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::pin!(firehose, transport);
        let results = tokio::select! {
            result = async { tokio::try_join!(async { firehose.as_mut().await.map_err(|(e, slot)| anyhow::anyhow!("ArchiveSource at {slot}: {e}")) }, transport.as_mut()) } => result,
            _ = &mut cancel => anyhow::bail!("Interrupted: worker cancelled"),
        };
        results?;
    }
    let coverage = audit.finish(&request.present, request.index_hash)?;
    send(socket, &Frame::Complete(coverage)).await?;
    Ok(())
}
