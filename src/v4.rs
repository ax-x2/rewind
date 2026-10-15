//! CoreBPF loader-v4 replay. Snapshot recursion and resizing are cold-path work;
//! wire decoding and applying writes borrow slices without allocation.
use crate::{
    Result,
    archive::{self, Archive},
    decode::{self, V4},
    ensure, history,
    reconstruct::{self, Reconstruction},
    types::*,
};
use anyhow::Context;
use solana_address::Address;
use std::{
    cell::Cell,
    fs::File,
    io::{BufReader, Read},
    rc::Rc,
};

pub const MAX_IMAGE_MEMORY: usize = 64 * 1024 * 1024;
pub const MAX_SOURCE_DEPTH: usize = 16;
pub const MAX_SOURCE_REQUESTS: usize = 64;
const MAX_OPERATIONS: usize = 1_000_000;

pub fn detect(mut reader: impl Read, account: Address) -> Result<LoaderKind> {
    let mut kind = None;
    while let Some(record) = archive::read_record::<TransactionRecord>(&mut reader)? {
        archive::validate_record(&record)?;
        let accepted = reconstruct::committed_candidates(&record, Target::Buffer(account))?;
        for (ix, committed) in record.instructions.iter().zip(accepted) {
            if !committed || !reconstruct::relevant(&record, ix, Target::Buffer(account))? {
                continue;
            }
            let id = record.program(ix)?;
            ensure!(
                id != NATIVE_V4,
                "UnsupportedLoader: native LoaderV4 is not the supplied CoreBPF v4 format"
            );
            if id == SYSTEM {
                if matches!(decode::tag(&ix.data)?, 0 | 3) && record.account(ix, 1)? == account {
                    let (_, owner) = decode::system_creation(&ix.data)?
                        .context("MalformedInstruction: missing creation")?;
                    kind = match owner {
                        LOADER => Some(LoaderKind::V3),
                        LOADER_V4 => Some(LoaderKind::V4),
                        _ => None,
                    };
                }
            } else if id == LOADER_V4 {
                let instruction = decode::v4(&ix.data)?;
                if record.account(ix, 0)? == account
                    || (instruction == V4::Deploy
                        && decode::v4_source(&record, ix)? == Some(account))
                {
                    kind = Some(LoaderKind::V4);
                }
            } else if id == LOADER {
                let role = match decode::loader(&ix.data)? {
                    decode::Loader::Deploy { .. } => 3,
                    decode::Loader::Upgrade => 2,
                    _ => 0,
                };
                if record.account(ix, role)? == account {
                    kind = Some(LoaderKind::V3);
                }
            }
        }
    }
    kind.context(
        "HistoryOutsideSearchRange: no supported loader management history for this account",
    )
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn aggregate_image_budget_reserves_before_allocating_and_releases_on_drop() {
        let budget = Rc::new(Budget::default());
        let image = Image::zeroed(8, &budget).unwrap();
        assert_eq!(budget.0.get(), 9);
        let next = image.resized(16, &budget).unwrap();
        assert_eq!(budget.0.get(), 27);
        drop(image);
        assert_eq!(budget.0.get(), 18);
        drop(next);
        assert_eq!(budget.0.get(), 0);
        budget.0.set(MAX_IMAGE_MEMORY);
        assert!(Image::zeroed(1, &budget).is_err());
        assert_eq!(budget.0.get(), MAX_IMAGE_MEMORY);
    }
}

#[derive(Default)]
struct Budget(Cell<usize>);

struct Reservation {
    budget: Rc<Budget>,
    bytes: usize,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.0.set(self.budget.0.get() - self.bytes);
    }
}

struct Image {
    bytes: Vec<u8>,
    written: Vec<u8>,
    _memory: Reservation,
}
impl Image {
    fn zeroed(size: usize, budget: &Rc<Budget>) -> Result<Self> {
        ensure!(
            size > 0 && size <= MAX_PAYLOAD,
            "SourceResourceLimit: v4 payload size"
        );
        let memory = size + size.div_ceil(8);
        ensure!(
            budget.0.get().saturating_add(memory) <= MAX_IMAGE_MEMORY,
            "SourceResourceLimit: aggregate v4 image storage exceeds 64 MiB"
        );
        budget.0.set(budget.0.get() + memory);
        let reservation = Reservation {
            budget: budget.clone(),
            bytes: memory,
        };
        Ok(Self {
            bytes: vec![0; size],
            written: vec![0; size.div_ceil(8)],
            _memory: reservation,
        })
    }

    fn resized(&self, size: usize, budget: &Rc<Budget>) -> Result<Self> {
        let mut next = Self::zeroed(size, budget)?;
        let prefix = self.bytes.len().min(size);
        next.bytes[..prefix].copy_from_slice(&self.bytes[..prefix]);
        let words = self.written.len().min(next.written.len());
        next.written[..words].copy_from_slice(&self.written[..words]);
        if !size.is_multiple_of(8) {
            *next.written.last_mut().expect("nonempty bitmap") &= (1 << (size % 8)) - 1;
        }
        Ok(next)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Status {
    #[default]
    Unknown,
    Retracted,
    Deployed,
    Finalized,
}

#[derive(Default)]
struct State {
    image: Option<Image>,
    origin: Option<Address>,
    created: Option<OrderKey>,
    initialized: Option<OrderKey>,
    zero_at: Option<OrderKey>,
    closed_at: Option<OrderKey>,
    status: Status,
}

impl State {
    fn zero(position: OrderKey) -> Self {
        Self {
            zero_at: Some(position),
            created: Some(position),
            ..Self::default()
        }
    }
    fn close(&mut self, position: OrderKey) {
        self.zero_at = Some(position);
        self.closed_at = Some(position);
        self.status = Status::Unknown;
    }
    fn retracted(&self) -> Result<()> {
        if self.status != Status::Retracted || self.closed_at.is_some() || self.image.is_none() {
            return Err(crate::bulk::missing_baseline(
                "HistoryOutsideSearchRange: v4 operation has no proven retracted payload baseline",
            ));
        }
        Ok(())
    }
}

pub struct Resolver<'a> {
    archive: &'a mut Archive,
    runtime: Option<&'a tokio::runtime::Runtime>,
    budget: Rc<Budget>,
    active: Vec<(Address, OrderKey)>,
    requests: usize,
    operations: usize,
}

impl<'a> Resolver<'a> {
    pub fn new(archive: &'a mut Archive, runtime: Option<&'a tokio::runtime::Runtime>) -> Self {
        Self {
            archive,
            runtime,
            budget: Rc::new(Budget::default()),
            active: Vec::with_capacity(MAX_SOURCE_DEPTH),
            requests: 0,
            operations: 0,
        }
    }

    pub fn reconstruct(mut self) -> Result<Reconstruction> {
        let selection = self.archive.manifest.selection.clone();
        self.reconstruct_selected(selection.as_ref())
    }

    pub fn reconstruct_selection(mut self, selection: &Selection) -> Result<Reconstruction> {
        self.reconstruct_selected(Some(selection))
    }

    fn reconstruct_selected(&mut self, selection: Option<&Selection>) -> Result<Reconstruction> {
        let (account, before) = if let Some(selection) = selection {
            ensure!(
                selection.loader == LoaderKind::V4 && selection.programdata.is_none(),
                "CorruptArchive: invalid v4 selection"
            );
            (selection.buffer, selection.position)
        } else {
            (
                self.archive.manifest.config.target.address(),
                OrderKey {
                    slot: self.archive.manifest.config.range.end,
                    transaction: 0,
                    outer: 0,
                    ordinal: 0,
                },
            )
        };
        let mut state = self.snapshot(account, before)?;
        if selection.is_some() {
            state.retracted()?;
        }
        let image = state.image.take().ok_or_else(|| {
            crate::bulk::missing_baseline(
                "HistoryOutsideSearchRange: missing v4 initialization and payload",
            )
        })?;
        let initialized = state.initialized.ok_or_else(|| {
            crate::bulk::missing_baseline("HistoryOutsideSearchRange: missing initial v4 Truncate")
        })?;
        let created = state.created.ok_or_else(|| {
            crate::bulk::missing_baseline(
                "HistoryOutsideSearchRange: missing zero-size creation/reset",
            )
        })?;
        let consumed = selection
            .as_ref()
            .and_then(|s| (s.buffer != s.program).then_some(s.position))
            .or(state.closed_at);
        Ok(Reconstruction {
            loader: LoaderKind::V4,
            baseline_account: state.origin.ok_or_else(|| {
                crate::bulk::missing_baseline(
                    "HistoryOutsideSearchRange: missing v4 payload origin",
                )
            })?,
            explicitly_written: image.written.iter().map(|b| b.count_ones() as usize).sum(),
            bytes: image.bytes,
            created,
            initialized,
            consumed,
            buffer: account,
        })
    }

    fn snapshot(&mut self, account: Address, before: OrderKey) -> Result<State> {
        ensure!(
            self.active.len() < MAX_SOURCE_DEPTH,
            "SourceResourceLimit: v4 source dependency depth exceeds 16"
        );
        ensure!(
            self.requests < MAX_SOURCE_REQUESTS,
            "SourceResourceLimit: v4 source snapshot requests exceed 64"
        );
        ensure!(
            !self.active.contains(&(account, before)),
            "CorruptArchive: cyclic v4 source dependency"
        );
        ensure!(
            self.active
                .last()
                .is_none_or(|(_, caller)| before < *caller),
            "CorruptArchive: v4 dependency does not precede its consumer"
        );
        self.requests += 1;
        self.active.push((account, before));
        let range = SearchRange {
            start: self.archive.manifest.config.range.start,
            end: before
                .slot
                .saturating_add(1)
                .min(self.archive.manifest.config.range.end),
        };
        if range.start >= range.end {
            return Err(crate::bulk::missing_baseline(
                "HistoryOutsideSearchRange: v4 source precedes lower search bound",
            ));
        }
        let (target, range) = if self.archive.manifest.config.target == Target::Program(account) {
            // The discovery pass already contains this account's complete history.
            (Target::Program(account), self.archive.manifest.config.range)
        } else {
            (Target::Buffer(account), range)
        };
        let paths = match self.runtime {
            Some(runtime) => history::supervisor::collect(self.archive, runtime, target, range)?,
            None => crate::cli::required_paths(self.archive, target, range)?,
        };
        let sorted = self.archive.sorted(&paths)?;
        let baseline = self.baseline(BufReader::new(sorted.reopen()?), account, before)?;
        let result = self.replay(
            BufReader::new(File::open(sorted.path())?),
            account,
            before,
            baseline,
        );
        self.archive.discard_temporary(sorted)?;
        self.active.pop();
        result
    }

    fn operation(&mut self) -> Result<()> {
        self.operations += 1;
        ensure!(
            self.operations <= MAX_OPERATIONS,
            "SourceResourceLimit: v4 replay operation budget"
        );
        Ok(())
    }

    /// A full source replacement or new incarnation supersedes older byte history.
    /// A close alone still requires the preceding payload for a buffer snapshot.
    fn baseline(
        &mut self,
        mut reader: impl Read,
        account: Address,
        before: OrderKey,
    ) -> Result<Option<OrderKey>> {
        let mut baseline = None;
        let mut zero = None;
        while let Some(record) = archive::read_record::<TransactionRecord>(&mut reader)? {
            archive::validate_record(&record)?;
            if record.slot > before.slot {
                break;
            }
            let accepted = reconstruct::committed_candidates(&record, Target::Buffer(account))?;
            for (ix, committed) in record.instructions.iter().zip(accepted) {
                let position = record.key(ix);
                if !committed
                    || position >= before
                    || !reconstruct::relevant(&record, ix, Target::Buffer(account))?
                {
                    continue;
                }
                self.operation()?;
                let id = record.program(ix)?;
                if id == SYSTEM {
                    if matches!(decode::tag(&ix.data)?, 0 | 3)
                        && record.account(ix, 1)? == account
                        && decode::system_creation(&ix.data)? == Some((0, LOADER_V4))
                    {
                        baseline = Some(position);
                        zero = None;
                    }
                } else if id == LOADER_V4 {
                    let operation = decode::v4(&ix.data)?;
                    if record.account(ix, 0)? == account {
                        match operation {
                            V4::Deploy if decode::v4_source(&record, ix)?.is_some() => {
                                baseline = Some(position);
                                zero = None;
                            }
                            V4::Truncate { size: 0 } => zero = Some(position),
                            V4::Truncate { .. } => {
                                if let Some(reset) = zero.take() {
                                    baseline = Some(reset);
                                }
                            }
                            _ => {}
                        }
                    } else if operation == V4::Deploy
                        && decode::v4_source(&record, ix)? == Some(account)
                    {
                        zero = Some(position);
                    }
                }
            }
        }
        Ok(baseline)
    }

    fn replay(
        &mut self,
        mut reader: impl Read,
        account: Address,
        before: OrderKey,
        baseline: Option<OrderKey>,
    ) -> Result<State> {
        let mut state = State::default();
        while let Some(record) = archive::read_record::<TransactionRecord>(&mut reader)? {
            archive::validate_record(&record)?;
            if record.slot > before.slot {
                break;
            }
            let accepted = reconstruct::committed_candidates(&record, Target::Buffer(account))?;
            for (ix, committed) in record.instructions.iter().zip(accepted) {
                let position = record.key(ix);
                if !committed
                    || position >= before
                    || baseline.is_some_and(|baseline| position < baseline)
                    || !reconstruct::relevant(&record, ix, Target::Buffer(account))?
                {
                    continue;
                }
                self.operation()?;
                let id = record.program(ix)?;
                if id == SYSTEM {
                    let tag = decode::tag(&ix.data)?;
                    if matches!(tag, 2 | 11) {
                        continue;
                    }
                    let destination = if matches!(tag, 0 | 3 | 13) { 1 } else { 0 };
                    if record.account(ix, destination)? != account {
                        continue;
                    }
                    let (size, owner) = decode::system_creation(&ix.data)?
                        .context("MalformedInstruction: missing v4 account creation")?;
                    ensure!(
                        owner == LOADER_V4 && size == 0,
                        "UnsupportedMutation: v4 baseline requires a zero-size CoreBPF-owned creation followed by Truncate"
                    );
                    state = State::zero(position);
                    continue;
                }
                ensure!(
                    id == LOADER_V4,
                    "UnsupportedLoader: v4 payload history contains another loader"
                );
                let operation = decode::v4(&ix.data)?;
                record.account(ix, 1)?;
                if record.account(ix, 0)? != account {
                    if operation == V4::Deploy && decode::v4_source(&record, ix)? == Some(account) {
                        state.close(position);
                    }
                    continue;
                }
                match operation {
                    V4::Write { offset, bytes } => {
                        state.retracted()?;
                        let image = state.image.as_mut().expect("validated image");
                        reconstruct::apply_write(
                            &mut image.bytes,
                            &mut image.written,
                            offset,
                            bytes,
                        )?;
                    }
                    V4::Truncate { size: 0 } => {
                        ensure!(
                            matches!(state.status, Status::Unknown | Status::Retracted),
                            "CorruptArchive: truncate on deployed/finalized v4 account"
                        );
                        state.close(position);
                    }
                    V4::Truncate { size } => {
                        if state.image.is_none() || state.closed_at.is_some() {
                            let zero = state.zero_at.ok_or_else(|| crate::bulk::missing_baseline("HistoryOutsideSearchRange: initial v4 Truncate has no proven zero-size baseline"))?;
                            state.image = Some(Image::zeroed(size, &self.budget)?);
                            state.origin = Some(account);
                            state.created = Some(zero);
                            state.initialized = Some(position);
                            state.closed_at = None;
                            state.status = Status::Retracted;
                        } else {
                            state.retracted()?;
                            let image = state.image.as_ref().expect("validated image");
                            if size != image.bytes.len() {
                                state.image = Some(image.resized(size, &self.budget)?);
                            }
                        }
                    }
                    V4::Deploy => {
                        if let Some(source) = decode::v4_source(&record, ix)? {
                            ensure!(
                                source != account && state.status != Status::Finalized,
                                "CorruptArchive: invalid v4 deployment source/status"
                            );
                            let mut replacement = self.snapshot(source, position)?;
                            replacement.retracted()?;
                            state.image = replacement.image.take();
                            state.origin = replacement.origin;
                            state.created = replacement.created;
                            state.initialized = replacement.initialized;
                            state.closed_at = None;
                            state.zero_at = None;
                        } else {
                            state.retracted()?;
                        }
                        state.status = Status::Deployed;
                    }
                    V4::Retract => {
                        if state.status != Status::Deployed || state.image.is_none() {
                            return Err(crate::bulk::missing_baseline(
                                "HistoryOutsideSearchRange: v4 Retract has no proven deployment history",
                            ));
                        }
                        state.status = Status::Retracted;
                    }
                    V4::Authority => {
                        record.account(ix, 2)?;
                        ensure!(
                            state.status != Status::Finalized,
                            "CorruptArchive: authority transfer on finalized v4 account"
                        );
                    }
                    V4::Finalize => {
                        record.account(ix, 2)?;
                        if state.status != Status::Deployed {
                            return Err(crate::bulk::missing_baseline(
                                "HistoryOutsideSearchRange: v4 Finalize has no proven deployment",
                            ));
                        }
                        state.status = Status::Finalized;
                    }
                }
            }
        }
        if state.image.is_none() {
            return Err(crate::bulk::missing_baseline(
                "HistoryOutsideSearchRange: v4 payload creation/initialization is missing",
            ));
        }
        Ok(state)
    }
}
