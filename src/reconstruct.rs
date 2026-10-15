use crate::{
    Result,
    archive::read_record,
    bail,
    decode::{self, Loader},
    ensure,
    types::*,
};
use std::io::Read;

pub(crate) fn relevant(
    record: &TransactionRecord,
    ix: &RawInstruction,
    target: Target,
) -> Result<bool> {
    let id = record.program(ix)?;
    if !managed_loader(id) && id != SYSTEM {
        return Ok(false);
    }
    Ok(ix.accounts.iter().any(|i| {
        record
            .keys
            .get(*i as usize)
            .is_some_and(|key| target.related(key))
    }))
}

pub(crate) fn committed_candidates(
    record: &TransactionRecord,
    target: Target,
) -> Result<Vec<bool>> {
    let inner = record
        .instructions
        .iter()
        .filter(|ix| ix.ordinal != 0)
        .try_fold(false, |found, ix| {
            Ok::<_, anyhow::Error>(found || relevant(record, ix, target)?)
        })?;
    if inner {
        decode::committed(record)
    } else {
        Ok(vec![true; record.instructions.len()])
    }
}

pub fn discover(
    reader: impl Read,
    program: solana_address::Address,
    signature: Option<solana_signature::Signature>,
) -> Result<Selection> {
    discover_with_policy(reader, program, signature, LoaderPolicy::Auto)
}

pub fn discover_with_policy(
    mut reader: impl Read,
    program: solana_address::Address,
    signature: Option<solana_signature::Signature>,
    policy: LoaderPolicy,
) -> Result<Selection> {
    let mut chosen: Option<Selection> = None;
    let mut matches = 0;
    while let Some(record) = read_record::<TransactionRecord>(&mut reader)? {
        crate::archive::validate_record(&record)?;
        let accepted = committed_candidates(&record, Target::Program(program))?;
        for (ix, committed) in record.instructions.iter().zip(accepted) {
            if !committed || !relevant(&record, ix, Target::Program(program))? {
                continue;
            }
            if let Some(selection) = decode::selection(&record, ix)? {
                if !policy.accepts(selection.loader) {
                    continue;
                }
                if selection.program != program
                    || signature.is_some_and(|s| s != selection.signature)
                {
                    continue;
                }
                matches += 1;
                if chosen
                    .as_ref()
                    .is_none_or(|previous| selection.position > previous.position)
                {
                    chosen = Some(selection);
                }
            }
        }
    }
    ensure!(
        signature.is_none() || matches <= 1,
        "AmbiguousSelection: multiple deployment instructions match signature"
    );
    chosen.ok_or_else(|| {
        anyhow::anyhow!("ProgramVersionNotFoundInRange: no matching deployment or upgrade")
    })
}

/// Bulk discovery is coordinator-only and retains a strictly bounded version list.
pub fn discover_all_with_policy(
    mut reader: impl Read,
    program: solana_address::Address,
    policy: LoaderPolicy,
    limit: usize,
) -> Result<Vec<Selection>> {
    ensure!(
        limit > 0 && limit <= crate::bulk::MAX_VERSIONS,
        "InvalidConfig: version limit"
    );
    let mut versions = Vec::with_capacity(limit);
    while let Some(record) = read_record::<TransactionRecord>(&mut reader)? {
        crate::archive::validate_record(&record)?;
        let accepted = committed_candidates(&record, Target::Program(program))?;
        for (ix, committed) in record.instructions.iter().zip(accepted) {
            if !committed || !relevant(&record, ix, Target::Program(program))? {
                continue;
            }
            if let Some(selection) = decode::selection(&record, ix)?
                && selection.program == program
                && policy.accepts(selection.loader)
            {
                if let Some(previous) = versions.last() {
                    let previous: &Selection = previous;
                    ensure!(
                        selection.position >= previous.position,
                        "CorruptArchive: unordered version discovery"
                    );
                    if selection.position == previous.position {
                        ensure!(
                            &selection == previous,
                            "CorruptArchive: conflicting deployment identity"
                        );
                        continue;
                    }
                }
                ensure!(
                    versions.len() < limit,
                    "SourceResourceLimit: version limit exceeded before export"
                );
                versions.push(selection);
            }
        }
    }
    ensure!(
        !versions.is_empty(),
        "ProgramVersionNotFoundInRange: no matching deployment or upgrade"
    );
    Ok(versions)
}

#[derive(Debug)]
pub struct Reconstruction {
    pub loader: LoaderKind,
    pub baseline_account: solana_address::Address,
    pub bytes: Vec<u8>,
    pub explicitly_written: usize,
    pub created: OrderKey,
    pub initialized: OrderKey,
    pub consumed: Option<OrderKey>,
    pub buffer: solana_address::Address,
}

/// The copy itself neither allocates nor locks. Overlap implements last committed write wins.
pub fn apply_write(
    payload: &mut [u8],
    coverage: &mut [u8],
    offset: usize,
    bytes: &[u8],
) -> Result<()> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or_else(|| anyhow::anyhow!("WriteOutOfBounds: overflow"))?;
    ensure!(
        end <= payload.len() && coverage.len() == payload.len().div_ceil(8),
        "WriteOutOfBounds: exceeds buffer allocation"
    );
    payload[offset..end].copy_from_slice(bytes);
    for position in offset..end {
        coverage[position / 8] |= 1 << (position % 8);
    }
    Ok(())
}

pub fn reconstruct(
    mut reader: impl Read,
    buffer: solana_address::Address,
    selection: Option<&Selection>,
) -> Result<Reconstruction> {
    let mut payload: Option<Vec<u8>> = None;
    let mut written = Vec::new();
    let mut created = None;
    let mut initialized = None;
    let mut consumed = None;
    let mut tainted = true;
    let mut found_selection = false;
    while let Some(record) = read_record::<TransactionRecord>(&mut reader)? {
        crate::archive::validate_record(&record)?;
        let accepted = committed_candidates(&record, Target::Buffer(buffer))?;
        for (ix, committed) in record.instructions.iter().zip(accepted) {
            let position = record.key(ix);
            if selection.is_some_and(|s| position > s.position) {
                continue;
            }
            if !committed || !relevant(&record, ix, Target::Buffer(buffer))? {
                continue;
            }
            let id = record.program(ix)?;
            if id == SYSTEM {
                // Transfer instructions never modify account data, regardless of role.
                let code = decode::tag(&ix.data)?;
                if code == 2 || code == 11 {
                    continue;
                }
                let destination = if code == 0 || code == 3 || code == 13 {
                    1
                } else {
                    0
                };
                if record.account(ix, destination)? != buffer {
                    continue;
                }
                let Some((size, owner)) = decode::system_creation(&ix.data)? else {
                    continue;
                };
                ensure!(
                    owner == LOADER,
                    "UnsupportedMutation: buffer creation owner is not loader-v3"
                );
                let header = solana_loader_v3_interface::state::UpgradeableLoaderState::size_of_buffer_metadata();
                ensure!(
                    size > header && size - header <= MAX_PAYLOAD,
                    "SourceResourceLimit: buffer allocation size"
                );
                payload = Some(vec![0; size - header]);
                written = vec![0; (size - header).div_ceil(8)];
                created = Some(position);
                initialized = None;
                consumed = None;
                tainted = false;
                continue;
            }
            ensure!(
                id == LOADER,
                "UnsupportedMutation: mixed loader history in v3 payload replay"
            );
            match decode::loader(&ix.data)? {
                Loader::Initialize if record.account(ix, 0)? == buffer => {
                    ensure!(
                        initialized.is_none() || consumed.is_some(),
                        "CorruptArchive: repeated buffer initialization without recreation"
                    );
                    if consumed.is_some() {
                        tainted = true;
                    }
                    initialized = Some(position);
                    consumed = None;
                }
                Loader::Write { offset, bytes } if record.account(ix, 0)? == buffer => {
                    if initialized.is_none() || consumed.is_some() || payload.is_none() {
                        tainted = true;
                        continue;
                    }
                    apply_write(
                        payload.as_mut().expect("checked payload"),
                        &mut written,
                        offset,
                        bytes,
                    )?;
                }
                Loader::Deploy { .. } | Loader::Upgrade => {
                    if let Some(event) =
                        decode::selection(&record, ix)?.filter(|s| s.buffer == buffer)
                    {
                        ensure!(
                            consumed.is_none(),
                            "CorruptArchive: consumed buffer reused without recreation"
                        );
                        consumed = Some(position);
                        if let Some(expected) = selection.filter(|s| s.position == position) {
                            ensure!(
                                &event == expected,
                                "CorruptArchive: deployment evidence mismatch"
                            );
                            if let Some(capacity) = event.capacity {
                                ensure!(
                                    payload.as_ref().is_none_or(|p| p.len() as u64 <= capacity),
                                    "CorruptArchive: deployment capacity below upload size"
                                );
                            }
                            found_selection = true;
                        }
                    }
                }
                Loader::Close if record.account(ix, 0)? == buffer => {
                    consumed = Some(position);
                }
                Loader::Extend if record.account(ix, 0)? == buffer => {
                    bail!("UnsupportedMutation: ExtendProgram on buffer")
                }
                _ => {}
            }
        }
    }
    ensure!(
        selection.is_none() || found_selection,
        "IncompleteHistory: selected deployment not present in buffer evidence"
    );
    if tainted || payload.is_none() || created.is_none() || initialized.is_none() {
        return Err(crate::bulk::missing_baseline(
            "HistoryOutsideSearchRange: creation and initialization baseline missing; extend the lower search bound",
        ));
    }
    let explicitly_written = written.iter().map(|b| b.count_ones() as usize).sum();
    Ok(Reconstruction {
        loader: LoaderKind::V3,
        baseline_account: buffer,
        bytes: payload.expect("validated payload"),
        explicitly_written,
        created: created.expect("validated creation"),
        initialized: initialized.expect("validated initialization"),
        consumed,
        buffer,
    })
}
