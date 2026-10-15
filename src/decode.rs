//! Borrowed decoding is allocation-free; execution proof is a bounded cold-path operation.
use crate::{Result, bail, ensure, types::*};
use solana_address::Address;

#[derive(Debug, PartialEq, Eq)]
pub enum Loader<'a> {
    Initialize,
    Write { offset: usize, bytes: &'a [u8] },
    Deploy { capacity: u64 },
    Upgrade,
    Authority,
    Close,
    Extend,
}

pub fn tag(data: &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data.get(..4)
            .ok_or_else(|| anyhow::anyhow!("MalformedInstruction: missing discriminator"))?
            .try_into()?,
    ))
}

fn u64_at(data: &[u8], start: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        data.get(start..start + 8)
            .ok_or_else(|| anyhow::anyhow!("MalformedInstruction: truncated scalar"))?
            .try_into()?,
    ))
}

pub fn loader(data: &[u8]) -> Result<Loader<'_>> {
    let code = tag(data)?;
    let expected = match code {
        0 | 3 | 4 | 5 | 7 => 4,
        2 => 12,
        6 => 8,
        1 => {
            let len = usize::try_from(u64_at(data, 8)?)?;
            let end = 16usize
                .checked_add(len)
                .ok_or_else(|| anyhow::anyhow!("MalformedInstruction: write length overflow"))?;
            ensure!(
                end == data.len(),
                "MalformedInstruction: write length mismatch"
            );
            let offset = u32::from_le_bytes(data[4..8].try_into()?) as usize;
            return Ok(Loader::Write {
                offset,
                bytes: &data[16..],
            });
        }
        _ => bail!("UnsupportedMutation: loader instruction {code}"),
    };
    ensure!(
        data.len() == expected,
        "MalformedInstruction: loader length mismatch"
    );
    Ok(match code {
        0 => Loader::Initialize,
        2 => Loader::Deploy {
            capacity: u64_at(data, 4)?,
        },
        3 => Loader::Upgrade,
        4 | 7 => Loader::Authority,
        5 => Loader::Close,
        6 => Loader::Extend,
        _ => unreachable!(),
    })
}

/// Returns a known-zero new account's payload size, or None for a lamport-only transfer.
pub fn system_creation(data: &[u8]) -> Result<Option<(usize, Address)>> {
    let (space_at, owner_at, end) = match tag(data)? {
        0 => (12, 20, 52),
        3 => {
            let seed_len = usize::try_from(u64_at(data, 36)?)?;
            ensure!(seed_len <= 32, "MalformedInstruction: seed too long");
            let start = 44 + seed_len;
            (start + 8, start + 16, start + 48)
        }
        2 => {
            ensure!(data.len() == 12, "MalformedInstruction: transfer length");
            return Ok(None);
        }
        11 => return Ok(None), // TransferWithSeed cannot change account bytes.
        code => bail!("UnsupportedMutation: System instruction {code}"),
    };
    ensure!(
        data.len() == end,
        "MalformedInstruction: System creation length"
    );
    Ok(Some((
        usize::try_from(u64_at(data, space_at)?)?,
        Address::new_from_array(data[owner_at..owner_at + 32].try_into()?),
    )))
}

/// Resolve successful invocation ancestry for recorded inner instructions.
/// Exact runtime prefixes exclude user-controlled `Program log:` output.
pub fn committed(record: &TransactionRecord) -> Result<Vec<bool>> {
    let mut accepted = vec![true; record.instructions.len()];
    if !record.instructions.iter().any(|i| i.ordinal != 0) {
        return Ok(accepted);
    }
    #[derive(Debug)]
    struct Invocation {
        id: Address,
        depth: u32,
        parent: Option<usize>,
        ok: Option<bool>,
    }
    let logs = record
        .logs
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("AmbiguousExecution: inner instructions have no logs"))?;
    let mut invocations: Vec<Invocation> = Vec::with_capacity(record.instructions.len());
    let mut stack: Vec<usize> = Vec::with_capacity(8);
    for line in logs {
        let Some(rest) = line.strip_prefix("Program ") else {
            continue;
        };
        let Some((address, action)) = rest.split_once(' ') else {
            continue;
        };
        if let Some(depth) = action
            .strip_prefix("invoke [")
            .and_then(|s| s.strip_suffix(']'))
        {
            let depth: u32 = depth.parse()?;
            ensure!(
                depth as usize == stack.len() + 1 && depth <= 64,
                "AmbiguousExecution: invalid invocation depth"
            );
            ensure!(
                invocations.len() < 8192,
                "SourceResourceLimit: invocation count"
            );
            let id = address.parse()?;
            invocations.push(Invocation {
                id,
                depth,
                parent: stack.last().copied(),
                ok: None,
            });
            stack.push(invocations.len() - 1);
        } else if action == "success" || action.starts_with("failed:") {
            let index = stack
                .pop()
                .ok_or_else(|| anyhow::anyhow!("AmbiguousExecution: unmatched return"))?;
            ensure!(
                invocations[index].id == address.parse::<Address>()?,
                "AmbiguousExecution: return program mismatch"
            );
            invocations[index].ok = Some(action == "success");
        }
    }
    ensure!(stack.is_empty(), "AmbiguousExecution: truncated logs");
    let mut cursor = 0;
    for (i, ix) in record.instructions.iter().enumerate() {
        let program = record.program(ix)?;
        if ix.ordinal == 0 {
            // Builtins/precompiles may have no invocation logs. Only skip a top-level
            // instruction when it has no recorded inner instructions.
            if invocations
                .get(cursor)
                .is_some_and(|v| v.depth == 1 && v.id == program)
            {
                cursor += 1;
            } else {
                ensure!(
                    !record
                        .instructions
                        .get(i + 1)
                        .is_some_and(|v| v.outer == ix.outer),
                    "AmbiguousExecution: missing outer invocation"
                );
            }
        } else {
            let node = invocations
                .get(cursor)
                .ok_or_else(|| anyhow::anyhow!("AmbiguousExecution: missing inner invocation"))?;
            ensure!(
                node.id == program && Some(node.depth) == ix.depth && node.depth > 1,
                "AmbiguousExecution: inner trace mismatch"
            );
            let mut ancestor = Some(cursor);
            while let Some(index) = ancestor {
                accepted[i] &= invocations[index].ok == Some(true);
                ancestor = invocations[index].parent;
            }
            cursor += 1;
        }
    }
    ensure!(
        cursor == invocations.len(),
        "AmbiguousExecution: unaccounted invocation logs"
    );
    Ok(accepted)
}

pub fn selection(record: &TransactionRecord, ix: &RawInstruction) -> Result<Option<Selection>> {
    let id = record.program(ix)?;
    ensure!(
        id != NATIVE_V4,
        "UnsupportedLoader: native LoaderV4 has a different wire format from CoreBPF loader-v4"
    );
    if id == LOADER_V4 {
        if v4(&ix.data)? != V4::Deploy {
            return Ok(None);
        }
        record.account(ix, 1)?;
        let program = record.account(ix, 0)?;
        let source = v4_source(record, ix)?.unwrap_or(program);
        ensure!(
            ix.accounts.get(2).is_none() || record.account(ix, 2)? != program,
            "MalformedInstruction: v4 deploy source aliases destination"
        );
        return Ok(Some(Selection {
            loader: LoaderKind::V4,
            program,
            programdata: None,
            buffer: source,
            position: record.key(ix),
            signature: record.signature,
            capacity: None,
        }));
    }
    if id != LOADER {
        return Ok(None);
    }
    let (program_role, buffer_role, data_role, capacity) = match loader(&ix.data)? {
        Loader::Deploy { capacity } => (2, 3, 1, Some(capacity)),
        Loader::Upgrade => (1, 2, 0, None),
        _ => return Ok(None),
    };
    let program = record.account(ix, program_role)?;
    let data = record.account(ix, data_role)?;
    ensure!(
        data == programdata(&program),
        "MalformedInstruction: ProgramData derivation mismatch"
    );
    Ok(Some(Selection {
        loader: LoaderKind::V3,
        program,
        programdata: Some(data),
        buffer: record.account(ix, buffer_role)?,
        position: record.key(ix),
        signature: record.signature,
        capacity,
    }))
}

#[derive(Debug, PartialEq, Eq)]
pub enum V4<'a> {
    Write { offset: usize, bytes: &'a [u8] },
    Truncate { size: usize },
    Deploy,
    Retract,
    Authority,
    Finalize,
}

pub fn v4(data: &[u8]) -> Result<V4<'_>> {
    let tag = *data
        .first()
        .ok_or_else(|| anyhow::anyhow!("MalformedInstruction: missing v4 discriminator"))?;
    let scalar = |start: usize| -> Result<u32> {
        Ok(u32::from_le_bytes(
            data.get(start..start + 4)
                .ok_or_else(|| anyhow::anyhow!("MalformedInstruction: truncated v4 scalar"))?
                .try_into()?,
        ))
    };
    match tag {
        0 => {
            let offset = scalar(1)? as usize;
            let len = scalar(5)? as usize;
            ensure!(
                9usize.checked_add(len) == Some(data.len()),
                "MalformedInstruction: v4 write length mismatch"
            );
            Ok(V4::Write {
                offset,
                bytes: &data[9..],
            })
        }
        1 => {
            ensure!(data.len() == 5, "MalformedInstruction: v4 truncate length");
            Ok(V4::Truncate {
                size: scalar(1)? as usize,
            })
        }
        2..=5 => {
            ensure!(
                data.len() == 1,
                "MalformedInstruction: v4 instruction length"
            );
            Ok(match tag {
                2 => V4::Deploy,
                3 => V4::Retract,
                4 => V4::Authority,
                5 => V4::Finalize,
                _ => unreachable!(),
            })
        }
        _ => bail!("UnsupportedMutation: CoreBPF v4 instruction {tag}"),
    }
}

pub fn v4_source(record: &TransactionRecord, ix: &RawInstruction) -> Result<Option<Address>> {
    if ix.accounts.len() < 3 {
        return Ok(None);
    }
    Ok(Some(record.account(ix, 2)?).filter(|source| *source != LOADER_V4))
}
