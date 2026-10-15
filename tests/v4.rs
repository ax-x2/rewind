mod common;
use common::*;
use rewind::{
    archive::{self, Archive},
    coverage::hash,
    decode::{self, V4},
    reconstruct,
    types::*,
    v4,
};
use solana_address::Address;
use solana_loader_v4_program_client::instructions::*;
use std::path::Path;

fn archive_records(
    root: &Path,
    records: &[TransactionRecord],
    accounts: &[Address],
    buffer_mode: bool,
) -> Archive {
    let mut config = config();
    config.range.end = records.iter().map(|r| r.slot + 1).max().unwrap();
    if buffer_mode {
        config.target = Target::Buffer(program());
    }
    let mut archive = Archive::open(root, config.clone(), false).unwrap();
    let mut requests = vec![(config.target, config.range)];
    for account in accounts {
        requests.push((Target::Buffer(*account), config.range));
    }
    for (target, range) in requests {
        if archive.verified(target, range).unwrap().is_some() {
            continue;
        }
        let bytes = stream(
            &records
                .iter()
                .filter(|r| r.slot >= range.start && r.slot < range.end)
                .cloned()
                .collect::<Vec<_>>(),
        );
        let partial = root.join("test.partial");
        archive.reserve(bytes.len() as u64).unwrap();
        std::fs::write(&partial, &bytes).unwrap();
        let slots = (range.start..range.end)
            .map(|slot| SlotCoverage {
                slot,
                transactions: records.iter().filter(|r| r.slot == slot).count() as u64,
            })
            .collect();
        archive
            .commit(
                target,
                range,
                &partial,
                Coverage {
                    range,
                    index_hash: hash(b"fixture index"),
                    slots,
                },
            )
            .unwrap();
    }
    if !buffer_mode {
        archive.manifest.selection =
            Some(reconstruct::discover(stream(records).as_slice(), program(), None).unwrap());
    }
    archive
}

#[test]
fn all_generated_wire_encodings_and_optional_source_are_distinct() {
    let authority = Address::new_from_array([2; 32]);
    let write = v4_write(program(), 17, vec![1, 2, 3]);
    assert_eq!(write.program_id, LOADER_V4);
    assert_eq!(
        decode::v4(&write.data).unwrap(),
        V4::Write {
            offset: 17,
            bytes: &[1, 2, 3]
        }
    );
    assert!(decode::v4(&write.data[..write.data.len() - 1]).is_err());
    let truncate = Truncate {
        program: program(),
        authority,
        destination: None,
    }
    .instruction(TruncateInstructionArgs { new_size: 123 });
    assert_eq!(
        decode::v4(&truncate.data).unwrap(),
        V4::Truncate { size: 123 }
    );
    for (instruction, expected) in [
        (v4_deploy(program(), None), V4::Deploy),
        (
            Retract {
                program: program(),
                authority,
            }
            .instruction(),
            V4::Retract,
        ),
        (
            TransferAuthority {
                program: program(),
                current_authority: authority,
                new_authority: buffer(),
            }
            .instruction(),
            V4::Authority,
        ),
        (
            Finalize {
                program: program(),
                authority,
                next_version: program(),
            }
            .instruction(),
            V4::Finalize,
        ),
    ] {
        assert_eq!(decode::v4(&instruction.data).unwrap(), expected);
        let mut extra = instruction.data;
        extra.push(0);
        assert!(decode::v4(&extra).is_err());
    }
    let mut record = from_instructions(432001, 0, 1, vec![v4_deploy(program(), None)]);
    assert_eq!(
        decode::v4_source(&record, &record.instructions[0]).unwrap(),
        None
    );
    record.instructions[0].accounts.truncate(2);
    let selection = decode::selection(&record, &record.instructions[0])
        .unwrap()
        .unwrap();
    assert_eq!(selection.loader, LoaderKind::V4);
    assert_eq!(selection.buffer, program());
    assert_eq!(selection.programdata, None);
    assert!(decode::v4(&[]).is_err());
    assert!(decode::v4(&[6]).is_err());
    let mut native = from_instructions(432001, 0, 1, vec![v4_deploy(program(), None)]);
    let index = native.instructions[0].program as usize;
    native.keys[index] = NATIVE_V4;
    assert!(
        decode::selection(&native, &native.instructions[0])
            .unwrap_err()
            .to_string()
            .contains("UnsupportedLoader")
    );
}

#[test]
fn direct_and_separate_source_payloads_recover_without_header_guessing() {
    for source in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let records = v4_dataset(source);
        let mut archive = archive_records(
            &temp.path().join("archive"),
            &records,
            &[program(), buffer()],
            false,
        );
        let result = v4::Resolver::new(&mut archive, None).reconstruct().unwrap();
        assert_eq!(result.bytes, elf());
        assert_eq!(result.loader, LoaderKind::V4);
        assert_eq!(
            result.baseline_account,
            if source { buffer() } else { program() }
        );
        assert_eq!(result.explicitly_written, 184);
    }
}

#[test]
fn source_chain_then_in_place_redeployment_preserves_payload_origin() {
    let third = Address::new_from_array([7; 32]);
    let mut records = v4_dataset(true);
    // The first upload was to a third account. Deploy it to the intermediate
    // buffer, retract that buffer, then deploy from it to the target program.
    records[0] = from_instructions(
        432001,
        0,
        11,
        [
            v4_create(third, 184),
            v4_create(buffer(), 184),
            v4_create(program(), 184),
        ]
        .concat(),
    );
    records[1] = from_instructions(432002, 0, 12, vec![v4_write(third, 0, elf())]);
    records.remove(2);
    let authority = Address::new_from_array([2; 32]);
    records[2] = from_instructions(
        432003,
        0,
        14,
        vec![
            v4_deploy(buffer(), Some(third)),
            Retract {
                program: buffer(),
                authority,
            }
            .instruction(),
        ],
    );
    records.push(from_instructions(
        432004,
        0,
        15,
        vec![
            v4_deploy(program(), Some(buffer())),
            Retract {
                program: program(),
                authority,
            }
            .instruction(),
        ],
    ));
    records.push(from_instructions(
        432005,
        0,
        16,
        vec![v4_deploy(program(), None)],
    ));
    let temp = tempfile::tempdir().unwrap();
    let mut archive = archive_records(
        &temp.path().join("archive"),
        &records,
        &[third, buffer(), program()],
        false,
    );
    let result = v4::Resolver::new(&mut archive, None).reconstruct().unwrap();
    assert_eq!(result.bytes, elf());
    assert_eq!(result.baseline_account, third);
    let a = archive::chunk_stem(Target::Buffer(third), archive.manifest.config.range);
    let b = archive::chunk_stem(Target::Buffer(buffer()), archive.manifest.config.range);
    assert_ne!(a, b);
    assert!(archive.root.join(format!("{a}.raw")).exists());
    assert!(archive.root.join(format!("{b}.raw")).exists());
}

#[test]
fn shrink_regrow_clears_discarded_bytes_and_written_bits() {
    let mut records = v4_dataset(false);
    records.pop();
    let authority = Address::new_from_array([2; 32]);
    records.push(from_instructions(
        432003,
        0,
        14,
        vec![
            Truncate {
                program: program(),
                authority,
                destination: None,
            }
            .instruction(TruncateInstructionArgs { new_size: 91 }),
            Truncate {
                program: program(),
                authority,
                destination: None,
            }
            .instruction(TruncateInstructionArgs { new_size: 200 }),
            v4_deploy(program(), None),
        ],
    ));
    let temp = tempfile::tempdir().unwrap();
    let mut archive = archive_records(&temp.path().join("archive"), &records, &[program()], false);
    let result = v4::Resolver::new(&mut archive, None).reconstruct().unwrap();
    assert_eq!(&result.bytes[..91], &elf()[..91]);
    assert!(result.bytes[91..].iter().all(|b| *b == 0));
    assert_eq!(result.explicitly_written, 91);
}

#[test]
fn zero_size_close_and_recreation_do_not_join_incarnations() {
    let mut records = v4_dataset(false);
    records.pop();
    let authority = Address::new_from_array([2; 32]);
    records.push(from_instructions(
        432003,
        0,
        14,
        vec![
            Truncate {
                program: program(),
                authority,
                destination: Some(buffer()),
            }
            .instruction(TruncateInstructionArgs { new_size: 0 }),
        ],
    ));
    let temp = tempfile::tempdir().unwrap();
    let mut archive = archive_records(&temp.path().join("first"), &records, &[program()], true);
    let closed = v4::Resolver::new(&mut archive, None).reconstruct().unwrap();
    assert_eq!(closed.bytes, elf());
    assert!(closed.consumed.is_some());
    records.push(from_instructions(
        432004,
        0,
        15,
        vec![
            Truncate {
                program: program(),
                authority,
                destination: None,
            }
            .instruction(TruncateInstructionArgs { new_size: 10 }),
            v4_write(program(), 0, vec![9; 3]),
        ],
    ));
    let mut archive = archive_records(&temp.path().join("second"), &records, &[program()], true);
    let result = v4::Resolver::new(&mut archive, None).reconstruct().unwrap();
    assert_eq!(result.bytes, vec![9, 9, 9, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(result.explicitly_written, 3);
}

#[test]
fn missing_baseline_bad_offsets_and_oversized_images_fail() {
    let temp = tempfile::tempdir().unwrap();
    for (name, records) in [
        ("baseline", v4_dataset(false)[1..].to_vec()),
        ("offset", {
            let mut r = v4_dataset(false);
            r[1] = from_instructions(432002, 0, 12, vec![v4_write(program(), u32::MAX, vec![1])]);
            r
        }),
        ("size", {
            let mut r = v4_dataset(false);
            r[0] = from_instructions(432001, 0, 11, v4_create(program(), MAX_PAYLOAD as u32 + 1));
            r
        }),
    ] {
        let mut archive = archive_records(&temp.path().join(name), &records, &[program()], false);
        assert!(
            v4::Resolver::new(&mut archive, None).reconstruct().is_err(),
            "{name}"
        );
    }
}

#[test]
fn explicit_earlier_version_and_finalize_do_not_follow_next_version_pointer() {
    let mut records = v4_dataset(false);
    let old = records.last().unwrap().signature;
    let authority = Address::new_from_array([2; 32]);
    records.push(from_instructions(
        432004,
        0,
        15,
        vec![
            Retract {
                program: program(),
                authority,
            }
            .instruction(),
            v4_write(program(), 0, vec![9; 3]),
            v4_deploy(program(), None),
            Finalize {
                program: program(),
                authority,
                next_version: Address::new_from_array([99; 32]),
            }
            .instruction(),
        ],
    ));
    let selection =
        reconstruct::discover(stream(&records).as_slice(), program(), Some(old)).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut archive = archive_records(&temp.path().join("archive"), &records, &[program()], false);
    archive.manifest.selection = Some(selection);
    let result = v4::Resolver::new(&mut archive, None).reconstruct().unwrap();
    assert_eq!(result.bytes, elf());
    let mut archive = archive_records(&temp.path().join("buffer"), &records, &[program()], true);
    let result = v4::Resolver::new(&mut archive, None).reconstruct().unwrap();
    assert_eq!(&result.bytes[..3], &[9; 3]);
}

#[test]
fn complete_source_replacement_supersedes_unknown_older_uploads() {
    let mut records = v4_dataset(true);
    let authority = Address::new_from_array([2; 32]);
    // Only the source has a known creation baseline. The destination's older
    // writes are outside the recovered incarnation's complete replacement.
    records[0] = from_instructions(432001, 0, 11, v4_create(buffer(), 184));
    records.insert(
        1,
        from_instructions(432001, 1, 20, vec![v4_write(program(), 0, vec![7; 8])]),
    );
    records.last_mut().unwrap().instructions = from_instructions(
        432003,
        0,
        14,
        vec![
            v4_deploy(program(), Some(buffer())),
            Retract {
                program: program(),
                authority,
            }
            .instruction(),
        ],
    )
    .instructions;
    records.push(from_instructions(
        432004,
        0,
        15,
        vec![v4_deploy(program(), None)],
    ));
    let temp = tempfile::tempdir().unwrap();
    let mut archive = archive_records(
        &temp.path().join("archive"),
        &records,
        &[buffer(), program()],
        false,
    );
    let result = v4::Resolver::new(&mut archive, None).reconstruct().unwrap();
    assert_eq!(result.bytes, elf());
    assert_eq!(result.baseline_account, buffer());
}

#[test]
fn caught_cpi_failure_excludes_v4_writes_and_missing_logs_fail() {
    let mut records = v4_dataset(false);
    records.last_mut().unwrap().slot = 432004;
    let mut cpi = from_instructions(432003, 0, 20, vec![v4_write(program(), 180, vec![9])]);
    let mut leaf = cpi.instructions.remove(0);
    leaf.ordinal = 2;
    leaf.depth = Some(3);
    let outer_id = Address::new_from_array([50; 32]);
    let parent_id = Address::new_from_array([51; 32]);
    cpi.keys.extend([outer_id, parent_id]);
    let outer_index = (cpi.keys.len() - 2) as u8;
    let parent_index = (cpi.keys.len() - 1) as u8;
    let mut outer = ix(outer_index, &[4], vec![], 0);
    outer.depth = Some(1);
    let mut parent = ix(parent_index, &[4], vec![], 0);
    parent.ordinal = 1;
    parent.depth = Some(2);
    cpi.instructions = vec![outer, parent, leaf];
    cpi.logs = Some(vec![
        format!("Program {outer_id} invoke [1]"),
        format!("Program {parent_id} invoke [2]"),
        format!("Program {LOADER_V4} invoke [3]"),
        format!("Program {LOADER_V4} success"),
        format!("Program {parent_id} failed: caught error"),
        format!("Program {outer_id} success"),
    ]);
    records.insert(3, cpi);
    let temp = tempfile::tempdir().unwrap();
    let mut archive = archive_records(&temp.path().join("failed"), &records, &[program()], false);
    assert_eq!(
        v4::Resolver::new(&mut archive, None)
            .reconstruct()
            .unwrap()
            .bytes,
        elf()
    );
    records[3].logs = None;
    // Selecting the top-level Deploy does not require this unrelated earlier
    // CPI's logs; v4 replay must still refuse its unknown commit status.
    let mut archive = archive_records(&temp.path().join("missing"), &records, &[program()], true);
    assert!(v4::Resolver::new(&mut archive, None).reconstruct().is_err());
}

#[test]
fn source_depth_limit_rejects_excessive_historical_dependency_chains() {
    let accounts: Vec<_> = (30..47)
        .map(|id| Address::new_from_array([id; 32]))
        .collect();
    let authority = Address::new_from_array([2; 32]);
    let mut creates = Vec::new();
    for account in accounts.iter().copied().chain([program()]) {
        creates.extend(v4_create(account, 184));
    }
    let mut records = vec![
        from_instructions(432001, 0, 1, creates),
        from_instructions(432002, 0, 2, vec![v4_write(accounts[0], 0, elf())]),
    ];
    for index in 1..accounts.len() {
        records.push(from_instructions(
            432002 + index as u64,
            0,
            (index + 2) as u8,
            vec![
                v4_deploy(accounts[index], Some(accounts[index - 1])),
                Retract {
                    program: accounts[index],
                    authority,
                }
                .instruction(),
            ],
        ));
    }
    records.push(from_instructions(
        432020,
        0,
        50,
        vec![v4_deploy(program(), Some(*accounts.last().unwrap()))],
    ));
    let temp = tempfile::tempdir().unwrap();
    let mut archive = archive_records(&temp.path().join("deep"), &records, &accounts, false);
    let error = v4::Resolver::new(&mut archive, None)
        .reconstruct()
        .unwrap_err();
    assert!(error.to_string().contains("depth exceeds"), "{error:#}");
}
