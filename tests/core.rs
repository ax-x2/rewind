mod common;
use common::*;
use rewind::{
    archive,
    coverage::{Audit, parse_index},
    decode, reconstruct,
    types::*,
};
use solana_loader_v3_interface::instruction::UpgradeableLoaderInstruction as L;

#[test]
fn official_write_encoding_and_checked_lengths() {
    for len in [0, 1, 960, 1232] {
        let bytes = vec![8; len];
        let wire = bincode::serialize(&L::Write {
            offset: 13440,
            bytes: bytes.clone(),
        })
        .unwrap();
        assert_eq!(
            decode::loader(&wire).unwrap(),
            decode::Loader::Write {
                offset: 13440,
                bytes: &bytes
            }
        );
        assert!(decode::loader(&wire[..wire.len() - 1]).is_err());
        let mut extra = wire.clone();
        extra.push(0);
        assert!(decode::loader(&extra).is_err());
    }
    assert!(decode::loader(&[1, 0, 0, 0]).is_err());
}

#[test]
fn official_seeded_creation_and_size() {
    let wire = bincode::serialize(
        &solana_system_interface::instruction::SystemInstruction::CreateAccountWithSeed {
            base: program(),
            seed: "abc".into(),
            lamports: 1,
            space: 14389,
            owner: LOADER,
        },
    )
    .unwrap();
    assert_eq!(
        decode::system_creation(&wire).unwrap(),
        Some((14389, LOADER))
    );
    assert!(decode::system_creation(&wire[..wire.len() - 1]).is_err());
}

#[test]
fn discovers_program_and_reconstructs_payload_not_programdata_capacity() {
    let raw = stream(&dataset());
    let selection = reconstruct::discover(raw.as_slice(), program(), None).unwrap();
    assert_eq!(selection.buffer, buffer());
    assert_eq!(selection.capacity, Some(4096));
    let result = reconstruct::reconstruct(raw.as_slice(), buffer(), Some(&selection)).unwrap();
    assert_eq!(result.bytes, elf());
    assert_eq!(result.explicitly_written, elf().len());
    rewind::output::validate_elf(&result.bytes).unwrap();
}

#[test]
fn overlapping_writes_and_zero_baseline() {
    let mut payload = vec![0; 16];
    let mut coverage = vec![0; 2];
    reconstruct::apply_write(&mut payload, &mut coverage, 4, &[1, 2, 3]).unwrap();
    reconstruct::apply_write(&mut payload, &mut coverage, 5, &[9, 8]).unwrap();
    assert_eq!(&payload[3..8], &[0, 1, 9, 8, 0]);
    assert_eq!(coverage.iter().map(|b| b.count_ones()).sum::<u32>(), 3);
    assert!(reconstruct::apply_write(&mut payload, &mut coverage, usize::MAX, &[1]).is_err());
    assert!(reconstruct::apply_write(&mut payload, &mut coverage, 16, &[1]).is_err());
    let mut data = dataset();
    data[1].instructions[0] = loader(
        L::Write {
            offset: 1,
            bytes: vec![7],
        },
        &[1, 0],
        0,
    );
    data.remove(2);
    let result = reconstruct::reconstruct(stream(&data).as_slice(), buffer(), None).unwrap();
    assert_eq!(result.explicitly_written, 1);
    assert_eq!(result.bytes[0], 0);
    assert_eq!(result.bytes[1], 7);
}

#[test]
fn refuses_unknown_baseline_and_stops_at_exact_deployment_instruction() {
    let data = dataset();
    assert!(reconstruct::reconstruct(stream(&data[1..]).as_slice(), buffer(), None).is_err());
    let mut data = data;
    let selection = reconstruct::discover(stream(&data).as_slice(), program(), None).unwrap();
    data.last_mut().unwrap().instructions.push(loader(
        L::Write {
            offset: 0,
            bytes: vec![0; 8],
        },
        &[1, 0],
        1,
    ));
    let result =
        reconstruct::reconstruct(stream(&data).as_slice(), buffer(), Some(&selection)).unwrap();
    assert_eq!(result.bytes, elf());
}

#[test]
fn coverage_counts_unrelated_and_failed_transactions_and_rejects_holes() {
    let range = SearchRange::inclusive(42, 43).unwrap();
    let audit = Audit::new(range).unwrap();
    audit.transaction(42, 0).unwrap();
    audit.transaction(42, 2).unwrap();
    audit.block(42, 3).unwrap();
    assert!(audit.finish(&[true, false], "index".into()).is_err());
    audit.transaction(42, 1).unwrap();
    audit.transaction(42, 1).unwrap(); // retries do not inflate counts
    assert_eq!(
        audit.finish(&[true, false], "index".into()).unwrap().slots[0].transactions,
        3
    );
    assert!(audit.finish(&[true, true], "index".into()).is_err());
    assert!(audit.transaction(42, MAX_TX).is_err());
    audit.fail();
    assert!(audit.finish(&[true, false], "index".into()).is_err());
}

#[test]
fn unknown_index_is_not_skipped_history() {
    let range = SearchRange::inclusive(432001, 432003).unwrap();
    assert!(parse_index(&[], range).is_err());
    let mut index = vec![0; 432000 * 12];
    index[20..24].copy_from_slice(&4u32.to_le_bytes());
    assert_eq!(
        parse_index(&index, range).unwrap(),
        vec![true, false, false]
    );
    index[32..36].copy_from_slice(&4u32.to_le_bytes()); // overlapping offset zero
    assert!(parse_index(&index, range).is_err());
}

#[test]
fn cpi_success_under_failed_ancestor_is_rolled_back() {
    let mut record = record(432001, 0, 6);
    record.keys.extend([
        solana_address::Address::new_from_array([9; 32]),
        solana_address::Address::new_from_array([10; 32]),
    ]);
    let mut outer = ix(8, &[], vec![], 0);
    let mut parent = ix(9, &[], vec![], 0);
    parent.ordinal = 1;
    parent.depth = Some(2);
    let mut inner = loader(L::InitializeBuffer, &[1, 0], 0);
    inner.ordinal = 2;
    inner.depth = Some(3);
    outer.depth = Some(1);
    record.instructions = vec![outer, parent, inner];
    let a = record.keys[8];
    let b = record.keys[9];
    record.logs = Some(vec![
        format!("Program {a} invoke [1]"),
        format!("Program {b} invoke [2]"),
        format!("Program {LOADER} invoke [3]"),
        format!("Program {LOADER} success"),
        format!("Program {b} failed: custom error"),
        format!("Program {a} success"),
    ]);
    assert_eq!(
        decode::committed(&record).unwrap(),
        vec![true, false, false]
    );
    record.logs.as_mut().unwrap()[4] = format!("Program {b} success");
    assert!(decode::committed(&record).unwrap().iter().all(|ok| *ok));
    record.logs = None;
    assert!(decode::committed(&record).is_err());
}

#[test]
fn external_sort_deduplicates_and_rejects_conflicting_signatures() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("evidence");
    let mut archive = archive::Archive::open(&root, config(), false).unwrap();
    let mut data = dataset();
    data.reverse();
    data.push(data[0].clone());
    let path = root.join("source");
    std::fs::write(&path, stream(&data)).unwrap();
    let sorted = archive.sorted(std::slice::from_ref(&path)).unwrap();
    let read = std::fs::read(sorted.path()).unwrap();
    assert_eq!(read, stream(&dataset()));
    archive.discard_temporary(sorted).unwrap();
    data.last_mut().unwrap().slot += 1;
    std::fs::write(&path, stream(&data)).unwrap();
    assert!(archive.sorted(&[path]).is_err());
}

#[test]
fn supplied_fixtures_are_partial_and_match_documented_roles() {
    let init: serde_json::Value =
        serde_json::from_str(include_str!("../raw/initbuffer.json")).unwrap();
    let deploy: serde_json::Value =
        serde_json::from_str(include_str!("../raw/deployWithMaxDataLen.json")).unwrap();
    assert_eq!(init["slot"], 432642976u64);
    assert_eq!(
        init["transaction"]["message"]["instructions"][0]["parsed"]["info"]["space"],
        14389u64
    );
    assert_eq!(
        deploy["transaction"]["message"]["instructions"][1]["parsed"]["info"]["maxDataLen"],
        14352u64
    );
    for (json, offset) in [
        (include_str!("../raw/write.json"), 13440),
        (include_str!("../raw/write2.json"), 12480),
    ] {
        let write: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(
            write["transaction"]["message"]["instructions"][0]["parsed"]["info"]["offset"],
            offset
        );
    }
}

#[test]
fn raw_protocol_and_disk_budgets_reject_growth() {
    assert!(archive::decode::<TransactionRecord>(&vec![0; MAX_FRAME + 1]).is_err());
    assert!(archive::read_record::<TransactionRecord>(&mut [1, 0, 0].as_slice()).is_err());
    assert!(
        archive::read_record::<TransactionRecord>(&mut u32::MAX.to_le_bytes().as_slice()).is_err()
    );
    let temp = tempfile::tempdir().unwrap();
    let mut archive =
        archive::Archive::open(&temp.path().join("evidence"), config(), false).unwrap();
    assert!(archive.reserve(MAX_SPOOL + 1).is_err());
}

#[test]
fn buffer_recreation_and_explicit_old_version_do_not_mix_payloads() {
    let first = dataset();
    let selection = reconstruct::discover(
        stream(&first).as_slice(),
        program(),
        Some(first[3].signature),
    )
    .unwrap();
    let mut second = dataset();
    for record in &mut second {
        record.slot += 10;
        record.signature =
            solana_signature::Signature::from([record.signature.as_ref()[0] + 20; 64]);
    }
    second[1].instructions[0] = loader(
        L::Write {
            offset: 0,
            bytes: vec![9; 92],
        },
        &[1, 0],
        0,
    );
    let mut all = first;
    all.extend(second);
    let bytes = stream(&all);
    let latest = reconstruct::discover(bytes.as_slice(), program(), None).unwrap();
    assert!(latest.position > selection.position);
    let old = reconstruct::reconstruct(bytes.as_slice(), buffer(), Some(&selection)).unwrap();
    assert_eq!(old.bytes, elf());
    let latest = reconstruct::reconstruct(bytes.as_slice(), buffer(), Some(&latest)).unwrap();
    assert_eq!(&latest.bytes[..92], &[9; 92]);
    assert_eq!(&latest.bytes[92..], &elf()[92..]);
}

#[test]
fn elf_bounds_and_output_preservation() {
    let mut bytes = elf();
    bytes[96..104].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(rewind::output::validate_elf(&bytes).is_err());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("existing.so");
    std::fs::write(&path, b"keep").unwrap();
    let raw = stream(&dataset());
    let result = reconstruct::reconstruct(raw.as_slice(), buffer(), None).unwrap();
    assert!(rewind::output::publish(&path, &result, &config(), None).is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"keep");
}
