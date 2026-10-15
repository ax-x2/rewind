mod common;
use clap::Parser;
use common::*;
use rewind::{
    archive::{self, Archive},
    bulk,
    cli::Cli,
    coverage::hash,
    reconstruct,
    types::*,
};
use serde_json::Value;
use std::{
    path::Path,
    process::{Command, Output},
};

fn seed(
    root: &Path,
    records: &[TransactionRecord],
    sources: &[solana_address::Address],
    limit: usize,
) {
    let mut config = config();
    config.range.end = records.iter().map(|record| record.slot + 1).max().unwrap();
    let mut archive = Archive::open_history(root, config.clone(), false, limit).unwrap();
    for target in std::iter::once(config.target).chain(sources.iter().copied().map(Target::Buffer))
    {
        if archive.verified(target, config.range).unwrap().is_some() {
            continue;
        }
        let bytes = stream(records);
        let partial = root.join("fixture.partial");
        archive.reserve(bytes.len() as u64).unwrap();
        std::fs::write(&partial, bytes).unwrap();
        archive
            .commit(
                target,
                config.range,
                &partial,
                Coverage {
                    range: config.range,
                    index_hash: hash(b"fixture"),
                    slots: vec![],
                },
            )
            .unwrap();
    }
    let selections = reconstruct::discover_all_with_policy(
        stream(records).as_slice(),
        program(),
        LoaderPolicy::Auto,
        limit,
    )
    .unwrap();
    // Populate discovery through public JSON to exercise the persisted schema.
    let mut value = serde_json::to_value(&archive.manifest).unwrap();
    value["history"]["discovery_complete"] = true.into();
    value["history"]["versions"] = selections.iter().map(|selection| serde_json::json!({"selection": selection, "filename": bulk::filename(selection), "state": "pending", "payload_bytes": null, "sha256": null, "error": null})).collect::<Vec<_>>().into();
    archive.manifest = serde_json::from_value(value).unwrap();
    archive.save().unwrap();
}

fn replay(root: &Path, out: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rewind"))
        .args([
            "replay",
            "--all-versions",
            "--archive",
            root.to_str().unwrap(),
            "--out-dir",
            out.to_str().unwrap(),
        ])
        .args(extra)
        .output()
        .unwrap()
}
fn json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn success(result: Output) {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn bulk_is_opt_in_and_clap_rejects_ambiguous_modes() {
    let program = program().to_string();
    let base = [
        "rewind",
        "recover",
        "--program",
        &program,
        "--slots",
        "432001:432023",
    ];
    assert!(Cli::try_parse_from(base.into_iter().chain(["--out", "program.so"])).is_ok());
    assert!(
        Cli::try_parse_from(base.into_iter().chain([
            "--all-versions",
            "--out-dir",
            "versions",
            "--archive",
            "evidence"
        ]))
        .is_ok()
    );
    for args in [
        vec!["--out-dir", "versions"],
        vec!["--all-versions", "--out", "program.so"],
        vec!["--out", "program.so", "--keep-going"],
        vec!["--out", "program.so", "--max-versions", "2"],
        vec![
            "--all-versions",
            "--out-dir",
            "versions",
            "--deployment-signature",
            &solana_signature::Signature::from([7; 64]).to_string(),
        ],
    ] {
        assert!(
            Cli::try_parse_from(base.into_iter().chain(args.clone())).is_err(),
            "accepted {args:?}"
        );
    }
}

#[test]
fn discovers_bounded_versions_without_merging_equal_payloads_or_instruction_identities() {
    let records = historical_v3_dataset();
    let versions = reconstruct::discover_all_with_policy(
        stream(&records).as_slice(),
        program(),
        LoaderPolicy::Auto,
        3,
    )
    .unwrap();
    assert_eq!(versions.len(), 3);
    assert!(
        versions
            .windows(2)
            .all(|pair| pair[0].position < pair[1].position)
    );
    assert!(
        reconstruct::discover_all_with_policy(
            stream(&records).as_slice(),
            program(),
            LoaderPolicy::Auto,
            2
        )
        .unwrap_err()
        .to_string()
        .contains("version limit")
    );
    assert!(
        reconstruct::discover_all_with_policy(
            stream(&records).as_slice(),
            program(),
            LoaderPolicy::V4,
            3
        )
        .is_err()
    );
    let latest = reconstruct::discover(stream(&records).as_slice(), program(), None).unwrap();
    assert_eq!(latest, versions[2]);
    assert_eq!(
        reconstruct::discover(
            stream(&records).as_slice(),
            program(),
            Some(versions[0].signature)
        )
        .unwrap(),
        versions[0]
    );
    let mut same_slot = versions[0].clone();
    same_slot.position.ordinal += 1;
    assert_ne!(bulk::filename(&same_slot), bulk::filename(&versions[0]));
    let mut conflict = records.last().unwrap().clone();
    conflict.signature = solana_signature::Signature::from([99; 64]);
    let mut records = records;
    records.push(conflict);
    assert!(
        reconstruct::discover_all_with_policy(
            stream(&records).as_slice(),
            program(),
            LoaderPolicy::Auto,
            4
        )
        .unwrap_err()
        .to_string()
        .contains("conflicting")
    );
}

#[test]
fn offline_v3_exports_all_incarnations_and_resumes_orphaned_and_missing_files() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("evidence");
    let out = temp.path().join("versions");
    seed(&root, &historical_v3_dataset(), &[buffer()], 3);
    success(replay(&root, &out, &[]));
    let index = json(&out.join("versions.json"));
    assert_eq!(index["complete"], true);
    let versions = index["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 3);
    for (i, version) in versions.iter().enumerate() {
        assert_eq!(version["status"], "published");
        let mut expected = elf();
        *expected.last_mut().unwrap() = i as u8;
        let path = out.join(version["filename"].as_str().unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), expected);
        assert_eq!(version["sha256"], hash(&expected));
    }
    // Simulate a crash after binary persistence but before sidecar/index update.
    let first = out.join(versions[0]["filename"].as_str().unwrap());
    std::fs::remove_file(rewind::output::manifest_path(&first)).unwrap();
    let mut interrupted = index.clone();
    interrupted["complete"] = false.into();
    interrupted["versions"][0]["status"] = "pending".into();
    std::fs::write(
        out.join("versions.json"),
        serde_json::to_vec(&interrupted).unwrap(),
    )
    .unwrap();
    let last = out.join(versions[2]["filename"].as_str().unwrap());
    std::fs::remove_file(&last).unwrap();
    std::fs::remove_file(rewind::output::manifest_path(&last)).unwrap();
    let unfinished = out.join(".rewind-tmp-a1b2C3");
    std::fs::write(&unfinished, b"unfinished publication").unwrap();
    success(replay(&root, &out, &[]));
    assert!(!unfinished.exists());
    assert!(rewind::output::manifest_path(&first).is_file());
    assert!(last.is_file());
    assert_eq!(json(&out.join("versions.json"))["complete"], true);
    success(replay(&root, &out, &[]));
    assert_eq!(archive::load_manifest(&root).unwrap().format, 3);
    assert!(archive::load_manifest(&root).unwrap().complete);
}

#[test]
fn offline_v4_sources_and_in_place_versions_preserve_exact_snapshots() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("evidence");
    let out = temp.path().join("versions");
    seed(
        &root,
        &historical_v4_dataset(),
        &[buffer(), solana_address::Address::new_from_array([55; 32])],
        3,
    );
    success(replay(&root, &out, &[]));
    let index = json(&out.join("versions.json"));
    for (i, version) in index["versions"].as_array().unwrap().iter().enumerate() {
        let mut expected = elf();
        *expected.last_mut().unwrap() = i as u8;
        assert_eq!(
            std::fs::read(out.join(version["filename"].as_str().unwrap())).unwrap(),
            expected
        );
    }
    assert_eq!(archive::load_manifest(&root).unwrap().chunks.len(), 3);
}

#[test]
fn fail_fast_and_keep_going_record_missing_baselines_and_still_exit_nonzero() {
    for keep_going in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let out = temp.path().join("versions");
        let mut records = historical_v3_dataset();
        records.remove(0);
        seed(&root, &records, &[buffer()], 3);
        let result = replay(
            &root,
            &out,
            if keep_going { &["--keep-going"] } else { &[] },
        );
        assert!(!result.status.success());
        let index = json(&out.join("versions.json"));
        assert_eq!(index["complete"], false);
        assert_eq!(index["versions"][0]["status"], "failed");
        assert_eq!(index["versions"][0]["error"]["kind"], "missing_baseline");
        assert_eq!(
            index["versions"][1]["status"],
            if keep_going { "published" } else { "pending" }
        );
    }
}

#[test]
fn quotas_corruption_and_symlinks_never_overwrite_existing_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("evidence");
    let out = temp.path().join("versions");
    seed(&root, &historical_v3_dataset(), &[buffer()], 3);
    assert!(
        !replay(&root, &out, &["--max-output-bytes", "185"])
            .status
            .success()
    );
    let index = json(&out.join("versions.json"));
    let first = out.join(index["versions"][0]["filename"].as_str().unwrap());
    assert_eq!(std::fs::read(&first).unwrap(), elf());
    std::fs::write(&first, b"keep this content").unwrap();
    assert!(!replay(&root, &out, &["--keep-going"]).status.success());
    assert_eq!(std::fs::read(&first).unwrap(), b"keep this content");
    std::fs::remove_file(&first).unwrap();
    let external = temp.path().join("external");
    std::fs::write(&external, elf()).unwrap();
    std::os::unix::fs::symlink(&external, &first).unwrap();
    assert!(!replay(&root, &out, &[]).status.success());
    assert_eq!(std::fs::read(external).unwrap(), elf());
}

#[test]
fn frozen_discovery_and_mode_mismatch_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("evidence");
    seed(&root, &historical_v3_dataset(), &[buffer()], 3);
    let single = Command::new(env!("CARGO_BIN_EXE_rewind"))
        .args([
            "replay",
            "--archive",
            root.to_str().unwrap(),
            "--out",
            temp.path().join("single.so").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!single.status.success());
    let mut manifest = json(&root.join("archive.json"));
    manifest["history"]["versions"]
        .as_array_mut()
        .unwrap()
        .pop();
    std::fs::write(
        root.join("archive.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let result = replay(&root, &temp.path().join("versions"), &[]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("frozen"));
}

#[test]
fn identical_payloads_still_export_each_deployment() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("evidence");
    let out = temp.path().join("versions");
    let mut records = historical_v3_dataset();
    for record in &mut records {
        for instruction in &mut record.instructions {
            if let Ok(rewind::decode::Loader::Write { offset: 92, .. }) =
                rewind::decode::loader(&instruction.data)
            {
                instruction.data = bincode::serialize(
                    &solana_loader_v3_interface::instruction::UpgradeableLoaderInstruction::Write {
                        offset: 92,
                        bytes: elf()[92..].to_vec(),
                    },
                )
                .unwrap();
            }
        }
    }
    seed(&root, &records, &[buffer()], 3);
    success(replay(&root, &out, &[]));
    let index = json(&out.join("versions.json"));
    let versions = index["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 3);
    assert!(
        versions
            .iter()
            .all(|version| version["sha256"] == hash(&elf()))
    );
    assert_ne!(versions[0]["filename"], versions[1]["filename"]);
}

#[test]
fn discovery_limit_is_enforced_before_any_binary_is_published() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("evidence");
    let out = temp.path().join("versions");
    seed(&root, &historical_v3_dataset(), &[buffer()], 3);
    let mut archive = Archive::open_history(
        &root,
        archive::load_manifest(&root).unwrap().config,
        true,
        3,
    )
    .unwrap();
    archive.manifest.history = Some(bulk::History::new(2));
    archive.save().unwrap();
    drop(archive);
    let result = Command::new(env!("CARGO_BIN_EXE_rewind"))
        .args([
            "recover",
            "--all-versions",
            "--program",
            &program().to_string(),
            "--slots",
            "432001:432023",
            "--resume",
            root.to_str().unwrap(),
            "--out-dir",
            out.to_str().unwrap(),
            "--max-versions",
            "2",
            "--index-base",
            "http://127.0.0.1:1",
            "--car-base",
            "http://127.0.0.1:1",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("version limit"));
    assert!(
        std::fs::read_dir(out)
            .unwrap()
            .all(|entry| entry.unwrap().file_name() == "versions.json")
    );
    assert!(
        !archive::load_manifest(&root)
            .unwrap()
            .history
            .unwrap()
            .discovery_complete
    );
}

#[test]
fn corruption_is_fatal_even_with_keep_going_and_output_lock_is_exclusive() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("evidence");
    let out = temp.path().join("versions");
    seed(&root, &historical_v3_dataset(), &[buffer()], 3);
    std::fs::create_dir(&out).unwrap();
    std::fs::write(out.join(".rewind.lock"), b"owned by another exporter").unwrap();
    let result = replay(&root, &out, &[]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("OutputBusy"));
    std::fs::remove_file(out.join(".rewind.lock")).unwrap();
    let manifest = archive::load_manifest(&root).unwrap();
    let source = manifest
        .chunks
        .iter()
        .find(|chunk| chunk.target == Target::Buffer(buffer()))
        .unwrap();
    std::fs::write(root.join(format!("{}.raw", source.stem)), b"corrupt").unwrap();
    let result = replay(&root, &out, &["--keep-going"]);
    assert!(!result.status.success());
    let index = json(&out.join("versions.json"));
    assert_eq!(index["versions"][0]["error"]["kind"], "fatal");
    assert_eq!(index["versions"][1]["status"], "pending");
    assert_eq!(index["complete"], false);
}

#[test]
fn incomplete_discovery_cannot_claim_all_versions_but_partial_source_replay_is_reported() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("evidence");
    seed(&root, &historical_v3_dataset(), &[], 3);
    let out = temp.path().join("partial");
    let result = replay(&root, &out, &["--keep-going"]);
    assert!(!result.status.success());
    let index = json(&out.join("versions.json"));
    assert!(
        index["versions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|version| version["error"]["kind"] == "missing_source")
    );
    let mut archive = Archive::open_history(
        &root,
        archive::load_manifest(&root).unwrap().config,
        true,
        3,
    )
    .unwrap();
    archive.manifest.history = Some(bulk::History::new(3));
    archive.save().unwrap();
    drop(archive);
    let unpublished = temp.path().join("unpublished");
    let result = replay(&root, &unpublished, &[]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("discovery is incomplete"));
    assert!(!unpublished.exists());
}

#[test]
fn nested_output_path_is_rejected_without_adding_a_directory_to_the_archive() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("evidence");
    seed(&root, &historical_v3_dataset(), &[buffer()], 3);
    let nested = root.join("versions");
    assert!(!replay(&root, &nested, &[]).status.success());
    assert!(!nested.exists());
    success(replay(&root, &temp.path().join("valid-output"), &[]));
}
