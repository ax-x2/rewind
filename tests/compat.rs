mod common;
use common::*;
use rewind::{
    archive::{self, Archive},
    coverage::hash,
    reconstruct,
    types::*,
};

#[test]
fn complete_v1_archives_replay_and_incomplete_v1_scans_require_a_fresh_archive() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("legacy");
    let config = config();
    let records = dataset();
    let mut archive = Archive::open(&root, config.clone(), false).unwrap();
    for target in [Target::Program(program()), Target::Buffer(buffer())] {
        let bytes = stream(&records);
        let partial = root.join("test.partial");
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
    archive.manifest.selection =
        Some(reconstruct::discover(stream(&records).as_slice(), program(), None).unwrap());
    archive.manifest.complete = true;
    archive.save().unwrap();
    // Reproduce v1's account-independent filenames and JSON field set, while
    // retaining its original raw binary record/proof encoding.
    for chunk in &mut archive.manifest.chunks {
        let label = match chunk.target {
            Target::Program(_) => "program",
            Target::Buffer(_) => "buffer",
        };
        let legacy = format!("{label}-{}-{}", chunk.range.start, chunk.range.end);
        for suffix in ["raw", "proof"] {
            std::fs::rename(
                root.join(format!("{}.{suffix}", chunk.stem)),
                root.join(format!("{legacy}.{suffix}")),
            )
            .unwrap();
        }
        chunk.stem = legacy;
    }
    let mut json = serde_json::to_value(&archive.manifest).unwrap();
    json["format"] = serde_json::json!(1);
    json["config"].as_object_mut().unwrap().remove("loader");
    json["selection"].as_object_mut().unwrap().remove("loader");
    std::fs::write(
        root.join("archive.json"),
        serde_json::to_vec(&json).unwrap(),
    )
    .unwrap();
    drop(archive);
    let before = std::fs::read(root.join("archive.json")).unwrap();
    let out = temp.path().join("replayed.so");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_rewind"))
        .args([
            "replay",
            "--archive",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(std::fs::read(out).unwrap(), elf());
    assert_eq!(std::fs::read(root.join("archive.json")).unwrap(), before);
    json["complete"] = serde_json::json!(false);
    std::fs::write(
        root.join("archive.json"),
        serde_json::to_vec(&json).unwrap(),
    )
    .unwrap();
    let legacy = archive::load_manifest(&root).unwrap();
    assert_eq!(legacy.config.loader, LoaderPolicy::V3);
    let error = Archive::open(&root, legacy.config, true)
        .err()
        .expect("incomplete v1 must not resume");
    assert!(error.to_string().contains("incomplete v1"));
}
