mod common;
use cid::Cid;
use common::*;
use prost::Message as _;
use rewind::types::*;
use serde_cbor::Value::{self, Array, Bytes, Integer, Map, Null, Text};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::Command,
};

fn varint(mut value: usize, output: &mut Vec<u8>) {
    while value >= 128 {
        output.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    output.push(value as u8);
}
fn append(nodes: &mut Vec<u8>, value: Value) -> Cid {
    let bytes = serde_cbor::to_vec(&value).unwrap();
    let cid = Cid::new_v1(
        0x71,
        multihash::Multihash::wrap(0x12, &Sha256::digest(&bytes)).unwrap(),
    );
    let key = cid.to_bytes();
    varint(key.len() + bytes.len(), nodes);
    nodes.extend(key);
    nodes.extend(bytes);
    cid
}
fn link(cid: Cid) -> Value {
    let mut bytes = vec![0];
    bytes.extend(cid.to_bytes());
    Bytes(bytes)
}
fn frame(bytes: Vec<u8>) -> Value {
    Array(vec![Integer(6), Null, Null, Null, Bytes(bytes)])
}

fn fixture() -> (Vec<u8>, Vec<u8>) {
    fixture_omitting(false)
}

fn fixture_omitting(omit_transaction: bool) -> (Vec<u8>, Vec<u8>) {
    fixture_records(dataset(), omit_transaction)
}

fn fixture_records(input: Vec<TransactionRecord>, omit_transaction: bool) -> (Vec<u8>, Vec<u8>) {
    let mut slots: BTreeMap<u64, Vec<TransactionRecord>> = BTreeMap::new();
    for record in input {
        slots.entry(record.slot).or_default().push(record);
    }
    let sentinel = slots.keys().last().unwrap() + 1;
    slots.insert(sentinel, vec![]); // read-ahead sentinel beyond the requested range
    let mut nodes = Vec::new();
    let mut records = Vec::new();
    let mut root = None;
    for (slot, transactions) in slots {
        let offset = nodes.len();
        let mut tx_links = Vec::new();
        for record in transactions {
            let transaction = solana_transaction::versioned::VersionedTransaction {
                signatures: vec![record.signature],
                message: solana_message::VersionedMessage::Legacy(
                    solana_message::legacy::Message {
                        header: solana_message::MessageHeader {
                            num_required_signatures: 1,
                            num_readonly_signed_accounts: 0,
                            num_readonly_unsigned_accounts: 0,
                        },
                        account_keys: record.keys.clone(),
                        recent_blockhash: Default::default(),
                        instructions: record
                            .instructions
                            .iter()
                            .map(
                                |i| solana_message::compiled_instruction::CompiledInstruction {
                                    program_id_index: i.program,
                                    accounts: i.accounts.clone(),
                                    data: i.data.clone(),
                                },
                            )
                            .collect(),
                    },
                ),
            };
            let metadata = solana_storage_proto::convert::generated::TransactionStatusMeta {
                pre_balances: vec![1; record.keys.len()],
                post_balances: vec![1; record.keys.len()],
                ..Default::default()
            };
            let mut discarded = Vec::new();
            let target = if omit_transaction && record.slot == 432002 && record.index == 1 {
                &mut discarded
            } else {
                &mut nodes
            };
            let cid = append(
                target,
                Array(vec![
                    Integer(0),
                    frame(wincode::serialize(&transaction).unwrap()),
                    frame(metadata.encode_to_vec()),
                    Integer(slot.into()),
                    Integer(record.index.into()),
                ]),
            );
            tx_links.push(link(cid));
        }
        let entry = append(
            &mut nodes,
            Array(vec![
                Integer(1),
                Integer(1),
                Bytes(vec![0; 32]),
                Array(tx_links),
            ]),
        );
        root = Some(append(
            &mut nodes,
            Array(vec![
                Integer(2),
                Integer(slot.into()),
                Array(vec![]),
                Array(vec![link(entry)]),
                Array(vec![
                    Integer((slot - 1).into()),
                    Integer(0),
                    Integer(slot.into()),
                ]),
                Null,
            ]),
        ));
        records.push((slot, offset, nodes.len() - offset));
    }
    let header = serde_cbor::to_vec(&Map([
        (Text("roots".into()), Array(vec![link(root.unwrap())])),
        (Text("version".into()), Integer(1)),
    ]
    .into()))
    .unwrap();
    let mut car = Vec::new();
    varint(header.len(), &mut car);
    car.extend(header);
    let header_len = car.len();
    car.extend(nodes);
    let mut index = vec![0; 432000 * 12];
    for (slot, offset, len) in records {
        let pos = (slot % 432000) as usize * 12;
        index[pos..pos + 8].copy_from_slice(&((offset + header_len) as u64).to_le_bytes());
        index[pos + 8..pos + 12].copy_from_slice(&(len as u32).to_le_bytes());
    }
    (car, index)
}

async fn serve(
    mut socket: TcpStream,
    car: Arc<Vec<u8>>,
    index: Arc<Vec<u8>>,
    requests: Arc<AtomicUsize>,
) {
    requests.fetch_add(1, Ordering::Relaxed);
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let Ok(byte) = socket.read_u8().await else {
            return;
        };
        header.push(byte);
        if header.len() > 16384 {
            return;
        }
    }
    let header = String::from_utf8(header).unwrap();
    let mut words = header.lines().next().unwrap().split_whitespace();
    let method = words.next().unwrap();
    let path = words.next().unwrap();
    if method == "POST" {
        let length = header
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .map(|(_, v)| v.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        let mut body = vec![0; length];
        socket.read_exact(&mut body).await.unwrap();
        let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let result=match request["method"].as_str().unwrap() {
            "getGenesisHash"=>serde_json::json!({"jsonrpc":"2.0","id":1,"result":GENESIS}),
            "getSignaturesForAddress" if path=="/rpc-error"=>serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"code":-32009,"message":"history pruned"}}),
            "getSignaturesForAddress" if path=="/rpc-partial"=>serde_json::json!({"jsonrpc":"2.0","id":1,"result":[{"signature":dataset()[2].signature.to_string(),"slot":432002,"err":null}]}),
            "getSignaturesForAddress"=>serde_json::json!({"jsonrpc":"2.0","id":1,"result":[]}),
            "getTransaction"=>serde_json::json!({"jsonrpc":"2.0","id":1,"result":null}),
            method=>panic!("unexpected RPC {method}"),
        }.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{result}",
            result.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
        return;
    }
    let body = match path {
        "/1/epoch-1.car" => car,
        "/1/epoch-1-slot-ranges.raw" => index,
        _ => {
            let _ = socket
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return;
        }
    };
    let range = header.lines().find_map(|line| {
        line.split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("range"))
            .map(|(_, v)| v.trim())
    });
    let (status, start, end, extra) = if let Some(range) = range {
        let (first, last) = range
            .strip_prefix("bytes=")
            .unwrap()
            .split_once('-')
            .unwrap();
        let first: usize = first.parse().unwrap();
        let last = last
            .parse::<usize>()
            .unwrap_or(body.len() - 1)
            .min(body.len() - 1);
        (
            "206 Partial Content",
            first,
            last + 1,
            format!("Content-Range: bytes {first}-{last}/{}\r\n", body.len()),
        )
    } else {
        ("200 OK", 0, body.len(), String::new())
    };
    if start >= end || start >= body.len() {
        let _ = socket.write_all(b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        return;
    }
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\n{extra}Connection: close\r\n\r\n",
        end - start
    );
    if socket.write_all(response.as_bytes()).await.is_ok() && method != "HEAD" {
        let _ = socket.write_all(&body[start..end]).await;
    }
}

async fn run(args: &[&str]) -> std::process::Output {
    tokio::time::timeout(
        Duration::from_secs(60),
        Command::new(env!("CARGO_BIN_EXE_rewind"))
            .args(args)
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("ALL_PROXY")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("rewind timed out")
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_sdk_recovers_without_rpc_and_with_empty_pruned_or_partial_rpc() {
    let (car, index) = fixture();
    let car = Arc::new(car);
    let index = Arc::new(index);
    let requests = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server_requests = requests.clone();
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(serve(
                socket,
                car.clone(),
                index.clone(),
                server_requests.clone(),
            ));
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let program = program().to_string();
    for mode in ["disabled", "rpc-empty", "rpc-error", "rpc-partial"] {
        let archive = temp.path().join(format!("archive-{mode}"));
        let out = temp.path().join(format!("{mode}.so"));
        let rpc = format!("{base}/{mode}");
        let mut args = vec![
            "recover",
            "--program",
            &program,
            "--slots",
            "432001:432003",
            "--index-base",
            &base,
            "--car-base",
            &base,
            "--archive",
            archive.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ];
        if mode != "disabled" {
            args.extend(["--rpc-url", &rpc]);
        }
        let result = run(&args).await;
        assert!(
            result.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(std::fs::read(&out).unwrap(), elf());
        let replay = temp.path().join(format!("replay-{mode}.so"));
        let before = requests.load(Ordering::Relaxed);
        let result = run(&[
            "replay",
            "--archive",
            archive.to_str().unwrap(),
            "--out",
            replay.to_str().unwrap(),
        ])
        .await;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(std::fs::read(replay).unwrap(), elf());
        assert_eq!(
            requests.load(Ordering::Relaxed),
            before,
            "offline replay made a network request"
        );
    }
    // Reuse committed chunks with the source switched off. The matching source
    // configuration stays in provenance, but resuming requires no network calls.
    server.abort();
    let archive = temp.path().join("archive-disabled");
    let out = temp.path().join("resume.so");
    let result = run(&[
        "recover",
        "--program",
        &program,
        "--slots",
        "432001:432003",
        "--index-base",
        &base,
        "--car-base",
        &base,
        "--resume",
        archive.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ])
    .await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(archive.join("archive.json")).unwrap()).unwrap();
    let stem = manifest["chunks"][0]["stem"].as_str().unwrap();
    let raw = archive.join(format!("{stem}.raw"));
    let mut bytes = std::fs::read(&raw).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(raw, bytes).unwrap();
    let bad = temp.path().join("bad.so");
    let result = run(&[
        "replay",
        "--archive",
        archive.to_str().unwrap(),
        "--out",
        bad.to_str().unwrap(),
    ])
    .await;
    assert!(!result.status.success());
    assert!(!bad.exists());
}

async fn start_server(car: Vec<u8>, index: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let car = Arc::new(car);
    let index = Arc::new(index);
    let requests = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(serve(socket, car.clone(), index.clone(), requests.clone()));
        }
    });
    (base, server)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn buffer_mode_and_resuming_a_partial_chunk_preserve_exact_bytes() {
    let (car, index) = fixture();
    let (base, server) = start_server(car, index).await;
    let temp = tempfile::tempdir().unwrap();
    let archive = temp.path().join("evidence");
    let out = temp.path().join("buffer.so");
    let buffer = buffer().to_string();
    let args = [
        "recover",
        "--buffer",
        &buffer,
        "--slots",
        "432001:432003",
        "--index-base",
        &base,
        "--car-base",
        &base,
        "--archive",
        archive.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ];
    let result = run(&args).await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(std::fs::read(&out).unwrap(), elf());
    let second = run(&args).await;
    assert!(!second.status.success());
    assert_eq!(std::fs::read(&out).unwrap(), elf());
    // Simulate an interruption before the chunk's journal commit: its raw/proof
    // files and a partially received record exist but are not complete evidence.
    let manifest_path = archive.join("archive.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    manifest["complete"] = serde_json::json!(false);
    manifest["chunks"] = serde_json::json!([]);
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let partial = rewind::archive::chunk_stem(
        Target::Buffer(buffer.parse().unwrap()),
        SearchRange::inclusive(432001, 432003).unwrap(),
    );
    std::fs::write(archive.join(format!("{partial}.partial")), [0; 32]).unwrap();
    let resumed = temp.path().join("resumed.so");
    let result = run(&[
        "recover",
        "--buffer",
        &buffer,
        "--slots",
        "432001:432003",
        "--index-base",
        &base,
        "--car-base",
        &base,
        "--resume",
        archive.to_str().unwrap(),
        "--out",
        resumed.to_str().unwrap(),
    ])
    .await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(std::fs::read(resumed).unwrap(), elf());
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_unrelated_source_coverage_and_missing_baseline_never_publish() {
    let (car, index) = fixture_omitting(true);
    let (base, server) = start_server(car, index).await;
    let temp = tempfile::tempdir().unwrap();
    let program = program().to_string();
    let archive = temp.path().join("missing-tx");
    let out = temp.path().join("bad.so");
    let result = run(&[
        "recover",
        "--program",
        &program,
        "--slots",
        "432001:432003",
        "--index-base",
        &base,
        "--car-base",
        &base,
        "--archive",
        archive.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ])
    .await;
    assert!(!result.status.success());
    assert!(!out.exists());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(archive.join("archive.json")).unwrap()).unwrap();
    assert_eq!(manifest["complete"], false);
    server.abort();
    let (car, index) = fixture();
    let (base, server) = start_server(car, index).await;
    let archive = temp.path().join("missing-baseline");
    let result = run(&[
        "recover",
        "--program",
        &program,
        "--slots",
        "432002:432003",
        "--index-base",
        &base,
        "--car-base",
        &base,
        "--archive",
        archive.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ])
    .await;
    assert!(!result.status.success());
    assert!(!out.exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("HistoryOutsideSearchRange"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(archive.join("archive.json")).unwrap()).unwrap();
    assert_eq!(manifest["complete"], false);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "downloads real historical CAR data; run explicitly with archive network access"]
async fn historical_closed_program_archive_only() {
    let temp = tempfile::tempdir().unwrap();
    let archive = temp.path().join("archive");
    let out = temp.path().join("program.so");
    let result = run(&[
        "recover",
        "--program",
        "31fGaME7XZQsCncCjtTN2CckuSmpqDQChoUfr2X1jGXR",
        "--slots",
        "432642976:432642980",
        "--history-source",
        "jetstreamer",
        "--archive",
        archive.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ])
    .await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(std::fs::metadata(out).unwrap().len(), 14352);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v4_actual_sdk_auto_detection_source_recovery_offline_replay_and_resume() {
    for source in [false, true] {
        let (car, index) = fixture_records(v4_dataset(source), false);
        let (base, server) = start_server(car, index).await;
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("v4-evidence");
        let out = temp.path().join("v4.so");
        let program = program().to_string();
        let rpc = format!("{base}/rpc-empty");
        let result = run(&[
            "recover",
            "--program",
            &program,
            "--slots",
            "432001:432003",
            "--index-base",
            &base,
            "--car-base",
            &base,
            "--rpc-url",
            &rpc,
            "--archive",
            archive.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .await;
        assert!(
            result.status.success(),
            "source={source}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(std::fs::read(&out).unwrap(), elf());
        let provenance: serde_json::Value =
            serde_json::from_slice(&std::fs::read(rewind::output::manifest_path(&out)).unwrap())
                .unwrap();
        assert_eq!(provenance["loader"], "V4");
        assert_eq!(provenance["loader_id"], LOADER_V4.to_string());
        assert_eq!(
            provenance["selection"]["programdata"],
            serde_json::Value::Null
        );
        // Preserve a valid archive but require recovery to revalidate it and reuse
        // all committed chunks after a simulated interruption before completion.
        let manifest_path = archive.join("archive.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        manifest["complete"] = serde_json::json!(false);
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let resumed = temp.path().join("resumed.so");
        let result = run(&[
            "recover",
            "--program",
            &program,
            "--slots",
            "432001:432003",
            "--index-base",
            &base,
            "--car-base",
            &base,
            "--resume",
            archive.to_str().unwrap(),
            "--out",
            resumed.to_str().unwrap(),
        ])
        .await;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        server.abort();
        let replay = temp.path().join("offline.so");
        let result = run(&[
            "replay",
            "--archive",
            archive.to_str().unwrap(),
            "--out",
            replay.to_str().unwrap(),
        ])
        .await;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(std::fs::read(replay).unwrap(), elf());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v4_buffer_mode_detects_payload_before_source_consumption() {
    let (car, index) = fixture_records(v4_dataset(true), false);
    let (base, server) = start_server(car, index).await;
    let temp = tempfile::tempdir().unwrap();
    let archive = temp.path().join("buffer");
    let out = temp.path().join("buffer.so");
    let buffer = buffer().to_string();
    let result = run(&[
        "recover",
        "--buffer",
        &buffer,
        "--loader",
        "v4",
        "--slots",
        "432001:432003",
        "--index-base",
        &base,
        "--car-base",
        &base,
        "--archive",
        archive.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ])
    .await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(std::fs::read(out).unwrap(), elf());
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_sdk_exports_three_versions_reuses_chunks_and_resumes_offline() {
    for (records, expected_chunks) in [(historical_v3_dataset(), 2), (historical_v4_dataset(), 3)] {
        let last = records.iter().map(|record| record.slot).max().unwrap();
        let (car, index) = fixture_records(records, false);
        let car = Arc::new(car);
        let index = Arc::new(index);
        let requests = Arc::new(AtomicUsize::new(0));
        let server_requests = requests.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                tokio::spawn(serve(
                    socket,
                    car.clone(),
                    index.clone(),
                    server_requests.clone(),
                ));
            }
        });
        let temp = tempfile::tempdir().unwrap();
        let evidence = temp.path().join("evidence");
        let out = temp.path().join("versions");
        let address = program().to_string();
        let range = format!("432001:{last}");
        let rpc = format!("{base}/rpc-empty");
        let mut args = vec![
            "recover",
            "--program",
            &address,
            "--slots",
            &range,
            "--all-versions",
            "--archive",
            evidence.to_str().unwrap(),
            "--out-dir",
            out.to_str().unwrap(),
            "--index-base",
            &base,
            "--car-base",
            &base,
            "--rpc-url",
            &rpc,
        ];
        let result = run(&args).await;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let diagnostics = String::from_utf8_lossy(&result.stderr);
        assert_eq!(
            diagnostics.matches("Jetstreamer: ").count(),
            expected_chunks,
            "one scan per unique account/chunk: {diagnostics}"
        );
        let manifest = rewind::archive::load_manifest(&evidence).unwrap();
        assert!(manifest.complete);
        assert_eq!(manifest.chunks.len(), expected_chunks);
        assert!(
            manifest
                .chunks
                .iter()
                .all(|chunk| chunk.range == manifest.config.range)
        );
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("versions.json")).unwrap()).unwrap();
        assert_eq!(index["complete"], true);
        for (i, version) in index["versions"].as_array().unwrap().iter().enumerate() {
            let mut expected = elf();
            *expected.last_mut().unwrap() = i as u8;
            assert_eq!(
                std::fs::read(out.join(version["filename"].as_str().unwrap())).unwrap(),
                expected
            );
        }
        let before = requests.load(Ordering::Relaxed);
        server.abort();
        // A completed bulk resume rechecks its evidence/files without RPC or archive requests.
        let archive_index = args.iter().position(|arg| *arg == "--archive").unwrap();
        args[archive_index] = "--resume";
        let result = run(&args).await;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let replay = temp.path().join("offline");
        let result = run(&[
            "replay",
            "--all-versions",
            "--archive",
            evidence.to_str().unwrap(),
            "--out-dir",
            replay.to_str().unwrap(),
        ])
        .await;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(requests.load(Ordering::Relaxed), before);
        assert_eq!(
            std::fs::read(replay.join("versions.json")).unwrap(),
            std::fs::read(out.join("versions.json")).unwrap()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_failed_shared_source_is_requested_once_per_run() {
    let (car, index) = fixture();
    let car = Arc::new(car);
    let index = Arc::new(index);
    let requests = Arc::new(AtomicUsize::new(0));
    let server_requests = requests.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(serve(
                socket,
                car.clone(),
                index.clone(),
                server_requests.clone(),
            ));
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("evidence");
    let out = temp.path().join("versions");
    let mut config = config();
    config.range.end = 432024;
    config.index_base = format!("{base}/unavailable");
    config.car_base = base.clone();
    let mut archive =
        rewind::archive::Archive::open_history(&root, config.clone(), false, 3).unwrap();
    let bytes = stream(&historical_v3_dataset());
    let partial = root.join("fixture.partial");
    archive.reserve(bytes.len() as u64).unwrap();
    std::fs::write(&partial, bytes).unwrap();
    archive
        .commit(
            config.target,
            config.range,
            &partial,
            Coverage {
                range: config.range,
                index_hash: rewind::coverage::hash(b"fixture"),
                slots: vec![],
            },
        )
        .unwrap();
    drop(archive);
    let result = run(&[
        "recover",
        "--all-versions",
        "--program",
        &program().to_string(),
        "--slots",
        "432001:432023",
        "--max-versions",
        "3",
        "--keep-going",
        "--resume",
        root.to_str().unwrap(),
        "--out-dir",
        out.to_str().unwrap(),
        "--index-base",
        &config.index_base,
        "--car-base",
        &base,
    ])
    .await;
    assert!(!result.status.success());
    assert_eq!(
        requests.load(Ordering::Relaxed),
        1,
        "shared unavailable source should not be retried by every version"
    );
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("versions.json")).unwrap()).unwrap();
    assert_eq!(index["complete"], false);
    assert!(
        index["versions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|version| version["status"] == "failed"
                && version["error"]["kind"] == "missing_source")
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_cancellation_stops_a_worker_waiting_for_car_data() {
    let (car, index) = fixture_records(historical_v3_dataset(), false);
    let car = Arc::new(car);
    let index = Arc::new(index);
    let requests = Arc::new(AtomicUsize::new(0));
    let stalled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let marker = stalled.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let (car, index, requests, marker) =
                (car.clone(), index.clone(), requests.clone(), marker.clone());
            tokio::spawn(async move {
                let mut prefix = [0; 64];
                let count = loop {
                    let count = socket.peek(&mut prefix).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    if count >= 25 {
                        break count;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                };
                if prefix[..count].starts_with(b"GET /1/epoch-1.car ") {
                    marker.store(true, Ordering::Release);
                    // Hold the response open until the test runtime drops this task.
                    std::future::pending::<()>().await;
                } else {
                    serve(socket, car, index, requests).await;
                }
            });
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("evidence");
    let out = temp.path().join("versions");
    let child = Command::new(env!("CARGO_BIN_EXE_rewind"))
        .args([
            "recover",
            "--all-versions",
            "--program",
            &program().to_string(),
            "--slots",
            "432001:432023",
            "--archive",
            root.to_str().unwrap(),
            "--out-dir",
            out.to_str().unwrap(),
            "--index-base",
            &base,
            "--car-base",
            &base,
        ])
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !stalled.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker never requested CAR data");
    // Signal only the coordinator created by this test, not the test process/group.
    assert_eq!(
        unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGINT) },
        0
    );
    let result = tokio::time::timeout(Duration::from_secs(8), child.wait_with_output())
        .await
        .expect("cancelled coordinator/worker did not terminate")
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("Interrupted"));
    assert!(!root.join(".lock").exists());
    assert!(!out.join(".rewind.lock").exists());
    let manifest = rewind::archive::load_manifest(&root).unwrap();
    assert!(!manifest.complete);
    assert!(!manifest.history.unwrap().discovery_complete);
    server.abort();
}
