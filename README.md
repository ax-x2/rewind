# Rewind

Recover Solana loader-v3 and CoreBPF loader-v4 payloads from historical transactions, including closed program/upload accounts. Rewind uses the **Jetstreamer Rust SDK** to search an explicit slot/epoch range, discover the payload account and deployment sources, collect raw instructions, and reconstruct bytes in ledger order.

`getSignaturesForAddress` is optional. Recovery works with RPC disabled, pruned history, empty responses, and incomplete signature pages. RPC hints never exclude required archive history.

## Build

Requires Linux, Rust 1.99+, the native build prerequisites used by Jetstreamer/Agave (including a C/C++ toolchain, CMake, pkg-config and libclang), and access to the Git dependencies on the first build. Cargo fetches both dependencies automatically; sibling checkouts are not required.

```sh
cargo build --release --locked
target/release/rewind --help
```

`Cargo.toml` pins the [Jetstreamer fork](https://github.com/vaultic-win/jetstreamer/tree/c7ba76b017c830d7e2ac4b13690939202d95c511) and [loader-v4 client](https://github.com/solana-program/loader-v4/tree/76f8ce27d3bcb7492e5adb83c6eae8b5a6d2ee39) to tested Git commits. `Cargo.lock` records those sources and the compatible Agave dependency set. Updating these dependencies requires reviewing the integration and the revision constants used in archive/output provenance. No project build script or local checkout verification is needed.

## Recover a program

The search range is inclusive and must include the buffer's creation and upload, as well as the selected deployment/upgrade:

```sh
target/release/rewind recover \
  --program 31fGaME7XZQsCncCjtTN2CckuSmpqDQChoUfr2X1jGXR \
  --slots 432642976:432642980 \
  --history-source jetstreamer \
  --archive ./program-evidence \
  --out ./program.so
```

The program account may already be closed. `--loader auto` is the default: infer the loader from successful historical management instructions and choose the latest matching deployment/upgrade **inside the search range**. Use `--loader v3` or `--loader v4` to restrict selection. `--deployment-signature SIGNATURE` selects a particular deployment; ambiguous matches are rejected.

Use `--epochs FIRST:LAST` instead of `--slots` for inclusive mainnet epoch bounds. Mainnet's supported epoch schedule has 432000 slots per epoch. Rewind supports mainnet-beta, loader-v3, the supplied CoreBPF loader-v4 interface, HTTP(S) CAR archives, and Old Faithful's `slot-ranges.raw` presence indexes.

If the buffer's creation or initialization predates the lower bound, recovery fails with `HistoryOutsideSearchRange`. Start a new recovery with an earlier bound. Rewind never silently expands the requested search.

For a known buffer, substitute `--buffer BUFFER_ADDRESS` for `--program`. The output is its latest incarnation's active payload at the range end, or the payload just before that incarnation's deployment/upgrade/close. Provenance identifies the chosen boundary.

## Export all historical versions (optional)

Normal recovery exports one version. Add `--all-versions` and use `--out-dir` to export every successful matching deployment/upgrade inside the requested range:

```sh
target/release/rewind recover --program PROGRAM_ADDRESS --slots FIRST:LAST \
  --all-versions --history-source jetstreamer \
  --archive ./all-version-evidence --out-dir ./versions

target/release/rewind recover --program PROGRAM_ADDRESS --slots FIRST:LAST \
  --all-versions --resume ./all-version-evidence --out-dir ./versions

target/release/rewind replay --archive ./all-version-evidence \
  --all-versions --out-dir ./offline-versions
```

Bulk mode supports loader-v3 and the supplied CoreBPF loader-v4. It requires `--program`, `--out-dir` and a persistent `--archive` or `--resume`. It conflicts with `--buffer`, `--out` and `--deployment-signature`. Without the flag, the latest/explicit-signature single-version behavior remains the default.

Program deployment history is discovered once. Versions are reconstructed oldest-first, one at a time; verified evidence is shared across versions. Source scans use fixed chunks inside the explicit search range, while each replay enforces its exact deployment instruction cutoff. Distinct source accounts may still require separate archive scans. The range must include necessary upload/source creation baselines; bulk mode never expands it automatically.

Each deployment gets `<slot>-<transaction>-<outer>-<ordinal>-<signature>.so` and a `.so.json` provenance sidecar. Separate deployments remain separate entries even when their hashes match. `versions.json` lists every discovered version, its identity, filename, payload size/hash and publication state (`pending`, `published`, or `failed`). Its `complete` flag is true only when every version is exported successfully.

The default is fail-fast: prior exports remain available and unprocessed versions stay pending. `--keep-going` continues after a version has an unavailable baseline/source or invalid ELF; any failed version still makes the command exit nonzero. Corrupt/conflicting evidence, ambiguous execution, unsupported mutations, local I/O errors, resource exhaustion and cancellation stop the run. Worker failures that cannot be distinguished safely from incomplete/corrupt history also stop the run. Failed shared index requests are not retried for each dependent version during the same run; an explicit resume can retry them.

`--max-versions N` defaults to 1024 and cannot exceed 1024. Discovery exceeding that bound fails before any binary export. `--max-output-bytes N` limits the sum of exported binary sizes, including existing files on resume, and defaults to a hard maximum of 1073741824 bytes (1 GiB). Both limits can be lowered. The evidence archive retains its separate 1 GiB quota and 16384-chunk limit. When using a lower version limit, repeat `--max-versions N` on recovery resume to match the archive. Replay uses the archive's recorded version limit.

Resume/replay rechecks discovery, source proofs, exact payloads, existing hashes and sidecars; existence alone never means success. Missing binaries/sidecars can be regenerated when both are absent. A matching binary left without its sidecar before publication completed can have the sidecar completed; mismatching files and orphan sidecars are rejected and never overwritten. Evidence and output directories must be separate. Each output directory has an exclusive `.rewind.lock`; after a forced kill, confirm no exporter is running before removing a stale lock. An existing nonempty output directory must have a matching `versions.json`; unrelated files and symlinks are rejected.

Offline bulk replay also accepts an incomplete batch if deployment discovery finished. It exports versions whose required evidence is available, reports missing source evidence, and never initializes network clients. Use `--keep-going` to attempt the remaining versions. Incomplete deployment discovery cannot establish an exhaustive version list and is rejected.

Bulk publication reserves `.rewind-tmp-XXXXXX` names for unfinished binary, sidecar and index writes. Under the output lock, resume removes at most 16 matching regular temporary files (each at most 10 MiB) left by a crash. Symlinks and unrelated names are rejected.

## CoreBPF loader-v4

```sh
target/release/rewind recover --program PROGRAM_ADDRESS --loader v4 \
  --slots FIRST:LAST --history-source jetstreamer \
  --archive ./v4-evidence --out ./program-v4.so
```

This uses the supplied [Rust client](https://github.com/solana-program/loader-v4/tree/76f8ce27d3bcb7492e5adb83c6eae8b5a6d2ee39/clients/rust) for program ID `CoreBPFLoaderV41111111111111111111111111111`. Its six Borsh instruction tags differ from the older native `LoaderV411...` interface, which includes a Copy operation and is explicitly unsupported. The CoreBPF encoding is defined in the [client's generated instructions](https://github.com/solana-program/loader-v4/tree/76f8ce27d3bcb7492e5adb83c6eae8b5a6d2ee39/clients/rust/src/generated/instructions).

V4 keeps payload bytes in the program account. Deploy may use that account's bytes or take a separate source account; Rewind discovers and resolves the source at the exact deployment position. Earlier source deployments are followed recursively. An in-place redeployment after source replacement reconstructs the replacement and subsequent committed writes. Finalize's next-version pointer is metadata and is not followed as a byte source.

V4 replay handles initial Truncate, writes, shrink/grow, zero-size close, recreation, Deploy, Retract, authority transfer and Finalize. Resizing preserves retained bytes, discards truncated bytes and written-byte coverage, and zero-fills newly exposed bytes. Baselines require successful zero-size CoreBPF-owned System creation followed by a positive Truncate, an observed zero-size reset followed by initialization, or a fully recovered source replacement. This avoids guessing account-header size or treating an unknown earlier allocation as zero. A later complete replacement supersedes older payload history; only required source dependencies are resolved.

The output sidecar records the loader ID/client revision, selected deployment and original baseline account. Payload origin can differ from the final program and immediate upload source when deployments form a chain. Supporting the generated instruction format and source reconstruction does not verify execution in a validator; v4 tests use generated wire instructions and synthetic historical CAR fixtures. No real v4 historical address fixture is currently supplied.

## Optional RPC and archive mirrors

Omit `--rpc-url` for archive-only recovery. To request bounded RPC hints:

```sh
target/release/rewind recover --program PROGRAM_ADDRESS \
  --slots FIRST:LAST --rpc-url https://your-rpc.example \
  --archive ./evidence --out ./program.so
```

`--history-source jetstreamer` bypasses an RPC URL even when one is supplied. A positively identified RPC genesis mismatch is a configuration error. RPC runtime failures fall back to Jetstreamer.

`--index-base URL` and `--car-base URL` select archive mirrors. Defaults honor `JETSTREAMER_COMPACT_INDEX_BASE_URL`, `JETSTREAMER_HTTP_BASE_URL`, then `JETSTREAMER_ARCHIVE_BASE`, otherwise `https://files.old-faithful.net`. Mirrors must serve mainnet history. Base URLs cannot include query strings or fragments.

The SDK downloads slot CAR ranges and decodes transactions before callbacks. Filtering discards unrelated data at the earliest available callback; it does not remove all unrelated network traffic or SDK decode costs. Program discovery followed by buffer collection can require two scans of overlapping history.

## Evidence, replay, and resume

```sh
target/release/rewind replay --archive ./program-evidence --out ./replayed.so

target/release/rewind recover --program PROGRAM_ADDRESS --slots FIRST:LAST \
  --resume ./program-evidence --out ./program.so
```

Replay verifies evidence hashes and complete required chunks, selects the same historical deployment, and reconstructs without initializing network clients. Resume requires the same target, range, selection, archive bases, and decoder/SDK versions; it reuses committed chunks and retries incomplete chunks.

New single-version archives use format 2, recording loader policy and account-qualified filenames for independent source histories. Optional bulk archives use format 3 with a frozen deployment list and per-version evidence state. Their archive `complete` flag certifies validated payload evidence; the output directory's `versions.json` separately tracks file publication. Replay/resume must use the same single/bulk mode. Completed format-1 loader-v3 archives remain replayable. Incomplete format-1 scans must start a fresh archive because their historical filter omitted v4 transactions. To resume a completed old v3 archive, use `--loader v3` to match its implicit loader policy.

An explicit `--archive` directory must be new. Omitting it uses a temporary evidence spool, removed after success and retained with its path printed after failure. Each archive uses a `.lock` file to prevent concurrent writers. Normal exit releases the lock. If the coordinator was forcibly killed, confirm that no recovery process is using that directory before removing its stale `.lock`.

Archives contain:

- `archive.json`: versioned configuration, selection, RPC diagnostics and chunk journal. `complete` is set only after required source coverage, reconstruction and ELF validation succeed.
- `program-ADDRESS-START-END.raw` / `buffer-ADDRESS-START-END.raw`: length-prefixed binary transaction envelopes with raw instruction bytes, historical account keys, exact positions, and invocation logs when available. Filenames use an exclusive `END`; format-1 archives used names without `ADDRESS`.
- Matching `.proof` files: index identity, source coverage certificate, raw size and SHA-256.
- `.partial` files after interruption: uncommitted evidence, excluded from replay.

Keep the directory together. Checksums detect accidental alteration; they do not independently authenticate the archive provider. Replay creates bounded temporary sort files in the archive and requires write access and an exclusive lock.

## Reconstruction and resource behavior

Writes are applied by slot, transaction index, outer instruction and inner execution ordinal. Later committed writes overwrite earlier bytes, including partial overlaps. Failed transactions never contribute mutations. Relevant CPI writes require sufficient invocation logs and stack metadata to prove that the invocation and all ancestors committed; ambiguous execution is rejected.

For v3, buffer size comes from successful System creation, excluding loader metadata. `maxDataLen` is ProgramData capacity and is not used to guess upload length. V4 payload length follows its initialization/resizing/source replacement history. Known-zero unwritten bytes require a proven baseline and complete intervening history. Rewind supports `CreateAccount` and `CreateAccountWithSeed`; other allocation/assignment patterns produce an explicit unsupported error.

Output contains the loader buffer payload, including any uploader-allocated padding. It excludes loader headers and ProgramData spare capacity. Structural ELF validation checks ELF64 little-endian SBF objects, header/section/segment bounds and machine identifiers; the binary is never executed. An output `.so.json` sidecar records the payload length, SHA-256, source/configuration, buffer incarnation, chosen deployment and known-zero/written-byte counts. The sidecar is published last as the completion marker. Existing outputs are never overwritten.

The borrowed account filter, write decoder and payload-copy loop allocate nothing after setup. SDK ingestion and boxed callbacks allocate; those costs are isolated in a supervised worker process.

| Resource | Limit |
| --- | --- |
| Concurrent archive workers | 1 |
| Chunk | At most 8192 slots; never crosses an epoch |
| Worker address space | 4 GiB (`RLIMIT_AS`, not an RSS guarantee) |
| SDK sequential download window | 64 MiB where the SDK uses that path |
| Candidate/control queue | 8 entries, backpressure without dropping records |
| Retained candidate transaction | Conservative 1 MiB capacity bound |
| Encoded frame | 256 KiB |
| Transactions per slot | 65536 |
| Sort working storage | 32 MiB for run generation; merge fan-in 16 |
| Buffer payload | 10 MiB |
| Optional bulk versions | At most 1024; one active reconstruction |
| Optional bulk exported binary bytes | 1 GiB including existing binaries on resume |
| Aggregate live v4 payload/coverage storage | 64 MiB, including old/new images during resize |
| V4 source recursion | Depth 16; 64 snapshot requests/reconstruction |
| V4 management operations | 1,000,000 across baseline discovery and replay |
| Archive including sorting temporaries | 1 GiB |
| Search | At most 16384 chunks |
| RPC hints | 32 pages of 1000 signatures; at most 16 transaction probes |
| RPC timeout | 5 seconds/request; 2 attempts; 30-second pagination/hint budget, plus bounded genesis identification |
| Archive deadline | 120 seconds without new progress; 30 minutes/chunk |
| SDK retry errors | 3 without completed-slot progress; 16 total/chunk |

The coordinator owns reconstruction and disk I/O. V4 source snapshots transfer payload ownership; source recursion creates no new tasks, queues or shared reconstruction locks. Verified chunks covering an earlier source cutoff can be reused while replay enforces the exact instruction boundary. Full queues propagate backpressure into awaited callbacks. Socket buffers are explicitly requested at 64 KiB; the OS may round them. SDK global caches are discarded when each chunk worker exits. Ctrl-C requests shutdown; the coordinator terminates and reaps an unresponsive child after five seconds. Resource exhaustion, missing indexes, incomplete blocks/transactions, corrupt evidence, unsupported mutations and malformed input cannot produce a complete output.

## Validation

```sh
cargo fmt --check
cargo check --locked --all-targets
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Tests cover official/generated instruction encodings, account lookup resolution, overlap/zero handling, CPI rollback, missing history, conflicting duplicates, actual SDK streaming against a local CAR server, RPC fallback, offline replay, source coverage holes, buffer mode, resume, output preservation, corruption and allocation counts. V4 cases include direct/source deployments, source chains, later replacement baselines, historical cutoffs, shrink/regrow, close/recreate, Finalize, depth/memory limits, and v1 archive compatibility.

Bulk cases cover multiple v3 incarnations and v4 source/in-place versions, equal payloads at distinct deployments, opt-in CLI validation, bounded discovery, canonical chunk reuse, empty RPC, offline resume/replay, fail-fast/keep-going, shared unavailable sources, output quotas, interrupted publication, locks, symlinks and fatal corruption.

Run the external historical test explicitly:

```sh
cargo test --locked --test e2e historical_closed_program_archive_only -- --ignored --nocapture
```

