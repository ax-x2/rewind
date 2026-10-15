#![allow(dead_code)]
use rewind::types::*;
use solana_address::Address;
use solana_loader_v3_interface::instruction::UpgradeableLoaderInstruction as L;
use solana_signature::Signature;

pub fn program() -> Address {
    Address::new_from_array([3; 32])
}
pub fn buffer() -> Address {
    Address::new_from_array([4; 32])
}

pub fn elf() -> Vec<u8> {
    let mut bytes = vec![0u8; 184];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&247u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[40..48].copy_from_slice(&120u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    bytes[96..104].copy_from_slice(&184u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&184u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&8u64.to_le_bytes());
    bytes
}

pub fn record(slot: u64, index: u32, id: u8) -> TransactionRecord {
    TransactionRecord {
        slot,
        index,
        signature: Signature::from([id; 64]),
        keys: vec![
            Address::new_from_array([2; 32]),
            buffer(),
            SYSTEM,
            LOADER,
            program(),
            programdata(&program()),
            solana_sdk_ids::sysvar::rent::id(),
            solana_sdk_ids::sysvar::clock::id(),
        ],
        instructions: vec![],
        logs: None,
    }
}

pub fn ix(program: u8, accounts: &[u8], data: Vec<u8>, outer: u16) -> RawInstruction {
    RawInstruction {
        program,
        accounts: accounts.to_vec(),
        data,
        outer,
        ordinal: 0,
        depth: Some(1),
    }
}

pub fn loader(instruction: L, accounts: &[u8], outer: u16) -> RawInstruction {
    ix(
        3,
        accounts,
        bincode::serialize(&instruction).unwrap(),
        outer,
    )
}

pub fn dataset() -> Vec<TransactionRecord> {
    let bytes = elf();
    let mut create = record(432001, 0, 1);
    create.instructions.push(ix(
        2,
        &[0, 1],
        bincode::serialize(
            &solana_system_interface::instruction::SystemInstruction::CreateAccount {
                lamports: 1,
                space: (bytes.len() + 37) as u64,
                owner: LOADER,
            },
        )
        .unwrap(),
        0,
    ));
    create
        .instructions
        .push(loader(L::InitializeBuffer, &[1, 0], 1));
    let mut write = record(432002, 0, 2);
    write.instructions.push(loader(
        L::Write {
            offset: 0,
            bytes: bytes[..92].to_vec(),
        },
        &[1, 0],
        0,
    ));
    let mut write2 = record(432002, 1, 3);
    write2.instructions.push(loader(
        L::Write {
            offset: 92,
            bytes: bytes[92..].to_vec(),
        },
        &[1, 0],
        0,
    ));
    let mut deploy = record(432003, 0, 4);
    deploy.instructions.push(loader(
        L::DeployWithMaxDataLen { max_data_len: 4096 },
        &[0, 5, 4, 1, 6, 7, 2, 0],
        0,
    ));
    vec![create, write, write2, deploy]
}

pub fn stream(records: &[TransactionRecord]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for record in records {
        rewind::archive::write_record(&mut bytes, record).unwrap();
    }
    bytes
}

pub fn config() -> RecoveryConfig {
    RecoveryConfig {
        loader: LoaderPolicy::Auto,
        target: Target::Program(program()),
        range: SearchRange::inclusive(432001, 432003).unwrap(),
        deployment: None,
        index_base: "http://127.0.0.1:1".into(),
        car_base: "http://127.0.0.1:1".into(),
        genesis: GENESIS.into(),
    }
}

pub fn from_instructions(
    slot: u64,
    index: u32,
    id: u8,
    instructions: Vec<solana_instruction::Instruction>,
) -> TransactionRecord {
    let mut record = record(slot, index, id);
    for (outer, instruction) in instructions.into_iter().enumerate() {
        let mut key_index = |key| {
            if let Some(index) = record.keys.iter().position(|existing| *existing == key) {
                index as u8
            } else {
                record.keys.push(key);
                (record.keys.len() - 1) as u8
            }
        };
        let program = key_index(instruction.program_id);
        let accounts = instruction
            .accounts
            .into_iter()
            .map(|account| key_index(account.pubkey))
            .collect();
        record.instructions.push(RawInstruction {
            program,
            accounts,
            data: instruction.data,
            outer: outer as u16,
            ordinal: 0,
            depth: Some(1),
        });
    }
    record
}

pub fn v4_create(account: Address, size: u32) -> Vec<solana_instruction::Instruction> {
    vec![
        solana_system_interface::instruction::create_account(
            &Address::new_from_array([2; 32]),
            &account,
            1,
            0,
            &LOADER_V4,
        ),
        solana_loader_v4_program_client::instructions::Truncate {
            program: account,
            authority: Address::new_from_array([2; 32]),
            destination: None,
        }
        .instruction(
            solana_loader_v4_program_client::instructions::TruncateInstructionArgs {
                new_size: size,
            },
        ),
    ]
}

pub fn v4_write(account: Address, offset: u32, bytes: Vec<u8>) -> solana_instruction::Instruction {
    solana_loader_v4_program_client::instructions::Write {
        program: account,
        authority: Address::new_from_array([2; 32]),
    }
    .instruction(
        solana_loader_v4_program_client::instructions::WriteInstructionArgs { offset, bytes },
    )
}

pub fn v4_deploy(account: Address, source: Option<Address>) -> solana_instruction::Instruction {
    solana_loader_v4_program_client::instructions::Deploy {
        program: account,
        authority: Address::new_from_array([2; 32]),
        source,
    }
    .instruction()
}

pub fn v4_dataset(source: bool) -> Vec<TransactionRecord> {
    let bytes = elf();
    let upload = if source { buffer() } else { program() };
    let mut create = v4_create(upload, bytes.len() as u32);
    if source {
        create.extend(v4_create(program(), bytes.len() as u32));
    }
    vec![
        from_instructions(432001, 0, 11, create),
        from_instructions(
            432002,
            0,
            12,
            vec![v4_write(upload, 0, bytes[..92].to_vec())],
        ),
        from_instructions(
            432002,
            1,
            13,
            vec![v4_write(upload, 92, bytes[92..].to_vec())],
        ),
        from_instructions(
            432003,
            0,
            14,
            vec![v4_deploy(program(), source.then_some(buffer()))],
        ),
    ]
}

/// Three committed versions; later v3 uploads recreate the same buffer address.
pub fn historical_v3_dataset() -> Vec<TransactionRecord> {
    let mut all = Vec::new();
    for version in 0..3u8 {
        let mut records = dataset();
        for record in &mut records {
            record.slot += u64::from(version) * 10;
            record.signature = Signature::from([record.signature.as_ref()[0] + version * 10; 64]);
        }
        if version != 0 {
            records[3].instructions[0] = loader(L::Upgrade, &[5, 4, 1, 0, 6, 7, 0], 0);
        }
        let mut tail = elf()[92..].to_vec();
        *tail.last_mut().unwrap() = version;
        records[2].instructions[0] = loader(
            L::Write {
                offset: 92,
                bytes: tail,
            },
            &[1, 0],
            0,
        );
        all.extend(records);
    }
    all
}

/// Separate sources followed by an in-place v4 redeployment.
pub fn historical_v4_dataset() -> Vec<TransactionRecord> {
    use solana_loader_v4_program_client::instructions::Retract;
    let authority = Address::new_from_array([2; 32]);
    let source = Address::new_from_array([55; 32]);
    let mut all = v4_dataset(true);
    let mut replacement = elf();
    *replacement.last_mut().unwrap() = 1;
    let mut upload = v4_create(source, replacement.len() as u32);
    upload.push(v4_write(source, 0, replacement));
    all.push(from_instructions(432010, 0, 21, upload));
    let retract = || {
        Retract {
            program: program(),
            authority,
        }
        .instruction()
    };
    all.push(from_instructions(
        432011,
        0,
        22,
        vec![retract(), v4_deploy(program(), Some(source))],
    ));
    all.push(from_instructions(
        432020,
        0,
        23,
        vec![
            retract(),
            v4_write(program(), (elf().len() - 1) as u32, vec![2]),
            v4_deploy(program(), None),
        ],
    ));
    all
}
