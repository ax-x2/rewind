use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signature::Signature;

pub const FORMAT: u32 = 2;
pub const SDK_REVISION: &str = "c7ba76b017c830d7e2ac4b13690939202d95c511";
pub const V4_CLIENT_REVISION: &str = "76f8ce27d3bcb7492e5adb83c6eae8b5a6d2ee39";
pub const GENESIS: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
pub const SLOTS_PER_EPOCH: u64 = 432_000;
pub const CHUNK_SLOTS: u64 = 8192;
pub const MAX_TX: usize = 65_536;
pub const MAX_FRAME: usize = 256 * 1024;
pub const MAX_PAYLOAD: usize = 10 * 1024 * 1024;
pub const MAX_SPOOL: u64 = 1024 * 1024 * 1024;
pub const LOADER: Address = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
pub const LOADER_V4: Address = solana_loader_v4_program_client::ID;
pub const NATIVE_V4: Address = solana_sdk_ids::loader_v4::ID;
pub const SYSTEM: Address = Address::from_str_const("11111111111111111111111111111111");

pub fn managed_loader(id: Address) -> bool {
    matches!(id, LOADER | LOADER_V4 | NATIVE_V4)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoaderKind {
    #[default]
    V3,
    V4,
}

impl LoaderKind {
    pub fn id(self) -> Address {
        match self {
            Self::V3 => LOADER,
            Self::V4 => LOADER_V4,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum LoaderPolicy {
    Auto,
    #[default]
    V3,
    V4,
}

impl LoaderPolicy {
    pub fn accepts(self, kind: LoaderKind) -> bool {
        matches!(
            (self, kind),
            (Self::Auto, _) | (Self::V3, LoaderKind::V3) | (Self::V4, LoaderKind::V4)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchRange {
    pub start: u64,
    pub end: u64,
}

impl SearchRange {
    pub fn inclusive(first: u64, last: u64) -> Result<Self> {
        ensure!(first <= last, "InvalidRange: first slot exceeds last slot");
        let end = last
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("InvalidRange: overflow"))?;
        Ok(Self { start: first, end })
    }

    pub fn chunks(self) -> impl Iterator<Item = Self> {
        let mut next = self.start;
        std::iter::from_fn(move || {
            if next >= self.end {
                return None;
            }
            let epoch_end = (next / SLOTS_PER_EPOCH + 1).saturating_mul(SLOTS_PER_EPOCH);
            let end = next
                .saturating_add(CHUNK_SLOTS)
                .min(epoch_end)
                .min(self.end);
            let range = Self { start: next, end };
            next = end;
            Some(range)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    Program(Address),
    Buffer(Address),
}

impl Target {
    pub fn address(self) -> Address {
        match self {
            Self::Program(p) | Self::Buffer(p) => p,
        }
    }
    pub fn related(self, key: &Address) -> bool {
        *key == self.address() || matches!(self, Self::Program(p) if *key == programdata(&p))
    }
}

pub fn programdata(program: &Address) -> Address {
    solana_loader_v3_interface::get_program_data_address(program)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OrderKey {
    pub slot: u64,
    pub transaction: u32,
    pub outer: u16,
    pub ordinal: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawInstruction {
    pub program: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
    pub outer: u16,
    pub ordinal: u16,
    pub depth: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub slot: u64,
    pub index: u32,
    pub signature: Signature,
    pub keys: Vec<Address>,
    pub instructions: Vec<RawInstruction>,
    pub logs: Option<Vec<String>>,
}

impl TransactionRecord {
    pub fn key(&self, instruction: &RawInstruction) -> OrderKey {
        OrderKey {
            slot: self.slot,
            transaction: self.index,
            outer: instruction.outer,
            ordinal: instruction.ordinal,
        }
    }

    pub fn account(&self, ix: &RawInstruction, role: usize) -> Result<Address> {
        let index = ix
            .accounts
            .get(role)
            .ok_or_else(|| anyhow::anyhow!("MalformedInstruction: missing account role {role}"))?;
        self.keys
            .get(*index as usize)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("MalformedInstruction: account index out of bounds"))
    }

    pub fn program(&self, ix: &RawInstruction) -> Result<Address> {
        self.keys
            .get(ix.program as usize)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("MalformedInstruction: program index out of bounds"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selection {
    #[serde(default)]
    pub loader: LoaderKind,
    pub program: Address,
    pub programdata: Option<Address>,
    pub buffer: Address,
    pub position: OrderKey,
    pub signature: Signature,
    pub capacity: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryConfig {
    #[serde(default)]
    pub loader: LoaderPolicy,
    pub target: Target,
    pub range: SearchRange,
    pub deployment: Option<Signature>,
    pub index_base: String,
    pub car_base: String,
    pub genesis: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotCoverage {
    pub slot: u64,
    pub transactions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub range: SearchRange,
    pub index_hash: String,
    pub slots: Vec<SlotCoverage>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Frame {
    Transaction(TransactionRecord),
    Progress(u64),
    Complete(Coverage),
    Error(String),
}
