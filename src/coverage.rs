use crate::{Result, ensure, types::*};
use sha2::{Digest, Sha256};
use std::{
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}
pub fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub async fn bounded_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    response.error_for_status_ref()?;
    ensure!(
        response.content_length().is_none_or(|n| n <= limit as u64),
        "SourceResourceLimit: response length"
    );
    let mut bytes =
        Vec::with_capacity(response.content_length().unwrap_or(4096).min(limit as u64) as usize);
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= limit,
            "SourceResourceLimit: response body"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub fn parse_index(bytes: &[u8], range: SearchRange) -> Result<Vec<bool>> {
    ensure!(
        range.start < range.end && range.end - range.start <= CHUNK_SLOTS,
        "InvalidRange: coverage chunk"
    );
    let epoch = range.start / SLOTS_PER_EPOCH;
    ensure!(
        (range.end - 1) / SLOTS_PER_EPOCH == epoch,
        "InvalidRange: chunk crosses epoch"
    );
    ensure!(
        bytes.len() == SLOTS_PER_EPOCH as usize * 12,
        "UnknownCoverage: invalid slot-ranges index length"
    );
    let mut previous_end = 0;
    for record in bytes.as_chunks::<12>().0 {
        let offset = u64::from_le_bytes(record[..8].try_into()?);
        let length = u32::from_le_bytes(record[8..].try_into()?) as u64;
        if length != 0 {
            ensure!(
                offset >= previous_end,
                "UnknownCoverage: overlapping archive ranges"
            );
            previous_end = offset
                .checked_add(length)
                .ok_or_else(|| anyhow::anyhow!("UnknownCoverage: index overflow"))?;
        }
    }
    Ok((range.start..range.end)
        .map(|slot| {
            let pos = (slot % SLOTS_PER_EPOCH) as usize * 12 + 8;
            bytes[pos..pos + 4] != [0; 4]
        })
        .collect())
}

pub async fn fetch_index(base: &str, range: SearchRange) -> Result<(Vec<bool>, String)> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let epoch = range.start / SLOTS_PER_EPOCH;
    let url = format!(
        "{}/{epoch}/epoch-{epoch}-slot-ranges.raw",
        base.trim_end_matches('/')
    );
    let response = client.get(url).send().await?;
    let bytes = bounded_body(response, 8 * 1024 * 1024).await?;
    Ok((parse_index(&bytes, range)?, hash(&bytes)))
}

pub struct Audit {
    range: SearchRange,
    bits: Vec<AtomicU64>,
    blocks: Vec<AtomicU64>,
    failed: AtomicBool,
}

impl Audit {
    pub fn new(range: SearchRange) -> Result<Self> {
        ensure!(
            range.start < range.end && range.end - range.start <= CHUNK_SLOTS,
            "InvalidRange: audit"
        );
        let slots = (range.end - range.start) as usize;
        Ok(Self {
            range,
            bits: (0..slots * (MAX_TX / 64))
                .map(|_| AtomicU64::new(0))
                .collect(),
            blocks: (0..slots).map(|_| AtomicU64::new(u64::MAX)).collect(),
            failed: AtomicBool::new(false),
        })
    }

    fn index(&self, slot: u64) -> Result<usize> {
        ensure!(
            slot >= self.range.start && slot < self.range.end,
            "UnknownCoverage: callback outside requested range"
        );
        Ok((slot - self.range.start) as usize)
    }

    pub fn transaction(&self, slot: u64, index: usize) -> Result<()> {
        let slot_index = self.index(slot)?;
        ensure!(index < MAX_TX, "SourceResourceLimit: transaction index");
        self.bits[slot_index * (MAX_TX / 64) + index / 64]
            .fetch_or(1u64 << (index % 64), Ordering::Relaxed);
        Ok(())
    }

    pub fn block(&self, slot: u64, count: u64) -> Result<()> {
        let index = self.index(slot)?;
        ensure!(
            count <= MAX_TX as u64,
            "SourceResourceLimit: block transaction count"
        );
        let previous = self.blocks[index].swap(count, Ordering::Relaxed);
        ensure!(
            previous == u64::MAX || previous == count,
            "UnknownCoverage: conflicting block counts"
        );
        Ok(())
    }

    pub fn fail(&self) {
        self.failed.store(true, Ordering::Release);
    }

    pub fn finish(&self, present: &[bool], index_hash: String) -> Result<Coverage> {
        ensure!(
            !self.failed.load(Ordering::Acquire),
            "UnknownCoverage: a handler failed"
        );
        ensure!(
            present.len() == self.blocks.len(),
            "UnknownCoverage: presence length mismatch"
        );
        let mut slots = Vec::new();
        for (i, &expected) in present.iter().enumerate() {
            let count = self.blocks[i].load(Ordering::Relaxed);
            let words = &self.bits[i * (MAX_TX / 64)..(i + 1) * (MAX_TX / 64)];
            if !expected {
                ensure!(
                    count == u64::MAX && words.iter().all(|w| w.load(Ordering::Relaxed) == 0),
                    "UnknownCoverage: data in indexed skipped slot"
                );
                continue;
            }
            ensure!(
                count != u64::MAX,
                "UnknownCoverage: missing block {}",
                self.range.start + i as u64
            );
            for (word_index, word) in words.iter().enumerate() {
                let bits = count.saturating_sub((word_index * 64) as u64).min(64);
                let expected_word = if bits == 64 {
                    u64::MAX
                } else {
                    (1u64 << bits) - 1
                };
                ensure!(
                    word.load(Ordering::Relaxed) == expected_word,
                    "UnknownCoverage: missing/conflicting transaction indexes in slot {}",
                    self.range.start + i as u64
                );
            }
            slots.push(SlotCoverage {
                slot: self.range.start + i as u64,
                transactions: count,
            });
        }
        Ok(Coverage {
            range: self.range,
            index_hash,
            slots,
        })
    }
}
