//! RPC is a finite hint probe. It never certifies coverage or gates archive recovery.
use crate::{Result, coverage::bounded_body, ensure, types::*};
use serde_json::{Value, json};
use std::time::Duration;

async fn call(client: &reqwest::Client, url: &str, method: &str, params: Value) -> Result<Value> {
    let mut last_error = None;
    for _ in 0..2 {
        let result: Result<Value> = async {
            let response = client
                .post(url)
                .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
                .send()
                .await?;
            let bytes = bounded_body(response, 4 * 1024 * 1024).await?;
            let body: Value = serde_json::from_slice(&bytes)?;
            ensure!(body.get("error").is_none(), "RPC returned an error");
            body.get("result")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("RPC result missing"))
        }
        .await;
        match result {
            Ok(value) => return Ok(value),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("two attempts"))
}

pub async fn probe(
    url: Option<&str>,
    config: &RecoveryConfig,
    archive_only: bool,
) -> Result<String> {
    let Some(url) = url.filter(|_| !archive_only) else {
        return Ok("disabled; Jetstreamer discovers history directly".into());
    };
    let parsed = reqwest::Url::parse(url)?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https"),
        "InvalidConfig: RPC URL must be HTTP(S)"
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    // A positively identified wrong cluster is a configuration error. Unavailable
    // RPC metadata is allowed: the archive-only path has its own fixed identity.
    if let Ok(genesis) = call(&client, url, "getGenesisHash", json!([])).await {
        ensure!(
            genesis.as_str() == Some(GENESIS),
            "InvalidConfig: RPC genesis is not mainnet-beta"
        );
    }
    let work = async {
        let mut before: Option<String> = None;
        let mut cursors = std::collections::HashSet::with_capacity(32);
        let mut signatures = 0;
        let mut fetched = 0;
        let mut previous_slot = u64::MAX;
        for _ in 0..32 {
            let mut options = json!({"commitment":"finalized","limit":1000});
            if let Some(before) = &before {
                options["before"] = json!(before);
            }
            let result = call(
                &client,
                url,
                "getSignaturesForAddress",
                json!([config.target.address().to_string(), options]),
            )
            .await?;
            let rows = result
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("RPC signature array missing"))?;
            ensure!(rows.len() <= 1000, "RPC page exceeds limit");
            if rows.is_empty() {
                return Ok::<_, anyhow::Error>(format!(
                    "empty/exhausted after {signatures} signatures; history remains unproven; using Jetstreamer"
                ));
            }
            for row in rows {
                let slot = row["slot"]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("RPC slot missing"))?;
                ensure!(slot <= previous_slot, "RPC pagination order inconsistent");
                previous_slot = slot;
                let signature = row["signature"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("RPC signature missing"))?;
                signature.parse::<solana_signature::Signature>()?;
                signatures += 1;
                // Fetch bounded transaction hints, without trusting parsed instruction
                // output or using it to narrow authoritative archive coverage.
                if slot >= config.range.start
                    && slot < config.range.end
                    && fetched < 16
                    && row["err"].is_null()
                {
                    let _ = call(&client, url, "getTransaction", json!([signature,{"encoding":"json","commitment":"finalized","maxSupportedTransactionVersion":1}])).await?;
                    fetched += 1;
                }
            }
            if previous_slot < config.range.start || rows.len() < 1000 {
                return Ok(format!(
                    "{signatures} signature hints, {fetched} transaction probes; coverage unproven; using Jetstreamer"
                ));
            }
            let cursor = rows
                .last()
                .and_then(|row| row["signature"].as_str())
                .ok_or_else(|| anyhow::anyhow!("RPC cursor missing"))?
                .to_owned();
            ensure!(cursors.insert(cursor.clone()), "RPC cursor did not advance");
            before = Some(cursor);
        }
        Ok(format!(
            "truncated at {signatures} hints (page budget); using Jetstreamer"
        ))
    };
    Ok(
        match tokio::time::timeout(Duration::from_secs(30), work).await {
            Ok(Ok(report)) => report,
            Ok(Err(_)) => {
                "unavailable, pruned, or inconsistent RPC history; using Jetstreamer".into()
            }
            Err(_) => "RPC hint deadline exhausted; using Jetstreamer".into(),
        },
    )
}
