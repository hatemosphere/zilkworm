use base64::{self, Engine};
use reqwest::Client;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tracing::{error, info, warn};

#[derive(Clone, Debug)]
pub struct EthProofsConfig {
    pub endpoint: String,
    pub token: String,
    pub cluster_id: u64,
}

#[derive(Clone, Debug)]
pub struct EthproofsClient {
    cluster_id: u64,
    endpoint: String,
    api_token: String,
    client: Client,
    /// When set, proved payloads that exhaust the retry ladder are written here
    /// and resubmitted by [`Self::resubmit_spooled`] until accepted or expired,
    /// so a sustained ethproofs outage cannot discard computed proofs.
    pub spool_dir: Option<PathBuf>,
}

impl EthproofsClient {
    pub fn new(config: EthProofsConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            cluster_id: config.cluster_id,
            endpoint: config.endpoint,
            api_token: config.token,
            client,
            spool_dir: None,
        }
    }

    // Transient ethproofs outages happen (2026-07-27: ~9s of 500s cost a scored
    // block); callers are detached tokio tasks, so waiting out a blip is free.
    async fn post_json(&self, path: &str, json: &serde_json::Value) -> Result<(), String> {
        const RETRY_DELAYS_SECS: [u64; 4] = [2, 10, 30, 60];

        let mut last_err;
        match self.post_json_once(path, json).await {
            Ok(()) => return Ok(()),
            Err((false, msg)) => return Err(msg),
            Err((true, msg)) => last_err = msg,
        }
        for (i, delay) in RETRY_DELAYS_SECS.iter().enumerate() {
            tokio::time::sleep(Duration::from_secs(*delay)).await;
            warn!("ethproofs {} retry {}/{} after: {}", path, i + 1, RETRY_DELAYS_SECS.len(), last_err);
            match self.post_json_once(path, json).await {
                Ok(()) => return Ok(()),
                Err((false, msg)) => return Err(msg),
                Err((true, msg)) => last_err = msg,
            }
        }
        Err(last_err)
    }

    /// Err is (retryable, message): retryable = transport failure or 408/429/5xx.
    async fn post_json_once(&self, path: &str, json: &serde_json::Value) -> Result<(), (bool, String)> {
        let url = format!("{}{}", self.endpoint, path);

        // Print the full request JSON (truncate proof field to avoid flooding logs)
        let mut debug_json = json.clone();
        if let Some(obj) = debug_json.as_object_mut() {
            if let Some(proof_val) = obj.get("proof") {
                if let Some(s) = proof_val.as_str() {
                    if s.len() > 100 {
                        obj.insert("proof".to_string(), serde_json::json!(format!("{}...({} chars)", &s[..80], s.len())));
                    }
                }
            }
        }
        info!("ethproofs POST {}\n  {}", url, serde_json::to_string_pretty(&debug_json).unwrap_or_default());

        let response = self.client.post(&url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(json)
            .send()
            .await
            .map_err(|e| (true, format!("request failed: {}", e)))?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status.is_success() {
            info!("ethproofs {} -> {} {}", path, status, &body);
            Ok(())
        } else {
            let msg = format!("ethproofs {} -> {} {}", path, status, body);
            error!("{}", msg);
            let retryable = status.is_server_error()
                || status == reqwest::StatusCode::REQUEST_TIMEOUT
                || status == reqwest::StatusCode::TOO_MANY_REQUESTS;
            Err((retryable, msg))
        }
    }

    pub async fn queued(&self, block_number: u64) {
        let json = serde_json::json!({
            "block_number": block_number,
            "cluster_id": self.cluster_id,
        });
        if let Err(e) = self.post_json("/proofs/queued", &json).await {
            warn!("ethproofs queued block={} failed: {}", block_number, e);
        }
    }

    pub async fn proving(&self, block_number: u64) {
        let json = serde_json::json!({
            "block_number": block_number,
            "cluster_id": self.cluster_id,
        });
        if let Err(e) = self.post_json("/proofs/proving", &json).await {
            warn!("ethproofs proving block={} failed: {}", block_number, e);
        }
    }

    pub async fn proved(
        &self,
        proof_bytes: &[u8],
        block_number: u64,
        cycle_count: u64,
        proving_millis: u64,
        verifier_id: &str,
    ) {
        let proof_b64 = base64::engine::general_purpose::STANDARD.encode(proof_bytes);
        info!(
            "ethproofs proved block={} cycles={} time={}ms proof_size={} proof_b64_len={}",
            block_number, cycle_count, proving_millis, proof_bytes.len(), proof_b64.len()
        );

        let json = serde_json::json!({
            "block_number": block_number,
            "cluster_id": self.cluster_id,
            "proving_time": proving_millis,
            "proving_cycles": cycle_count,
            "proof": proof_b64,
            "verifier_id": verifier_id,
        });

        if let Err(e) = self.post_json("/proofs/proved", &json).await {
            error!("ethproofs proved block={} FAILED: {}", block_number, e);
            self.spool(block_number, &json);
        }
    }

    fn spool(&self, block_number: u64, json: &serde_json::Value) {
        let Some(dir) = &self.spool_dir else { return };
        let write = || -> std::io::Result<()> {
            std::fs::create_dir_all(dir)?;
            let tmp = dir.join(format!("{}.json.tmp", block_number));
            std::fs::write(&tmp, serde_json::to_vec(json).unwrap_or_default())?;
            std::fs::rename(&tmp, dir.join(format!("{}.json", block_number)))
        };
        match write() {
            Ok(()) => info!("ethproofs proved block={} spooled for resubmission", block_number),
            Err(e) => error!("ethproofs spool block={} failed: {}", block_number, e),
        }
    }

    /// Resubmits spooled proved payloads. Files are removed on acceptance, on a
    /// 4xx (permanent), on parse failure, or after 6 days (past the weekly
    /// snapshot window they can no longer count).
    pub async fn resubmit_spooled(&self) {
        let Some(dir) = &self.spool_dir else { return };
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let expired = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .is_some_and(|age| age > Duration::from_secs(6 * 24 * 3600));
            if expired {
                warn!("ethproofs spool {:?} expired, dropping", path.file_name());
                let _ = std::fs::remove_file(&path);
                continue;
            }
            let json: serde_json::Value = match std::fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
            {
                Some(v) => v,
                None => {
                    warn!("ethproofs spool {:?} unreadable, dropping", path.file_name());
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
            };
            match self.post_json("/proofs/proved", &json).await {
                Ok(()) => {
                    info!("ethproofs spool {:?} resubmitted OK", path.file_name());
                    let _ = std::fs::remove_file(&path);
                }
                Err(e) if e.contains("-> 4") => {
                    warn!("ethproofs spool {:?} rejected permanently: {}", path.file_name(), e);
                    let _ = std::fs::remove_file(&path);
                }
                Err(e) => warn!("ethproofs spool {:?} resubmit failed, keeping: {}", path.file_name(), e),
            }
        }
    }
}
