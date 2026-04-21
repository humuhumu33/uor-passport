use rmcp::model::{CallToolResult, Meta};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Config;

/// The UOR Passport Envelope injected into every tool response via `_meta.uor.passport`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportEnvelope {
    /// Schema version for future-proofing ("uor.passport.v1")
    pub version: String,
    /// SHA-256 fingerprint of the canonical content bytes (64 hex chars)
    pub fingerprint: String,
    /// Hashing algorithm identifier ("uor-sha256-v1")
    pub algorithm: String,
    /// MIME type of the fingerprinted payload
    pub content_type: String,
    /// Byte length of the canonical payload that was hashed
    pub length: usize,
    /// ISO 8601 UTC timestamp of when the passport was issued
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

impl PassportEnvelope {
    pub const VERSION: &'static str = "uor.passport.v1";
    pub const ALGORITHM: &'static str = "uor-sha256-v1";
}

/// Attach a UOR passport to a `CallToolResult`.
///
/// This function is intentionally non-failing: if passport computation encounters any
/// error, it logs a warning and returns the original result unmodified so that MCP
/// clients always receive a valid response.
pub fn attach(mut result: CallToolResult, config: &Config) -> CallToolResult {
    match try_attach(&result, config) {
        Ok(envelope) => {
            if let Ok(v) = serde_json::to_value(&envelope) {
                let meta = result.meta.get_or_insert_with(Meta::new);
                meta.insert("uor.passport".to_string(), v);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "passport attachment failed — returning original result");
        }
    }
    result
}

fn try_attach(result: &CallToolResult, config: &Config) -> anyhow::Result<PassportEnvelope> {
    let payload = serde_json::to_value(&result.content)?;
    let (canonical, content_type) = canonicalize(&payload, config.use_jcs)?;
    Ok(PassportEnvelope {
        version: PassportEnvelope::VERSION.to_string(),
        fingerprint: sha256_hex(&canonical),
        algorithm: PassportEnvelope::ALGORITHM.to_string(),
        content_type,
        length: canonical.len(),
        timestamp: Some(chrono::Utc::now().to_rfc3339()),
    })
}

/// Compute the SHA-256 fingerprint of a JSON value.
///
/// Uses JCS (RFC 8785) canonicalization when `use_jcs` is true, which ensures
/// identical content produces identical fingerprints regardless of key ordering.
pub fn compute_fingerprint(
    value: &serde_json::Value,
    use_jcs: bool,
) -> anyhow::Result<(String, usize)> {
    let (bytes, _ct) = canonicalize(value, use_jcs)?;
    let fp = sha256_hex(&bytes);
    let len = bytes.len();
    Ok((fp, len))
}

fn canonicalize(value: &serde_json::Value, use_jcs: bool) -> anyhow::Result<(Vec<u8>, String)> {
    if use_jcs {
        let bytes = serde_json_canonicalizer::to_vec(value)
            .map_err(|e| anyhow::anyhow!("JCS canonicalization failed: {e}"))?;
        Ok((bytes, "application/json".to_string()))
    } else {
        let bytes = serde_json::to_vec(value)?;
        Ok((bytes, "application/json".to_string()))
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Verify a passport envelope against its claimed content.
pub fn verify(
    content: &serde_json::Value,
    envelope: &PassportEnvelope,
    use_jcs: bool,
) -> VerifyResult {
    match compute_fingerprint(content, use_jcs) {
        Ok((computed_fp, computed_len)) => {
            if computed_fp != envelope.fingerprint {
                VerifyResult {
                    valid: false,
                    reason: Some(format!(
                        "fingerprint mismatch: expected {}, got {computed_fp}",
                        envelope.fingerprint
                    )),
                    computed_fingerprint: Some(computed_fp),
                    expected_fingerprint: Some(envelope.fingerprint.clone()),
                }
            } else if computed_len != envelope.length {
                VerifyResult {
                    valid: false,
                    reason: Some(format!(
                        "length mismatch: expected {}, got {computed_len}",
                        envelope.length
                    )),
                    computed_fingerprint: Some(computed_fp),
                    expected_fingerprint: Some(envelope.fingerprint.clone()),
                }
            } else {
                VerifyResult {
                    valid: true,
                    reason: None,
                    computed_fingerprint: Some(computed_fp),
                    expected_fingerprint: Some(envelope.fingerprint.clone()),
                }
            }
        }
        Err(e) => VerifyResult {
            valid: false,
            reason: Some(format!("fingerprint computation failed: {e}")),
            computed_fingerprint: None,
            expected_fingerprint: Some(envelope.fingerprint.clone()),
        },
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computed_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_fingerprint: Option<String>,
}
