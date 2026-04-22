use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, ErrorData},
    schemars, tool, tool_router,
};
use serde::Deserialize;

use crate::passport::{self, PassportEnvelope};

/// Maximum canonical-byte size for content passed to `encode_address`. Guards
/// against pathological DoS inputs; 64 KB comfortably holds any realistic
/// MCP tool-call payload, agent memory object, or A2A message.
pub const UOR_CANONICAL_MAX_BYTES: usize = 65_536;

// Local alias matching rmcp's internal convention
type McpError = ErrorData;

#[derive(Debug, Clone)]
pub struct UorTools {
    pub(crate) tool_router: ToolRouter<UorTools>,
    pub use_jcs: bool,
}

impl UorTools {
    pub fn new(use_jcs: bool) -> Self {
        Self {
            tool_router: Self::tool_router(),
            use_jcs,
        }
    }
}

// ── Request types (all must derive JsonSchema for rmcp macro system) ──────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EncodeAddressRequest {
    /// Content to fingerprint. Any JSON value is accepted — string, number,
    /// boolean, null, array, or object. The server JCS-canonicalizes (RFC 8785)
    /// the value directly and SHA-256 hashes the canonical bytes. Canonical
    /// form must not exceed 64 KB.
    pub content: serde_json::Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyPassportRequest {
    /// The original content value that was fingerprinted
    pub content: serde_json::Value,
    /// Passport envelope to verify
    pub passport: PassportEnvelopeInput,
}

/// Passport envelope fields for verification input
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[allow(dead_code)]
pub struct PassportEnvelopeInput {
    pub fingerprint: String,
    pub length: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

#[cfg(feature = "mcps")]
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyReceiptRequest {
    /// The MCPS receipt to verify. Accepted as arbitrary JSON so the client
    /// can paste the entire `_meta."uor.mcps.receipt"` field verbatim.
    pub receipt: serde_json::Value,
}

// ── Tool implementations ───────────────────────────────────────────────────────

#[tool_router]
impl UorTools {
    /// Compute the UOR content address (SHA-256 fingerprint) of any JSON value.
    ///
    /// Accepts strings, numbers, booleans, null, arrays, and objects. The server
    /// NFC-normalizes all strings, RFC 8785 JCS-canonicalizes the value, and
    /// SHA-256 hashes the canonical bytes. Returns the full canonical byte
    /// string alongside the fingerprint so any runtime with a SHA-256 primitive
    /// can independently reproduce the hash.
    ///
    /// Two callers on two different runtimes (Python, Node, Rust, Go…) who pass
    /// the same semantic object — regardless of their local serializer's key
    /// order, whitespace, integer-vs-float representation, or Unicode NFC/NFD
    /// form — will receive the same fingerprint.
    #[tool(
        description = "Compute the UOR content address (SHA-256 fingerprint) of any JSON value. Accepts string, number, bool, null, array, or object — server NFC-normalizes and RFC 8785 JCS-canonicalizes, then SHA-256s. Canonical form must not exceed 64 KB. Returns sha256:<64-hex> address, canonical bytes, and passport fields."
    )]
    async fn encode_address(
        &self,
        Parameters(EncodeAddressRequest { content }): Parameters<EncodeAddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        // Canonicalize the value itself — not a wrapper. This is the behavioral
        // change from v0.1.x: any JSON input is accepted and its canonical form
        // is what gets hashed. `compute_fingerprint` NFC-normalizes strings first.
        let (canonical_bytes, fingerprint, length) =
            passport::canonicalize_and_hash(&content, self.use_jcs)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if length > UOR_CANONICAL_MAX_BYTES {
            return Err(McpError::invalid_params(
                format!(
                    "canonical form exceeds {UOR_CANONICAL_MAX_BYTES} bytes ({length} bytes). Split the payload into smaller addressable chunks."
                ),
                None,
            ));
        }

        let canonical_form = String::from_utf8(canonical_bytes)
            .map_err(|_| McpError::internal_error("canonical bytes not UTF-8", None))?;

        let address = format!("sha256:{fingerprint}");

        let result_json = serde_json::json!({
            "address": address,
            "fingerprint": fingerprint,
            "canonical_form": canonical_form,
            "algorithm": PassportEnvelope::ALGORITHM,
            "version": PassportEnvelope::VERSION,
            "length": length,
            "canonicalization": if self.use_jcs { "jcs-rfc8785+nfc" } else { "none" },
        });

        Ok(CallToolResult::success(vec![
            Content::text(address),
            Content::json(result_json)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
        ]))
    }

    /// Verify a UOR Passport Envelope against its content.
    ///
    /// Re-computes the SHA-256 fingerprint of the content and compares it to the
    /// passport's claimed fingerprint. Returns `{"valid": true}` on match or
    /// `{"valid": false, "reason": "..."}` on mismatch.
    #[tool(
        description = "Verify a UOR Passport Envelope against its content. Re-computes the fingerprint and returns {valid: bool, reason?: string}."
    )]
    async fn verify_passport(
        &self,
        Parameters(VerifyPassportRequest {
            content,
            passport: passport_input,
        }): Parameters<VerifyPassportRequest>,
    ) -> Result<CallToolResult, McpError> {
        // Envelope-field enforcement (v0.2.1): algorithm, version, and
        // content_type were cosmetic in v0.1.x. Now an explicit non-default
        // value is rejected rather than silently ignored; missing (None) is
        // still accepted as "caller didn't claim anything."
        if let Some(claimed) = passport_input.algorithm.as_deref() {
            if claimed != PassportEnvelope::ALGORITHM {
                return Err(McpError::invalid_params(
                    format!(
                        "unsupported algorithm: {claimed} (this server implements only {})",
                        PassportEnvelope::ALGORITHM
                    ),
                    None,
                ));
            }
        }
        if let Some(claimed) = passport_input.version.as_deref() {
            if claimed != PassportEnvelope::VERSION {
                return Err(McpError::invalid_params(
                    format!(
                        "unsupported passport version: {claimed} (this server implements only {})",
                        PassportEnvelope::VERSION
                    ),
                    None,
                ));
            }
        }
        if let Some(claimed) = passport_input.content_type.as_deref() {
            if claimed != "application/json" {
                return Err(McpError::invalid_params(
                    format!(
                        "unsupported content_type: {claimed} (this server implements only application/json)"
                    ),
                    None,
                ));
            }
        }

        let envelope = PassportEnvelope {
            version: PassportEnvelope::VERSION.to_string(),
            fingerprint: passport_input.fingerprint,
            algorithm: PassportEnvelope::ALGORITHM.to_string(),
            content_type: "application/json".to_string(),
            length: passport_input.length,
            timestamp: passport_input.timestamp,
        };

        let result = passport::verify(&content, &envelope, self.use_jcs);
        let result_json = serde_json::to_value(&result)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let summary = if result.valid {
            "Passport is valid — fingerprint matches content.".to_string()
        } else {
            format!(
                "Passport is INVALID: {}",
                result.reason.as_deref().unwrap_or("unknown reason")
            )
        };

        Ok(CallToolResult::success(vec![
            Content::text(summary),
            Content::json(result_json)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
        ]))
    }

    /// Verify an MCPS signed receipt. Stateless — works even when
    /// `UOR_MCPS_ENABLED=false` (this server can always *verify* any
    /// MCPS receipt it is given, whether or not it issues its own).
    ///
    /// Returns `{valid: bool, reason?: string}`. Verification is local-only:
    /// the Ed25519 signature is checked against the receipt's embedded
    /// public key over SHA-256(JCS({fingerprint, nonce, timestamp, trust_level})).
    /// No network, no PKI, no third party.
    #[cfg(feature = "mcps")]
    #[tool(
        description = "Verify an Ed25519-signed MCPS receipt (the uor.mcps.receipt value). Returns {valid: bool, reason?: string}. Fully local — no PKI, no network."
    )]
    async fn verify_receipt(
        &self,
        Parameters(VerifyReceiptRequest { receipt }): Parameters<VerifyReceiptRequest>,
    ) -> Result<CallToolResult, McpError> {
        let parsed: crate::mcps::McpsReceipt = serde_json::from_value(receipt).map_err(|e| {
            McpError::invalid_params(
                format!("receipt JSON is not a valid McpsReceipt: {e}"),
                None,
            )
        })?;
        let result = crate::mcps::verify(&parsed);
        let result_json = serde_json::to_value(&result)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let summary = if result.valid {
            "Receipt is valid — Ed25519 signature verifies against embedded public key.".to_string()
        } else {
            format!(
                "Receipt is INVALID: {}",
                result.reason.as_deref().unwrap_or("unknown reason")
            )
        };

        Ok(CallToolResult::success(vec![
            Content::text(summary),
            Content::json(result_json)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
        ]))
    }
}
