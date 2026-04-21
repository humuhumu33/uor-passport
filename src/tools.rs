use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, ErrorCode, ErrorData},
    schemars, tool, tool_router,
};
use serde::Deserialize;

use crate::passport::{self, PassportEnvelope};

/// Maximum UTF-8 character count per the uor-foundation string capability.
pub const UOR_STRING_MAX_LEN: usize = 1000;

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
    /// UTF-8 content to address (max 1000 characters — UOR string capability)
    pub content: String,
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
    pub timestamp: Option<String>,
}

#[cfg(feature = "mcps")]
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyReceiptRequest {
    /// The MCPS receipt to verify. Accepted as arbitrary JSON so the client
    /// can paste the entire `_meta."uor.mcps.receipt"` field verbatim.
    pub receipt: serde_json::Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SignRequest {
    /// Content to sign (UTF-8, max 1000 chars)
    pub content: String,
    /// Signing algorithm — only "ed25519" is planned
    #[serde(default = "default_sign_algorithm")]
    pub algorithm: String,
}

fn default_sign_algorithm() -> String {
    "ed25519".to_string()
}

// ── Tool implementations ───────────────────────────────────────────────────────

#[tool_router]
impl UorTools {
    /// Compute the UOR content address (SHA-256 fingerprint) for a UTF-8 string.
    ///
    /// Accepts strings up to 1000 characters (the UOR Foundation string capability).
    /// Returns a content address in the format `sha256:<64-hex-chars>` along with
    /// the full passport envelope fields for verification.
    #[tool(
        description = "Compute the UOR content address (SHA-256 fingerprint) for a UTF-8 string. Accepts up to 1000 characters (UOR string capability). Returns sha256:<64-hex> address and passport fields."
    )]
    async fn encode_address(
        &self,
        Parameters(EncodeAddressRequest { content }): Parameters<EncodeAddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        if content.chars().count() > UOR_STRING_MAX_LEN {
            return Err(McpError::invalid_params(
                format!(
                    "content exceeds UOR string capability limit of {UOR_STRING_MAX_LEN} characters"
                ),
                None,
            ));
        }

        // JCS-canonicalize a JSON wrapper for deterministic hashing across runtimes
        let wrapper = serde_json::json!({ "content": content });
        let (fingerprint, length) = passport::compute_fingerprint(&wrapper, self.use_jcs)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let address = format!("sha256:{fingerprint}");

        let result_json = serde_json::json!({
            "address": address,
            "fingerprint": fingerprint,
            "algorithm": PassportEnvelope::ALGORITHM,
            "version": PassportEnvelope::VERSION,
            "length": length,
            "content_char_count": content.chars().count(),
            "canonicalization": if self.use_jcs { "jcs-rfc8785" } else { "none" },
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
            McpError::invalid_params(format!("receipt JSON is not a valid McpsReceipt: {e}"), None)
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

    /// Sign content with a UOR identity key (Ed25519).
    ///
    /// Note: Signing support is planned for v0.2. This tool is registered as a
    /// capability placeholder and will return a not-implemented error until then.
    #[tool(
        description = "Sign content with a UOR identity key (Ed25519). Note: signing is planned for v0.2 — this is a capability placeholder."
    )]
    async fn sign(
        &self,
        Parameters(SignRequest { content, algorithm }): Parameters<SignRequest>,
    ) -> Result<CallToolResult, McpError> {
        let _ = (content, algorithm);
        Err(McpError::new(
            ErrorCode::INVALID_REQUEST,
            "uor.sign is not yet implemented — planned for v0.2 with Ed25519 support",
            None,
        ))
    }
}
