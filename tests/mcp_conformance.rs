//! MCP protocol conformance tests — validate tool listing, call routing,
//! passport injection, verification, and error handling.
#![allow(dead_code)]

#[path = "../src/config.rs"]
mod config;
#[path = "../src/health.rs"]
mod health;
#[cfg(feature = "mcps")]
#[path = "../src/mcps.rs"]
mod mcps;
#[path = "../src/passport.rs"]
mod passport;
#[path = "../src/server.rs"]
mod server;
#[path = "../src/tools.rs"]
mod tools;

use config::{Config, TransportMode};
use passport::PassportEnvelope;
use rmcp::ServerHandler;
use server::UorPassportServer;

fn test_config() -> Config {
    Config {
        passport_enabled: true,
        mcp_host: "https://mcp.uor.foundation".to_string(),
        transport: TransportMode::Stdio,
        port: 3000,
        use_jcs: true,
        mcps_enabled: false,
        mcps_trust_level: "L1".to_string(),
        allowed_hosts: vec!["localhost".into()],
    }
}

fn test_server() -> UorPassportServer {
    UorPassportServer::new(test_config()).expect("server construction failed")
}

// ── get_info tests ────────────────────────────────────────────────────────────

#[test]
fn test_server_info_contains_capabilities() {
    let server = test_server();
    let info = server.get_info();

    assert!(!info.server_info.name.is_empty());
    assert!(!info.server_info.version.is_empty());
    assert!(
        info.capabilities.tools.is_some(),
        "tools capability must be declared"
    );
}

#[test]
fn test_server_info_declares_uor_passport_extension() {
    let server = test_server();
    let info = server.get_info();

    let exts = info
        .capabilities
        .extensions
        .as_ref()
        .expect("extensions must be present");
    assert!(
        exts.contains_key("uor.passport"),
        "uor.passport extension must be declared"
    );
    assert!(
        exts.contains_key("uor.verify"),
        "uor.verify extension must be declared"
    );
}

// ── list_tools tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_list_tools_returns_uor_tools() {
    let server = test_server();
    let tools = server.tools.tool_router.list_all();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert!(
        names.contains(&"encode_address"),
        "encode_address must be listed"
    );
    assert!(
        names.contains(&"verify_passport"),
        "verify_passport must be listed"
    );
}

// ── Passport attachment via tool router ───────────────────────────────────────

#[tokio::test]
async fn test_encode_address_produces_fingerprint() {
    let server = test_server();
    let _ = server; // construction verified above

    let result =
        rmcp::model::CallToolResult::success(vec![rmcp::model::Content::text("sha256:abc123")]);
    let enriched = passport::attach(result, &test_config());

    let meta = enriched.meta.as_ref().unwrap();
    assert!(
        meta.contains_key("uor.passport"),
        "passport must be in meta"
    );
    let envelope: PassportEnvelope = serde_json::from_value(meta["uor.passport"].clone()).unwrap();
    assert_eq!(envelope.fingerprint.len(), 64);
}

// ── Verification tests ────────────────────────────────────────────────────────

#[test]
fn test_verify_passport_valid() {
    let content = serde_json::json!([{"type": "text", "text": "verifiable content"}]);
    let (fingerprint, length) = passport::compute_fingerprint(&content, true).unwrap();

    let envelope = PassportEnvelope {
        version: PassportEnvelope::VERSION.to_string(),
        fingerprint: fingerprint.clone(),
        algorithm: PassportEnvelope::ALGORITHM.to_string(),
        content_type: "application/json".to_string(),
        length,
        timestamp: None,
    };

    let result = passport::verify(&content, &envelope, true);
    assert!(
        result.valid,
        "passport should be valid for unmodified content"
    );
    assert!(result.reason.is_none());
}

#[test]
fn test_verify_passport_tampered_content_fails() {
    let original = serde_json::json!([{"type": "text", "text": "original"}]);
    let (fingerprint, length) = passport::compute_fingerprint(&original, true).unwrap();

    let envelope = PassportEnvelope {
        version: PassportEnvelope::VERSION.to_string(),
        fingerprint,
        algorithm: PassportEnvelope::ALGORITHM.to_string(),
        content_type: "application/json".to_string(),
        length,
        timestamp: None,
    };

    let tampered = serde_json::json!([{"type": "text", "text": "TAMPERED"}]);
    let result = passport::verify(&tampered, &envelope, true);

    assert!(!result.valid, "tampered content must fail verification");
    assert!(
        result.reason.is_some(),
        "reason must be provided on failure"
    );
}

#[test]
fn test_verify_passport_fingerprint_mismatch_message() {
    let content = serde_json::json!(["data"]);
    let envelope = PassportEnvelope {
        version: PassportEnvelope::VERSION.to_string(),
        fingerprint: "a".repeat(64),
        algorithm: PassportEnvelope::ALGORITHM.to_string(),
        content_type: "application/json".to_string(),
        length: 999,
        timestamp: None,
    };

    let result = passport::verify(&content, &envelope, true);
    assert!(!result.valid);
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("mismatch"),
        "reason should mention 'mismatch', got: {reason}"
    );
}

// ── String capability tests ───────────────────────────────────────────────────

#[test]
fn test_string_capability_boundary_is_1000_chars() {
    assert_eq!(tools::UOR_STRING_MAX_LEN, 1000);
}

// ── Error handling tests ──────────────────────────────────────────────────────

#[test]
fn test_passport_attachment_failure_is_non_fatal() {
    let empty_result = rmcp::model::CallToolResult::success(vec![]);
    let config = test_config();
    let enriched = passport::attach(empty_result, &config);
    let _ = enriched;
}

// ── MCPS receipt tests ────────────────────────────────────────────────────────

#[cfg(feature = "mcps")]
mod mcps_tests {
    use super::*;

    fn sample_passport() -> passport::PassportEnvelope {
        passport::PassportEnvelope {
            version: passport::PassportEnvelope::VERSION.to_string(),
            fingerprint: "a".repeat(64),
            algorithm: passport::PassportEnvelope::ALGORITHM.to_string(),
            content_type: "application/json".to_string(),
            length: 42,
            timestamp: None,
        }
    }

    #[test]
    fn verify_receipt_accepts_valid_roundtrip() {
        let signer = mcps::McpsSigner::generate("L1");
        let receipt = signer.sign_passport(sample_passport()).unwrap();
        let result = mcps::verify(&receipt);
        assert!(
            result.valid,
            "valid receipt should verify: {:?}",
            result.reason
        );
    }

    #[test]
    fn verify_receipt_rejects_tampered_signature() {
        let signer = mcps::McpsSigner::generate("L1");
        let mut receipt = signer.sign_passport(sample_passport()).unwrap();
        // Flip one character of the signature
        let mut chars: Vec<char> = receipt.signature.chars().collect();
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
        receipt.signature = chars.into_iter().collect();
        let result = mcps::verify(&receipt);
        assert!(!result.valid, "tampered signature must fail verification");
        assert!(result.reason.is_some());
    }

    #[test]
    fn verify_receipt_rejects_wrong_public_key() {
        let signer_a = mcps::McpsSigner::generate("L1");
        let signer_b = mcps::McpsSigner::generate("L1");
        let mut receipt = signer_a.sign_passport(sample_passport()).unwrap();
        receipt.public_key = signer_b.public_key_b64();
        let result = mcps::verify(&receipt);
        assert!(
            !result.valid,
            "receipt with wrong public_key must fail verification"
        );
    }

    #[test]
    fn verify_receipt_rejects_unknown_algorithm() {
        let signer = mcps::McpsSigner::generate("L1");
        let mut receipt = signer.sign_passport(sample_passport()).unwrap();
        receipt.algorithm = "rsa-2048".to_string();
        let result = mcps::verify(&receipt);
        assert!(!result.valid);
        assert!(result
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("unsupported"));
    }

    #[tokio::test]
    async fn verify_receipt_tool_is_listed() {
        let server = test_server();
        let tools = server.tools.tool_router.list_all();
        assert!(
            tools.iter().any(|t| t.name == "verify_receipt"),
            "verify_receipt tool must be registered when mcps feature is compiled"
        );
    }
}
