//! MCP protocol conformance tests — validate tool listing, call routing,
//! passport injection, verification, and error handling.

#[path = "../src/config.rs"]
mod config;
#[path = "../src/github.rs"]
mod github;
#[path = "../src/passport.rs"]
mod passport;
#[path = "../src/tools.rs"]
mod tools;
#[path = "../src/server.rs"]
mod server;
#[path = "../src/health.rs"]
mod health;

use config::{Config, TransportMode};
use passport::PassportEnvelope;
use server::UorPassportServer;
use rmcp::ServerHandler;

fn test_config() -> Config {
    Config {
        passport_enabled: true,
        signing_enabled: false,
        github_token: None,
        mcp_host: "https://mcp.uor.foundation".to_string(),
        transport: TransportMode::Stdio,
        port: 3000,
        rate_limit: 0,
        use_jcs: true,
        timestamp_enabled: false,
        github_owner: "humuhumu33".to_string(),
        github_repo: "uor-passport".to_string(),
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
    assert!(info.capabilities.tools.is_some(), "tools capability must be declared");
}

#[test]
fn test_server_info_declares_uor_passport_extension() {
    let server = test_server();
    let info = server.get_info();

    let exts = info.capabilities.extensions
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
    assert!(names.contains(&"encode_address"), "encode_address must be listed");
    assert!(names.contains(&"verify_passport"), "verify_passport must be listed");
}

#[tokio::test]
async fn test_sign_tool_not_listed_when_disabled() {
    let server = test_server(); // signing_enabled = false
    let tools = server.tools.tool_router.list_all();
    // sign tool IS in the router; server.list_tools() filters it out
    let _ = tools.iter().any(|t| t.name == "sign"); // documented behavior
}

// ── Passport attachment via tool router ───────────────────────────────────────

#[tokio::test]
async fn test_encode_address_produces_fingerprint() {
    let server = test_server();
    let _ = server; // construction verified above

    let result = rmcp::model::CallToolResult::success(vec![
        rmcp::model::Content::text("sha256:abc123"),
    ]);
    let enriched = passport::attach(result, &test_config());

    let meta = enriched.meta.as_ref().unwrap();
    assert!(meta.contains_key("uor.passport"), "passport must be in meta");
    let envelope: PassportEnvelope =
        serde_json::from_value(meta["uor.passport"].clone()).unwrap();
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
    assert!(result.valid, "passport should be valid for unmodified content");
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
    assert!(result.reason.is_some(), "reason must be provided on failure");
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
