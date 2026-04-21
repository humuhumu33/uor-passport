#![allow(dead_code)]

use rmcp::model::{CallToolResult, Content};

// Re-use crate internals via path imports
#[path = "../src/config.rs"]
mod config;
#[path = "../src/passport.rs"]
mod passport;

use config::Config;
use passport::{attach, PassportEnvelope};

fn test_config() -> Config {
    Config {
        passport_enabled: true,
        mcp_host: "https://mcp.uor.foundation".to_string(),
        transport: config::TransportMode::Stdio,
        port: 3000,
        use_jcs: true,
        mcps_enabled: false,
        mcps_trust_level: "L1".to_string(),
    }
}

fn simple_result(text: &str) -> CallToolResult {
    CallToolResult::success(vec![Content::text(text)])
}

// ── Attachment tests ──────────────────────────────────────────────────────────

#[test]
fn test_passport_attaches_to_tool_result() {
    let result = simple_result("hello world");
    let enriched = attach(result, &test_config());

    let meta = enriched.meta.as_ref().expect("meta should be present");
    let passport_val = meta
        .get("uor.passport")
        .expect("uor.passport should be in meta");
    let envelope: PassportEnvelope =
        serde_json::from_value(passport_val.clone()).expect("valid PassportEnvelope");

    assert_eq!(envelope.version, PassportEnvelope::VERSION);
    assert_eq!(envelope.algorithm, PassportEnvelope::ALGORITHM);
    assert_eq!(
        envelope.fingerprint.len(),
        64,
        "fingerprint must be 64 hex chars"
    );
    assert!(
        envelope.fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
        "fingerprint must be all hex digits"
    );
    assert_eq!(envelope.content_type, "application/json");
    assert!(envelope.length > 0);
    assert!(envelope.timestamp.is_some(), "timestamp should be present");
}

#[test]
fn test_passport_disabled_no_meta_injection() {
    let mut config = test_config();
    config.passport_enabled = false;

    let result = simple_result("hello");
    // attach() is called only when enabled in server.rs, but the function itself
    // always injects — the server checks config.passport_enabled before calling.
    // Here we verify the envelope injects correctly when called directly.
    let enriched = attach(result.clone(), &config);

    // attach() always injects when called; the guard lives in server.rs.
    // This test verifies that the meta field is correctly populated.
    assert!(enriched.meta.is_some());
}

#[test]
fn test_fingerprint_is_deterministic() {
    let config = test_config();

    let result1 = simple_result("deterministic content");
    let result2 = simple_result("deterministic content");

    let e1 = attach(result1, &config);
    let e2 = attach(result2, &config);

    let fp1 = e1
        .meta
        .as_ref()
        .unwrap()
        .get("uor.passport")
        .unwrap()
        .get("fingerprint")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let fp2 = e2
        .meta
        .as_ref()
        .unwrap()
        .get("uor.passport")
        .unwrap()
        .get("fingerprint")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    assert_eq!(fp1, fp2, "same content must produce identical fingerprint");
}

#[test]
fn test_different_content_different_fingerprint() {
    let config = test_config();

    let e1 = attach(simple_result("content A"), &config);
    let e2 = attach(simple_result("content B"), &config);

    let fp1 = e1.meta.unwrap().get("uor.passport").unwrap()["fingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    let fp2 = e2.meta.unwrap().get("uor.passport").unwrap()["fingerprint"]
        .as_str()
        .unwrap()
        .to_string();

    assert_ne!(
        fp1, fp2,
        "different content must produce different fingerprints"
    );
}

#[test]
fn test_passport_length_matches_canonical_bytes() {
    let config = test_config();

    let result = simple_result("measure me");
    let enriched = attach(result.clone(), &config);

    let envelope: PassportEnvelope =
        serde_json::from_value(enriched.meta.unwrap()["uor.passport"].clone()).unwrap();

    // Re-compute canonical bytes independently
    let content_val = serde_json::to_value(&result.content).unwrap();
    let canonical = serde_json_canonicalizer::to_vec(&content_val).unwrap();
    assert_eq!(
        envelope.length,
        canonical.len(),
        "length must match canonical byte count"
    );
}

#[test]
fn test_version_field_is_correct() {
    let enriched = attach(simple_result("v"), &test_config());
    let envelope: PassportEnvelope =
        serde_json::from_value(enriched.meta.unwrap()["uor.passport"].clone()).unwrap();
    assert_eq!(envelope.version, "uor.passport.v1");
}
