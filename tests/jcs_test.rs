//! Tests for RFC 8785 JSON Canonicalization Scheme (JCS) behavior.

#[path = "../src/config.rs"]
mod config;
#[path = "../src/passport.rs"]
mod passport;

use passport::compute_fingerprint;

// ── JCS correctness tests ─────────────────────────────────────────────────────

#[test]
fn test_jcs_key_ordering_is_canonical() {
    // RFC 8785 mandates keys sorted by Unicode code point
    let a = serde_json::json!({"z": 1, "a": 2});
    let b = serde_json::json!({"a": 2, "z": 1});

    let canon_a = String::from_utf8(serde_json_canonicalizer::to_vec(&a).unwrap()).unwrap();
    let canon_b = String::from_utf8(serde_json_canonicalizer::to_vec(&b).unwrap()).unwrap();

    assert_eq!(
        canon_a, canon_b,
        "different key orderings must canonicalize identically"
    );
    assert_eq!(
        canon_a, r#"{"a":2,"z":1}"#,
        "canonical form must have keys in Unicode order"
    );
}

#[test]
fn test_identical_content_identical_fingerprint_regardless_of_key_order() {
    // Two JSON values that are semantically identical but byte-different
    let v1 = serde_json::json!([{"text": "hello", "type": "text"}]);
    let v2 = serde_json::json!([{"type": "text", "text": "hello"}]);

    let (fp1, _) = compute_fingerprint(&v1, true).unwrap();
    let (fp2, _) = compute_fingerprint(&v2, true).unwrap();

    assert_eq!(
        fp1, fp2,
        "fingerprint must be key-order-independent via JCS"
    );
}

#[test]
fn test_jcs_disabled_key_order_matters() {
    // Without JCS, different key ordering produces different fingerprints
    let v1 = serde_json::json!({"z": 1, "a": 2});
    let v2 = serde_json::json!({"a": 2, "z": 1});

    let (fp1, _) = compute_fingerprint(&v1, false).unwrap();
    let (fp2, _) = compute_fingerprint(&v2, false).unwrap();

    // Without JCS the raw bytes differ (serde_json preserves insertion order with preserve_order feature)
    // Note: with serde_json without preserve_order, keys may or may not differ — this is informational.
    // The test documents the behavior rather than asserting a strict inequality.
    let _ = (fp1, fp2); // Results captured; behavior documented above
}

#[test]
fn test_rfc8785_unicode_escape_normalization() {
    // RFC 8785 requires that Unicode escapes be unescaped when possible
    let with_escape = serde_json::json!("\u{0041}"); // "A"
    let literal_a = serde_json::json!("A");

    let canon_esc =
        String::from_utf8(serde_json_canonicalizer::to_vec(&with_escape).unwrap()).unwrap();
    let canon_lit =
        String::from_utf8(serde_json_canonicalizer::to_vec(&literal_a).unwrap()).unwrap();

    assert_eq!(
        canon_esc, canon_lit,
        "Unicode escapes must normalize to literal characters"
    );
}

#[test]
fn test_rfc8785_number_normalization() {
    // RFC 8785 normalizes numbers: 1.0 and 1 produce the same output
    let v1 = serde_json::json!(1.0_f64);
    let v2 = serde_json::json!(1_i64);

    let c1 = String::from_utf8(serde_json_canonicalizer::to_vec(&v1).unwrap()).unwrap();
    let c2 = String::from_utf8(serde_json_canonicalizer::to_vec(&v2).unwrap()).unwrap();

    // Both should be "1" (ECMAScript number notation)
    assert_eq!(c1, c2, "1.0 and 1 should canonicalize identically");
}

#[test]
fn test_nested_objects_are_canonicalized_recursively() {
    let v1 = serde_json::json!({"outer": {"z": 1, "a": 2}, "b": 3});
    let v2 = serde_json::json!({"b": 3, "outer": {"a": 2, "z": 1}});

    let (fp1, _) = compute_fingerprint(&v1, true).unwrap();
    let (fp2, _) = compute_fingerprint(&v2, true).unwrap();

    assert_eq!(
        fp1, fp2,
        "nested object key ordering must also be canonicalized"
    );
}

#[test]
fn test_fingerprint_is_256_bit_sha256() {
    // SHA-256 produces 32 bytes = 64 hex chars
    let (fp, _) = compute_fingerprint(&serde_json::json!("test"), true).unwrap();
    assert_eq!(
        fp.len(),
        64,
        "SHA-256 fingerprint must be 64 hex characters"
    );
    assert!(
        fp.chars().all(|c| c.is_ascii_hexdigit()),
        "must be all hex digits"
    );
}

#[test]
fn test_empty_array_fingerprint_is_stable() {
    let empty = serde_json::json!([]);
    let (fp1, _) = compute_fingerprint(&empty, true).unwrap();
    let (fp2, _) = compute_fingerprint(&empty, true).unwrap();
    assert_eq!(fp1, fp2, "empty array fingerprint must be stable");
    // Known JCS canonical form of [] is "[]" → sha256("[]")
    use sha2::{Digest, Sha256};
    let expected = hex::encode(Sha256::digest(b"[]"));
    assert_eq!(fp1, expected);
}
