//! UOR MCPS — Ed25519-signed receipts anchored on the UOR Passport fingerprint.
//!
//! # Design
//!
//! The UOR Passport guarantees **integrity** (what was produced) without any
//! trust layer. MCPS adds an optional **authentication** layer (who produced
//! it, when, with what trust level, with replay protection) on top of the
//! passport. Because the signature is over the JCS-canonicalized digest of a
//! small structure that *references* the passport fingerprint, the whole
//! construction survives re-serialization just as the passport does.
//!
//! This is the exact design SEP-2395 attempted — made safe by anchoring on
//! the UOR canonicalization primitive.
//!
//! # Verification
//!
//! Receipts are self-verifying: the embedded public key, signed payload,
//! and the passport are sufficient to verify locally with no network call
//! and no PKI. Key rotation (if desired) lives at a higher layer.

// `verify` and `VerifyResult` are used by the `verify_receipt` tool (commit 2)
// and by the module's own unit tests — silence dead_code during commit 1.
#![allow(dead_code)]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::passport::PassportEnvelope;

/// A signed MCPS receipt attached to tool responses under `_meta."uor.mcps.receipt"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpsReceipt {
    /// The UOR passport this receipt authenticates.
    pub passport: PassportEnvelope,
    /// Ed25519 signature over SHA-256(JCS(signed-payload)), base64 (standard).
    pub signature: String,
    /// Ed25519 verifying key, base64 (standard). 32 bytes decoded.
    pub public_key: String,
    /// Unique per-receipt nonce (base64 of 16 random bytes) for replay protection.
    pub nonce: String,
    /// ISO 8601 UTC timestamp when the receipt was issued.
    pub timestamp: String,
    /// Trust level assigned by the signer (e.g. "L1").
    pub trust_level: String,
    /// Signature algorithm identifier.
    pub algorithm: String,
}

impl McpsReceipt {
    pub const ALGORITHM: &'static str = "ed25519";
}

/// The small structure we actually sign. Kept separate so verification is
/// deterministic regardless of how the outer `McpsReceipt` is serialized.
#[derive(Debug, Serialize)]
struct SignedPayload<'a> {
    fingerprint: &'a str,
    nonce: &'a str,
    timestamp: &'a str,
    trust_level: &'a str,
}

/// Holds a single Ed25519 signing key for the lifetime of the process.
/// Key is generated on startup; persistence across restarts is intentionally
/// out of scope for v0.1 (and would require a key-management design).
///
/// # Key rotation (roadmap)
///
/// The receipt's embedded `public_key` is authoritative for *that* receipt —
/// there is no issuer registry and no CA. Rotation is therefore intrinsic:
/// a new server instance is a new key, and the old public key simply stops
/// appearing on new receipts (old receipts remain verifiable with their
/// embedded key forever — they are content-addressed).
///
/// Future work (v0.3+) will add optional key persistence via a mounted
/// secret (`UOR_MCPS_KEY_PATH`) and an optional `published_at` URI
/// (e.g. the server's `/.well-known/uor-key.json` endpoint or a GitHub
/// commit) so relying parties can check revocation/rotation out-of-band
/// without the passport itself depending on any such infrastructure.
pub struct McpsSigner {
    key: SigningKey,
    trust_level: String,
}

impl McpsSigner {
    pub fn generate(trust_level: impl Into<String>) -> Self {
        let mut csprng = OsRng;
        let key = SigningKey::generate(&mut csprng);
        Self {
            key,
            trust_level: trust_level.into(),
        }
    }

    pub fn public_key_b64(&self) -> String {
        BASE64.encode(self.key.verifying_key().to_bytes())
    }

    pub fn sign_passport(&self, passport: PassportEnvelope) -> anyhow::Result<McpsReceipt> {
        let nonce_bytes: [u8; 16] = rand::random();
        let nonce = BASE64.encode(nonce_bytes);
        let timestamp = chrono::Utc::now().to_rfc3339();

        let payload = SignedPayload {
            fingerprint: &passport.fingerprint,
            nonce: &nonce,
            timestamp: &timestamp,
            trust_level: &self.trust_level,
        };
        let canonical = serde_json_canonicalizer::to_vec(&payload)
            .map_err(|e| anyhow::anyhow!("canonicalize signed payload: {e}"))?;
        let digest = Sha256::digest(&canonical);
        let sig: Signature = self.key.sign(&digest);

        Ok(McpsReceipt {
            passport,
            signature: BASE64.encode(sig.to_bytes()),
            public_key: self.public_key_b64(),
            nonce,
            timestamp,
            trust_level: self.trust_level.clone(),
            algorithm: McpsReceipt::ALGORITHM.to_string(),
        })
    }
}

/// Result of verifying a signed receipt.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl VerifyResult {
    fn valid() -> Self {
        Self {
            valid: true,
            reason: None,
        }
    }
    fn invalid(r: impl Into<String>) -> Self {
        Self {
            valid: false,
            reason: Some(r.into()),
        }
    }
}

/// Verify a receipt with only the data it contains. No network, no PKI.
///
/// Checks that the signature validates against the receipt's public key
/// for the canonical digest of (fingerprint, nonce, timestamp, trust_level).
pub fn verify(receipt: &McpsReceipt) -> VerifyResult {
    if receipt.algorithm != McpsReceipt::ALGORITHM {
        return VerifyResult::invalid(format!("unsupported algorithm: {}", receipt.algorithm));
    }

    let payload = SignedPayload {
        fingerprint: &receipt.passport.fingerprint,
        nonce: &receipt.nonce,
        timestamp: &receipt.timestamp,
        trust_level: &receipt.trust_level,
    };
    let canonical = match serde_json_canonicalizer::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => return VerifyResult::invalid(format!("canonicalize: {e}")),
    };
    let digest = Sha256::digest(&canonical);

    let pk_bytes = match BASE64.decode(&receipt.public_key) {
        Ok(b) => b,
        Err(e) => return VerifyResult::invalid(format!("public_key base64 decode: {e}")),
    };
    if pk_bytes.len() != 32 {
        return VerifyResult::invalid(format!("public_key length {} != 32", pk_bytes.len()));
    }
    let pk_array: [u8; 32] = pk_bytes.as_slice().try_into().unwrap();
    let vk = match VerifyingKey::from_bytes(&pk_array) {
        Ok(v) => v,
        Err(e) => return VerifyResult::invalid(format!("verifying key parse: {e}")),
    };

    let sig_bytes = match BASE64.decode(&receipt.signature) {
        Ok(b) => b,
        Err(e) => return VerifyResult::invalid(format!("signature base64 decode: {e}")),
    };
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => return VerifyResult::invalid(format!("signature parse: {e}")),
    };

    match vk.verify(&digest, &sig) {
        Ok(()) => VerifyResult::valid(),
        Err(e) => VerifyResult::invalid(format!("signature verification failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_passport() -> PassportEnvelope {
        PassportEnvelope {
            version: PassportEnvelope::VERSION.to_string(),
            fingerprint: "a".repeat(64),
            algorithm: PassportEnvelope::ALGORITHM.to_string(),
            content_type: "application/json".to_string(),
            length: 42,
            timestamp: None,
        }
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let signer = McpsSigner::generate("L1");
        let receipt = signer.sign_passport(test_passport()).unwrap();
        let result = verify(&receipt);
        assert!(result.valid, "roundtrip verify failed: {:?}", result.reason);
    }

    #[test]
    fn tampered_fingerprint_fails_verification() {
        let signer = McpsSigner::generate("L1");
        let mut receipt = signer.sign_passport(test_passport()).unwrap();
        receipt.passport.fingerprint = "b".repeat(64);
        let result = verify(&receipt);
        assert!(!result.valid);
    }

    #[test]
    fn tampered_nonce_fails_verification() {
        let signer = McpsSigner::generate("L1");
        let mut receipt = signer.sign_passport(test_passport()).unwrap();
        receipt.nonce = BASE64.encode([0u8; 16]);
        let result = verify(&receipt);
        assert!(!result.valid);
    }

    #[test]
    fn two_signers_produce_different_public_keys() {
        let a = McpsSigner::generate("L1");
        let b = McpsSigner::generate("L1");
        assert_ne!(a.public_key_b64(), b.public_key_b64());
    }

    #[test]
    fn nonces_are_unique_per_receipt() {
        let signer = McpsSigner::generate("L1");
        let r1 = signer.sign_passport(test_passport()).unwrap();
        let r2 = signer.sign_passport(test_passport()).unwrap();
        assert_ne!(r1.nonce, r2.nonce);
        assert_ne!(r1.signature, r2.signature);
    }
}
