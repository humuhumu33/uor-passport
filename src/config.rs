use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Config {
    /// Whether to attach a UOR passport to every tool response (UOR_PASSPORT_ENABLED)
    pub passport_enabled: bool,
    /// Whether to register and expose the uor.sign tool (UOR_SIGNING)
    pub signing_enabled: bool,
    /// GitHub personal access token for passport storage (GITHUB_TOKEN)
    pub github_token: Option<String>,
    /// Canonical MCP endpoint URL — logged on startup (UOR_MCP_HOST)
    pub mcp_host: String,
    /// Transport mode: "stdio" or "http" (UOR_TRANSPORT)
    pub transport: TransportMode,
    /// HTTP listen port in HTTP mode (PORT)
    pub port: u16,
    /// Requests per second rate limit, 0 = unlimited (RATE_LIMIT)
    #[allow(dead_code)]
    pub rate_limit: u32,
    /// Whether to use RFC 8785 JCS canonicalization for fingerprinting (UOR_USE_JCS)
    pub use_jcs: bool,
    /// Whether to include ISO 8601 timestamp in passport envelope
    pub timestamp_enabled: bool,
    /// GitHub repo owner for passport storage (UOR_GITHUB_OWNER)
    pub github_owner: String,
    /// GitHub repo name for passport storage (UOR_GITHUB_REPO)
    pub github_repo: String,
    /// Whether to attach an Ed25519-signed MCPS receipt to tool responses (UOR_MCPS_ENABLED)
    pub mcps_enabled: bool,
    /// Default trust level for signed receipts (UOR_MCPS_TRUST_LEVEL)
    pub mcps_trust_level: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransportMode {
    Stdio,
    Http,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let passport_enabled = env_bool("UOR_PASSPORT_ENABLED", true);
        let signing_enabled = {
            let v = std::env::var("UOR_SIGNING").unwrap_or_default();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("ed25519")
        };
        let github_token = std::env::var("GITHUB_TOKEN").ok().filter(|s| !s.is_empty());
        let mcp_host = std::env::var("UOR_MCP_HOST")
            .unwrap_or_else(|_| "https://mcp.uor.foundation".to_string());
        let transport = match std::env::var("UOR_TRANSPORT")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "http" | "streamable-http" | "streamablehttp" => TransportMode::Http,
            _ => TransportMode::Stdio,
        };
        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3000);
        let rate_limit: u32 = std::env::var("RATE_LIMIT")
            .ok()
            .and_then(|r| r.parse().ok())
            .unwrap_or(100);
        let use_jcs = env_bool("UOR_USE_JCS", true);
        let github_owner =
            std::env::var("UOR_GITHUB_OWNER").unwrap_or_else(|_| "humuhumu33".to_string());
        let github_repo =
            std::env::var("UOR_GITHUB_REPO").unwrap_or_else(|_| "uor-passport".to_string());
        let mcps_enabled = env_bool("UOR_MCPS_ENABLED", false);
        let mcps_trust_level =
            std::env::var("UOR_MCPS_TRUST_LEVEL").unwrap_or_else(|_| "L1".to_string());

        // Validate port range
        if port == 0 {
            anyhow::bail!("PORT must be a non-zero value");
        }

        Ok(Config {
            passport_enabled,
            signing_enabled,
            github_token,
            mcp_host,
            transport,
            port,
            rate_limit,
            use_jcs,
            timestamp_enabled: true,
            github_owner,
            github_repo,
            mcps_enabled,
            mcps_trust_level,
        })
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => !matches!(v.to_lowercase().as_str(), "0" | "false" | "no" | "off"),
        Err(_) => default,
    }
}
