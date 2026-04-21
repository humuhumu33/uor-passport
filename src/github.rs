//! GitHub personal storage for UOR passport envelopes.
//!
//! When GITHUB_TOKEN is set, passport envelopes are stored at
//! `passports/{fingerprint}.json` in the configured repository.
//! Storage is best-effort: failures are logged but never propagated to MCP responses.

#[cfg(feature = "github-storage")]
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::{config::Config, passport::PassportEnvelope};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GitHubClient {
    token: String,
    owner: String,
    repo: String,
    #[cfg(feature = "github-storage")]
    client: reqwest::Client,
}

impl GitHubClient {
    pub fn from_config(config: &Config) -> Option<Self> {
        config.github_token.as_ref().map(|token| Self {
            token: token.clone(),
            owner: config.github_owner.clone(),
            repo: config.github_repo.clone(),
            #[cfg(feature = "github-storage")]
            client: reqwest::Client::new(),
        })
    }

    /// Store a passport envelope in the GitHub repository.
    ///
    /// Creates or updates `passports/{fingerprint}.json`.
    pub async fn store_passport(
        &self,
        fingerprint: &str,
        envelope: &PassportEnvelope,
        content: &serde_json::Value,
    ) -> anyhow::Result<()> {
        #[cfg(feature = "github-storage")]
        {
            self.store_passport_impl(fingerprint, envelope, content).await
        }
        #[cfg(not(feature = "github-storage"))]
        {
            let _ = (fingerprint, envelope, content);
            tracing::debug!("github-storage feature not compiled — skipping persistence");
            Ok(())
        }
    }

    #[cfg(feature = "github-storage")]
    async fn store_passport_impl(
        &self,
        fingerprint: &str,
        envelope: &PassportEnvelope,
        content: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let path = format!("passports/{fingerprint}.json");
        let body = serde_json::json!({
            "fingerprint": fingerprint,
            "envelope": envelope,
            "content": content,
            "stored_at": chrono::Utc::now().to_rfc3339(),
        });
        let encoded = BASE64.encode(serde_json::to_string_pretty(&body)?);

        let api_url = format!(
            "https://api.github.com/repos/{}/{}/contents/{}",
            self.owner, self.repo, path
        );

        // Fetch the current file SHA (needed for updates)
        let existing_sha = self.get_file_sha(&api_url).await.ok();

        let mut payload = serde_json::json!({
            "message": format!("store UOR passport {}", &fingerprint[..8]),
            "content": encoded,
        });
        if let Some(sha) = existing_sha {
            payload["sha"] = serde_json::Value::String(sha);
        }

        let resp = self
            .client
            .put(&api_url)
            .bearer_auth(&self.token)
            .header("User-Agent", "mcp-uor-server/0.1")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GitHub API returned {status}: {body}");
        }

        tracing::debug!(fingerprint, "passport stored in GitHub repository");
        Ok(())
    }

    #[cfg(feature = "github-storage")]
    async fn get_file_sha(&self, api_url: &str) -> anyhow::Result<String> {
        let resp = self
            .client
            .get(api_url)
            .bearer_auth(&self.token)
            .header("User-Agent", "mcp-uor-server/0.1")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("file not found");
        }

        let json: serde_json::Value = resp.json().await?;
        json["sha"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("sha field missing in response"))
    }
}
