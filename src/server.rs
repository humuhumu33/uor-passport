use std::sync::Arc;

use std::collections::BTreeMap;

use rmcp::{
    handler::server::tool::ToolCallContext,
    model::{
        CallToolRequestParams, CallToolResult, ErrorData, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool, ToolsCapability,
    },
    service::RequestContext,
    RoleServer, ServerHandler,
};

use crate::{config::Config, github::GitHubClient, passport, tools::UorTools};

// Local alias matching rmcp's internal convention
type McpError = ErrorData;

#[derive(Clone)]
pub struct UorPassportServer {
    pub config: Arc<Config>,
    pub tools: Arc<UorTools>,
    pub github_client: Option<Arc<GitHubClient>>,
}

impl UorPassportServer {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let github_client = GitHubClient::from_config(&config).map(Arc::new);
        let use_jcs = config.use_jcs;
        Ok(Self {
            config: Arc::new(config),
            tools: Arc::new(UorTools::new(use_jcs)),
            github_client,
        })
    }

    fn build_capabilities(&self) -> ServerCapabilities {
        // BTreeMap<String, JsonObject> is the type for experimental/extensions
        let mut ext: BTreeMap<String, serde_json::Map<String, serde_json::Value>> = BTreeMap::new();

        if self.config.passport_enabled {
            let mut cap = serde_json::Map::new();
            cap.insert("enabled".into(), serde_json::Value::Bool(true));
            cap.insert(
                "algorithm".into(),
                serde_json::Value::String(passport::PassportEnvelope::ALGORITHM.to_string()),
            );
            cap.insert(
                "version".into(),
                serde_json::Value::String(passport::PassportEnvelope::VERSION.to_string()),
            );
            cap.insert("jcs".into(), serde_json::Value::Bool(self.config.use_jcs));
            ext.insert("uor.passport".to_string(), cap);
        }

        {
            let mut cap = serde_json::Map::new();
            cap.insert("enabled".into(), serde_json::Value::Bool(true));
            ext.insert("uor.verify".to_string(), cap);
        }

        if self.config.signing_enabled {
            let mut cap = serde_json::Map::new();
            cap.insert("enabled".into(), serde_json::Value::Bool(true));
            cap.insert(
                "algorithms".into(),
                serde_json::Value::Array(vec![serde_json::Value::String("ed25519".into())]),
            );
            ext.insert("uor.sign".to_string(), cap);
        }

        // ServerCapabilities is #[non_exhaustive], so build via Default + mutation
        let mut caps = ServerCapabilities::default();
        caps.tools = Some(ToolsCapability {
            list_changed: Some(false),
        });
        caps.extensions = if ext.is_empty() { None } else { Some(ext) };
        caps
    }
}

impl ServerHandler for UorPassportServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(self.build_capabilities())
            .with_server_info(
                Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
                    .with_description(
                        "Canonical reference implementation of the UOR Passport Envelope",
                    )
                    .with_website_url("https://mcp.uor.foundation"),
            )
            .with_instructions(
                "UOR Passport MCP Server: every tool response includes a `uor.passport` \
                 envelope in its `_meta` field. Use `uor.encode_address` to compute content \
                 addresses and `uor.verify_passport` to verify them.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut tools: Vec<Tool> = self.tools.tool_router.list_all();

        // Filter out uor.sign when signing is disabled
        if !self.config.signing_enabled {
            tools.retain(|t| t.name != "sign");
        }

        Ok(ListToolsResult {
            meta: None,
            tools,
            next_cursor: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // Block disabled tools before routing
        if !self.config.signing_enabled && request.name == "sign" {
            return Err(McpError::invalid_request(
                "uor.sign is not enabled on this server (set UOR_SIGNING=true)",
                None,
            ));
        }

        // Delegate to the tool router
        let ctx = ToolCallContext::new(self.tools.as_ref(), request, context);
        let result = self
            .tools
            .tool_router
            .call(ctx)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        // Inject passport envelope (non-failing; errors logged inside attach())
        let result = if self.config.passport_enabled {
            let enriched = passport::attach(result, &self.config);

            // Optional background persistence to GitHub (best-effort)
            if let Some(gh) = &self.github_client {
                if let Some(meta) = enriched.meta.as_ref() {
                    if let Some(passport_val) = meta.get("uor.passport") {
                        if let Ok(envelope) = serde_json::from_value::<passport::PassportEnvelope>(
                            passport_val.clone(),
                        ) {
                            let content_val =
                                serde_json::to_value(&enriched.content).unwrap_or_default();
                            let fingerprint = envelope.fingerprint.clone();
                            let gh = gh.clone();
                            tokio::spawn(async move {
                                if let Err(e) = gh
                                    .store_passport(&fingerprint, &envelope, &content_val)
                                    .await
                                {
                                    tracing::warn!(
                                        error = %e,
                                        "github passport storage failed (best-effort)"
                                    );
                                }
                            });
                        }
                    }
                }
            }

            enriched
        } else {
            result
        };

        Ok(result)
    }
}
