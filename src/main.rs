mod config;
mod github;
mod health;
mod passport;
mod server;
mod tools;

use config::{Config, TransportMode};
use server::UorPassportServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".to_string().into()),
        )
        .init();

    let config = Config::from_env()?;

    // ── Startup banner ────────────────────────────────────────────────────────
    let transport_label = match config.transport {
        TransportMode::Stdio => "stdio",
        TransportMode::Http => "http",
    };
    let passport_status = if config.passport_enabled {
        format!(
            "enabled ({}, {})",
            passport::PassportEnvelope::ALGORITHM,
            if config.use_jcs { "JCS" } else { "raw JSON" }
        )
    } else {
        "disabled".to_string()
    };
    let signing_status = if config.signing_enabled {
        "enabled (Ed25519 — v0.2)"
    } else {
        "disabled"
    };
    let github_status = if config.github_token.is_some() {
        "enabled"
    } else {
        "disabled"
    };

    eprintln!("╔══════════════════════════════════════════════════════╗");
    eprintln!("║         UOR Passport MCP Server v{:<20} ║", env!("CARGO_PKG_VERSION"));
    eprintln!("║  Endpoint : {:<41} ║", config.mcp_host);
    eprintln!("║  Transport: {:<41} ║", transport_label);
    eprintln!("║  Passport : {:<41} ║", passport_status);
    eprintln!("║  Signing  : {:<41} ║", signing_status);
    eprintln!("║  GitHub   : {:<41} ║", github_status);
    eprintln!("╚══════════════════════════════════════════════════════╝");

    tracing::info!(
        endpoint = %config.mcp_host,
        transport = transport_label,
        passport_enabled = config.passport_enabled,
        signing_enabled = config.signing_enabled,
        github_storage = config.github_token.is_some(),
        "MCP Endpoint: {}",
        config.mcp_host,
    );
    tracing::info!(
        "Capabilities: uor.passport{}{} (uor.verify always on)",
        if config.signing_enabled { ", uor.sign" } else { "" },
        if config.github_token.is_some() { ", github-storage" } else { "" },
    );

    match config.transport {
        TransportMode::Stdio => run_stdio(config).await,
        TransportMode::Http => run_http(config).await,
    }
}

async fn run_stdio(config: Config) -> anyhow::Result<()> {
    use rmcp::ServiceExt;

    let server = UorPassportServer::new(config)?;
    let service = server.serve(rmcp::transport::io::stdio()).await?;
    tracing::info!("MCP server ready (stdio)");
    service.waiting().await?;
    Ok(())
}

async fn run_http(config: Config) -> anyhow::Result<()> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    use tokio_util::sync::CancellationToken;

    let port = config.port;
    let ct = CancellationToken::new();
    let ct_child = ct.child_token();
    let config = std::sync::Arc::new(config);

    let config_factory = config.clone();
    let service = StreamableHttpService::new(
        move || {
            UorPassportServer::new((*config_factory).clone())
                .map_err(|e| std::io::Error::other(e.to_string()))
        },
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_cancellation_token(ct_child),
    );

    let app = axum::Router::new()
        .nest_service("/mcp", service)
        .route("/health", axum::routing::get(health::handler));

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("MCP server ready — listening on http://{addr}/mcp");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install CTRL+C handler");
            tracing::info!("Shutdown signal received");
            ct.cancel();
        })
        .await?;

    Ok(())
}
