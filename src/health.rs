use axum::{http::StatusCode, response::IntoResponse, Json};

pub async fn handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "service": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
        })),
    )
}
