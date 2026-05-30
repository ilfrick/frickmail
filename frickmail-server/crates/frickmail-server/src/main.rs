use std::net::SocketAddr;

use anyhow::Context;
use fm_core::FrickmailConfig;
use fm_http::{build_router, AppState};
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "frickmail_server=info,fm_http=info,tower_http=info".into()),
        )
        .init();

    let config = FrickmailConfig::from_env().context("load configuration")?;
    let addr: SocketAddr = config
        .bind_addr
        .parse()
        .with_context(|| format!("parse bind address {}", config.bind_addr))?;

    let app = build_router(AppState::new(config));
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "starting Frickmail Rust server");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install ctrl-c handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
