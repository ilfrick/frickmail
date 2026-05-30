use tower_sessions::{cookie::SameSite, Expiry, MemoryStore, SessionManagerLayer};

pub fn session_layer() -> SessionManagerLayer<MemoryStore> {
    // Development-only store for the first migration slice. Production cutover
    // must replace this with Redis or the configured database-backed store.
    let store = MemoryStore::default();
    SessionManagerLayer::new(store)
        .with_name("FrickmailSession")
        .with_same_site(SameSite::Lax)
        .with_http_only(true)
        .with_expiry(Expiry::OnInactivity(
            tower_sessions::cookie::time::Duration::hours(12),
        ))
}
