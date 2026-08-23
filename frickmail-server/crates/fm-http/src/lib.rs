#![allow(clippy::result_large_err)]

pub mod router;
pub mod state;
mod uid_cache;

pub use router::build_router;
pub use state::AppState;
