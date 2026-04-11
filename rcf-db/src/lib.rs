//! Database layer for host tracking, credentials, and session management.
//!
//! Uses Diesel + SQLite with embedded migrations for:
//! - Host discovery tracking
//! - Service enumeration
//! - Credential storage (encrypted at rest via SQLite)
//! - Session management
//! - Loot/artifact storage
//! - Vulnerability tracking
//! - Export to JSON, CSV, XML

pub mod connection;
pub mod export;
pub mod models;
pub mod schema;

pub use connection::RcfDatabase;
pub use export::ExportFormat;
pub use models::*;
