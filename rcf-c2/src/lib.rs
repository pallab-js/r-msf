//! Command and control server and session management for RCF.
//!
//! Provides:
//! - C2 server with TLS-encrypted listener
//! - Session management with unique IDs
//! - Interactive session handler for command execution
//! - Session multiplexing (multiple channels per session)
//! - Meterpreter-style commands (sysinfo, getpid, ps, upload, download)

pub mod control;
pub mod handler;
pub mod meterpreter;
pub mod server;
pub mod session;

pub use control::{C2ControlClient, start_control_server};
pub use handler::SessionHandler;
pub use meterpreter::{MeterpreterCommand, MeterpreterResponse, execute_meterpreter_command};
pub use server::C2Server;
pub use session::{Session, SessionManager, SessionType};
