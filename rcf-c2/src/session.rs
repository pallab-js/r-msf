//! Session management for C2.
//!
//! Tracks active sessions, provides session lifecycle,
//! and manages session state.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, mpsc};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Types of C2 sessions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionType {
    /// Interactive shell (like meterpreter)
    Shell,
    /// Command execution (single command, then exit)
    Command,
    /// SOCKS proxy tunnel
    Socks,
    /// File transfer channel
    Transfer,
}

impl std::fmt::Display for SessionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionType::Shell => write!(f, "shell"),
            SessionType::Command => write!(f, "command"),
            SessionType::Socks => write!(f, "socks"),
            SessionType::Transfer => write!(f, "transfer"),
        }
    }
}

/// A single C2 session (agent connection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session UUID
    pub id: String,
    /// Numeric session ID (for display)
    pub num: u32,
    /// Type of session
    pub type_: SessionType,
    /// Remote address of the agent
    pub remote_addr: String,
    /// Local tunnel address
    pub tunnel_local: String,
    /// Agent platform info
    pub platform: Option<String>,
    /// Agent username
    pub username: Option<String>,
    /// Information about the session
    pub info: String,
    /// When the session was created
    pub created_at: i64,
    /// When the session last communicated
    pub last_seen: i64,
    /// Whether the session is still active
    pub active: bool,
    /// Sender for sending commands to this session
    #[serde(skip)]
    pub command_tx: Option<mpsc::Sender<SessionCommand>>,
}

impl Session {
    pub fn new(num: u32, remote_addr: &str, type_: SessionType) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            num,
            type_,
            remote_addr: remote_addr.to_string(),
            tunnel_local: String::new(),
            platform: None,
            username: None,
            info: String::new(),
            created_at: chrono::Utc::now().timestamp(),
            last_seen: chrono::Utc::now().timestamp(),
            active: true,
            command_tx: None,
        }
    }

    /// Mark session as inactive.
    pub fn close(&mut self) {
        self.active = false;
        self.last_seen = chrono::Utc::now().timestamp();
    }

    /// Update last-seen timestamp.
    pub fn heartbeat(&mut self) {
        self.last_seen = chrono::Utc::now().timestamp();
    }
}

/// Commands that can be sent to a session.
#[derive(Debug, Clone)]
pub enum SessionCommand {
    /// Execute a command (shell type)
    Execute(String),
    /// Send raw data
    Data(Vec<u8>),
    /// Close the session
    Close,
}

/// Session result from command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionOutput {
    pub session_id: String,
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

/// Central session manager.
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<u32, Session>>>,
    next_num: Arc<Mutex<u32>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            next_num: Arc::new(Mutex::new(1)),
        }
    }

    /// Create a new session and return its numeric ID.
    pub async fn create_session(
        &self,
        remote_addr: &str,
        type_: SessionType,
    ) -> u32 {
        let mut num_lock = self.next_num.lock().await;
        let num = *num_lock;
        *num_lock += 1;

        let session = Session::new(num, remote_addr, type_);

        let mut sessions = self.sessions.write().await;
        sessions.insert(num, session);

        num
    }

    /// Register a command sender for a session.
    pub async fn register_sender(&self, session_num: u32, tx: mpsc::Sender<SessionCommand>) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&session_num) {
            session.command_tx = Some(tx);
        }
    }

    /// Update session address and info.
    pub async fn update_session_info(&self, session_num: u32, local: &str, info: &str) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&session_num) {
            session.tunnel_local = local.to_string();
            session.info = info.to_string();
        }
    }

    /// Get a session by number.
    pub async fn get_session(&self, num: u32) -> Option<Session> {
        self.sessions.read().await.get(&num).cloned()
    }

    /// List all active sessions.
    pub async fn list_sessions(&self) -> Vec<Session> {
        self.sessions
            .read()
            .await
            .values()
            .filter(|s| s.active)
            .cloned()
            .collect()
    }

    /// List all sessions (including inactive).
    pub async fn list_all_sessions(&self) -> Vec<Session> {
        self.sessions.read().await.values().cloned().collect()
    }

    /// Kill a session.
    pub async fn kill_session(&self, num: u32) -> Option<Session> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&num) {
            // Send close command if there's a sender
            if let Some(tx) = &session.command_tx {
                let _ = tx.send(SessionCommand::Close).await;
            }
            session.close();
            Some(session.clone())
        } else {
            None
        }
    }

    /// Kill all active sessions (for graceful shutdown).
    pub async fn kill_all(&self) {
        let mut sessions = self.sessions.write().await;
        for (_, session) in sessions.iter_mut() {
            if session.active {
                // Send close command if there's a sender
                if let Some(tx) = &session.command_tx {
                    let _ = tx.send(SessionCommand::Close).await;
                }
                session.close();
            }
        }
    }

    /// Send a command to a session.
    pub async fn send_command(&self, session_num: u32, command: &str) -> anyhow::Result<()> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&session_num) {
            if let Some(tx) = &session.command_tx {
                tx.send(SessionCommand::Execute(command.to_string()))
                    .await?;
                return Ok(());
            }
        }
        Err(anyhow::anyhow!("Session {} not found or has no command channel", session_num))
    }

    /// Count active sessions.
    pub async fn active_count(&self) -> usize {
        self.sessions
            .read()
            .await
            .values()
            .filter(|s| s.active)
            .count()
    }

    /// Format sessions for display.
    pub async fn format_sessions(&self) -> String {
        let sessions = self.list_sessions().await;
        if sessions.is_empty() {
            return "No active sessions".to_string();
        }

        let mut lines = Vec::new();
        lines.push(format!(
            "\n  {:<6} {:<8} {:<18}  {:<12}  {}",
            "ID".bold(),
            "Type".bold(),
            "Remote".bold(),
            "Platform".bold(),
            "Info".bold()
        ));
        lines.push(format!(
            "  {:<6} {:<8} {:<18}  {:<12}  {}",
            "--".bold(),
            "----".bold(),
            "------".bold(),
            "--------".bold(),
            "----".bold()
        ));

        for s in sessions {
            let platform = s.platform.as_deref().unwrap_or("unknown");
            lines.push(format!(
                "  {:<6} {:<8} {:<18}  {:<12}  {}",
                s.num, s.type_, s.remote_addr, platform, s.info
            ));
        }

        lines.join("\n")
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

// Re-import colored for bold in SessionManager
use colored::Colorize;
