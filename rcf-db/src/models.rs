//! Diesel models for the RCF database.

use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::*;

// ─── Host ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = hosts)]
pub struct Host {
    pub id: String,
    pub address: String,
    pub mac_address: Option<String>,
    pub os: Option<String>,
    pub os_accuracy: Option<String>,
    pub state: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub notes: Option<String>,
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = hosts)]
pub struct NewHost {
    pub id: String,
    pub address: String,
    pub mac_address: Option<String>,
    pub os: Option<String>,
    pub os_accuracy: Option<String>,
    pub state: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub notes: Option<String>,
}

impl NewHost {
    pub fn new(address: &str) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            id: Uuid::new_v4().to_string(),
            address: address.to_string(),
            mac_address: None,
            os: None,
            os_accuracy: None,
            state: "alive".to_string(),
            first_seen: now,
            last_seen: now,
            notes: None,
        }
    }
}

// ─── Service ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = services)]
pub struct Service {
    pub id: String,
    pub host_id: String,
    pub port: i32,
    pub protocol: String,
    pub state: String,
    pub name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    pub banner: Option<String>,
    pub discovered_at: i64,
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = services)]
pub struct NewService {
    pub id: String,
    pub host_id: String,
    pub port: i32,
    pub protocol: String,
    pub state: String,
    pub name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    pub banner: Option<String>,
    pub discovered_at: i64,
}

impl NewService {
    pub fn new(host_id: &str, port: u16) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            host_id: host_id.to_string(),
            port: port as i32,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            name: None,
            product: None,
            version: None,
            extra_info: None,
            banner: None,
            discovered_at: chrono::Utc::now().timestamp(),
        }
    }
}

// ─── Credential ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct Credential {
    pub id: String,
    pub host_id: String,
    pub port: i32,
    pub service: String,
    pub username: String,
    pub password: String,
    pub password_type: String,
    pub source: String,
    pub created_at: i64,
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub id: String,
    pub host_id: String,
    pub port: i32,
    pub service: String,
    pub username: String,
    pub password: String,
    pub password_type: String,
    pub source: String,
    pub created_at: i64,
}

impl NewCredential {
    pub fn new(host_id: &str, service: &str, username: &str, password: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            host_id: host_id.to_string(),
            port: 0,
            service: service.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            password_type: "password".to_string(),
            source: "manual".to_string(),
            created_at: chrono::Utc::now().timestamp(),
        }
    }
}

// ─── Vulnerability ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = vulnerabilities)]
pub struct Vulnerability {
    pub id: String,
    pub host_id: String,
    pub port: Option<i32>,
    pub service: String,
    pub name: String,
    pub cve: Option<String>,
    pub severity: String,
    pub proof: Option<String>,
    #[diesel(column_name = references_col)]
    pub references: Option<String>,
    pub discovered_at: i64,
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = vulnerabilities)]
pub struct NewVulnerability {
    pub id: String,
    pub host_id: String,
    pub port: Option<i32>,
    pub service: String,
    pub name: String,
    pub cve: Option<String>,
    pub severity: String,
    pub proof: Option<String>,
    #[diesel(column_name = references_col)]
    pub references: Option<String>,
    pub discovered_at: i64,
}

impl NewVulnerability {
    pub fn new(host_id: &str, name: &str, severity: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            host_id: host_id.to_string(),
            port: None,
            service: String::new(),
            name: name.to_string(),
            cve: None,
            severity: severity.to_string(),
            proof: None,
            references: None,
            discovered_at: chrono::Utc::now().timestamp(),
        }
    }
}

// ─── Session ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = sessions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Session {
    pub id: i32,
    pub session_uuid: String,
    pub host_id: String,
    #[diesel(column_name = type_)]
    pub type_: String,
    pub tunnel_local: Option<String>,
    pub tunnel_remote: Option<String>,
    pub via_payload: Option<String>,
    pub started_at: i64,
    pub last_seen: i64,
    pub info: Option<String>,
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = sessions)]
pub struct NewSession {
    pub id: i32,
    pub session_uuid: String,
    pub host_id: String,
    #[diesel(column_name = type_)]
    pub type_: String,
    pub tunnel_local: Option<String>,
    pub tunnel_remote: Option<String>,
    pub via_payload: Option<String>,
    pub started_at: i64,
    pub last_seen: i64,
    pub info: Option<String>,
}

impl NewSession {
    pub fn new(host_id: &str, type_: &str) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            id: 0, // AUTOINCREMENT
            session_uuid: Uuid::new_v4().to_string(),
            host_id: host_id.to_string(),
            type_: type_.to_string(),
            tunnel_local: None,
            tunnel_remote: None,
            via_payload: None,
            started_at: now,
            last_seen: now,
            info: None,
        }
    }
}

// ─── Loot ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = loot)]
pub struct Loot {
    pub id: String,
    pub host_id: String,
    #[diesel(column_name = ltype)]
    pub ltype: String,
    pub path: String,
    pub content: Option<String>,
    pub info: Option<String>,
    pub created_at: i64,
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = loot)]
pub struct NewLoot {
    pub id: String,
    pub host_id: String,
    pub ltype: String,
    pub path: String,
    pub content: Option<String>,
    pub info: Option<String>,
    pub created_at: i64,
}

impl NewLoot {
    pub fn new(host_id: &str, ltype: &str, path: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            host_id: host_id.to_string(),
            ltype: ltype.to_string(),
            path: path.to_string(),
            content: None,
            info: None,
            created_at: chrono::Utc::now().timestamp(),
        }
    }
}
