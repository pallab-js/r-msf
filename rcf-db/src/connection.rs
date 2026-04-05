//! Database connection and CRUD operations.

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use tracing::{info, warn};

use crate::models::*;
use crate::schema::*;

/// Embedded migrations — no external migration files needed.
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!();

/// RCF Database connection wrapper.
pub struct RcfDatabase {
    pub conn: SqliteConnection,
    pub path: String,
}

impl RcfDatabase {
    /// Create or open a database at the given path.
    ///
    /// Use `:memory:` for an in-memory database (testing).
    pub fn new(path: &str) -> anyhow::Result<Self> {
        let conn = SqliteConnection::establish(path)?;
        info!("Connected to database at {}", path);
        Ok(Self {
            conn,
            path: path.to_string(),
        })
    }

    /// Initialize database schema (run migrations).
    pub fn init(&mut self) -> anyhow::Result<()> {
        self.conn
            .run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("Migration failed: {}", e))?;
        info!("Database schema initialized");
        Ok(())
    }

    // ─── Hosts ─────────────────────────────────────────────────────────

    /// Add or update a host.
    pub fn save_host(&mut self, address: &str) -> anyhow::Result<String> {
        // Check if host exists
        let existing: Option<Host> = hosts::table
            .filter(hosts::address.eq(address))
            .first(&mut self.conn)
            .optional()?;

        if let Some(host) = existing {
            // Update last_seen
            diesel::update(hosts::table.filter(hosts::id.eq(&host.id)))
                .set(hosts::last_seen.eq(chrono::Utc::now().timestamp()))
                .execute(&mut self.conn)?;
            Ok(host.id)
        } else {
            // Insert new host
            let new_host = NewHost::new(address);
            let host_id = new_host.id.clone();
            diesel::insert_into(hosts::table)
                .values(&new_host)
                .execute(&mut self.conn)?;
            info!("Added host: {} ({})", address, host_id);
            Ok(host_id)
        }
    }

    /// Update host OS information.
    pub fn update_host_os(&mut self, host_id: &str, os: &str, accuracy: &str) -> anyhow::Result<()> {
        diesel::update(hosts::table.filter(hosts::id.eq(host_id)))
            .set((
                hosts::os.eq(os),
                hosts::os_accuracy.eq(accuracy),
            ))
            .execute(&mut self.conn)?;
        Ok(())
    }

    /// Get all hosts.
    pub fn list_hosts(&mut self) -> anyhow::Result<Vec<Host>> {
        let hosts_list = hosts::table.load::<Host>(&mut self.conn)?;
        Ok(hosts_list)
    }

    /// Get host by address.
    pub fn find_host(&mut self, address: &str) -> anyhow::Result<Option<Host>> {
        let result = hosts::table
            .filter(hosts::address.eq(address))
            .first(&mut self.conn)
            .optional()?;
        Ok(result)
    }

    /// Delete a host and all related data.
    pub fn delete_host(&mut self, host_id: &str) -> anyhow::Result<()> {
        // Delete related records first (SQLite doesn't have cascading by default)
        diesel::delete(services::table.filter(services::host_id.eq(host_id)))
            .execute(&mut self.conn)?;
        diesel::delete(credentials::table.filter(credentials::host_id.eq(host_id)))
            .execute(&mut self.conn)?;
        diesel::delete(vulnerabilities::table.filter(vulnerabilities::host_id.eq(host_id)))
            .execute(&mut self.conn)?;
        diesel::delete(sessions::table.filter(sessions::host_id.eq(host_id)))
            .execute(&mut self.conn)?;
        diesel::delete(loot::table.filter(loot::host_id.eq(host_id)))
            .execute(&mut self.conn)?;
        diesel::delete(hosts::table.filter(hosts::id.eq(host_id)))
            .execute(&mut self.conn)?;
        Ok(())
    }

    // ─── Services ──────────────────────────────────────────────────────

    /// Add a discovered service.
    pub fn add_service(&mut self, service: NewService) -> anyhow::Result<()> {
        diesel::insert_into(services::table)
            .values(&service)
            .execute(&mut self.conn)?;
        info!(
            "Added service: {}:{} ({}) on host {}",
            service.port,
            service.protocol,
            service.name.as_deref().unwrap_or("unknown"),
            service.host_id
        );
        Ok(())
    }

    /// List services for a host.
    pub fn list_services(&mut self, host_id: &str) -> anyhow::Result<Vec<Service>> {
        let services_list = services::table
            .filter(services::host_id.eq(host_id))
            .order(services::port.asc())
            .load::<Service>(&mut self.conn)?;
        Ok(services_list)
    }

    // ─── Credentials ───────────────────────────────────────────────────

    /// Store discovered credentials.
    ///
    /// # Security Note
    /// By default, passwords are hashed using SHA-256 with a per-host/per-user salt
    /// before storage. This prevents plaintext credential exposure if the database
    /// is accessed by unauthorized parties.
    pub fn add_credential(&mut self, cred: NewCredential) -> anyhow::Result<()> {
        // Avoid duplicates
        let existing: Option<Credential> = credentials::table
            .filter(
                credentials::host_id
                    .eq(&cred.host_id)
                    .and(credentials::username.eq(&cred.username))
                    .and(credentials::service.eq(&cred.service)),
            )
            .first(&mut self.conn)
            .optional()?;

        if existing.is_some() {
            warn!("Duplicate credential skipped: {}@{}", cred.username, cred.host_id);
            return Ok(());
        }

        // Hash password if it's not already hashed
        let final_cred = if cred.password.starts_with("hash:") {
            cred
        } else {
            use sha2::{Digest, Sha256};
            let salt = format!("{}:{}:rcf_salt_2026", cred.host_id, cred.username);
            let mut hasher = Sha256::new();
            hasher.update(format!("{}{}", salt, cred.password));
            let hash_hex = format!("{:x}", hasher.finalize());
            NewCredential {
                password: format!("hash:sha256:{}", hash_hex),
                ..cred
            }
        };

        diesel::insert_into(credentials::table)
            .values(&final_cred)
            .execute(&mut self.conn)?;
        info!(
            "Stored credential (hashed): {}@{}",
            final_cred.username, final_cred.host_id
        );
        Ok(())
    }

    /// List all credentials.
    pub fn list_credentials(&mut self) -> anyhow::Result<Vec<Credential>> {
        let creds = credentials::table.load::<Credential>(&mut self.conn)?;
        Ok(creds)
    }

    /// List credentials for a specific host.
    pub fn list_credentials_for_host(&mut self, host_id: &str) -> anyhow::Result<Vec<Credential>> {
        let creds = credentials::table
            .filter(credentials::host_id.eq(host_id))
            .load::<Credential>(&mut self.conn)?;
        Ok(creds)
    }

    // ─── Vulnerabilities ───────────────────────────────────────────────

    /// Record a discovered vulnerability.
    pub fn add_vulnerability(&mut self, vuln: NewVulnerability) -> anyhow::Result<()> {
        diesel::insert_into(vulnerabilities::table)
            .values(&vuln)
            .execute(&mut self.conn)?;
        info!(
            "Recorded vulnerability: {} ({}) on host {}",
            vuln.name, vuln.severity, vuln.host_id
        );
        Ok(())
    }

    /// List all vulnerabilities.
    pub fn list_vulnerabilities(&mut self) -> anyhow::Result<Vec<Vulnerability>> {
        let vulns = vulnerabilities::table.load::<Vulnerability>(&mut self.conn)?;
        Ok(vulns)
    }

    // ─── Sessions ──────────────────────────────────────────────────────

    /// Create a new session.
    pub fn create_session(&mut self, session: NewSession) -> anyhow::Result<i32> {
        diesel::insert_into(sessions::table)
            .values(&session)
            .execute(&mut self.conn)?;

        // Get the inserted ID
        let last_id: i32 = sessions::table
            .select(diesel::dsl::max(sessions::id))
            .first::<Option<i32>>(&mut self.conn)?
            .unwrap_or(0);
        Ok(last_id)
    }

    /// List active sessions.
    pub fn list_sessions(&mut self) -> anyhow::Result<Vec<Session>> {
        let sessions_list = sessions::table.load::<Session>(&mut self.conn)?;
        Ok(sessions_list)
    }

    /// Update session last_seen timestamp.
    pub fn update_session_heartbeat(&mut self, session_id: i32) -> anyhow::Result<()> {
        diesel::update(sessions::table.filter(sessions::id.eq(session_id)))
            .set(sessions::last_seen.eq(chrono::Utc::now().timestamp()))
            .execute(&mut self.conn)?;
        Ok(())
    }

    // ─── Loot ──────────────────────────────────────────────────────────

    /// Add a loot/artifact record.
    pub fn add_loot(&mut self, loot: NewLoot) -> anyhow::Result<()> {
        diesel::insert_into(loot::table)
            .values(&loot)
            .execute(&mut self.conn)?;
        info!("Stored loot: {} ({})", loot.ltype, loot.path);
        Ok(())
    }

    /// List loot for a host.
    pub fn list_loot(&mut self, host_id: &str) -> anyhow::Result<Vec<Loot>> {
        let loot_list = loot::table
            .filter(loot::host_id.eq(host_id))
            .load::<Loot>(&mut self.conn)?;
        Ok(loot_list)
    }

    // ─── Statistics ────────────────────────────────────────────────────

    /// Get database statistics.
    pub fn stats(&mut self) -> anyhow::Result<DbStats> {
        let host_count: i64 = hosts::table.count().get_result(&mut self.conn)?;
        let service_count: i64 = services::table.count().get_result(&mut self.conn)?;
        let cred_count: i64 = credentials::table.count().get_result(&mut self.conn)?;
        let vuln_count: i64 = vulnerabilities::table.count().get_result(&mut self.conn)?;
        let session_count: i64 = sessions::table.count().get_result(&mut self.conn)?;
        let loot_count: i64 = loot::table.count().get_result(&mut self.conn)?;

        Ok(DbStats {
            hosts: host_count as usize,
            services: service_count as usize,
            credentials: cred_count as usize,
            vulnerabilities: vuln_count as usize,
            sessions: session_count as usize,
            loot: loot_count as usize,
        })
    }
}

/// Database statistics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DbStats {
    pub hosts: usize,
    pub services: usize,
    pub credentials: usize,
    pub vulnerabilities: usize,
    pub sessions: usize,
    pub loot: usize,
}

impl std::fmt::Display for DbStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  {:<18} {}", "Hosts:", self.hosts)?;
        writeln!(f, "  {:<18} {}", "Services:", self.services)?;
        writeln!(f, "  {:<18} {}", "Credentials:", self.credentials)?;
        writeln!(f, "  {:<18} {}", "Vulnerabilities:", self.vulnerabilities)?;
        writeln!(f, "  {:<18} {}", "Sessions:", self.sessions)?;
        writeln!(f, "  {:<18} {}", "Loot:", self.loot)
    }
}
