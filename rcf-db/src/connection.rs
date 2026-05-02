//! Database connection and CRUD operations.

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use tracing::{info, warn};

use crate::models::*;
use crate::schema::*;

/// Helper for `RETURNING id` queries.
#[derive(QueryableByName)]
struct IdRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    id: String,
}

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
    ///
    /// # Security
    /// Sets file permissions to 0600 (owner read/write only) on Unix systems
    /// to protect credential data from unauthorized access.
    pub fn new(path: &str) -> anyhow::Result<Self> {
        // Check if this is a new database file
        let is_new_file = !std::path::Path::new(path).exists() && path != ":memory:";

        let mut conn = SqliteConnection::establish(path)?;

        // Enable WAL journal mode for better concurrent read/write performance
        diesel::sql_query("PRAGMA journal_mode=WAL;")
            .execute(&mut conn)
            .ok();

        // Set restrictive permissions on new database files (Unix only)
        if is_new_file {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(path) {
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o600);
                    let _ = std::fs::set_permissions(path, perms);
                }
            }
        }

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

    /// Add or update a host. Uses a single INSERT ... ON CONFLICT upsert — no SELECT round-trip.
    /// Returns the host's UUID (existing or newly created).
    pub fn save_host(&mut self, address: &str) -> anyhow::Result<String> {
        let new_host = NewHost::new(address);
        let host_id = new_host.id.clone();
        let now = chrono::Utc::now().timestamp();

        // Single atomic upsert: insert new row or update last_seen on address conflict.
        // first_seen and id are preserved on conflict.
        diesel::sql_query(
            "INSERT INTO hosts (id, address, state, first_seen, last_seen) \
             VALUES (?1, ?2, 'alive', ?3, ?3) \
             ON CONFLICT(address) DO UPDATE SET last_seen = excluded.last_seen \
             RETURNING id"
        )
        .bind::<diesel::sql_types::Text, _>(&host_id)
        .bind::<diesel::sql_types::Text, _>(address)
        .bind::<diesel::sql_types::BigInt, _>(now)
        .get_result::<IdRow>(&mut self.conn)
        .map(|row| row.id)
        .or_else(|_| {
            // Fallback: RETURNING not supported on older SQLite — query the id after upsert
            diesel::sql_query(
                "INSERT INTO hosts (id, address, state, first_seen, last_seen) \
                 VALUES (?1, ?2, 'alive', ?3, ?3) \
                 ON CONFLICT(address) DO UPDATE SET last_seen = excluded.last_seen"
            )
            .bind::<diesel::sql_types::Text, _>(&host_id)
            .bind::<diesel::sql_types::Text, _>(address)
            .bind::<diesel::sql_types::BigInt, _>(now)
            .execute(&mut self.conn)?;

            hosts::table
                .filter(hosts::address.eq(address))
                .select(hosts::id)
                .first::<String>(&mut self.conn)
                .map_err(|e| anyhow::anyhow!(e))
        })
    }

    /// Upsert multiple hosts in a single transaction. Returns their UUIDs in order.
    pub fn save_hosts_batch(&mut self, addresses: &[&str]) -> anyhow::Result<Vec<String>> {
        self.conn.transaction(|conn| {
            let now = chrono::Utc::now().timestamp();
            let mut ids = Vec::with_capacity(addresses.len());

            for address in addresses {
                let new_host = NewHost::new(address);
                let host_id = new_host.id.clone();

                diesel::sql_query(
                    "INSERT INTO hosts (id, address, state, first_seen, last_seen) \
                     VALUES (?1, ?2, 'alive', ?3, ?3) \
                     ON CONFLICT(address) DO UPDATE SET last_seen = excluded.last_seen"
                )
                .bind::<diesel::sql_types::Text, _>(&host_id)
                .bind::<diesel::sql_types::Text, _>(*address)
                .bind::<diesel::sql_types::BigInt, _>(now)
                .execute(conn)?;

                let id = hosts::table
                    .filter(hosts::address.eq(*address))
                    .select(hosts::id)
                    .first::<String>(conn)?;
                ids.push(id);
            }
            Ok(ids)
        })
    }

    /// Update host OS information.
    pub fn update_host_os(
        &mut self,
        host_id: &str,
        os: &str,
        accuracy: &str,
    ) -> anyhow::Result<()> {
        diesel::update(hosts::table.filter(hosts::id.eq(host_id)))
            .set((hosts::os.eq(os), hosts::os_accuracy.eq(accuracy)))
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
        diesel::delete(loot::table.filter(loot::host_id.eq(host_id))).execute(&mut self.conn)?;
        diesel::delete(hosts::table.filter(hosts::id.eq(host_id))).execute(&mut self.conn)?;
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
    /// Passwords are hashed with Argon2 before storage. The plaintext is held in a
    /// `Zeroizing<String>` buffer that is zeroed from memory immediately after hashing.
    pub fn add_credential(&mut self, cred: NewCredential) -> anyhow::Result<()> {
        use zeroize::Zeroizing;

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
            warn!(
                "Duplicate credential skipped: {}@{}",
                cred.username, cred.host_id
            );
            return Ok(());
        }

        // Hash password if it's not already hashed
        let final_cred = if cred.password.starts_with("hash:") {
            cred
        } else {
            use argon2::{
                Argon2,
                password_hash::{PasswordHasher, SaltString},
            };

            // Hold plaintext in a Zeroizing buffer — zeroed on drop after hashing.
            let plaintext = Zeroizing::new(cred.password.clone());

            let mut salt_bytes = [0u8; 16];
            getrandom::getrandom(&mut salt_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to generate random salt: {}", e))?;
            let salt = SaltString::encode_b64(&salt_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to encode salt: {}", e))?;

            let hash = Argon2::default()
                .hash_password(plaintext.as_bytes(), &salt)
                .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;

            // `plaintext` is dropped (and zeroed) here before constructing final_cred.
            NewCredential {
                password: format!("hash:argon2:{}", hash),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{NewCredential, NewVulnerability};

    fn test_db() -> RcfDatabase {
        let mut db = RcfDatabase::new(":memory:").expect("in-memory db");
        db.init().expect("migrations");
        db
    }

    #[test]
    fn test_save_and_retrieve_host() {
        let mut db = test_db();
        let id = db.save_host("10.0.0.1").unwrap();
        assert!(!id.is_empty());
        let hosts = db.list_hosts().unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].address, "10.0.0.1");
    }

    #[test]
    fn test_credential_is_hashed_on_insert() {
        let mut db = test_db();
        let host_id = db.save_host("10.0.0.2").unwrap();
        let cred = NewCredential::new(&host_id, "ssh", "admin", "s3cr3t");
        db.add_credential(cred).unwrap();

        let creds = db.list_credentials().unwrap();
        assert_eq!(creds.len(), 1);
        assert!(
            creds[0].password.starts_with("hash:argon2:"),
            "password should be hashed, got: {}",
            creds[0].password
        );
        assert_ne!(creds[0].password, "s3cr3t");
    }

    #[test]
    fn test_duplicate_credential_skipped() {
        let mut db = test_db();
        let host_id = db.save_host("10.0.0.3").unwrap();
        let cred1 = NewCredential::new(&host_id, "ftp", "user", "pass1");
        let cred2 = NewCredential::new(&host_id, "ftp", "user", "pass2");
        db.add_credential(cred1).unwrap();
        db.add_credential(cred2).unwrap(); // should be silently skipped

        let creds = db.list_credentials().unwrap();
        assert_eq!(creds.len(), 1);
    }

    #[test]
    fn test_save_vulnerability() {
        let mut db = test_db();
        let host_id = db.save_host("10.0.0.4").unwrap();
        let vuln = NewVulnerability::new(&host_id, "CVE-2021-44228 Log4Shell", "critical");
        db.add_vulnerability(vuln).unwrap();

        let vulns = db.list_vulnerabilities().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].severity, "critical");
        assert!(vulns[0].name.contains("Log4Shell"));
    }
}
