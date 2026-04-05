-- Hosts: Discovered machines
CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    address TEXT NOT NULL UNIQUE,
    mac_address TEXT,
    os TEXT,
    os_accuracy TEXT,
    state TEXT NOT NULL DEFAULT 'unknown',
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    notes TEXT
);

-- Services: Open ports and detected services
CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL DEFAULT 'open',
    name TEXT,
    product TEXT,
    version TEXT,
    extra_info TEXT,
    banner TEXT,
    discovered_at INTEGER NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);

CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_services_port ON services(port);

-- Credentials: Discovered usernames/passwords/hashes
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 0,
    service TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    password_type TEXT NOT NULL DEFAULT 'password',
    source TEXT NOT NULL DEFAULT 'manual',
    created_at INTEGER NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);

CREATE INDEX IF NOT EXISTS idx_credentials_host ON credentials(host_id);

-- Vulnerabilities: CVEs and weaknesses
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    port INTEGER,
    service TEXT NOT NULL,
    name TEXT NOT NULL,
    cve TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    proof TEXT,
    "references" TEXT,
    discovered_at INTEGER NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host ON vulnerabilities(host_id);

-- Sessions: Active command shells/sessions
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_uuid TEXT NOT NULL UNIQUE,
    host_id TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'shell',
    tunnel_local TEXT,
    tunnel_remote TEXT,
    via_payload TEXT,
    started_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    info TEXT,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_host ON sessions(host_id);

-- Loot: Captured files, screenshots, notes
CREATE TABLE IF NOT EXISTS loot (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    ltype TEXT NOT NULL,
    path TEXT NOT NULL,
    content TEXT,
    info TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);

CREATE INDEX IF NOT EXISTS idx_loot_host ON loot(host_id);
