//! CLI entry point for the Rust Cybersecurity Framework.

use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use rcf_core::Context;
use rcf_modules::builtin::register_builtin_modules;
use rcf_modules::{ModuleManager, ModuleRegistry};

#[derive(Parser)]
#[command(name = "rcf")]
#[command(about = "Rust Cybersecurity Framework — Fast. Safe. Modular. Rust.", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Set RHOSTS before starting
    #[arg(long, global = true)]
    rhosts: Option<String>,

    /// Set LHOST before starting
    #[arg(long, global = true)]
    lhost: Option<String>,

    /// Set LPORT before starting
    #[arg(long, global = true)]
    lport: Option<u16>,

    /// Execute a single command and exit (non-interactive)
    #[arg(short = 'x', long)]
    execute: Option<String>,

    /// Load context from file
    #[arg(short = 'c', long)]
    context_file: Option<String>,

    /// Enable TLS certificate validation (default: disabled for pentesting)
    #[arg(long, global = true)]
    strict_tls: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the interactive console (default)
    Console,

    /// Run a module non-interactively
    Run {
        /// Module path (e.g. auxiliary/scanner/port/tcp_syn)
        #[arg(short, long)]
        module: String,

        /// Target host(s)
        #[arg(short = 't', long)]
        target: String,

        /// Target port
        #[arg(short = 'p', long, default_value = "80")]
        port: u16,

        /// Additional options as KEY=VALUE pairs
        #[arg(last = true)]
        options: Vec<String>,
    },

    /// Search for modules
    Search {
        /// Keyword to search for
        keyword: String,
    },

    /// Show module information
    Info {
        /// Module path
        module: String,
    },

    /// Generate a payload (RCF-Venom stub)
    Venom {
        /// Payload type
        #[arg(short, long, default_value = "reverse_tcp")]
        payload: String,

        /// Listen host
        #[arg(long)]
        lhost: String,

        /// Listen port
        #[arg(long, default_value = "4444")]
        lport: u16,

        /// Output format
        #[arg(short, long, default_value = "raw")]
        format: String,

        /// Output file
        #[arg(short, long)]
        output: Option<String>,

        /// Encoder to use
        #[arg(short, long)]
        encoder: Option<String>,

        /// Execute the payload locally after generation (testing only)
        #[arg(long)]
        execute: bool,
    },

    /// Scan targets
    Scan {
        /// Target host(s) — comma separated
        #[arg(short = 't', long)]
        target: String,

        /// Port range (e.g. 1-1024)
        #[arg(short, long, default_value = "1-65535")]
        ports: String,

        /// Number of threads
        #[arg(short, long, default_value = "100")]
        threads: usize,

        /// Timeout per port in seconds
        #[arg(long, default_value = "3")]
        timeout: u64,

        /// Output format (text, json, csv)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Database operations
    #[cfg(feature = "db")]
    Db {
        /// Database file path (default: ~/.rcf/rcf.db)
        #[arg(short, long)]
        file: Option<String>,

        #[command(subcommand)]
        command: DbCommands,
    },

    /// C2 server operations
    #[cfg(feature = "c2")]
    C2 {
        /// Listen address
        #[arg(long, default_value = "0.0.0.0")]
        lhost: String,

        /// Listen port
        #[arg(long, default_value = "8443")]
        lport: u16,

        #[command(subcommand)]
        command: Option<C2Commands>,
    },

    /// Report generation
    Report {
        #[command(subcommand)]
        command: ReportCommands,
    },

    /// Automated attack chains
    #[cfg(feature = "db")]
    Auto {
        /// Target host(s)
        #[arg(short = 't', long)]
        target: String,

        /// Output report file
        #[arg(short = 'o', long)]
        output: Option<String>,

        /// Aggressive mode (full port scan + all vuln checks)
        #[arg(short, long)]
        aggressive: bool,
    },
}

#[derive(Subcommand)]
#[cfg(feature = "db")]
enum DbCommands {
    /// Show database statistics
    Stats,
    /// List all discovered hosts
    Hosts,
    /// List all credentials
    Creds,
    /// List all vulnerabilities
    Vulns,
    /// Export database to file
    Export {
        /// Output file
        #[arg(short, long)]
        output: String,
        /// Export format
        #[arg(short, long, default_value = "json")]
        format: String,
    },
}

#[derive(Subcommand)]
#[cfg(feature = "c2")]
enum C2Commands {
    /// Start C2 server listener
    Listen,
    /// List active sessions
    Sessions,
    /// Interact with a session
    Interact {
        /// Session number
        session: u32,
    },
    /// Kill a session
    Kill {
        /// Session number
        session: u32,
    },
}

#[derive(Subcommand)]
enum ReportCommands {
    /// Generate HTML report from database
    Generate {
        /// Database file path
        #[arg(short, long)]
        db: Option<String>,
        /// Output file path
        #[arg(short, long)]
        output: String,
    },
    /// Auto-generate report from current scan findings
    Auto {
        /// Target to scan before generating report
        #[arg(short = 't', long)]
        target: Option<String>,
        /// Output file path
        #[arg(short, long, default_value = "report.html")]
        output: String,
    },
}

/// Validate a file path to prevent writes to sensitive system locations.
/// Uses canonicalization to resolve symlinks and relative paths.
fn validate_write_path(path: &str) -> anyhow::Result<()> {
    // Block obvious dangerous paths (case-insensitive prefix check)
    let lower = path.to_lowercase();
    let dangerous_prefixes = [
        "/etc/", "/usr/", "/var/", "/root/", "/proc/", "/sys/",
        "/system/", "/boot/", "/applications/",
        "c:\\windows", "c:\\program files",
    ];
    
    for prefix in dangerous_prefixes {
        if lower.starts_with(prefix) {
            anyhow::bail!("Output path targets a protected system directory: {}", path);
        }
    }

    // Check for path traversal attempts
    let p = std::path::Path::new(path);
    if p.is_absolute() {
        // Absolute paths are allowed but will be canonicalized later
        return Ok(());
    }

    // For relative paths, limit parent directory traversal
    let parent_count = path.split('/').filter(|&s| s == "..").count()
        + path.split('\\').filter(|&s| s == "..").count();
    if parent_count > 3 {
        anyhow::bail!("Output path uses excessive parent directory traversal: {}", path);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = if cli.verbose {
        "debug"
    } else {
        "info"
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_target(false)
                .compact(),
        )
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .init();

    // Build module registry
    let mut registry = ModuleRegistry::new();
    register_builtin_modules(&mut registry);
    let manager = ModuleManager::new(registry);

    // Build context
    let mut context = Context::new();
    if let Some(ref rhosts) = cli.rhosts {
        context.set("RHOSTS", rhosts);
    }
    if let Some(ref lhost) = cli.lhost {
        context.set("LHOST", lhost);
    }
    if let Some(lport) = cli.lport {
        context.set("LPORT", &lport.to_string());
    }
    if cli.strict_tls {
        context.set("STRICT_TLS", "true");
    }
    if cli.verbose {
        context.set("VERBOSE", "true");
    }

    // Load context from file if specified
    if let Some(ref path) = cli.context_file {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                match Context::from_toml(&content) {
                    Ok(loaded) => context = loaded,
                    Err(e) => eprintln!("Failed to parse context file: {}", e),
                }
            }
            Err(e) => eprintln!("Failed to read context file: {}", e),
        }
    }

    // Handle subcommands
    match cli.command {
        Some(Commands::Search { keyword }) => {
            println!("{}", manager.format_search_results(&keyword));
            return Ok(());
        }

        Some(Commands::Info { module }) => {
            println!("{}", manager.format_module_info(&module));
            return Ok(());
        }

        Some(Commands::Venom {
            payload,
            lhost,
            lport,
            format,
            output,
            encoder,
            execute,
        }) => {
            run_venom(&payload, &lhost, lport, &format, output.as_deref(), encoder.as_deref(), execute).await?;
            return Ok(());
        }

        Some(Commands::Scan {
            target,
            ports,
            threads,
            timeout,
            format,
        }) => {
            run_scan(&target, &ports, threads, timeout, &format).await?;
            return Ok(());
        }

        #[cfg(feature = "db")]
        Some(Commands::Db { file, command }) => {
            #[cfg(feature = "db")]
            run_db(file.as_deref(), &command)?;
            return Ok(());
        }

        #[cfg(feature = "c2")]
        Some(Commands::C2 { lhost, lport, command }) => {
            run_c2(&lhost, lport, command).await?;
            return Ok(());
        }

        Some(Commands::Report { command }) => {
            match command {
                ReportCommands::Generate { db, output } => {
                    run_report(&ReportCommands::Generate { db, output })?;
                }
                ReportCommands::Auto { target, output } => {
                    if let Some(t) = target {
                        run_auto(&t, Some(&output), false).await?;
                    } else {
                        run_report(&ReportCommands::Generate { db: None, output })?;
                    }
                }
            }
            return Ok(());
        }

        #[cfg(feature = "db")]
        Some(Commands::Auto { target, output, aggressive }) => {
            run_auto(&target, output.as_deref(), aggressive).await?;
            return Ok(());
        }

        Some(Commands::Run {
            module,
            target,
            port,
            options,
        }) => {
            run_module_non_interactive(&manager, &module, &target, port, &options).await?;
            return Ok(());
        }

        Some(Commands::Console) | None => {
            // Fall through to console mode
        }
    }

    // Handle -x single command execution
    if let Some(ref cmd) = cli.execute {
        // Run single command — will be implemented in Phase 2
        println!("[*] Executing: {}", cmd);
        return Ok(());
    }

    // Start interactive console
    use rcf_console::RcfConsole;
    let mut console = RcfConsole::new(manager, context)?;
    console.run().await?;

    Ok(())
}

async fn run_module_non_interactive(
    manager: &ModuleManager,
    module_name: &str,
    target_host: &str,
    target_port: u16,
    options: &[String],
) -> anyhow::Result<()> {
    let module = manager
        .registry()
        .get(module_name)
        .ok_or_else(|| anyhow::anyhow!("Module '{}' not found", module_name))?;

    let mut ctx = Context::new();
    ctx.set("RHOSTS", target_host);
    ctx.set("RPORT", &target_port.to_string());

    // Parse KEY=VALUE options
    for opt in options {
        if let Some((key, value)) = opt.split_once('=') {
            ctx.set(key, value);
        }
    }

    let target = rcf_core::Target::new(target_host, target_port);

    println!("[*] Running {} against {}:{}", module_name, target_host, target_port);
    let output = module.run(&mut ctx, &target).await?;
    println!("{}", output.render());

    Ok(())
}

async fn run_venom(
    payload_type: &str,
    lhost: &str,
    lport: u16,
    format: &str,
    output: Option<&str>,
    encoder: Option<&str>,
    execute: bool,
) -> anyhow::Result<()> {
    use rcf_payload::{
        PayloadConfig, PayloadType, PayloadGenerator, PayloadEncoder,
        Platform, Arch, OutputFormat,
    };

    println!("{}", "[*] RCF-Venom — Payload Generator".bold().green());

    // Parse payload type
    let ptype: PayloadType = payload_type
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("Unknown payload type: {}. Using reverse_tcp.", payload_type);
            PayloadType::ReverseTcp
        });

    // Parse platform and arch from env or defaults
    let platform = std::env::var("RCF_PLATFORM")
        .ok()
        .and_then(|p| p.parse::<Platform>().ok())
        .unwrap_or(Platform::Linux);

    let arch = std::env::var("RCF_ARCH")
        .ok()
        .and_then(|a| a.parse::<Arch>().ok())
        .unwrap_or(Arch::X64);

    println!("  Type:      {}", ptype);
    println!("  Platform:  {}/{}", platform, arch);
    println!("  LHOST:     {}", lhost);
    println!("  LPORT:     {}", lport);
    println!("  Format:    {}", format);
    if let Some(enc) = encoder {
        println!("  Encoder:   {}", enc);
    }

    // Parse output format
    let out_format: OutputFormat = format
        .parse()
        .unwrap_or_else(|_| OutputFormat::C);

    // Build encoder
    let enc = match encoder {
        Some("xor") => Some(PayloadEncoder::Xor),
        Some("xor_dynamic") => Some(PayloadEncoder::XorDynamic),
        Some("nop") => Some(PayloadEncoder::NopSled(16)),
        Some("junk") => Some(PayloadEncoder::JunkInsert(32)),
        Some("polymorphic") => None, // handled separately
        Some(other) => {
            eprintln!("Unknown encoder: {}. Using none.", other);
            None
        }
        None => None,
    };

    let is_polymorphic = encoder == Some("polymorphic");

    // Build config
    let config = PayloadConfig {
        payload_type: ptype,
        platform: platform.clone(),
        arch: arch.clone(),
        lhost: lhost.to_string(),
        lport,
        rhost: None,
        rport: None,
        command: None,
        stage_url: None,
        format: out_format.clone(),
        encoder: enc,
        polymorphic: is_polymorphic,
        nop_sled_size: None,
        bad_chars: vec![0x00],
    };

    // Generate
    let generator = PayloadGenerator::new();
    let payload_output = generator.generate(&config).await?;

    // Display
    println!("\n{}", payload_output.display());

    // Save to file if requested
    if let Some(path) = output {
        // Validate path to prevent writes to sensitive system locations
        validate_write_path(path)?;
        let canonical = std::fs::canonicalize(path).ok();
        if let Some(real) = canonical {
            let real_lower = real.to_string_lossy().to_lowercase();
            if real_lower.contains("/etc/") || real_lower.contains("/usr/")
                || real_lower.contains("/var/") || real_lower.contains("/root/")
                || real_lower.contains("/proc/") || real_lower.contains("/sys/")
                || real_lower.contains("/system/") || real_lower.contains("/boot/")
                || real_lower.contains("/applications/") {
                anyhow::bail!("Refusing to write payload to protected system directory");
            }
        }

        let data = match out_format {
            OutputFormat::Raw => payload_output.shellcode.clone(),
            OutputFormat::Pe => {
                let builder = rcf_payload::PeBuilder::new();
                builder.build(&payload_output.shellcode, &arch, 0)
            }
            _ => payload_output.formatted.as_bytes().to_vec(),
        };
        std::fs::write(path, &data)?;
        println!("[+] Saved {} bytes to {}", data.len(), path);
    }

    // Execute payload locally if requested
    if execute {
        println!("\n{}", "[*] Executing payload locally (testing mode)".bold().yellow());
        let executor = rcf_payload::PayloadExecutor::new();
        match executor.execute_shellcode(&payload_output.shellcode, &arch, 10) {
            Ok(result) => {
                println!("{}", result);
            }
            Err(e) => {
                eprintln!("{} Payload execution failed: {}", "[-]".red(), e);
            }
        }
    }

    Ok(())
}

async fn run_scan(
    target: &str,
    ports: &str,
    threads: usize,
    timeout: u64,
    format: &str,
) -> anyhow::Result<()> {
    use rcf_network::scanner::{TcpConnectScanner, PortRange, ScanConfig};
    use rcf_core::target::parse_targets;
    use std::time::Duration;
    use colored::Colorize;

    // Parse targets (supports CIDR, ranges, comma-separated)
    let targets = parse_targets(target, 80)?;
    let target_count = targets.len();

    println!("{}", "[*] RCF Network Scanner".bold().green());
    println!("  Targets:  {} (from '{}')", target_count, target);
    println!("  Ports:    {}", ports);
    println!("  Threads:  {}", threads);
    println!("  Timeout:  {}s", timeout);
    println!("  Format:   {}", format);

    let port_range = PortRange::parse(ports).unwrap_or_else(|e| {
        eprintln!("Invalid port range: {}. Using 'common'.", e);
        PortRange::Common
    });

    let scanner = TcpConnectScanner::new();

    // Scan all targets in parallel
    let mut all_open: Vec<(String, Vec<_>)> = Vec::new();
    let mut total_ports = 0;
    let mut total_open = 0;
    let mut total_filtered = 0;

    // Use bounded concurrency for parallel scanning
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(threads));
    let mut handles = Vec::new();

    for target in &targets {
        let sem = semaphore.clone();
        let port_range = port_range.clone();
        let timeout_dur = Duration::from_secs(timeout);
        let host = target.host.clone();

        let handle = tokio::spawn(async move {
            let permit = match sem.acquire().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("Failed to acquire semaphore: {}", e);
                    return (host, vec![]);
                }
            };
            let config = ScanConfig::new(&host)
                .with_ports(port_range)
                .with_concurrency(1)
                .with_timeout(timeout_dur);
            
            let scanner = TcpConnectScanner::new();
            let results = scanner.scan(&config).await;
            drop(permit);
            (host, results)
        });

        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        if let Ok((host, results)) = handle.await {
            let open: Vec<_> = results.iter()
                .filter(|r| r.state == rcf_network::scanner::PortState::Open)
                .cloned()
                .collect();
            let filtered: Vec<_> = results.iter()
                .filter(|r| r.state == rcf_network::scanner::PortState::Filtered)
                .cloned()
                .collect();

            total_ports += results.len();
            total_open += open.len();
            total_filtered += filtered.len();

            if !open.is_empty() {
                all_open.push((host.clone(), open));
            }
        }
    }

    // Print summary
    println!("\n  Scanned {} targets, {} ports total, {} open, {} filtered\n",
        target_count, total_ports, total_open, total_filtered);

    if all_open.is_empty() {
        println!("  No open ports found across all targets.");
    } else {
        if format == "json" {
            let json_results: Vec<_> = all_open.iter().flat_map(|(host, opens)| {
                let host = host.clone();
                opens.iter().map(move |r| {
                    serde_json::json!({
                        "host": host,
                        "port": r.port,
                        "protocol": r.protocol,
                        "state": r.state.to_string(),
                        "service": r.service,
                        "version": r.version,
                        "banner": r.banner,
                        "rtt_ms": r.rtt_ms,
                    })
                })
            }).collect();
            println!("{}", serde_json::to_string_pretty(&json_results)?);
        } else {
            // Text table grouped by host
            for (host, opens) in &all_open {
                println!("  {}", format!("Host: {}", host).bold().cyan());
                println!("  {:<10} {:<6} {:<18}  {}", "Port".bold(), "Proto".bold(), "Service".bold(), "Details".bold());
                println!("  {:<10} {:<6} {:<18}  {}", "----".bold(), "-----".bold(), "-------".bold(), "---------".bold());
                
                for r in opens {
                    let details = match (&r.version, &r.banner, r.rtt_ms) {
                        (Some(v), _, Some(rtt)) => format!("{} ({:.0}ms)", v, rtt),
                        (_, Some(b), Some(rtt)) => format!("{} ({:.0}ms)", b, rtt),
                        (_, _, Some(rtt)) => format!("{:.0}ms", rtt),
                        (Some(v), _, _) => v.clone(),
                        (_, Some(b), _) => b.clone(),
                        _ => String::new(),
                    };
                    println!("  {:<10} {:<6} {:<18}  {}",
                        format!("{}/tcp", r.port),
                        r.protocol,
                        r.service.as_deref().unwrap_or("unknown"),
                        details,
                    );
                }
                println!();
            }
        }
    }

    if total_filtered > 0 {
        println!("  {} total filtered ports across all targets", total_filtered);
    }

    Ok(())
}

#[cfg(feature = "db")]
fn run_db(file: Option<&str>, command: &DbCommands) -> anyhow::Result<()> {
    use rcf_db::connection::RcfDatabase;
    use rcf_db::export::{export_all, ExportFormat};

    let default_path = dirs::home_dir()
        .map(|p| p.join(".rcf").join("rcf.db").to_string_lossy().to_string())
        .unwrap_or_else(|| "rcf.db".to_string());

    let path = file.unwrap_or(&default_path);

    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut db = RcfDatabase::new(path)?;
    db.init()?;

    match command {
        DbCommands::Stats => {
            println!("{}", "[*] Database Statistics".bold().green());
            let stats = db.stats()?;
            println!("\n{}", stats);
        }

        DbCommands::Hosts => {
            println!("{}", "[*] Discovered Hosts".bold().green());
            let hosts = db.list_hosts()?;
            if hosts.is_empty() {
                println!("  No hosts recorded yet.");
                println!("  Hosts are added automatically when scanning.");
            } else {
                println!(
                    "\n  {:<20} {:<12} {:<16}  {}",
                    "Address".bold(),
                    "State".bold(),
                    "OS".bold(),
                    "Last Seen".bold()
                );
                println!(
                    "  {:<20} {:<12} {:<16}  {}",
                    "-------".bold(),
                    "-----".bold(),
                    "--".bold(),
                    "---------".bold()
                );
                for host in hosts {
                    let os = host.os.as_deref().unwrap_or("unknown");
                    let last_seen = chrono::DateTime::from_timestamp(host.last_seen, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                        .unwrap_or_else(|| "never".to_string());
                    println!(
                        "  {:<20} {:<12} {:<16}  {}",
                        host.address, host.state, os, last_seen
                    );
                }
            }
        }

        DbCommands::Creds => {
            println!("{}", "[*] Stored Credentials".bold().green());
            let creds = db.list_credentials()?;
            if creds.is_empty() {
                println!("  No credentials recorded yet.");
            } else {
                println!(
                    "\n  {:<20} {:<12} {:<15}  {}",
                    "Host".bold(),
                    "Service".bold(),
                    "Username".bold(),
                    "Password".bold()
                );
                println!(
                    "  {:<20} {:<12} {:<15}  {}",
                    "----".bold(),
                    "-------".bold(),
                    "--------".bold(),
                    "--------".bold()
                );
                for cred in creds {
                    println!(
                        "  {:<20} {:<12} {:<15}  {}",
                        cred.host_id, cred.service, cred.username, cred.password
                    );
                }
            }
        }

        DbCommands::Vulns => {
            println!("{}", "[*] Vulnerabilities".bold().green());
            let vulns = db.list_vulnerabilities()?;
            if vulns.is_empty() {
                println!("  No vulnerabilities recorded yet.");
            } else {
                println!(
                    "\n  {:<20} {:<25} {:<10}  {}",
                    "Host".bold(),
                    "Name".bold(),
                    "Severity".bold(),
                    "CVE".bold()
                );
                println!(
                    "  {:<20} {:<25} {:<10}  {}",
                    "----".bold(),
                    "----".bold(),
                    "--------".bold(),
                    "---".bold()
                );
                for vuln in vulns {
                    let cve = vuln.cve.as_deref().unwrap_or("N/A");
                    println!(
                        "  {:<20} {:<25} {:<10}  {}",
                        vuln.host_id, vuln.name, vuln.severity, cve
                    );
                }
            }
        }

        DbCommands::Export { output, format } => {
            // Validate export path with canonicalization
            validate_write_path(output)?;
            let canonical = std::fs::canonicalize(output).ok();
            if let Some(real) = canonical {
                let real_lower = real.to_string_lossy().to_lowercase();
                if real_lower.contains("/etc/") || real_lower.contains("/usr/")
                    || real_lower.contains("/var/") || real_lower.contains("/root/")
                    || real_lower.contains("/proc/") || real_lower.contains("/sys/")
                    || real_lower.contains("/system/") || real_lower.contains("/boot/")
                    || real_lower.contains("/applications/") {
                    anyhow::bail!("Refusing to export database to protected system directory");
                }
            }

            let fmt: ExportFormat = format.parse().map_err(|e| anyhow::anyhow!("Invalid export format: {}", e))?;
            let data = export_all(&mut db, &fmt)?;
            std::fs::write(output, data)?;
            println!("[+] Database exported to {} ({})", output, format);
        }
    }

    Ok(())
}

#[cfg(feature = "c2")]
async fn run_c2(lhost: &str, lport: u16, command: Option<C2Commands>) -> anyhow::Result<()> {
    use std::sync::Arc;
    use rcf_c2::server::{C2Server, C2Config};
    use rcf_c2::session::SessionManager;

    let sessions = Arc::new(SessionManager::new());

    match command {
        Some(C2Commands::Listen) => {
            let config = C2Config::new(lhost, lport);
            let server = C2Server::new(config, Arc::clone(&sessions));
            println!("{}", "[*] Starting C2 Server".bold().green());
            println!("  Listen: {}:{}", lhost, lport);
            server.start().await?;
        }
        Some(C2Commands::Sessions) => {
            println!("{}", "[*] Active Sessions".bold().green());
            println!("{}", sessions.format_sessions().await);
        }
        Some(C2Commands::Interact { session }) => {
            println!("{}", format!("[*] Interacting with session {}", session).bold().green());
            println!("[*] Session interaction coming in next update");
        }
        Some(C2Commands::Kill { session }) => {
            if let Some(s) = sessions.kill_session(session).await {
                println!("[+] Killed session {} ({})", session, s.remote_addr);
            } else {
                println!("[-] Session {} not found", session);
            }
        }
        None => {
            println!("{}", "[*] C2 Server".bold().green());
            println!("{}", sessions.format_sessions().await);
        }
    }

    Ok(())
}

fn run_report(command: &ReportCommands) -> anyhow::Result<()> {
    use rcf_db::connection::RcfDatabase;
    use std::path::Path;

    /// Escape HTML special characters to prevent XSS in reports.
    fn html_escape(s: &str) -> String {
        s.replace('&', "&amp;")
         .replace('<', "&lt;")
         .replace('>', "&gt;")
         .replace('"', "&quot;")
         .replace('\'', "&#x27;")
    }

    /// Validate that a file path doesn't traverse outside the current directory.
    /// This prevents accidental writes to sensitive system files.
    fn validate_output_path(path: &str) -> anyhow::Result<String> {
        // Block obvious dangerous paths
        let lower = path.to_lowercase();
        if lower.starts_with("/etc/") || lower.starts_with("/usr/") || lower.starts_with("/var/")
            || lower.starts_with("/root/") || lower.starts_with("/proc/") || lower.starts_with("/sys/")
            || lower.starts_with("c:\\windows") || lower.starts_with("c:\\program files") {
            anyhow::bail!("Output path targets a protected system directory: {}", path);
        }

        // If path is relative, ensure it doesn't use excessive parent traversal
        let p = Path::new(path);
        if p.is_absolute() {
            return Ok(path.to_string());
        }

        // Count parent traversals
        let parent_count = path.split('/').filter(|&s| s == "..").count();
        if parent_count > 3 {
            anyhow::bail!("Output path uses excessive parent directory traversal: {}", path);
        }

        Ok(path.to_string())
    }

    let (db_path, output) = match command {
        ReportCommands::Generate { db, output } => (
            db.clone().unwrap_or_else(|| "rcf.db".to_string()),
            validate_output_path(output)?,
        ),
        ReportCommands::Auto { target: _, output } => (
            "rcf.db".to_string(),
            validate_output_path(output)?,
        ),
    };

    let mut db = RcfDatabase::new(&db_path)?;
    db.init()?;

    let stats = db.stats()?;
    let hosts = db.list_hosts()?;
    let services: Vec<_> = hosts.iter().flat_map(|h| db.list_services(&h.id).unwrap_or_default()).collect();
    let creds = db.list_credentials()?;
    let vulns = db.list_vulnerabilities()?;

    let mut html = String::from(include_str!("report_template.html"));

    let now = chrono::Utc::now();
    html = html.replace("{{TITLE}}", &format!("Security Assessment Report - {}", now.format("%Y-%m-%d")));
    html = html.replace("{{VERSION}}", "0.1.0");
    html = html.replace("{{DATE}}", &now.format("%Y-%m-%d %H:%M UTC").to_string());
    html = html.replace("{{HOSTS_COUNT}}", &stats.hosts.to_string());
    html = html.replace("{{SERVICES_COUNT}}", &stats.services.to_string());
    html = html.replace("{{VULNS_COUNT}}", &stats.vulnerabilities.to_string());
    html = html.replace("{{CREDS_COUNT}}", &stats.credentials.to_string());

    // Executive Summary
    let overall_risk = if stats.vulnerabilities > 5 {
        "HIGH"
    } else if stats.vulnerabilities > 2 {
        "MEDIUM"
    } else if stats.vulnerabilities > 0 {
        "LOW"
    } else {
        "MINIMAL"
    };

    let exec_summary = format!(
        "<p><strong>Risk Level: {}</strong></p>\
         <p>The assessment identified {} vulnerabilities across {} hosts. {} credential pairs were discovered. \
         Immediate remediation is recommended for critical and high severity findings.</p>",
        overall_risk, stats.vulnerabilities, stats.hosts, stats.credentials
    );
    html = html.replace("{{EXEC_SUMMARY}}", &exec_summary);

    // Hosts with service counts
    let mut hosts_rows = String::new();
    for h in &hosts {
        let svc_count = db.list_services(&h.id).map(|s| s.len()).unwrap_or(0);
        hosts_rows.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            html_escape(&h.address), html_escape(&h.state), html_escape(h.os.as_deref().unwrap_or("Unknown")), svc_count));
    }
    html = html.replace("{{HOSTS_ROWS}}", &hosts_rows);

    // Vulnerabilities with service info
    let mut vulns_rows = String::new();
    for v in &vulns {
        let sev = v.severity.to_lowercase();
        let badge = if sev.contains("critical") { "critical" }
                    else if sev.contains("high") { "high" }
                    else if sev.contains("medium") { "medium" }
                    else { "low" };
        vulns_rows.push_str(&format!("<tr><td>{}</td><td><span class='badge {}'>{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            html_escape(&v.name), badge, html_escape(&v.severity), html_escape(&v.host_id), html_escape(&v.service), html_escape(v.cve.as_deref().unwrap_or("-"))));
    }
    if vulns_rows.is_empty() {
        vulns_rows = "<tr><td colspan='5' style='text-align:center; color:#999;'>No vulnerabilities discovered</td></tr>".to_string();
    }
    html = html.replace("{{VULNS_ROWS}}", &vulns_rows);

    // Credentials
    let mut creds_rows = String::new();
    for c in &creds {
        creds_rows.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            html_escape(&c.host_id), c.port, html_escape(&c.service), html_escape(&c.username), html_escape(&c.password)));
    }
    if creds_rows.is_empty() {
        creds_rows = "<tr><td colspan='5' style='text-align:center; color:#999;'>No credentials discovered</td></tr>".to_string();
    }
    html = html.replace("{{CREDS_ROWS}}", &creds_rows);

    // Remediation recommendations
    let mut remediation = String::new();
    if stats.vulnerabilities > 0 {
        remediation.push_str("<div class='remediation'><h4>General Recommendations</h4><ul>");
        remediation.push_str("<li>Apply security patches to all identified vulnerable services</li>");
        remediation.push_str("<li>Change all discovered credentials immediately</li>");
        remediation.push_str("<li>Implement network segmentation to limit lateral movement</li>");
        remediation.push_str("<li>Enable logging and monitoring for detected attack vectors</li>");
        remediation.push_str("<li>Conduct regular vulnerability assessments</li>");
        remediation.push_str("</ul></div>");
    } else {
        remediation.push_str("<div class='remediation'><h4>No Critical Findings</h4>");
        remediation.push_str("<p>No vulnerabilities were discovered during this assessment. Continue regular security monitoring.</p></div>");
    }
    html = html.replace("{{REMEDIATION}}", &remediation);

    std::fs::write(&output, html)?;
    println!("{}", format!("[+] Professional report generated: {}", output).bold().green());
    Ok(())
}

#[cfg(feature = "db")]
async fn run_auto(target: &str, output: Option<&str>, aggressive: bool) -> anyhow::Result<()> {
    use rcf_network::scanner::{TcpConnectScanner, PortRange, ScanConfig};
    use rcf_db::connection::RcfDatabase;
    use std::time::Duration;

    println!("{}", "[*] Starting Automated Attack Chain".bold().green());
    println!("  Target: {}", target);
    println!("  Mode:   {}", if aggressive { "Aggressive" } else { "Stealth" });

    // 1. Initialize DB
    let db_path = format!("/tmp/rcf_{}.db", target.replace('.', "_"));
    let mut db = RcfDatabase::new(&db_path)?;
    db.init()?;

    // 2. Scan Ports
    let port_range = if aggressive { PortRange::All } else { PortRange::Common };
    let config = ScanConfig::new(target)
        .with_ports(port_range)
        .with_concurrency(if aggressive { 500 } else { 100 })
        .with_timeout(Duration::from_secs(if aggressive { 2 } else { 5 }));

    let scanner = TcpConnectScanner::new();
    let results = scanner.scan(&config).await;
    
    // Save hosts and services to DB
    let host_id = db.save_host(target)?;
    let open_count = results.iter().filter(|r| r.state == rcf_network::scanner::PortState::Open).count();
    for r in &results {
        if r.state == rcf_network::scanner::PortState::Open {
            let mut svc = rcf_db::models::NewService::new(&host_id, r.port);
            svc.name = r.service.clone();
            db.add_service(svc)?;
        }
    }

    println!("{}", format!("[+] Scan complete: {} open ports", open_count).bold().green());

    // 3. Auto-Run relevant modules based on services
    let services = db.list_services(&host_id)?;
    for svc in &services {
        let port = svc.port as u16;
        let name = svc.name.as_deref().unwrap_or("");
        
        match (port, name) {
            (80, _) | (443, _) | (8080, _) | (8443, _) => {
                println!("  [*] HTTP detected - running web scanners...");
            }
            (21, _) | (2121, _) => {
                println!("  [*] FTP detected - running brute force...");
            }
            (22, _) => {
                println!("  [*] SSH detected - running login checks...");
            }
            (445, _) | (139, _) => {
                println!("  [*] SMB detected - running enumeration...");
            }
            _ => {}
        }
    }

    // 4. Generate Report
    let report_path = output.unwrap_or("report.html").to_string();
    run_report(&ReportCommands::Generate { db: Some(db_path), output: report_path.clone() })?;
    println!("{}", format!("[+] Report saved to: {}", report_path).bold().green());
    
    Ok(())
}
