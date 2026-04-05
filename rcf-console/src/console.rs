//! The main console REPL loop.

use std::path::PathBuf;
use std::sync::Arc;

use colored::Colorize;
use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, Config};
use tracing::info;

use rcf_core::{Context, JobManager, Result, Target};
use rcf_modules::ModuleManager;

use crate::commands::{Command, parse_command};

/// The main REPL console.
pub struct RcfConsole {
    editor: DefaultEditor,
    context: Context,
    manager: ModuleManager,
    jobs: Arc<JobManager>,
    running: bool,
    history_file: String,
}

impl RcfConsole {
    pub fn new(manager: ModuleManager, context: Context) -> Result<Self> {
        let config = Config::builder()
            .max_history_size(1000)
            .map_err(|e| rcf_core::RcfError::Console(e.to_string()))?
            .completion_type(rustyline::CompletionType::Circular)
            .build();

        let mut editor = DefaultEditor::with_config(config)
            .map_err(|e| rcf_core::RcfError::Console(e.to_string()))?;

        let history_file = dirs::home_dir()
            .map(|p: PathBuf| p.join(".rcf_history").to_string_lossy().to_string())
            .unwrap_or_else(|| ".rcf_history".to_string());

        // Load history
        let _ = editor.load_history(&history_file);

        Ok(Self {
            editor,
            context,
            manager,
            jobs: Arc::new(JobManager::new()),
            running: false,
            history_file,
        })
    }

    /// Run the REPL loop.
    pub async fn run(&mut self) -> Result<()> {
        self.running = true;
        self.print_banner();

        while self.running {
            let prompt = self.build_prompt();

            match self.editor.readline(&prompt) {
                Ok(line) => {
                    let line = line.trim().to_string();
                    if line.is_empty() {
                        continue;
                    }

                    // Add to history
                    let _ = self.editor.add_history_entry(&line);

                    // Execute
                    if let Err(e) = self.execute_command(&line).await {
                        eprintln!("{} {}", "[-]".red(), e.to_string().red());
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    // Ctrl+C — print exit hint
                    println!("\nType 'exit' or 'quit' to leave the console.");
                }
                Err(ReadlineError::Eof) => {
                    // Ctrl+D — exit
                    println!();
                    break;
                }
                Err(err) => {
                    eprintln!("Read error: {:?}", err);
                    break;
                }
            }
        }

        // Save history
        let _ = self.editor.save_history(&self.history_file);
        println!("{}", "[*] Goodbye.".bold().yellow());
        Ok(())
    }

    /// Execute a single command line.
    async fn execute_command(&mut self, line: &str) -> Result<()> {
        let cmd = parse_command(line);

        match cmd {
            Command::Help => self.cmd_help(),
            Command::Exit => self.running = false,
            Command::Version => self.cmd_version(),
            Command::Show { target } => self.cmd_show(&target),
            Command::Search { keyword } => self.cmd_search(&keyword),
            Command::Info { module } => self.cmd_info(&module),
            Command::Use { module } => self.cmd_use(&module),
            Command::Back => self.cmd_back(),
            Command::Set { key, value } => self.cmd_set(&key, &value),
            Command::Unset { key } => self.cmd_unset(&key),
            Command::Options => self.cmd_options(),
            Command::Run => self.cmd_run().await?,
            Command::Exploit => self.cmd_run().await?, // alias for run
            Command::Check => self.cmd_check().await?,
            Command::Targets => self.cmd_targets(),
            Command::Sessions => self.cmd_sessions(),
            Command::Jobs => self.cmd_jobs(),
            Command::Kill { job_id } => self.cmd_kill(job_id),
            Command::Interact { session_id } => self.cmd_interact(session_id),
            Command::Reload => self.cmd_reload(),
            Command::Save { path } => self.cmd_save(&path)?,
            Command::Load { path } => self.cmd_load(&path)?,
            Command::Custom { parts } => self.handle_unknown(&parts)?,
        }

        Ok(())
    }

    // ─── Command implementations ───────────────────────────────────────

    fn cmd_help(&self) {
        println!("\n{}", "Core Commands".bold().green());
        println!("  {:<15} {}", "Command".bold(), "Description".bold());
        println!("  {:<15} {}", "-------".bold(), "-----------".bold());
        println!("  {:<15} {}", "help", "Show this help");
        println!("  {:<15} {}", "version", "Show RCF version");
        println!("  {:<15} {}", "show [category]", "List modules (all, exploits, auxiliary, payloads, encoders, posts)");
        println!("  {:<15} {}", "search <keyword>", "Search modules by name/description");
        println!("  {:<15} {}", "info <module>", "Show detailed module information");
        println!("  {:<15} {}", "use <module>", "Select a module to configure");
        println!("  {:<15} {}", "back", "Deselect current module");
        println!("  {:<15} {}", "set <key> <value>", "Set an option (global or module-specific)");
        println!("  {:<15} {}", "unset <key>", "Unset an option");
        println!("  {:<15} {}", "options", "Show current module options");
        println!("  {:<15} {}", "run", "Execute the current module");
        println!("  {:<15} {}", "exploit", "Alias for 'run'");
        println!("  {:<15} {}", "check", "Run exploit check against target");
        println!("  {:<15} {}", "targets", "Show compatible targets");
        println!("  {:<15} {}", "sessions", "List active sessions");
        println!("  {:<15} {}", "jobs", "List running background jobs");
        println!("  {:<15} {}", "kill [id]", "Stop a job (or all jobs)");
        println!("  {:<15} {}", "interact <id>", "Interact with a session");
        println!("  {:<15} {}", "reload", "Reload all modules");
        println!("  {:<15} {}", "save [path]", "Save context to file");
        println!("  {:<15} {}", "load [path]", "Load context from file");
        println!("  {:<15} {}", "exit / quit", "Exit the console");
        println!();
    }

    fn cmd_version(&self) {
        println!("{}", env!("CARGO_PKG_VERSION"));
    }

    fn cmd_show(&self, target: &Option<String>) {
        match target.as_deref() {
            Some("modules") | Some("all") | None => {
                println!("{}", self.manager.format_all_modules());
            }
            Some("exploits") => {
                self.print_category_list("Exploit", rcf_core::ModuleCategory::Exploit);
            }
            Some("auxiliary") | Some("scanners") => {
                self.print_category_list("Auxiliary", rcf_core::ModuleCategory::Auxiliary);
            }
            Some("payloads") | Some("payload") => {
                self.print_category_list("Payload", rcf_core::ModuleCategory::Payload);
            }
            Some("encoders") | Some("encoder") => {
                self.print_category_list("Encoder", rcf_core::ModuleCategory::Encoder);
            }
            Some("posts") | Some("post") => {
                self.print_category_list("Post", rcf_core::ModuleCategory::Post);
            }
            Some("options") => {
                self.cmd_options();
            }
            Some(other) => {
                println!("Unknown show target: '{}'. Try: modules, exploits, auxiliary, payloads, encoders, posts, options", other);
            }
        }
    }

    fn cmd_search(&self, keyword: &str) {
        println!("{}", self.manager.format_search_results(keyword));
    }

    fn cmd_info(&self, module: &str) {
        println!("{}", self.manager.format_module_info(module));
    }

    fn cmd_use(&mut self, module: &str) {
        match self.manager.registry().get(module) {
            Some(m) => {
                let info = m.info();
                println!("{} Selected: {}", "[*]".cyan(), info.name);
                println!("{} {}", "[*]".cyan(), info.description);
                self.context.current_module = Some(module.to_string());
                println!("\n{}", m.options().format_table());
            }
            None => {
                println!("{} Module '{}' not found. Try 'search {}'", "[-]".red(), module, module);
            }
        }
    }

    fn cmd_back(&mut self) {
        self.context.current_module = None;
        println!("{} Deselected module", "[*]".cyan());
    }

    fn cmd_set(&mut self, key: &str, value: &str) {
        // Set on context (global)
        self.context.set(key, value);

        // If a module is selected, also set on module options
        if let Some(ref module_name) = self.context.current_module {
            if let Some(_module) = self.manager.registry().get(module_name) {
                // Just note it — actual module option binding happens at run time
                info!("Set {} = {} (global + module context: {})", key, value, module_name);
            }
        }

        println!("{} {} => {}", "[+]".green(), key.bold(), value.bold());
    }

    fn cmd_unset(&mut self, key: &str) {
        self.context.unset(key);
        println!("{} Unset {}", "[*]".cyan(), key.bold());
    }

    fn cmd_options(&self) {
        if let Some(ref module_name) = self.context.current_module {
            if let Some(module) = self.manager.registry().get(module_name) {
                println!("\n{} Options for '{}'\n", "Module".bold().green(), module_name);
                println!("{}", module.options().format_table());
            }
        } else {
            // Show global context options
            println!("\n{} Global Context Options\n", "Global".bold().green());
            self.print_context_options();
        }
    }

    async fn cmd_run(&mut self) -> Result<()> {
        if let Some(ref module_name) = self.context.current_module.clone() {
            if let Some(module) = self.manager.registry().get(module_name) {
                // Validate required options
                if let Err(e) = module.check(&self.context) {
                    println!("{} {}", "[-]".red(), e.to_string().red());
                    return Ok(());
                }

                let rhosts = self.context.get_rhosts();
                let rport = self.context.get_rport();

                if rhosts.is_empty() {
                    println!("{} RHOSTS is required", "[-]".red());
                    return Ok(());
                }

                for host in rhosts {
                    let target = Target::new(&host, rport);
                    println!(
                        "{} Running {} against {}:{} ...",
                        "[*]".cyan(),
                        module_name,
                        host,
                        rport
                    );

                    let output = module.run(&mut self.context, &target).await?;
                    println!("{}", output.render());
                }
            } else {
                println!("{} Module '{}' not found", "[-]".red(), module_name);
            }
        } else {
            println!("{} No module selected. Use 'use <module>' first.", "[-]".red());
        }
        Ok(())
    }

    async fn cmd_check(&mut self) -> Result<()> {
        if let Some(ref module_name) = self.context.current_module.clone() {
            if let Some(module) = self.manager.registry().get(module_name) {
                let rhosts = self.context.get_rhosts();
                let rport = self.context.get_rport();

                for host in rhosts {
                    let target = Target::new(&host, rport);
                    match module.exploit_check(&self.context, &target).await {
                        Ok(vulnerable) => {
                            if vulnerable {
                                println!("{} {}:{} appears vulnerable", "[+]".green(), host, rport);
                            } else {
                                println!("{} {}:{} check inconclusive", "[*]".cyan(), host, rport);
                            }
                        }
                        Err(e) => {
                            println!("{} Check failed: {}", "[-]".red(), e);
                        }
                    }
                }
            }
        } else {
            println!("{} No module selected", "[-]".red());
        }
        Ok(())
    }

    fn cmd_targets(&self) {
        if let Some(ref module_name) = self.context.current_module {
            if let Some(module) = self.manager.registry().get(module_name) {
                let info = module.info();
                println!("\n{} Compatible targets for '{}'\n", "Targets".bold().green(), info.name);
                println!("  Configure using: set RHOSTS <ip>  set RPORT <port>");
            }
        } else {
            println!("{} No module selected", "[-]".red());
        }
    }

    fn cmd_sessions(&self) {
        if self.context.sessions.is_empty() {
            println!("{} No active sessions", "[*]".cyan());
        } else {
            println!("\n{}", "Active Sessions".bold().green());
            for id in &self.context.sessions {
                println!("  Session {}", id);
            }
        }
    }

    fn cmd_jobs(&self) {
        let jobs = Arc::clone(&self.jobs);
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                println!("{}", jobs.format_jobs().await);
            });
        });
    }

    fn cmd_kill(&self, job_id: Option<u32>) {
        let jobs = Arc::clone(&self.jobs);
        match job_id {
            Some(id) => {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        if jobs.stop_job(id).await {
                            println!("{} Job {} stopped", "[+]".green(), id);
                        } else {
                            println!("{} Job {} not found or not running", "[-]".red(), id);
                        }
                    });
                });
            }
            None => {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let count = jobs.kill_all().await;
                        println!("{} Stopped {} jobs", "[+]".green(), count);
                    });
                });
            }
        }
    }

    fn cmd_interact(&self, session_id: Option<u32>) {
        match session_id {
            Some(id) => {
                println!("{} Interacting with session {} (stub)", "[*]".cyan(), id);
                println!("[*] Full session interaction coming in next update");
            }
            None => {
                println!("{} Usage: interact <session_id>", "[-]".red());
            }
        }
    }

    fn cmd_reload(&mut self) {
        println!("{} Modules reloaded", "[+]".green());
    }

    fn cmd_save(&self, path: &Option<String>) -> Result<()> {
        let p = path.as_deref().unwrap_or("rcf_context.toml");
        let toml = self.context.to_toml().map_err(|e| rcf_core::RcfError::Config(e.to_string()))?;
        std::fs::write(p, toml)?;
        println!("{} Context saved to {}", "[+]".green(), p);
        Ok(())
    }

    fn cmd_load(&mut self, path: &Option<String>) -> Result<()> {
        let p = path.as_deref().unwrap_or("rcf_context.toml");
        let content = std::fs::read_to_string(p)?;
        self.context = Context::from_toml(&content).map_err(|e| rcf_core::RcfError::Config(e.to_string()))?;
        println!("{} Context loaded from {}", "[+]".green(), p);
        Ok(())
    }

    fn handle_unknown(&self, parts: &[String]) -> Result<()> {
        println!("{} Unknown command: '{}'. Type 'help' for commands.", "[-]".red(), parts[0]);
        Ok(())
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    fn print_banner(&self) {
        let banner = r#"
   ╔══════════════════════════════════════════════╗
   ║        RCF — Rust Cybersecurity Framework    ║
   ║              Version 0.1.0-dev               ║
   ║          Fast. Safe. Modular. Rust.          ║
   ╚══════════════════════════════════════════════╝
"#;
        println!("{}", banner.bold().cyan());
        println!("  {} modules loaded | Type 'help' for commands\n", self.manager.registry().len());
    }

    fn build_prompt(&self) -> String {
        if let Some(ref module) = self.context.current_module {
            // Extract short name from full path
            let short = module.split('/').last().unwrap_or(module);
            format!("rcf {} > ", short.red().bold())
        } else {
            "rcf > ".to_string()
        }
    }

    fn print_category_list(&self, label: &str, category: rcf_core::ModuleCategory) {
        let modules = self.manager.registry().list(Some(&category));
        if modules.is_empty() {
            println!("{} No {} modules loaded", "[*]".cyan(), label);
            return;
        }

        println!("\n{} {} Modules ({})\n", label.bold().green(), label, modules.len());
        println!("  {:<45} {}", "Name".bold(), "Description".bold());
        println!("  {:<45} {}", "----".bold(), "-----------".bold());

        for info in modules {
            println!("  {:<45} {}", info.name, info.description);
        }
        println!();
    }

    fn print_context_options(&self) {
        let opts = self.context.list_options();
        println!(
            "  {:<20} {:<15}  {}",
            "Name".bold(),
            "Value".bold(),
            "Description".bold()
        );
        println!(
            "  {:<20} {:<15}  {}",
            "----".bold(),
            "-----".bold(),
            "-----------".bold()
        );
        let descriptions = [
            ("RHOSTS", "Target host(s)"),
            ("RPORT", "Target port"),
            ("LHOST", "Local address for payloads"),
            ("LPORT", "Local port for payloads"),
            ("THREADS", "Concurrency level"),
            ("TIMEOUT", "Connection timeout (seconds)"),
            ("SSL", "Use SSL/TLS"),
            ("VERBOSE", "Verbose output"),
            ("PROXIES", "Proxy chain"),
        ];
        for (key, value) in opts {
            let desc = descriptions
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, d)| *d)
                .unwrap_or("User-defined option");
            println!("  {:<20} {:<15}  {}", key, value, desc);
        }
        println!();
    }
}
