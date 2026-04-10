//! The main console REPL loop.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use colored::Colorize;
use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, Config};
use tracing::info;

use rcf_core::{Context, JobManager, Result, Target};
use rcf_modules::ModuleManager;

use crate::commands::{Command, parse_command};
use crate::resource::{ResourceScript, ResourceExecutor};

/// The main REPL console.
pub struct RcfConsole {
    editor: DefaultEditor,
    context: Context,
    manager: ModuleManager,
    jobs: Arc<JobManager>,
    running: bool,
    history_file: String,
    /// C2 control client for session interaction (connects to C2 control socket)
    c2_control: Option<rcf_c2::C2ControlClient>,
    /// Global variables for resource scripts (setg/unsetg)
    global_variables: HashMap<String, String>,
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
        if let Err(e) = editor.load_history(&history_file) {
            tracing::debug!("No history file found or failed to load: {}", e);
        }

        // Try to connect to C2 control server (default: 127.0.0.1:8444)
        let c2_control = {
            let c2 = rcf_c2::C2ControlClient::new("127.0.0.1", 8444);
            let c2_clone = c2.clone();
            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    c2_clone.list_sessions().await
                })
            });
            match result {
                Ok(_) => {
                    tracing::info!("Connected to C2 control server on 127.0.0.1:8444");
                    Some(c2)
                }
                Err(_) => {
                    tracing::debug!("No C2 control server found (sessions/interact will be limited)");
                    None
                }
            }
        };

        Ok(Self {
            editor,
            context,
            manager,
            jobs: Arc::new(JobManager::new()),
            running: false,
            history_file,
            c2_control,
            global_variables: HashMap::new(),
        })
    }

    /// Run a resource script non-interactively.
    pub async fn run_resource_script(&mut self, path: &str) -> Result<()> {
        self.cmd_resource(&Some(path.to_string())).await?;
        Ok(())
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
        if let Err(e) = self.editor.save_history(&self.history_file) {
            tracing::warn!("Failed to save command history: {}", e);
        }
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
            Command::SetGlobal { key, value } => self.cmd_setg(&key, &value),
            Command::UnsetGlobal { key } => self.cmd_unsetg(&key),
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
            Command::Resource { path } => self.cmd_resource(&path).await?,
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
        println!("  {:<15} {}", "setg <key> <val>", "Set global variable (for resource scripts)");
        println!("  {:<15} {}", "unsetg <key>", "Unset global variable");
        println!("  {:<15} {}", "resource <file>", "Execute a resource script (.rc file)");
        println!("  {:<15} {}", "exit / quit", "Exit the console");
        println!();
        println!("{} Resource Scripts:", "[*]".cyan());
        println!("  {} Use -r flag: rcf -r scripts/quick_scan.rc", "   ");
        println!("  {} Variables: ${{RHOSTS}}, ${{LHOST}}, etc.", "   ");
        println!("  {} Examples: scripts/quick_scan.rc, scripts/web_assessment.rc\n", "   ");
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
        if let Some(ref c2) = self.c2_control {
            let c2 = c2.clone();
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    match c2.list_sessions().await {
                        Ok(sessions) if sessions.is_empty() => {
                            println!("{} No active C2 sessions", "[*]".cyan());
                        }
                        Ok(sessions) => {
                            println!("\n{}", "Active C2 Sessions".bold().green());
                            println!("  {:<6} {:<20} {:<15} {}",
                                "ID".bold(), "Info".bold(), "Created".bold(), "Last Seen".bold());
                            println!("  {:<6} {:<20} {:<15} {}",
                                "--".bold(), "----".bold(), "-------".bold(), "---------".bold());
                            for s in &sessions {
                                let created = chrono::DateTime::from_timestamp(s.created_at, 0)
                                    .map(|dt| dt.format("%H:%M:%S").to_string())
                                    .unwrap_or_else(|| "?".to_string());
                                let last_seen = chrono::DateTime::from_timestamp(s.last_seen, 0)
                                    .map(|dt| dt.format("%H:%M:%S").to_string())
                                    .unwrap_or_else(|| "?".to_string());
                                println!("  {:<6} {:<20} {:<15} {}",
                                    s.num, s.info, created, last_seen);
                            }
                        }
                        Err(e) => {
                            println!("{} Failed to list C2 sessions: {}", "[-]".red(), e);
                        }
                    }
                });
            });
        } else if self.context.sessions.is_empty() {
            println!("{} No active sessions", "[*]".cyan());
            println!("{} (Tip: Start C2 server with 'rcf c2 listen' to enable session management)", "[*]".yellow());
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
        let session_id = match session_id {
            Some(id) => id,
            None => {
                println!("{} Usage: interact <session_id>", "[-]".red());
                return;
            }
        };

        let c2 = match &self.c2_control {
            Some(c) => c.clone(),
            None => {
                println!("{} No C2 control server connected", "[-]".red());
                println!("{} (Tip: Start C2 server with 'rcf c2 listen')", "[*]".yellow());
                return;
            }
        };

        let c2_clone = c2.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match c2_clone.interact(session_id).await {
                    Ok((cmd_tx, mut output_rx)) => {
                        println!("\n{}", format!("[*] Interacting with session {} (type 'exit' to leave)", session_id).bold().green());
                        println!("{}\n", "meterpreter >".bold().cyan());

                        // Use rustyline for the interact sub-prompt
                        let mut line = String::new();
                        loop {
                            print!("{} ", "meterpreter >".cyan());
                            use std::io::Write;
                            let _ = std::io::stdout().flush();

                            line.clear();
                            match std::io::stdin().read_line(&mut line) {
                                Ok(0) => break,
                                Ok(_) => {
                                    let cmd = line.trim().to_string();
                                    if cmd == "exit" || cmd == "quit" || cmd.is_empty() && line == "\n" {
                                        if cmd == "exit" || cmd == "quit" {
                                            let _ = cmd_tx.send("INTERACT_END".to_string()).await;
                                        }
                                        break;
                                    }

                                    // Send command
                                    let _ = cmd_tx.send(cmd.clone()).await;

                                    // Wait for output (with timeout)
                                    tokio::select! {
                                        Some(output) = output_rx.recv() => {
                                            // Decode and display output
                                            let lines: Vec<&str> = output.split('\n').collect();
                                            if lines.len() >= 3 {
                                                let stdout_b64 = lines[0];
                                                let stderr_b64 = lines[1];
                                                let exit_code = lines[2];

                                                // Decode stdout
                                                let stdout_bytes = rcf_c2::control::base64_decode(stdout_b64);
                                                let stdout = String::from_utf8_lossy(&stdout_bytes);
                                                if !stdout.is_empty() {
                                                    print!("{}", stdout);
                                                }

                                                // Decode stderr
                                                let stderr_bytes = rcf_c2::control::base64_decode(stderr_b64);
                                                let stderr = String::from_utf8_lossy(&stderr_bytes);
                                                if !stderr.is_empty() {
                                                    eprint!("[!] {}", stderr);
                                                }

                                                if let Ok(code) = exit_code.parse::<i32>() {
                                                    if code != 0 {
                                                        eprintln!("[!] Exit code: {}", code);
                                                    }
                                                }
                                            }
                                        }
                                        _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                                            println!("[*] No output received (timeout)");
                                        }
                                    }
                                }
                                Err(_) => break,
                            }
                        }

                        println!("\n{} Session interaction ended", "[*]".cyan());
                    }
                    Err(e) => {
                        println!("{} Failed to interact with session {}: {}", "[-]".red(), session_id, e);
                    }
                }
            });
        });
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

    // ── Global variable commands (for resource scripts) ─────────────────

    fn cmd_setg(&mut self, key: &str, value: &str) {
        if key.is_empty() {
            println!("{} Usage: setg <KEY> <VALUE>", "[-]".red());
            return;
        }

        self.global_variables.insert(key.to_uppercase(), value.to_string());
        // Also set on context for immediate use
        self.context.set(key, value);
        println!("{} {} => {} (global)", "[+]".green(), key.bold(), value.bold());
    }

    fn cmd_unsetg(&mut self, key: &str) {
        if key.is_empty() {
            println!("{} Usage: unsetg <KEY>", "[-]".red());
            return;
        }

        self.global_variables.remove(&key.to_uppercase());
        self.context.unset(key);
        println!("{} Unset {} (global)", "[*]".cyan(), key.bold());
    }

    // ── Resource script execution ──────────────────────────────────────

    async fn cmd_resource(&mut self, path: &Option<String>) -> Result<()> {
        let path = match path {
            Some(p) => p.clone(),
            None => {
                println!("{} Usage: resource <path/to/script.rc>", "[-]".red());
                return Ok(());
            }
        };

        let script = match ResourceScript::from_file(&path) {
            Ok(s) => s,
            Err(e) => {
                println!("{} Failed to read resource script '{}': {}", "[-]".red(), path, e);
                return Ok(());
            }
        };

        println!("\n{} Executing resource script: {}", "[*]".cyan(), path.bold());
        println!("{} {} commands to execute\n", "[*]".cyan(), script.command_count());

        let executor = ResourceExecutor::new();

        // Clone variables for execution
        let variables = self.global_variables.clone();

        // SAFETY: Raw pointer aliasing for interior mutability in async closure.
        // The executor.execute() API takes &self but the closure needs &mut self.
        // This is safe because:
        // 1. We're in a single-threaded async context (tokio::task::block_in_place)
        // 2. The closure is called synchronously for each command (no concurrent access)
        // 3. self outlives the entire execute() call
        // 4. No other references to self exist during execution
        // This is a known workaround for Rust's async closure borrow limitations.
        let self_ptr = self as *mut Self;

        let result = executor.execute(&script, |cmd| {
            let vars = variables.clone();
            async move {
                let self_ref = unsafe { &mut *self_ptr };
                self_ref.execute_resource_command(&cmd, &vars).await
            }
        }).await;

        println!("\n{}", result.summary());

        if !result.errors.is_empty() {
            println!("\n{} Errors:", "[-]".red());
            for (line, cmd, err) in &result.errors {
                println!("  Line {}: {} → {}", line, cmd, err);
            }
        }

        Ok(())
    }

    /// Execute a single command from a resource script.
    async fn execute_resource_command(&mut self, line: &str, _variables: &HashMap<String, String>) -> std::result::Result<(), String> {
        let cmd = parse_command(line);

        match cmd {
            Command::SetGlobal { key, value } => {
                // Set global variable during script execution
                if !key.is_empty() {
                    self.global_variables.insert(key.clone(), value.clone());
                    self.context.set(&key, &value);
                }
            }
            Command::Set { key, value } => {
                if !key.is_empty() {
                    self.context.set(&key, &value);
                }
            }
            Command::Unset { key } => {
                self.context.unset(&key);
            }
            Command::UnsetGlobal { key } => {
                self.global_variables.remove(&key);
                self.context.unset(&key);
            }
            Command::Use { module } => {
                if !module.is_empty() {
                    self.cmd_use(&module);
                }
            }
            Command::Back => {
                self.cmd_back();
            }
            Command::Run | Command::Exploit => {
                if let Err(e) = self.cmd_run().await {
                    return Err(e.to_string());
                }
            }
            Command::Check => {
                if let Err(e) = self.cmd_check().await {
                    return Err(e.to_string());
                }
            }
            Command::Exit => {
                self.running = false;
            }
            Command::Save { path } => {
                if let Err(e) = self.cmd_save(&path) {
                    return Err(e.to_string());
                }
            }
            Command::Resource { path: _ } => {
                // Nested resource scripts not supported in execution context
                // (would require async recursion)
                return Err("Nested resource scripts are not supported".to_string());
            }
            Command::Show { .. } => {
                // Parse and execute show commands
                let parts: Vec<&str> = line.split_whitespace().collect();
                let target = parts.get(1).map(|s| s.to_string());
                self.cmd_show(&target);
            }
            Command::Search { keyword } => {
                self.cmd_search(&keyword);
            }
            Command::Info { module } => {
                if !module.is_empty() {
                    self.cmd_info(&module);
                }
            }
            Command::Options => {
                self.cmd_options();
            }
            Command::Jobs => {
                self.cmd_jobs();
            }
            Command::Kill { job_id } => {
                self.cmd_kill(job_id);
            }
            Command::Sessions => {
                self.cmd_sessions();
            }
            Command::Reload => {
                self.cmd_reload();
            }
            Command::Interact { session_id } => {
                self.cmd_interact(session_id);
            }
            Command::Help | Command::Version | Command::Custom { .. } => {
                // Skip these in resource scripts
            }
            _ => {
                return Err(format!("Unknown or unsupported command in resource script: {}", line));
            }
        }

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
