//! Command parsing for the RCF REPL.

/// All commands supported by the REPL.
#[derive(Debug)]
pub enum Command {
    Help,
    Exit,
    Version,
    Show { target: Option<String> },
    Search { keyword: String },
    Info { module: String },
    Use { module: String },
    Back,
    Set { key: String, value: String },
    Unset { key: String },
    Options,
    Run,
    Exploit,
    Check,
    Targets,
    Sessions,
    Jobs,
    Kill { job_id: Option<u32> },
    Interact { session_id: Option<u32> },
    Reload,
    Save { path: Option<String> },
    Load { path: Option<String> },
    SetGlobal { key: String, value: String },
    UnsetGlobal { key: String },
    Resource { path: Option<String> },
    Custom { parts: Vec<String> },
}

/// Parse a raw input line into a Command.
pub fn parse_command(line: &str) -> Command {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Command::Custom { parts: vec![] };
    }

    let cmd = parts[0].to_lowercase();
    let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

    match cmd.as_str() {
        "help" | "?" => Command::Help,
        "exit" | "quit" | "q" => Command::Exit,
        "version" => Command::Version,

        "show" => {
            let target = args.first().cloned();
            Command::Show { target }
        }

        "search" => {
            let keyword = args.join(" ");
            Command::Search {
                keyword: if keyword.is_empty() {
                    String::new()
                } else {
                    keyword
                },
            }
        }

        "info" => {
            if let Some(module) = args.first() {
                Command::Info {
                    module: module.to_string(),
                }
            } else {
                Command::Info {
                    module: String::new(),
                }
            }
        }

        "use" | "select" => {
            if let Some(module) = args.first() {
                Command::Use {
                    module: module.to_string(),
                }
            } else {
                Command::Use {
                    module: String::new(),
                }
            }
        }

        "back" => Command::Back,

        "set" => {
            if args.len() >= 2 {
                Command::Set {
                    key: args[0].to_uppercase(),
                    value: args[1..].join(" "),
                }
            } else {
                Command::Set {
                    key: String::new(),
                    value: String::new(),
                }
            }
        }

        "unset" | "remove" => {
            if let Some(key) = args.first() {
                Command::Unset {
                    key: key.to_uppercase(),
                }
            } else {
                Command::Unset { key: String::new() }
            }
        }

        "options" | "opts" => Command::Options,

        "run" | "execute" => Command::Run,
        "exploit" | "explo" => Command::Exploit,
        "check" => Command::Check,

        "targets" => Command::Targets,
        "sessions" | "session" | "sess" => Command::Sessions,
        "jobs" | "job" => Command::Jobs,

        "kill" => {
            let job_id = args.first().and_then(|s| s.parse().ok());
            Command::Kill { job_id }
        }

        "interact" | "session_interact" => {
            let session_id = args.first().and_then(|s| s.parse().ok());
            Command::Interact { session_id }
        }

        "reload" | "reload-modules" => Command::Reload,

        "save" => {
            let path = args.first().cloned();
            Command::Save { path }
        }

        "load" => {
            let path = args.first().cloned();
            Command::Load { path }
        }

        "setg" | "gset" => {
            // Global variable setting
            if args.len() >= 2 {
                Command::SetGlobal {
                    key: args[0].to_uppercase(),
                    value: args[1..].join(" "),
                }
            } else {
                Command::SetGlobal {
                    key: String::new(),
                    value: String::new(),
                }
            }
        }

        "unsetg" | "gunset" => {
            if let Some(key) = args.first() {
                Command::UnsetGlobal {
                    key: key.to_uppercase(),
                }
            } else {
                Command::UnsetGlobal { key: String::new() }
            }
        }

        "resource" | "run_script" => {
            let path = args.first().cloned();
            Command::Resource { path }
        }

        _ => Command::Custom {
            parts: parts.iter().map(|s| s.to_string()).collect(),
        },
    }
}
