//! Integration tests for the C2 agent.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// Start a mock C2 server that accepts one connection, sends auth + reads sysinfo,
/// sends a command, and reads the output.
fn run_mock_c2_server(port: u16, command: &str, running: Arc<AtomicBool>) -> String {
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("Failed to bind");

    let mut result = String::new();

    if let Ok((stream, _)) = listener.accept() {
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        let mut reader = BufReader::new(&stream);
        let mut writer = stream.try_clone().unwrap();

        // Read greeting
        let mut greeting = String::new();
        if reader.read_line(&mut greeting).is_ok() {
            result.push_str(&format!("GREETING: {}", greeting.trim()));
        }

        // Send auth success
        writer.write_all(b"RCF_AUTH_SUCCESS\n").ok();
        writer.flush().ok();

        // Read sysinfo block
        let mut marker = String::new();
        if reader.read_line(&mut marker).is_ok() {
            result.push_str(&format!(" MARKER: {}", marker.trim()));
        }
        let mut sysinfo_json = String::new();
        if reader.read_line(&mut sysinfo_json).is_ok() {
            result.push_str(&format!(" SYSINFO: {}", sysinfo_json.trim()));
        }
        let mut end_marker = String::new();
        reader.read_line(&mut end_marker).ok();

        // Send a test command
        writer.write_all(format!("{}\n", command).as_bytes()).ok();
        writer.flush().ok();

        // Read output block
        let mut out_marker = String::new();
        if reader.read_line(&mut out_marker).is_ok() {
            result.push_str(&format!(" OUT_MARKER: {}", out_marker.trim()));
        }
        let mut stdout_b64 = String::new();
        reader.read_line(&mut stdout_b64).ok();
        let mut stderr_b64 = String::new();
        reader.read_line(&mut stderr_b64).ok();
        let mut exit_code = String::new();
        reader.read_line(&mut exit_code).ok();
        let mut out_end = String::new();
        reader.read_line(&mut out_end).ok();

        // Send exit
        writer.write_all(b"RCF_EXIT\n").ok();
        writer.flush().ok();
    }

    running.store(false, Ordering::SeqCst);
    result
}

#[test]
fn test_agent_connects_and_authenticates() {
    let port = 19876u16;
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    // Start mock C2 server
    let handle = thread::spawn(move || run_mock_c2_server(port, "echo hello", running_clone));

    // Give server time to start
    thread::sleep(Duration::from_millis(200));

    // Start agent with PSK
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rcf-agent"))
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--psk",
            "test_psk",
        ])
        .output()
        .expect("Failed to start agent");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Wait for mock server to finish
    let server_result = handle.join().unwrap();

    // Verify the protocol
    assert!(
        server_result.contains("GREETING: RCF_AGENT_V1:test_psk"),
        "Agent should send greeting with PSK"
    );
    assert!(
        server_result.contains("MARKER: RCF_SYSINFO"),
        "Agent should send sysinfo marker"
    );
    assert!(
        server_result.contains("SYSINFO:"),
        "Agent should send sysinfo JSON"
    );
    assert!(
        server_result.contains("OUT_MARKER: RCF_OUTPUT"),
        "Agent should send output block"
    );

    // Verify agent exited cleanly
    assert!(output.status.success() || stderr.contains("Disconnected"));
}

#[test]
fn test_agent_builtin_commands() {
    let port = 19877u16;
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    let handle = thread::spawn(move || run_mock_c2_server(port, "sysinfo", running_clone));

    thread::sleep(Duration::from_millis(200));

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rcf-agent"))
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--psk",
            "test_psk",
        ])
        .output()
        .expect("Failed to start agent");

    let _server_result = handle.join().unwrap();
    assert!(output.status.success());
}

#[test]
fn test_agent_fails_gracefully_on_no_server() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rcf-agent"))
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            "59999",
            "--psk",
            "test_psk",
        ])
        .output()
        .expect("Failed to start agent");

    // Should fail with non-zero exit code (agent retries then fails when no server)
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to connect")
            || stderr.contains("Retry failed")
            || stderr.contains("Retry failed")
    );
}
