//! WAF detection and evasion helpers.

use serde::{Deserialize, Serialize};

/// WAF detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafDetection {
    pub detected: bool,
    pub waf_name: Option<String>,
    pub evasion_hints: Vec<String>,
    pub confidence: f32,
}

impl Default for WafDetection {
    fn default() -> Self {
        Self {
            detected: false,
            waf_name: None,
            evasion_hints: vec![],
            confidence: 0.0,
        }
    }
}

/// Detect WAF from HTTP response headers.
pub fn detect_waf(headers: &[(String, String)]) -> WafDetection {
    let mut detection = WafDetection::default();
    let headers_lower: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
        .collect();

    for (key, value) in &headers_lower {
        if key == "server" || key == "x-cache" || key == "cf-ray" {
            match value.as_str() {
                s if s.contains("cloudflare") => {
                    detection.detected = true;
                    detection.waf_name = Some("Cloudflare".to_string());
                    detection.confidence = 0.95;
                    detection.evasion_hints = vec![
                        "Use slower requests to avoid rate limiting".to_string(),
                        "Rotate User-Agent frequently".to_string(),
                        "Try HTTP/2 multiplexing".to_string(),
                    ];
                }
                s if s.contains("imperva") || s.contains("incapsula") => {
                    detection.detected = true;
                    detection.waf_name = Some("Imperva/Incapsula".to_string());
                    detection.confidence = 0.9;
                    detection.evasion_hints = vec![
                        "Add proper headers (Accept, Language)".to_string(),
                        "Use session cookies".to_string(),
                        "Vary User-Agent and Accept headers".to_string(),
                    ];
                }
                s if s.contains("akamai") || s.contains("ghost") => {
                    detection.detected = true;
                    detection.waf_name = Some("Akamai".to_string());
                    detection.confidence = 0.85;
                    detection.evasion_hints = vec![
                        "Do not repeat requests frequently".to_string(),
                        "Add proper Referer header".to_string(),
                    ];
                }
                s if s.contains("big-ip") || s.contains("f5") => {
                    detection.detected = true;
                    detection.waf_name = Some("F5 BIG-IP".to_string());
                    detection.confidence = 0.8;
                    detection.evasion_hints = vec![
                        "Avoid common attack patterns".to_string(),
                        "Use encoded payloads".to_string(),
                    ];
                }
                s if s.contains("fortiweb") || s.contains("fortigate") => {
                    detection.detected = true;
                    detection.waf_name = Some("FortiWeb/FortiGate".to_string());
                    detection.confidence = 0.75;
                    detection.evasion_hints = vec![
                        "Lower request frequency".to_string(),
                        "Use slow requests".to_string(),
                    ];
                }
                _ => {}
            }
        }

        if (key == "x-backend" || key == "x-cdn" || key == "x-served-by") && !detection.detected {
            detection.detected = true;
            detection.confidence = 0.6;
        }
    }

    detection
}

/// Check if an HTTP response indicates a WAF block.
pub fn is_waf_blocked(status: u16, body: &str) -> bool {
    const BLOCKED_STATUSES: [u16; 4] = [403, 406, 501, 999];
    if BLOCKED_STATUSES.contains(&status) {
        return true;
    }

    let block_patterns = [
        "blocked",
        "rate limit",
        "too many requests",
        "captcha",
        "security check",
        "attack detected",
        "sql injection",
        "xss",
        "forbidden",
        "access denied",
        "suspicious activity",
    ];

    let body_lower = body.to_lowercase();
    block_patterns.iter().any(|p| body_lower.contains(p))
}
