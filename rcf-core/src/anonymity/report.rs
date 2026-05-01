//! Report anonymization and log sanitization.

use rand::Rng;
use serde::{Deserialize, Serialize};

/// Configuration for anonymizing reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportAnonymizer {
    pub replace_ips: bool,
    pub replace_usernames: bool,
    pub replace_hostnames: bool,
    pub replace_emails: bool,
    pub ip_prefix: String,
    pub username_prefix: String,
    pub hostname_prefix: String,
    pub email_domain: String,
}

impl Default for ReportAnonymizer {
    fn default() -> Self {
        Self {
            replace_ips: true,
            replace_usernames: true,
            replace_hostnames: true,
            replace_emails: true,
            ip_prefix: "10.10.10".to_string(),
            username_prefix: "user".to_string(),
            hostname_prefix: "target".to_string(),
            email_domain: "redacted.local".to_string(),
        }
    }
}

impl ReportAnonymizer {
    pub fn sanitize_text(&self, text: &str) -> String {
        let mut result = text.to_string();

        if self.replace_ips {
            let ip_patterns = [
                (
                    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
                    "10.10.10.X",
                ),
                (
                    r"\b(?:172\.(?:1[6-9]|2[0-9]|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b",
                    "192.168.X.X",
                ),
                (r"\b(?:10\.\d{1,3}\.){2}\d{1,3}\b", "10.X.X.X"),
            ];
            for (pattern, replacement) in ip_patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    result = re.replace_all(&result, replacement).to_string();
                }
            }
        }

        if self.replace_usernames
            && let Ok(re) = regex::Regex::new(r"\b[a-zA-Z][a-zA-Z0-9_]{2,20}\b")
        {
            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    let m = caps.get(0).unwrap().as_str();
                    if !m.eq_ignore_ascii_case("root")
                        && !m.eq_ignore_ascii_case("admin")
                        && !m.eq_ignore_ascii_case("httpd")
                    {
                        format!(
                            "{}{}",
                            self.username_prefix,
                            rand::rng().random_range(100..999)
                        )
                    } else {
                        m.to_string()
                    }
                })
                .to_string();
        }

        if self.replace_emails
            && let Ok(re) =
                regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
        {
            result = re
                .replace_all(
                    &result,
                    &format!(
                        "user{}@{}",
                        rand::rng().random_range(100..999),
                        self.email_domain
                    ),
                )
                .to_string();
        }

        result
    }

    pub fn sanitize_file<P: std::io::Read + std::io::Write>(
        &self,
        input: P,
        output: P,
    ) -> std::io::Result<()> {
        use std::io::{BufRead, BufReader};

        let reader = BufReader::new(input);
        let mut writer = output;

        for line in reader.lines() {
            let line = line?;
            let sanitized = self.sanitize_text(&line);
            writeln!(writer, "{}", sanitized)?;
        }

        Ok(())
    }
}
