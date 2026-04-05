//! HTTP/HTTPS fingerprinter.
//!
//! Grabs banners, extracts titles, detects technologies from headers,
//! and identifies common web frameworks/CMS platforms.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::protocols::common::ServiceInfo;

/// HTTP/HTTPS fingerprinter.
pub struct HttpFingerprinter;

impl HttpFingerprinter {
    pub fn new() -> Self {
        Self
    }

    /// Connect to an HTTP service and extract fingerprints.
    pub async fn fingerprint(
        &self,
        host: &str,
        port: u16,
        ssl: bool,
    ) -> Option<ServiceInfo> {
        let scheme = if ssl { "https" } else { "http" };
        debug!("Fingerprinting {}://{}:{}", scheme, host, port);

        // Try a simple HTTP GET and parse response
        match self.grab_banner(host, port, ssl).await {
            Some(banner) => {
                let mut info = ServiceInfo::new(if ssl { "https" } else { "http" });
                
                // Extract Server header
                if let Some(server) = extract_header(&banner, "Server") {
                    info.version = Some(server.clone());
                    info = info.with_extra("server", &server);
                }

                // Extract X-Powered-By
                if let Some(xpb) = extract_header(&banner, "X-Powered-By") {
                    info = info.with_extra("x-powered-by", &xpb);
                }

                // Extract technology indicators
                detect_technology(&banner, &mut info);

                Some(info)
            }
            None => None,
        }
    }

    /// Grab HTTP banner by sending a HEAD request.
    async fn grab_banner(&self, host: &str, port: u16, _ssl: bool) -> Option<String> {
        let addr = format!("{}:{}", host, port);
        let result = timeout(
            Duration::from_secs(5),
            TcpStream::connect(&addr),
        )
        .await;

        let mut stream = match result {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        // Send HTTP HEAD request
        let request = format!(
            "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (RCF Scanner)\r\nConnection: close\r\nAccept: */*\r\n\r\n",
            host
        );

        if stream.write_all(request.as_bytes()).await.is_err() {
            return None;
        }

        // Read response headers (up to 8KB)
        let mut buf = vec![0u8; 8192];
        match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(n)) => {
                let response = String::from_utf8_lossy(&buf[..n]).to_string();
                debug!("HTTP banner ({}:{}):\n{}", host, port, response.lines().take(10).collect::<Vec<_>>().join("\n"));
                Some(response)
            }
            _ => None,
        }
    }

    /// Grab the page title by fetching the root path.
    pub async fn get_title(&self, host: &str, port: u16, _ssl: bool) -> Option<String> {
        let addr = format!("{}:{}", host, port);
        let result = timeout(
            Duration::from_secs(5),
            TcpStream::connect(&addr),
        )
        .await;

        let mut stream = match result {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (RCF Scanner)\r\nConnection: close\r\nAccept: text/html\r\n\r\n",
            host
        );

        if stream.write_all(request.as_bytes()).await.is_err() {
            return None;
        }

        let mut buf = vec![0u8; 65536];
        match timeout(Duration::from_secs(10), stream.read(&mut buf)).await {
            Ok(Ok(n)) => {
                let response = String::from_utf8_lossy(&buf[..n]).to_string();
                // Find title between <title> tags
                extract_title(&response)
            }
            _ => None,
        }
    }
}

impl Default for HttpFingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract a specific header value from an HTTP response.
fn extract_header(response: &str, header: &str) -> Option<String> {
    let header_lower = header.to_lowercase();
    for line in response.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().to_lowercase() == header_lower {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Extract the HTML title from a response body.
fn extract_title(html: &str) -> Option<String> {
    // Find <title>...</title> (case insensitive)
    let html_lower = html.to_lowercase();
    if let Some(start) = html_lower.find("<title>") {
        if let Some(end) = html_lower.find("</title>") {
            if end > start + 7 {
                let title = &html[start + 7..end];
                return Some(title.trim().to_string());
            }
        }
    }
    None
}

/// Detect common web technologies from HTTP response.
fn detect_technology(response: &str, info: &mut ServiceInfo) {
    let lower = response.to_lowercase();
    
    // WordPress
    if lower.contains("wp-content") || lower.contains("wordpress") {
        info.extra.insert("cms".to_string(), "WordPress".to_string());
    }
    
    // Drupal
    if lower.contains("drupal") || response.contains("X-Drupal-") {
        info.extra.insert("cms".to_string(), "Drupal".to_string());
    }
    
    // Django
    if lower.contains("django") || lower.contains("csrftoken") {
        info.extra.insert("framework".to_string(), "Django".to_string());
    }
    
    // Express.js
    if lower.contains("x-powered-by: express") {
        info.extra.insert("framework".to_string(), "Express.js".to_string());
    }
    
    // ASP.NET
    if lower.contains("asp.net") || lower.contains("x-aspnet-version") {
        info.extra.insert("framework".to_string(), "ASP.NET".to_string());
    }
    
    // PHP
    if lower.contains("x-powered-by: php") {
        info.extra.insert("language".to_string(), "PHP".to_string());
    }
    
    // JSP/Java
    if lower.contains("jsessionid") || lower.contains("x-powered-by: jsp") {
        info.extra.insert("language".to_string(), "Java/JSP".to_string());
    }
    
    // Nginx
    if lower.contains("server: nginx") {
        info.extra.insert("webserver".to_string(), "Nginx".to_string());
    }
    
    // Apache
    if lower.contains("server: apache") {
        info.extra.insert("webserver".to_string(), "Apache".to_string());
    }
    
    // Cloudflare
    if lower.contains("cf-ray") || lower.contains("cloudflare") {
        info.extra.insert("cdn".to_string(), "Cloudflare".to_string());
    }
    
    // AWS
    if lower.contains("x-amz-") {
        info.extra.insert("cloud".to_string(), "AWS".to_string());
    }
}
