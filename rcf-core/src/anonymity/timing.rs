//! Timing controls, jitter, and the AnonymityManager state machine.

use std::time::{Duration, Instant};

use rand::Rng;
use tokio::sync::RwLock;

use super::AnonymityConfig;
use super::waf::{WafDetection, detect_waf};

/// State manager for anonymity operations.
pub struct AnonymityManager {
    config: RwLock<AnonymityConfig>,
    last_request: RwLock<Instant>,
    request_count: RwLock<u64>,
    waf_detections: RwLock<Vec<WafDetection>>,
    silent_output: RwLock<bool>,
}

impl AnonymityManager {
    pub fn new(config: AnonymityConfig) -> Self {
        let silent = config.silent_mode;
        Self {
            config: RwLock::new(config),
            last_request: RwLock::new(Instant::now()),
            request_count: RwLock::new(0),
            waf_detections: RwLock::new(vec![]),
            silent_output: RwLock::new(silent),
        }
    }

    pub async fn apply_jitter(&self) {
        let config = self.config.read().await;
        let min = config.jitter_min_ms;
        let max = config.jitter_max_ms;
        drop(config);

        if min == 0 && max == 0 {
            return;
        }

        let delay: u64 = rand::rng().random_range(min..=max);
        tokio::time::sleep(Duration::from_millis(delay)).await;

        *self.last_request.write().await = Instant::now();
    }

    pub fn get_user_agent(&self, custom: Option<&str>) -> String {
        if let Some(ua) = custom {
            return ua.to_string();
        }

        const PROFILES: &[&str] = &[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        ];

        let idx = rand::rng().random_range(0..PROFILES.len());
        PROFILES[idx].to_string()
    }

    pub async fn check_waf(&self, headers: &[(String, String)]) -> Option<WafDetection> {
        if !self.config.read().await.waf_detection {
            return None;
        }

        let detection = detect_waf(headers);
        if detection.detected {
            self.waf_detections.write().await.push(detection.clone());
        }
        Some(detection)
    }

    pub async fn set_silent(&self, silent: bool) {
        *self.silent_output.write().await = silent;
    }

    pub async fn is_silent(&self) -> bool {
        *self.silent_output.read().await
    }

    pub async fn update_config(&self, config: AnonymityConfig) {
        *self.config.write().await = config;
    }

    pub async fn get_config(&self) -> AnonymityConfig {
        self.config.read().await.clone()
    }

    pub async fn increment_requests(&self) -> u64 {
        let mut count = self.request_count.write().await;
        *count += 1;
        *count
    }

    pub async fn get_request_count(&self) -> u64 {
        *self.request_count.read().await
    }

    pub async fn get_waf_detections(&self) -> Vec<WafDetection> {
        self.waf_detections.read().await.clone()
    }
}

impl Default for AnonymityManager {
    fn default() -> Self {
        Self::new(AnonymityConfig::default())
    }
}

/// Get a random source port for binding.
pub fn random_source_port() -> u16 {
    rand::rng().random_range(1024..65535)
}

/// Calculate safe delay based on rate limits.
pub fn calculate_delay(rate_limit: u32, current_rate: u32) -> Duration {
    if current_rate >= rate_limit {
        Duration::from_millis(rand::rng().random_range(1000..5000))
    } else {
        Duration::ZERO
    }
}
