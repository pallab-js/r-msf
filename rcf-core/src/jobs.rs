//! Job management system for background tasks.
//!
//! Allows running scans, exploits, and other operations
//! in the background while continuing to use the console.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

/// Status of a background job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Running,
    Completed,
    Failed(String),
    Stopped,
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobStatus::Running => write!(f, "running"),
            JobStatus::Completed => write!(f, "completed"),
            JobStatus::Failed(e) => write!(f, "failed ({})", e),
            JobStatus::Stopped => write!(f, "stopped"),
        }
    }
}

/// Serializable job info (without the JoinHandle).
#[derive(Debug, Clone, Serialize)]
pub struct JobInfo {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub status: JobStatus,
    pub started_at: i64,
    pub completed_at: Option<i64>,
}

impl JobInfo {
    fn from_job(job: &Job) -> Self {
        Self {
            id: job.id,
            name: job.name.clone(),
            description: job.description.clone(),
            status: job.status.clone(),
            started_at: job.started_at,
            completed_at: job.completed_at,
        }
    }
}

/// A background job.
pub struct Job {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub status: JobStatus,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub handle: Option<JoinHandle<anyhow::Result<()>>>,
}

impl Job {
    pub fn new(id: u32, name: &str, description: &str) -> Self {
        Self {
            id,
            name: name.to_string(),
            description: description.to_string(),
            status: JobStatus::Running,
            started_at: chrono::Utc::now().timestamp(),
            completed_at: None,
            handle: None,
        }
    }

    pub fn complete(&mut self) {
        self.status = JobStatus::Completed;
        self.completed_at = Some(chrono::Utc::now().timestamp());
    }

    pub fn fail(&mut self, error: String) {
        self.status = JobStatus::Failed(error);
        self.completed_at = Some(chrono::Utc::now().timestamp());
    }

    pub fn stop(&mut self) {
        self.status = JobStatus::Stopped;
        self.completed_at = Some(chrono::Utc::now().timestamp());
    }
}

/// Job manager — tracks and manages background jobs.
pub struct JobManager {
    jobs: Arc<RwLock<HashMap<u32, Job>>>,
    next_id: Arc<AtomicU32>,
}

impl JobManager {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(AtomicU32::new(1)),
        }
    }

    /// Start a new background job.
    pub async fn start_job(
        &self,
        name: &str,
        description: &str,
        task: impl std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
    ) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let job = Job::new(id, name, description);

        let jobs = Arc::clone(&self.jobs);
        let handle = tokio::spawn(async move {
            let result = task.await;
            let mut jobs_lock = jobs.write().await;
            if let Some(j) = jobs_lock.get_mut(&id) {
                match &result {
                    Ok(()) => j.complete(),
                    Err(e) => j.fail(e.to_string()),
                }
            }
            result
        });

        let mut jobs_lock = self.jobs.write().await;
        let job_entry = jobs_lock.entry(id).or_insert(job);
        job_entry.handle = Some(handle);

        id
    }

    /// Get job info by ID.
    pub async fn get_job(&self, id: u32) -> Option<JobInfo> {
        self.jobs.read().await.get(&id).map(JobInfo::from_job)
    }

    /// List all jobs.
    pub async fn list_jobs(&self) -> Vec<JobInfo> {
        self.jobs
            .read()
            .await
            .values()
            .map(JobInfo::from_job)
            .collect()
    }

    /// Stop a running job.
    pub async fn stop_job(&self, id: u32) -> bool {
        let mut jobs = self.jobs.write().await;
        if let Some(job) = jobs.get_mut(&id)
            && job.status == JobStatus::Running
        {
            job.stop();
            if let Some(handle) = job.handle.take() {
                handle.abort();
            }
            return true;
        }
        false
    }

    /// Kill all running jobs.
    pub async fn kill_all(&self) -> usize {
        let mut count = 0;
        let mut jobs = self.jobs.write().await;
        for job in jobs.values_mut() {
            if job.status == JobStatus::Running {
                job.stop();
                if let Some(handle) = job.handle.take() {
                    handle.abort();
                }
                count += 1;
            }
        }
        count
    }

    /// Format jobs for display.
    pub async fn format_jobs(&self) -> String {
        let jobs = self.list_jobs().await;
        if jobs.is_empty() {
            return "No jobs running".to_string();
        }

        let mut lines = Vec::new();
        lines.push(format!(
            "\n  {:<6} {:<20} {:<12}  {}",
            "ID".bold(),
            "Name".bold(),
            "Status".bold(),
            "Description".bold()
        ));
        lines.push(format!(
            "  {:<6} {:<20} {:<12}  {}",
            "--".bold(),
            "----".bold(),
            "------".bold(),
            "-----------".bold()
        ));

        for job in jobs {
            lines.push(format!(
                "  {:<6} {:<20} {:<12}  {}",
                job.id, job.name, job.status, job.description
            ));
        }

        lines.join("\n")
    }

    /// Count active jobs.
    pub async fn active_count(&self) -> usize {
        self.jobs
            .read()
            .await
            .values()
            .filter(|j| j.status == JobStatus::Running)
            .count()
    }
}

impl Default for JobManager {
    fn default() -> Self {
        Self::new()
    }
}

use colored::Colorize;
