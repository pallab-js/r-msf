//! Database export functionality — JSON, CSV, XML.

use serde::Serialize;
use std::fmt;

use crate::connection::RcfDatabase;
use crate::models::*;

/// Supported export formats.
#[derive(Debug, Clone)]
pub enum ExportFormat {
    Json,
    Csv,
    Xml,
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportFormat::Json => write!(f, "json"),
            ExportFormat::Csv => write!(f, "csv"),
            ExportFormat::Xml => write!(f, "xml"),
        }
    }
}

impl std::str::FromStr for ExportFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "json" => Ok(ExportFormat::Json),
            "csv" => Ok(ExportFormat::Csv),
            "xml" => Ok(ExportFormat::Xml),
            other => Err(format!("Unknown export format: {}", other)),
        }
    }
}

/// Complete database export.
#[derive(Serialize)]
pub struct DbExport {
    pub hosts: Vec<Host>,
    pub services: Vec<Service>,
    pub credentials: Vec<Credential>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub sessions: Vec<Session>,
    pub loot: Vec<Loot>,
}

/// Export the entire database.
pub fn export_all(db: &mut RcfDatabase, format: &ExportFormat) -> anyhow::Result<String> {
    let mut export = DbExport {
        hosts: db.list_hosts()?,
        services: Vec::new(),
        credentials: db.list_credentials()?,
        vulnerabilities: db.list_vulnerabilities()?,
        sessions: db.list_sessions()?,
        loot: Vec::new(),
    };

    // Load services and loot for all hosts
    for host in &export.hosts {
        let mut svc = db.list_services(&host.id)?;
        export.services.append(&mut svc);
        let mut loot = db.list_loot(&host.id)?;
        export.loot.append(&mut loot);
    }

    match format {
        ExportFormat::Json => Ok(serde_json::to_string_pretty(&export)?),
        ExportFormat::Csv => export_csv(&export),
        ExportFormat::Xml => export_xml(&export),
    }
}

/// Export hosts as CSV.
pub fn export_hosts_csv(db: &mut RcfDatabase) -> anyhow::Result<String> {
    let hosts = db.list_hosts()?;
    let mut wtr = csv::Writer::from_writer(Vec::new());
    for host in &hosts {
        wtr.serialize(host)?;
    }
    wtr.flush()?;
    Ok(String::from_utf8(wtr.into_inner()?)?)
}

/// Export credentials as CSV.
pub fn export_creds_csv(db: &mut RcfDatabase) -> anyhow::Result<String> {
    let creds = db.list_credentials()?;
    let mut wtr = csv::Writer::from_writer(Vec::new());
    for cred in &creds {
        wtr.serialize(cred)?;
    }
    wtr.flush()?;
    Ok(String::from_utf8(wtr.into_inner()?)?)
}

fn export_csv(export: &DbExport) -> anyhow::Result<String> {
    let mut output = String::new();

    // Hosts CSV
    output.push_str("# hosts\n");
    let mut wtr = csv::Writer::from_writer(Vec::new());
    for host in &export.hosts {
        wtr.serialize(host)?;
    }
    wtr.flush()?;
    output.push_str(&String::from_utf8(wtr.into_inner()?)?);
    output.push('\n');

    // Credentials CSV
    output.push_str("# credentials\n");
    let mut wtr = csv::Writer::from_writer(Vec::new());
    for cred in &export.credentials {
        wtr.serialize(cred)?;
    }
    wtr.flush()?;
    output.push_str(&String::from_utf8(wtr.into_inner()?)?);

    Ok(output)
}

fn export_xml(export: &DbExport) -> anyhow::Result<String> {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<rcf_export>\n");

    xml.push_str("  <hosts>\n");
    for host in &export.hosts {
        xml.push_str(&format!(
            "    <host address=\"{}\" os=\"{}\" state=\"{}\" />\n",
            escape_xml(&host.address),
            escape_xml(host.os.as_deref().unwrap_or("")),
            escape_xml(&host.state),
        ));
    }
    xml.push_str("  </hosts>\n");

    xml.push_str("  <credentials>\n");
    for cred in &export.credentials {
        xml.push_str(&format!(
            "    <credential host=\"{}\" user=\"{}\" service=\"{}\" />\n",
            escape_xml(&cred.host_id),
            escape_xml(&cred.username),
            escape_xml(&cred.service),
        ));
    }
    xml.push_str("  </credentials>\n");

    xml.push_str("  <vulnerabilities>\n");
    for vuln in &export.vulnerabilities {
        xml.push_str(&format!(
            "    <vulnerability name=\"{}\" severity=\"{}\" cve=\"{}\" />\n",
            escape_xml(&vuln.name),
            escape_xml(&vuln.severity),
            escape_xml(vuln.cve.as_deref().unwrap_or("")),
        ));
    }
    xml.push_str("  </vulnerabilities>\n");

    xml.push_str("</rcf_export>\n");
    Ok(xml)
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
