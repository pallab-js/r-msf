//! Metasploit module compatibility layer.
//!
//! Provides import/export functionality between RCF modules and Metasploit .rb modules.
//! Supports parsing basic .rb module metadata and generating compatible RCF modules.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metasploit module metadata parsed from .rb files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsfModuleInfo {
    /// Module name (e.g. "exploit/windows/smb/ms08_067_netapi")
    pub name: String,
    /// Module description
    pub description: String,
    /// Module license
    pub license: Option<String>,
    /// Author list
    pub authors: Vec<String>,
    /// Disclosure date
    pub disclosure_date: Option<String>,
    /// References (CVE, URLs, etc.)
    pub references: Vec<String>,
    /// Default options
    pub default_options: HashMap<String, String>,
    /// Target platforms
    pub platforms: Vec<String>,
    /// Target architectures
    pub arch: Vec<String>,
    /// Default target
    pub default_target: usize,
    /// Payload compatibility
    pub payload_space: Option<usize>,
}

/// Parser for Metasploit .rb module files.
pub struct MsfModuleParser;

impl MsfModuleParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse a Metasploit .rb module file and extract metadata.
    ///
    /// This is a simplified parser that extracts basic metadata.
    /// Full parsing would require a Ruby parser or regex-based extraction.
    pub fn parse_rb(&self, content: &str) -> anyhow::Result<MsfModuleInfo> {
        let mut info = MsfModuleInfo {
            name: String::new(),
            description: String::new(),
            license: None,
            authors: Vec::new(),
            disclosure_date: None,
            references: Vec::new(),
            default_options: HashMap::new(),
            platforms: Vec::new(),
            arch: Vec::new(),
            default_target: 0,
            payload_space: None,
        };

        // Extract 'Name' field
        if let Some(name) = extract_quoted_field(content, "'Name'")
            .or_else(|| extract_quoted_field(content, "\"Name\""))
        {
            info.name = name;
        }

        // Extract 'Description' field
        if let Some(desc) = extract_quoted_field(content, "'Description'")
            .or_else(|| extract_quoted_field(content, "\"Description\""))
        {
            info.description = desc;
        }

        // Extract 'License' field
        info.license = extract_quoted_field(content, "'License'")
            .or_else(|| extract_quoted_field(content, "\"License\""));

        // Extract 'Author' field (can be string or array)
        info.authors = extract_author_array(content);

        // Extract 'DisclosureDate'
        info.disclosure_date = extract_quoted_field(content, "'DisclosureDate'")
            .or_else(|| extract_quoted_field(content, "\"DisclosureDate\""));

        // Extract 'References'
        info.references = extract_references(content);

        // Extract 'Platform'
        info.platforms = extract_platforms(content);

        // Extract 'Arch'
        info.arch = extract_architectures(content);

        Ok(info)
    }

    /// Generate an RCF module stub from Metasploit module info.
    pub fn generate_rcf_stub(&self, info: &MsfModuleInfo) -> String {
        let mut output = String::new();

        output.push_str("//! Auto-generated RCF module from Metasploit\n");
        output.push_str(&format!("//! Source: {}\n\n", info.name));

        output.push_str("use std::pin::Pin;\n");
        output.push_str("use std::future::Future;\n\n");
        output.push_str("use rcf_core::{\n");
        output.push_str("    Context, Module, ModuleCategory, ModuleInfo, ModuleOptions,\n");
        output.push_str("    ModuleOutput, Result, Target,\n");
        output.push_str("};\n\n");

        output.push_str("static INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {{\n");
        output.push_str(&format!("    name: \"{}\".to_string(),\n", info.name));
        output.push_str(&format!(
            "    display_name: \"{}\".to_string(),\n",
            info.name.split('/').next_back().unwrap_or(&info.name)
        ));
        output.push_str(&format!(
            "    description: \"{}\".to_string(),\n",
            info.description.replace('"', "\\\"")
        ));
        output.push_str("    authors: vec![\n");
        for author in &info.authors {
            output.push_str(&format!("        \"{}\".to_string(),\n", author));
        }
        output.push_str("    ],\n");

        // Determine category from module path
        let category = if info.name.starts_with("exploit/") {
            "ModuleCategory::Exploit"
        } else if info.name.starts_with("auxiliary/") {
            "ModuleCategory::Auxiliary"
        } else if info.name.starts_with("payload/") {
            "ModuleCategory::Payload"
        } else if info.name.starts_with("post/") {
            "ModuleCategory::Post"
        } else if info.name.starts_with("encoder/") {
            "ModuleCategory::Encoder"
        } else {
            "ModuleCategory::Auxiliary"
        };
        output.push_str(&format!("    category: {},\n", category));
        output.push_str("    rank: 100,\n");
        output.push_str("    stability: \"imported\".to_string(),\n");

        if let Some(ref date) = info.disclosure_date {
            output.push_str(&format!(
                "    disclosure_date: Some(\"{}\".to_string()),\n",
                date
            ));
        }

        output.push_str("    references: vec![\n");
        for r in &info.references {
            output.push_str(&format!("        \"{}\".to_string(),\n", r));
        }
        output.push_str("    ],\n");
        output.push_str("});\n\n");

        // Generate module struct
        let struct_name = info
            .name
            .split('/')
            .next_back()
            .unwrap_or("ImportedModule")
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect::<String>();

        output.push_str(&format!("pub struct {};\n\n", struct_name));
        output.push_str(&format!("impl {} {{\n", struct_name));
        output.push_str("    pub fn new() -> Self {\n");
        output.push_str("        Self\n");
        output.push_str("    }\n");
        output.push_str("}\n\n");

        // Implement Module trait
        output.push_str(&format!("impl Module for {} {{\n", struct_name));
        output.push_str("    fn info(&self) -> &ModuleInfo {\n");
        output.push_str("        &INFO\n");
        output.push_str("    }\n\n");
        output.push_str("    fn options(&self) -> ModuleOptions {\n");
        output.push_str("        let mut opts = ModuleOptions::new();\n");

        for (key, value) in &info.default_options {
            output.push_str("        opts.add(rcf_core::ModuleOption::with_default(\n");
            output.push_str(&format!("            \"{}\",\n", key));
            output.push_str("            false,\n");
            output.push_str("            \"Imported from Metasploit\",\n");
            output.push_str(&format!(
                "            rcf_core::OptionValue::String(\"{}\".to_string()),\n",
                value
            ));
            output.push_str("        ));\n");
        }

        output.push_str("        opts\n");
        output.push_str("    }\n\n");
        output.push_str("    fn run(\n");
        output.push_str("        &self,\n");
        output.push_str("        ctx: &mut Context,\n");
        output.push_str("        _target: &Target,\n");
        output.push_str(
            "    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {\n",
        );
        output.push_str("        let info_name = self.info().name.clone();\n");
        output.push_str("        Box::pin(async move {\n");
        output.push_str("            let msg = \"Imported Metasploit module — implementation pending\".to_string();\n");
        output.push_str("            Ok(ModuleOutput::success(&info_name, \"target\", &msg))\n");
        output.push_str("        })\n");
        output.push_str("    }\n");
        output.push_str("}\n");

        output
    }
}

impl Default for MsfModuleParser {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helper Functions ──────────────────────────────────────────────────

fn extract_quoted_field(content: &str, field: &str) -> Option<String> {
    // Find 'Name' => "value" or 'Name' => 'value'
    let field_pattern = format!("{} =>", field);
    if let Some(pos) = content.find(&field_pattern) {
        let after = &content[pos + field_pattern.len()..];
        let trimmed = after.trim_start();
        if let Some(stripped) = trimmed.strip_prefix('"') {
            if let Some(end) = stripped.find('"') {
                return Some(stripped[..end].to_string());
            }
        } else if let Some(stripped) = trimmed.strip_prefix('\'')
            && let Some(end) = stripped.find('\'')
        {
            return Some(stripped[..end].to_string());
        }
    }
    None
}

fn extract_author_array(content: &str) -> Vec<String> {
    let mut authors = Vec::new();

    // Try array format: 'Author' => ['author1', 'author2']
    if let Some(pos) = content
        .find("'Author'")
        .or_else(|| content.find("\"Author\""))
    {
        let after = &content[pos..];
        if let Some(start) = after.find('[')
            && let Some(end) = after[start..].find(']')
        {
            let array_content = &after[start + 1..start + end];
            for author in array_content.split(',') {
                let author = author.trim().trim_matches(|c| c == '\'' || c == '"');
                if !author.is_empty() {
                    authors.push(author.to_string());
                }
            }
        }
    }

    authors
}

fn extract_references(content: &str) -> Vec<String> {
    let mut refs = Vec::new();

    if let Some(pos) = content
        .find("'References'")
        .or_else(|| content.find("\"References\""))
    {
        let after = &content[pos..];
        if let Some(start) = after.find('[') {
            // Find matching ]
            let mut depth = 0;
            let mut end_pos = None;
            for (i, c) in after[start..].char_indices() {
                match c {
                    '[' => depth += 1,
                    ']' => {
                        depth -= 1;
                        if depth == 0 {
                            end_pos = Some(start + i);
                            break;
                        }
                    }
                    _ => {}
                }
            }

            if let Some(end) = end_pos {
                let array_content = &after[start + 1..end];
                // Extract quoted strings
                for cap in regex_find_quoted_strings(array_content) {
                    refs.push(cap);
                }
            }
        }
    }

    refs
}

fn regex_find_quoted_strings(s: &str) -> Vec<String> {
    let mut strings = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '\'' || chars[i] == '"' {
            let quote = chars[i];
            let start = i + 1;
            if let Some(end) = chars[start..].iter().position(|&c| c == quote) {
                let s: String = chars[start..start + end].iter().collect();
                strings.push(s);
                i = start + end + 1;
                continue;
            }
        }
        i += 1;
    }

    strings
}

fn extract_platforms(content: &str) -> Vec<String> {
    let mut platforms = Vec::new();

    if let Some(pos) = content
        .find("'Platform'")
        .or_else(|| content.find("\"Platform\""))
    {
        let after = &content[pos..];
        // Try array format: 'Platform' => ['win', 'linux']
        if let Some(start) = after.find('[')
            && let Some(end) = after[start..].find(']')
        {
            let array_content = &after[start + 1..start + end];
            for platform in array_content.split(',') {
                let p = platform.trim().trim_matches(|c| c == '\'' || c == '"');
                if !p.is_empty() {
                    platforms.push(p.to_string());
                }
            }
        }
        // Try hash format: 'Platform' => { 'win' => [ ... ] }
        else if let Some(start) = after.find('{')
            && let Some(end) = after[start..].find('}')
        {
            let hash_content = &after[start + 1..start + end];
            for key in hash_content.split(',') {
                let key = key.trim().trim_matches(|c| c == '\'' || c == '"');
                if !key.is_empty() {
                    platforms.push(key.to_string());
                }
            }
        }
    }

    platforms
}

fn extract_architectures(content: &str) -> Vec<String> {
    let mut archs = Vec::new();

    if let Some(pos) = content.find("'Arch'").or_else(|| content.find("\"Arch\"")) {
        let after = &content[pos..];
        if let Some(start) = after.find('[')
            && let Some(end) = after[start..].find(']')
        {
            let array_content = &after[start + 1..start + end];
            for arch in array_content.split(',') {
                let a = arch.trim().trim_matches(|c| c == '\'' || c == '"');
                if !a.is_empty() {
                    archs.push(a.to_string());
                }
            }
        }
    }

    archs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_msf_module() {
        let parser = MsfModuleParser::new();
        let content = r#"
            'Name' => 'Test Exploit',
            'Description' => 'A test module',
            'License' => MSF_LICENSE,
            'Author' => ['author1', 'author2'],
            'DisclosureDate' => '2024-01-01',
            'References' => [
                ['CVE', '2024-1234'],
                ['URL', 'https://example.com']
            ],
            'Platform' => ['win', 'linux'],
            'Arch' => [ARCH_X86, ARCH_X64],
        "#;

        let info = match parser.parse_rb(content) {
            Ok(i) => i,
            Err(e) => {
                panic!("Failed to parse Metasploit module: {}", e);
            }
        };
        assert_eq!(info.name, "Test Exploit");
        assert_eq!(info.description, "A test module");
        assert_eq!(info.authors, vec!["author1", "author2"]);
        assert_eq!(info.disclosure_date, Some("2024-01-01".to_string()));
        assert_eq!(info.platforms, vec!["win", "linux"]);
    }

    #[test]
    fn test_generate_rcf_stub() {
        let parser = MsfModuleParser::new();
        let info = MsfModuleInfo {
            name: "exploit/windows/smb/test".to_string(),
            description: "Test module".to_string(),
            license: Some("MSF_LICENSE".to_string()),
            authors: vec!["test".to_string()],
            disclosure_date: Some("2024-01-01".to_string()),
            references: vec!["CVE-2024-1234".to_string()],
            default_options: HashMap::new(),
            platforms: vec!["win".to_string()],
            arch: vec!["x64".to_string()],
            default_target: 0,
            payload_space: None,
        };

        let stub = parser.generate_rcf_stub(&info);
        assert!(stub.contains("exploit/windows/smb/test"));
        assert!(stub.contains("ModuleCategory::Exploit"));
        assert!(stub.contains("impl Module"));
    }
}
