use crate::hashing::is_valid_sha256;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocEntry {
    pub hash: String,
    pub label: String,
}

pub struct IocLoadResult {
    pub entries: Vec<IocEntry>,
    pub invalid_count: usize,
}

pub fn load_iocs(path: &Path) -> Result<IocLoadResult, io::Error> {
    let content = fs::read_to_string(path)?;
    let mut entries = Vec::new();
    let mut invalid_count = 0;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, ',').collect();
        if parts.len() == 2 {
            let hash = parts[0].trim().to_lowercase();
            let label = parts[1].trim().to_string();
            if is_valid_sha256(&hash) {
                entries.push(IocEntry { hash, label });
            } else {
                invalid_count += 1;
            }
        } else {
            invalid_count += 1;
        }
    }
    Ok(IocLoadResult {
        entries,
        invalid_count,
    })
}
