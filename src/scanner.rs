use crate::hashing::hash_file_sha256;
use crate::ioc::IocEntry;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStatus {
    Clean,
    Match(String),
    Error(String),
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: String,
    pub sha256: Option<String>,
    pub status: ScanStatus,
}

pub fn scan_target(target: &Path, iocs: &[IocEntry]) -> Vec<ScanResult> {
    let mut results = Vec::new();

    if target.is_file() {
        results.push(scan_file(target, iocs));
    } else if target.is_dir() {
        collect_files_recursive(target, iocs, &mut results);
    } else {
        results.push(ScanResult {
            path: target.display().to_string(),
            sha256: None,
            status: ScanStatus::Error("Path does not exist or is not accessible".to_string()),
        });
    }

    results
}

fn collect_files_recursive(dir: &Path, iocs: &[IocEntry], results: &mut Vec<ScanResult>) {
    match fs::read_dir(dir) {
        Ok(entries) => {
            let mut paths: Vec<_> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
            paths.sort();

            for path in paths {
                if path.is_file() {
                    results.push(scan_file(&path, iocs));
                } else if path.is_dir() {
                    collect_files_recursive(&path, iocs, results);
                }
            }
        }
        Err(e) => {
            results.push(ScanResult {
                path: dir.display().to_string(),
                sha256: None,
                status: ScanStatus::Error(e.to_string()),
            });
        }
    }
}

fn scan_file(path: &Path, iocs: &[IocEntry]) -> ScanResult {
    match hash_file_sha256(path) {
        Ok(hash) => {
            let status = match iocs.iter().find(|ioc| ioc.hash == hash) {
                Some(ioc) => ScanStatus::Match(ioc.label.clone()),
                None => ScanStatus::Clean,
            };
            ScanResult {
                path: path.display().to_string(),
                sha256: Some(hash),
                status,
            }
        }
        Err(e) => ScanResult {
            path: path.display().to_string(),
            sha256: None,
            status: ScanStatus::Error(e.to_string()),
        },
    }
}
