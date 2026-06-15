use crate::scanner::{ScanResult, ScanStatus};
use std::fs;
use std::io;
use std::path::Path;

pub fn write_csv(results: &[ScanResult], output_path: &Path) -> Result<(), io::Error> {
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut csv = String::from("path,sha256,status,label\n");
    for result in results {
        let sha256 = result.sha256.as_deref().unwrap_or("");
        let (status, label) = match &result.status {
            ScanStatus::Clean => ("CLEAN", String::new()),
            ScanStatus::Match(label) => ("MATCH", label.clone()),
            ScanStatus::Error(msg) => ("ERROR", msg.clone()),
        };
        csv.push_str(&format!(
            "{},{},{},{}\n",
            result.path, sha256, status, label
        ));
    }
    fs::write(output_path, csv)
}
