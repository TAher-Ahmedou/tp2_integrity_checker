mod hashing;
mod ioc;
mod report;
mod scanner;

use ioc::load_iocs;
use report::write_csv;
use scanner::{scan_target, ScanStatus};
use std::path::Path;

struct Args {
    target: String,
    ioc: String,
    report: String,
    only_matches: bool,
    json: bool,
}

fn parse_args() -> Option<Args> {
    let args: Vec<String> = std::env::args().collect();
    let mut target = None;
    let mut ioc = None;
    let mut rep = None;
    let mut only_matches = false;
    let mut json = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                i += 1;
                target = args.get(i).cloned();
            }
            "--ioc" => {
                i += 1;
                ioc = args.get(i).cloned();
            }
            "--report" => {
                i += 1;
                rep = args.get(i).cloned();
            }
            "--only-matches" => {
                only_matches = true;
            }
            "--json" => {
                json = true;
            }
            _ => {}
        }
        i += 1;
    }

    match (target, ioc, rep) {
        (Some(t), Some(i), Some(r)) => Some(Args {
            target: t,
            ioc: i,
            report: r,
            only_matches,
            json,
        }),
        _ => None,
    }
}

fn main() {
    let args = match parse_args() {
        Some(a) => a,
        None => {
            eprintln!("Usage:");
            eprintln!("  tp2_integrity_checker --target <FILE_OR_DIRECTORY> --ioc <IOC_FILE> --report <REPORT_FILE> [--only-matches] [--json]");
            std::process::exit(1);
        }
    };

    println!("TP2 File Integrity Checker and IOC Matcher");
    println!("Target:   {}", args.target);
    println!("IOC file: {}", args.ioc);
    println!("Report:   {}", args.report);
    println!();

    let ioc_path = Path::new(&args.ioc);
    let ioc_result = match load_iocs(ioc_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: cannot read IOC file '{}': {}", args.ioc, e);
            std::process::exit(1);
        }
    };

    let target_path = Path::new(&args.target);
    let all_results = scan_target(target_path, &ioc_result.entries);

    // Filtrer si --only-matches
    let results: Vec<_> = if args.only_matches {
        all_results
            .iter()
            .filter(|r| matches!(&r.status, ScanStatus::Match(_)))
            .cloned()
            .collect()
    } else {
        all_results.clone()
    };

    let matches: Vec<_> = all_results
        .iter()
        .filter(|r| matches!(&r.status, ScanStatus::Match(_)))
        .collect();
    let errors = all_results
        .iter()
        .filter(|r| matches!(&r.status, ScanStatus::Error(_)))
        .count();

    // Affichage JSON
    if args.json {
        println!("{{");
        println!("  \"files_scanned\": {},", all_results.len());
        println!("  \"ioc_entries\": {},", ioc_result.entries.len());
        println!("  \"invalid_ioc_lines\": {},", ioc_result.invalid_count);
        println!("  \"matches_found\": {},", matches.len());
        println!("  \"errors\": {},", errors);
        println!("  \"results\": [");
        for (i, r) in results.iter().enumerate() {
            let sha = r.sha256.as_deref().unwrap_or("");
            let (status, label) = match &r.status {
                ScanStatus::Clean => ("CLEAN", String::new()),
                ScanStatus::Match(l) => ("MATCH", l.clone()),
                ScanStatus::Error(e) => ("ERROR", e.clone()),
            };
            let comma = if i + 1 < results.len() { "," } else { "" };
            println!("    {{\"path\": \"{}\", \"sha256\": \"{}\", \"status\": \"{}\", \"label\": \"{}\"}}{}", r.path, sha, status, label, comma);
        }
        println!("  ]");
        println!("}}");
    } else {
        // Affichage normal
        println!("Summary:");
        println!("  * Files scanned:      {}", all_results.len());
        println!("  * IOC entries loaded: {}", ioc_result.entries.len());
        println!("  * Invalid IOC lines:  {}", ioc_result.invalid_count);
        println!("  * Matches found:      {}", matches.len());
        println!("  * Errors:             {}", errors);
        println!();

        if !matches.is_empty() {
            println!("Matches:");
            for r in &matches {
                if let ScanStatus::Match(label) = &r.status {
                    println!("  [ALERT] {}", r.path);
                    println!("  SHA-256: {}", r.sha256.as_deref().unwrap_or("N/A"));
                    println!("  IOC label: {}", label);
                    println!();
                }
            }
        }
    }

    let report_path = Path::new(&args.report);
    match write_csv(&results, report_path) {
        Ok(_) => println!("CSV report written to {}", args.report),
        Err(e) => eprintln!("Error writing report: {}", e),
    }
}
