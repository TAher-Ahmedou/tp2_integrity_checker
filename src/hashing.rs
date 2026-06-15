use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub fn hash_file_sha256(path: &Path) -> Result<String, io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

pub fn is_valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_sha256_valid() {
        let hash = "44ea92bec1f9e8aa690d8aceddf1294e9fb4a71d39769d6f383e3915ac76bb3b";
        assert!(is_valid_sha256(hash));
    }

    #[test]
    fn test_is_valid_sha256_too_short() {
        assert!(!is_valid_sha256("44ea92bec1f9e8aa"));
    }

    #[test]
    fn test_is_valid_sha256_invalid_chars() {
        assert!(!is_valid_sha256(
            "INVALID_HASH_LINE_SHOULD_BE_IGNORED_____________"
        ));
    }

    #[test]
    fn test_hash_file_known_value() {
        let path = std::path::Path::new("samples/files/suspicious_dropper.txt");
        let hash = hash_file_sha256(path).expect("hashing failed");
        assert_eq!(
            hash,
            "44ea92bec1f9e8aa690d8aceddf1294e9fb4a71d39769d6f383e3915ac76bb3b"
        );
    }
}
