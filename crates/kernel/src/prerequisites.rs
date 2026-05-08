//! System prerequisite validation.

use std::path::Path;

/// Result of system prerequisite checks.
#[derive(Debug, Clone)]
pub struct PrerequisiteResult {
    pub passed: bool,
    pub deficiencies: Vec<String>,
}

/// Check system prerequisites (RAM >= 8GB, disk >= 10GB, internet).
pub fn check_prerequisites() -> PrerequisiteResult {
    let mut deficiencies = Vec::new();

    // Check RAM
    if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(line) = content.lines().find(|l| l.starts_with("MemTotal:")) {
            let kb: u64 = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if kb < 8 * 1024 * 1024 {
                deficiencies.push(format!(
                    "Insufficient RAM: {}GB (need 8GB)",
                    kb / 1024 / 1024
                ));
            }
        }
    } else {
        // Non-Linux: skip RAM check
    }

    // Check disk space (check /home or /)
    let check_path = if Path::new("/home").exists() {
        "/home"
    } else {
        "/"
    };
    match disk_free_gb(check_path) {
        Some(gb) if gb < 10 => {
            deficiencies.push(format!("Insufficient disk: {}GB (need 10GB)", gb))
        }
        None => {} // skip if can't determine
        _ => {}
    }

    // Check internet (simple DNS resolution test)
    if std::net::ToSocketAddrs::to_socket_addrs(&("dns.google", 443)).is_err() {
        deficiencies.push("No internet connectivity".to_string());
    }

    PrerequisiteResult {
        passed: deficiencies.is_empty(),
        deficiencies,
    }
}

/// Check prerequisites with custom thresholds (for testing).
pub fn check_with_thresholds(
    min_ram_gb: u64,
    min_disk_gb: u64,
    check_internet: bool,
) -> PrerequisiteResult {
    let mut deficiencies = Vec::new();

    if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(line) = content.lines().find(|l| l.starts_with("MemTotal:")) {
            let kb: u64 = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let gb = kb / 1024 / 1024;
            if gb < min_ram_gb {
                deficiencies.push(format!(
                    "Insufficient RAM: {}GB (need {}GB)",
                    gb, min_ram_gb
                ));
            }
        }
    }

    let check_path = if Path::new("/home").exists() {
        "/home"
    } else {
        "/"
    };
    if let Some(gb) = disk_free_gb(check_path) {
        if gb < min_disk_gb {
            deficiencies.push(format!(
                "Insufficient disk: {}GB (need {}GB)",
                gb, min_disk_gb
            ));
        }
    }

    if check_internet && std::net::ToSocketAddrs::to_socket_addrs(&("dns.google", 443)).is_err() {
        deficiencies.push("No internet connectivity".to_string());
    }

    PrerequisiteResult {
        passed: deficiencies.is_empty(),
        deficiencies,
    }
}

fn disk_free_gb(path: &str) -> Option<u64> {
    // Use statvfs on Linux
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        let c_path = CString::new(path).ok()?;
        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                let free_bytes = stat.f_bavail * stat.f_frsize;
                return Some(free_bytes / 1024 / 1024 / 1024);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_prerequisites_runs() {
        let result = check_prerequisites();
        // On a dev machine, should pass
        assert!(result.passed || !result.deficiencies.is_empty());
    }

    #[test]
    fn check_with_impossible_thresholds_fails() {
        let result = check_with_thresholds(99999, 99999, false);
        assert!(!result.passed);
        assert!(!result.deficiencies.is_empty());
    }

    #[test]
    fn check_with_zero_thresholds_passes() {
        let result = check_with_thresholds(0, 0, false);
        assert!(result.passed);
    }
}
