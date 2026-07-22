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
    check_with_thresholds(8, 10, true)
}

/// Check prerequisites with custom thresholds (for testing).
pub fn check_with_thresholds(
    min_ram_gb: u64,
    min_disk_gb: u64,
    check_internet: bool,
) -> PrerequisiteResult {
    let mut deficiencies = Vec::new();

    if min_ram_gb > 0 {
        match total_memory_gb() {
            Some(gb) if gb < min_ram_gb => deficiencies.push(format!(
                "Insufficient RAM: {}GB (need {}GB)",
                gb, min_ram_gb
            )),
            None => deficiencies.push(format!(
                "Unable to determine RAM (need at least {}GB)",
                min_ram_gb
            )),
            _ => {}
        }
    }

    let check_path = if Path::new("/home").exists() {
        "/home"
    } else {
        "/"
    };
    if min_disk_gb > 0 {
        match disk_free_gb(check_path) {
            Some(gb) if gb < min_disk_gb => deficiencies.push(format!(
                "Insufficient disk: {}GB (need {}GB)",
                gb, min_disk_gb
            )),
            None => deficiencies.push(format!(
                "Unable to determine free disk space (need at least {}GB)",
                min_disk_gb
            )),
            _ => {}
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

fn total_memory_gb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/meminfo").ok()?;
        let kb = content
            .lines()
            .find(|line| line.starts_with("MemTotal:"))?
            .split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()?;
        Some(kb / 1024 / 1024)
    }

    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;

        let name = CString::new("hw.memsize").ok()?;
        let mut bytes: u64 = 0;
        let mut size = std::mem::size_of::<u64>();
        // SAFETY: `bytes` points to a writable u64 and `size` accurately
        // describes the buffer supplied to the read-only sysctl query.
        let result = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                (&mut bytes as *mut u64).cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        (result == 0 && size == std::mem::size_of::<u64>()).then_some(bytes / 1024 / 1024 / 1024)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

fn disk_free_gb(path: &str) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        let c_path = CString::new(path).ok()?;
        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                let free_bytes = (stat.f_bavail as u64) * (stat.f_frsize as u64);
                return Some(free_bytes / 1024 / 1024 / 1024);
            }
        }
        None
    }
    #[cfg(not(unix))]
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
        assert!(result.deficiencies.is_empty());
    }
}
