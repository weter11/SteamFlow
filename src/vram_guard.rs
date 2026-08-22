//! Pre-launch GPU (VRAM) exhaustion guard.
//!
//! Detects when the GPU is already nearly out of memory before a game launch
//! and reports which processes are holding it, so the user can stop offenders
//! (typically local LLM / AI inference servers such as TabbyAPI) instead of
//! watching the game or its Proton/DXVK stack die inside the graphics driver
//! with an opaque `vkCreateDevice` failure.
//!
//! Best-effort by design: every probe returns `None` on any error and the
//! caller treats "unknown" as "no problem". Never blocks a launch by itself.

use std::collections::BTreeMap;
use std::process::Command;

/// One process currently holding GPU memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VramProcess {
    pub pid: u32,
    pub name: String,
    pub mem_mib: u64,
}

/// A snapshot of GPU memory usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VramSnapshot {
    /// Driver-reported total VRAM in MiB.
    pub total_mib: u64,
    /// Driver-reported used VRAM in MiB.
    pub used_mib: u64,
    /// Per-process consumers, largest first.
    pub processes: Vec<VramProcess>,
}

impl VramSnapshot {
    /// Used fraction of total VRAM, 0.0..=1.0 (`0.0` when unknown).
    pub fn used_fraction(&self) -> f32 {
        if self.total_mib == 0 {
            return 0.0;
        }
        (self.used_mib as f32 / self.total_mib as f32).clamp(0.0, 1.0)
    }
}

/// Probe the system's primary discrete GPU. NVIDIA is supported via
/// `nvidia-smi`; anything else returns `Err` and the caller treats
/// "unknown" as "no problem" (never blocks a launch).
pub fn probe_vram() -> Result<VramSnapshot, String> {
    match probe_nvidia() {
        Some(snapshot) => Ok(snapshot),
        None => Err("no NVIDIA telemetry available (nvidia-smi missing or failed)".to_string()),
    }
}

/// Probe the first discrete NVIDIA GPU via `nvidia-smi`. Returns `None` when
/// `nvidia-smi` is unavailable or fails to parse (non-NVIDIA systems).
pub fn probe_nvidia() -> Option<VramSnapshot> {
    let output = Command::new("nvidia-smi")
        .args([
            "--query-gpu=memory.total,memory.used",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // First line = first GPU, e.g. "8192, 7548"
    let mut fields = stdout.lines().next()?.split(',');
    let total_mib = fields.next()?.trim().parse::<u64>().ok()?;
    let used_mib = fields.next().and_then(|v| v.trim().parse::<u64>().ok())?;
    if total_mib == 0 {
        return None;
    }

    let processes = query_nvidia_processes();
    Some(VramSnapshot {
        total_mib,
        used_mib,
        processes,
    })
}

/// Per-process compute-app query. Fails cleanly on older drivers; the
/// aggregate numbers above are still returned in that case.
fn query_nvidia_processes() -> Vec<VramProcess> {
    let output = Command::new("nvidia-smi")
        .args([
            "--query-compute-apps=pid,used_memory,process_name",
            "--format=csv,noheader,nounits",
        ])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_compute_apps(&stdout)
}

/// Parse `pid, mem, name` CSV rows from `--query-compute-apps`, aggregating
/// rows that share a PID.
fn parse_compute_apps(stdout: &str) -> Vec<VramProcess> {
    let mut by_pid: BTreeMap<u32, VramProcess> = BTreeMap::new();
    for row in stdout.lines() {
        let row = row.trim();
        if row.is_empty() {
            continue;
        }
        let mut fields = row.split(',');
        let (Some(pid), Some(mem), Some(name)) =
            (fields.next(), fields.next(), fields.next().map(str::trim))
        else {
            continue;
        };
        let (Ok(pid), Ok(mem)) = (pid.trim().parse::<u32>(), mem.trim().parse::<u64>()) else {
            continue;
        };
        let entry = by_pid.entry(pid).or_insert_with(|| VramProcess {
            pid,
            name: name
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
            mem_mib: 0,
        });
        entry.mem_mib += mem;
    }
    let mut processes: Vec<VramProcess> = by_pid.into_values().collect();
    processes.sort_by(|a, b| b.mem_mib.cmp(&a.mem_mib).then(a.pid.cmp(&b.pid)));
    processes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compute_apps_and_aggregates_by_pid() {
        let stdout = "87947, 7000, python\n87947, 524, python3\n42, 300, blender\n";
        let procs = parse_compute_apps(stdout);
        assert_eq!(procs.len(), 2);
        assert_eq!(procs[0].pid, 87947);
        assert_eq!(procs[0].mem_mib, 7524);
        assert_eq!(procs[0].name, "python");
        assert_eq!(procs[1].pid, 42);
        assert_eq!(procs[1].mem_mib, 300);
    }

    #[test]
    fn skips_malformed_rows() {
        let stdout = "not-a-pid, 100, x\n87947, nan, python\n\n";
        assert!(parse_compute_apps(stdout).is_empty());
    }

    #[test]
    fn empty_query_output_yields_no_processes() {
        assert!(parse_compute_apps("").is_empty());
        assert!(parse_compute_apps("\n").is_empty());
    }

    #[test]
    fn used_fraction_clamps_to_unit_interval() {
        let snap = VramSnapshot {
            total_mib: 8192,
            used_mib: 7548,
            processes: Vec::new(),
        };
        assert!((snap.used_fraction() - 0.9214).abs() < 1e-3);

        let zero = VramSnapshot {
            total_mib: 0,
            used_mib: 100,
            processes: Vec::new(),
        };
        assert_eq!(zero.used_fraction(), 0.0);

        let over = VramSnapshot {
            total_mib: 8192,
            used_mib: 99999,
            processes: Vec::new(),
        };
        assert_eq!(over.used_fraction(), 1.0);
    }
}
