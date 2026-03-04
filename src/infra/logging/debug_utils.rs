use crate::infra::logging::LaunchSummary;
use anyhow::{Context, Result};
use std::path::Path;

pub fn load_launch_summary(log_dir: &Path) -> Result<LaunchSummary> {
    let summary_path = log_dir.join("summary.json");
    let content = std::fs::read_to_string(&summary_path)
        .with_context(|| format!("Failed to read summary at {}", summary_path.display()))?;
    let summary: LaunchSummary = serde_json::from_str(&content)?;
    Ok(summary)
}

pub fn print_launch_summary(summary: &LaunchSummary) {
    println!("--- Launch Summary ---");
    println!("Session ID    : {}", summary.session_id);
    println!("App           : {} ({})", summary.app_name.as_deref().unwrap_or("Unknown"), summary.app_id);
    println!("Result        : {:?}", summary.result);
    if let Some(stage) = &summary.failing_stage {
        println!("Failing Stage : {}", stage);
    }
    println!("Total Duration: {}ms", summary.total_duration_ms);
    println!("Stage Timings :");
    let mut sorted_stages: Vec<_> = summary.stage_durations_ms.iter().collect();
    sorted_stages.sort_by_key(|(_, &d)| std::cmp::Reverse(d));
    for (stage, duration) in sorted_stages {
        println!("  - {}: {}ms", stage, duration);
    }
    println!("----------------------");
}
