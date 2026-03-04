#[cfg(test)]
mod tests {
    use crate::infra::logging::{LaunchSessionId, LaunchSession, EventLogger, LogLevel, LogEvent};
    use std::path::PathBuf;
    use std::collections::HashSet;
    use tempfile::tempdir;

    #[test]
    fn test_launch_session_id_uniqueness() {
        let mut ids = HashSet::new();
        for _ in 0..100 {
            let id = LaunchSessionId::generate();
            assert!(ids.insert(id), "Duplicate session ID generated!");
        }
    }

    #[test]
    fn test_launch_session_path_generation() {
        let temp = PathBuf::from("/tmp/steamflow_logs");
        let session = LaunchSession::new(&temp);

        let id_str = session.id.to_string();
        assert!(session.log_dir.ends_with(&id_str));
        assert!(session.event_log_path().ends_with(format!("{}/events.jsonl", id_str)));
        assert!(session.stdout_path().ends_with(format!("{}/stdout.log", id_str)));
        assert!(session.stderr_path().ends_with(format!("{}/stderr.log", id_str)));
    }

    #[test]
    fn test_event_logger_append() {
        let dir = tempdir().expect("Failed to create temp dir");
        let session = LaunchSession::new(dir.path());
        let logger = EventLogger::new(&session).expect("Failed to create logger");

        logger.log(LogLevel::Info, "Test message".to_string(), Some("Init".to_string()))
            .expect("Failed to log event");

        let content = std::fs::read_to_string(session.event_log_path())
            .expect("Failed to read log file");

        let event: LogEvent = serde_json::from_str(&content)
            .expect("Failed to parse log event");

        assert_eq!(event.message, "Test message");
        assert_eq!(event.stage, Some("Init".to_string()));
        match event.level {
            LogLevel::Info => (),
            _ => panic!("Wrong log level"),
        }
    }
}
