use std::collections::VecDeque;

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallStage {
    GetManifestId,
    GetSecurityInfo,
    DownloadManifest,
    DownloadChunks,
    Complete,
    Failed,
}

#[derive(Debug, Clone)]
pub struct InstallJob {
    pub app_id: u32,
    pub stage: InstallStage,
    pub progress_percent: u8,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InstallEvent {
    pub app_id: u32,
    pub stage: InstallStage,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ProgressEvent {
    pub file_name: String,
    pub bytes_downloaded: u64,
    pub total_bytes: u64,
}

#[derive(Debug)]
pub struct InstallPipeline {
    queue: VecDeque<InstallJob>,
    progress_tx: UnboundedSender<ProgressEvent>,
    progress_rx: UnboundedReceiver<ProgressEvent>,
}

impl Default for InstallPipeline {
    fn default() -> Self {
        let (progress_tx, progress_rx) = unbounded_channel();
        Self {
            queue: VecDeque::new(),
            progress_tx,
            progress_rx,
        }
    }
}

impl InstallPipeline {
    pub fn enqueue(&mut self, app_id: u32) {
        if self
            .queue
            .iter()
            .any(|job| job.app_id == app_id && job.stage != InstallStage::Complete)
        {
            return;
        }

        self.queue.push_back(InstallJob {
            app_id,
            stage: InstallStage::GetManifestId,
            progress_percent: 0,
            last_error: None,
        });
    }

    pub fn jobs(&self) -> &VecDeque<InstallJob> {
        &self.queue
    }

    pub fn progress_sender(&self) -> UnboundedSender<ProgressEvent> {
        self.progress_tx.clone()
    }

    pub fn report_progress(&self, event: ProgressEvent) {
        let _ = self.progress_tx.send(event);
    }

    pub fn take_progress_events(&mut self) -> Vec<ProgressEvent> {
        let mut out = Vec::new();
        while let Ok(event) = self.progress_rx.try_recv() {
            out.push(event);
        }
        out
    }

    pub fn tick(&mut self) -> Vec<InstallEvent> {
        let mut events = Vec::new();

        for job in &mut self.queue {
            match job.stage {
                InstallStage::GetManifestId => {
                    job.stage = InstallStage::GetSecurityInfo;
                    job.progress_percent = 25;
                    events.push(InstallEvent {
                        app_id: job.app_id,
                        stage: job.stage,
                        message: "Phase 1/4 complete: manifest id resolved".to_string(),
                    });
                }
                InstallStage::GetSecurityInfo => {
                    job.stage = InstallStage::DownloadManifest;
                    job.progress_percent = 50;
                    events.push(InstallEvent {
                        app_id: job.app_id,
                        stage: job.stage,
                        message: "Phase 2/4 complete: depot key and CDN info resolved".to_string(),
                    });
                }
                InstallStage::DownloadManifest => {
                    job.stage = InstallStage::DownloadChunks;
                    job.progress_percent = 75;
                    events.push(InstallEvent {
                        app_id: job.app_id,
                        stage: job.stage,
                        message: "Phase 3/4 complete: manifest downloaded and parsed".to_string(),
                    });
                }
                InstallStage::DownloadChunks => {
                    job.stage = InstallStage::Complete;
                    job.progress_percent = 100;
                    events.push(InstallEvent {
                        app_id: job.app_id,
                        stage: job.stage,
                        message: "Phase 4/4 complete: chunk loop finished".to_string(),
                    });
                }
                InstallStage::Complete | InstallStage::Failed => {}
            }
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_pipeline_advances_in_order() {
        let mut pipeline = InstallPipeline::default();
        pipeline.enqueue(570);

        let first = pipeline.tick();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].stage, InstallStage::GetSecurityInfo);

        let second = pipeline.tick();
        assert_eq!(second[0].stage, InstallStage::DownloadManifest);

        let third = pipeline.tick();
        assert_eq!(third[0].stage, InstallStage::DownloadChunks);

        let fourth = pipeline.tick();
        assert_eq!(fourth[0].stage, InstallStage::Complete);
    }

    #[test]
    fn progress_events_round_trip() {
        let mut pipeline = InstallPipeline::default();
        pipeline.report_progress(ProgressEvent {
            file_name: "test.bin".to_string(),
            bytes_downloaded: 100,
            total_bytes: 400,
        });

        let events = pipeline.take_progress_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].file_name, "test.bin");
    }
}
