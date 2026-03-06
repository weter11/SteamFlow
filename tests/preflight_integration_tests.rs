use steamflow::launch::pipeline::{LaunchPipeline, PipelineContext};
use steamflow::launch::stages::preflight::PreflightStage;
use steamflow::infra::runners::CommandSpec;
use std::path::Path;

#[tokio::test]
async fn test_pipeline_preflight_prevents_spawn() {
    let mut pipeline = LaunchPipeline::new();
    pipeline.add_stage(Box::new(PreflightStage));
    // We add a dummy success stage that should NOT be reached if preflight fails
    struct SpawnShouldNotBeReached;
    #[async_trait::async_trait]
    impl steamflow::launch::pipeline::PipelineStage for SpawnShouldNotBeReached {
        fn name(&self) -> &str { "SpawnProcess" }
        async fn execute(&self, _ctx: &mut PipelineContext) -> Result<(), steamflow::launch::pipeline::LaunchError> {
            panic!("SpawnProcess stage reached but should have been prevented by Preflight!");
        }
    }
    pipeline.add_stage(Box::new(SpawnShouldNotBeReached));

    let mut ctx = PipelineContext::new(123);
    let mut spec = CommandSpec::default();
    spec.program = Path::new("/nonexistent/exe/that/fails/preflight").to_path_buf();
    ctx.command_spec = Some(spec);

    let result = pipeline.run(&mut ctx).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.stage_name, "Preflight");
}

#[tokio::test]
async fn test_spawn_process_failure_diagnostics() {
    use steamflow::launch::pipeline::{LaunchPipeline, PipelineContext, LaunchErrorKind};
    use steamflow::launch::stages::spawn_process::SpawnProcessStage;
    use steamflow::infra::runners::CommandSpec;

    let mut pipeline = LaunchPipeline::new();
    pipeline.add_stage(Box::new(SpawnProcessStage));

    let mut ctx = PipelineContext::new(123);
    let mut spec = CommandSpec::default();
    // Use an absolute path that is guaranteed not to exist for a reliable NotFound error
    spec.program = std::path::Path::new("/bin/nonexistent_utility_123456789").to_path_buf();

    // We need a dummy runner that will actually try to launch
    struct FailingRunner;
    #[async_trait::async_trait]
    impl steamflow::infra::runners::Runner for FailingRunner {
        fn name(&self) -> &str { "FailingRunner" }
        async fn prepare_prefix(&self, _: &steamflow::infra::runners::LaunchContext) -> Result<(), steamflow::launch::pipeline::LaunchError> { Ok(()) }
        async fn build_env(&self, _: &steamflow::infra::runners::LaunchContext) -> Result<std::collections::HashMap<String, String>, steamflow::launch::pipeline::LaunchError> { Ok(std::collections::HashMap::new()) }
        async fn build_command(&self, _: &steamflow::infra::runners::LaunchContext) -> Result<CommandSpec, steamflow::launch::pipeline::LaunchError> { Ok(CommandSpec::default()) }
        fn launch(&self, spec: &CommandSpec) -> Result<std::process::Child, steamflow::launch::pipeline::LaunchError> {
            let res = std::process::Command::new(&spec.program).spawn();
            match res {
                Ok(child) => Ok(child),
                Err(e) => Err(steamflow::launch::pipeline::LaunchError::new(LaunchErrorKind::Process, "spawn failed").with_source(anyhow::anyhow!(e))),
            }
        }
    }

    ctx.runner = Some(Box::new(FailingRunner));
    ctx.command_spec = Some(spec);

    let result = pipeline.run(&mut ctx).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.stage_name, "SpawnProcess");
    assert_eq!(err.inner.kind, LaunchErrorKind::GameData); // NotFound maps to GameData
    assert!(err.inner.message.contains("not found"));
    assert_eq!(err.inner.context.get("io_kind").unwrap(), "NotFound");
}
