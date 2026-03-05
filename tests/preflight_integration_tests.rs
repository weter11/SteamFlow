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
