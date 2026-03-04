pub mod resolve_game;
pub mod resolve_profile;
pub mod resolve_components;
pub mod prepare_prefix;
pub mod build_environment;
pub mod build_command;
pub mod spawn_process;
pub mod finalize;

pub use resolve_game::ResolveGameStage;
pub use resolve_profile::ResolveProfileStage;
pub use resolve_components::ResolveComponentsStage;
pub use prepare_prefix::PreparePrefixStage;
pub use build_environment::BuildEnvironmentStage;
pub use build_command::BuildCommandStage;
pub use spawn_process::SpawnProcessStage;
pub use finalize::FinalizeStage;
