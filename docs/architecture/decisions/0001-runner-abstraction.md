# ADR 0001: Runner Abstraction

## Status
Proposed (Day 1 Scaffolding)

## Context
The current launch logic is tightly coupled with specific runner implementations (like Master Steam or Proton). As we support more runners (e.g., Wine-TKG, vanilla Wine, different Proton flavors), we need a clean abstraction to decouple the launch pipeline from the specifics of how a runner prepares the environment and starts the process.

## Decision
Introduce a `Runner` trait that defines the interface for all game runners.
- `LaunchContext`: Carries information about the game being launched.
- `CommandSpec`: Describes the final command to be executed.
- `Runner` trait methods:
  - `prepare_prefix`: Sets up the WINEPREFIX or any necessary filesystem state.
  - `build_env`: Gathers all environment variables required for the launch.
  - `build_command`: Constructs the final `CommandSpec`.
  - `launch`: Executes the command.

## Non-Goals for Day 1
- Full migration of existing launch paths.
- Complete implementation of `WineTkgRunner`.
- Changes to runtime behavior.

## Planned Day 2 Integration
- Refactor the launch pipeline to use the `Runner` trait.
- Implement full logic for `WineTkgRunner`.
- Support dynamic runner selection based on configuration.
