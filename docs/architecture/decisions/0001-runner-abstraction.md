# ADR 0001: Runner Abstraction

## Status
Proposed (Scaffolding Phase)

## Context
The current game launch logic in `steam_client.rs` is monolithic and handles multiple responsibilities:
- Environment variable construction.
- WINEPREFIX preparation and Steam runtime cloning.
- Command-line argument assembly.
- Process spawning and monitoring.

As we add support for more runner types (e.g., Wine-tkg, different Proton versions, native containers), this logic becomes difficult to maintain and test.

## Decision
We will introduce a `Runner` trait to abstract the execution of games and tools. This allows for:
- Separation of concerns between the launcher UI/client and the execution backend.
- Easier unit testing of environment and command construction.
- Plugin-like support for different execution environments.

The abstraction consists of:
- `LaunchContext`: Captures all inputs required for a launch.
- `CommandSpec`: A platform-agnostic representation of the process to be spawned.
- `Runner` trait: Defines the lifecycle of a launch (prepare -> build env -> build command -> launch).

## Consequences
- **Positive:** Improved readability and maintainability of the launch path.
- **Positive:** Better testability of complex Wine/Proton environment logic.
- **Negative:** Initial overhead of refactoring existing logic into the new trait structure.
