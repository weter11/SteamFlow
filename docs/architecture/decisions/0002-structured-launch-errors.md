# ADR 0002: Structured Stage Error Model for Launch Pipeline

## Status
Accepted

## Context
As the game launch process became more complex with the introduction of a staged pipeline and runner abstraction (see ADR 0001), it became difficult to diagnose failures. Errors were often opaque `anyhow::Error` strings that didn't clearly indicate which stage failed or whether the issue was a validation error, a permission issue, or a process crash.

To improve diagnostics and enable actionable user remediation, we need a structured error model.

## Decision
We will introduce a `LaunchError` model that categorizes failures and attaches machine-readable context.

### Key Components:
1.  **`LaunchErrorKind` Enum**: Categorizes errors into broad buckets:
    *   `Validation`: Missing input data or context.
    *   `Environment`: System configuration issues (e.g., missing Proton).
    *   `Permission`: Filesystem access issues.
    *   `Runner`: Failure within a specific `Runner` implementation.
    *   `GameData`: Missing app manifests or executables.
    *   `Process`: Failure to spawn or manage child processes.
    *   `Dependency`: Missing external tools (e.g., MangoHud).
2.  **`LaunchError` Struct**: Carries the kind, a human-readable message, an optional `anyhow` source, and a metadata map for machine-readable context.
3.  **`PipelineError` Struct**: Wraps `LaunchError` with the `stage_name` that emitted it.
4.  **Error Normalization**: All pipeline stages and runners must return `LaunchError`. A mapping helper `map_anyhow_error` is provided to convert generic errors into categorized `LaunchError` instances.

### Logging Impact:
The `LaunchPipeline` execution loop and `EventLogger` will now include `error_kind` and `error_ctx_*` fields in the JSONL event logs.

## Consequences
*   **Improved Observability**: Logs now contain structured data that can be queried to find common failure patterns.
*   **Actionable UI**: The UI can now display stage-specific remediation hints based on the `LaunchErrorKind`.
*   **Strict Typing**: Stage implementations must now explicitly wrap or map their errors, which increases code quality but requires more boilerplate.
