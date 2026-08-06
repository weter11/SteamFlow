# AGENTS.md

## Project overview

SteamFlow is a Linux-first Steam client and launcher written in Rust. The
application uses `steam-vent` for Steam protocol communication, `egui`/`eframe`
for the native UI, and Proton/Wine integration for game launching.

## Repository layout

- `src/main.rs` — application entry point and startup sequence.
- `src/lib.rs` — public module declarations.
- `src/steam_client.rs` — Steam authentication, sessions, and API operations.
- `src/library.rs`, `src/models.rs` — game library and shared data models.
- `src/launch/` — staged game-launch pipeline, validation, fixups, and diagnostics.
- `src/infra/` — runners, logging, and other infrastructure.
- `src/ui.rs` — `egui` application and user interface.
- `tests/` — integration tests.
- `docs/` — architecture decisions and reverse-engineering notes.
- `vendor/steam-cdn/` — vendored and patched `steam-cdn` dependency.
- `Assets/` and `assets/` — application artwork and other static assets.

## Development commands

Run commands from the repository root:

```bash
# Check formatting
cargo fmt --all -- --check

# Run the full test suite
cargo test --all-targets

# Run static analysis
cargo clippy --all-targets --all-features -- -D warnings

# Build the application
cargo build

# Build the release binary
cargo build --release
```

The CI workflow builds on Ubuntu 24.04 and packages a Debian artifact with
`cargo deb`. Linux development requires the system libraries listed in the
README, including X11, Wayland, GTK, PulseAudio, OpenSSL, and XZ/LZMA
development packages.

## Testing guidance

- Add unit tests next to the module they cover when testing internal behavior.
- Add integration tests under `tests/` when validating behavior across modules.
- Keep tests deterministic and avoid requiring a running Steam client or a
  user-specific installation unless the test explicitly targets discovery or
  launch integration.
- Run focused tests during iteration, then run `cargo test --all-targets`
  before submitting changes.

## Code conventions

- Follow idiomatic Rust and the existing formatting produced by `rustfmt`.
- Use the existing `anyhow`, `tracing`, `serde`, and Tokio patterns rather than
  introducing new dependencies for common concerns.
- Preserve the staged launch pipeline and keep validation, resolution, process
  spawning, and finalization responsibilities in their existing layers.
- Propagate errors with the project's existing `Result`/`anyhow` conventions;
  add useful context at I/O and process boundaries.
- Use structured `tracing` logs for operational diagnostics instead of ad hoc
  output.
- Keep user-facing UI changes in `src/ui.rs` unless a feature-specific module
  already owns the relevant behavior.

## Dependency and generated-file guidance

- Update `Cargo.toml` and the root `Cargo.lock` together when changing
  dependencies.
- Treat `vendor/steam-cdn` as a deliberate local patch; do not replace it with
  an upstream dependency without checking compatibility.
- Do not commit build output, local Steam configuration, session data, or
  credentials.
- Avoid changing generated or vendored files unless the task specifically
  requires it.

## Change workflow

- Keep changes focused and update relevant documentation when behavior or
  architecture changes.
- Before submitting a pull request, run formatting, tests, Clippy, and a
  release build when the change affects production code.
- Describe behavior changes and test coverage clearly in the pull request.
