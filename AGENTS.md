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
- `vendor/steam-vent/` — vendored `steam-vent` 0.6.0 dependency (see below).
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
- Treat `vendor/steam-vent` the same way: it is a deliberate local vendoring of
  a third-party tree, not code we own.
- Do not commit build output, local Steam configuration, session data, or
  credentials.
- Avoid changing generated or vendored files unless the task specifically
  requires it.

## Vendored `steam-vent`

`vendor/steam-vent/` is upstream steam-vent 0.6.0 plus PR #19, committed as a
`git archive` of revision `54ecd10ebd385c6879a536725fd77cdb846fc9a3`. The
revision is recorded in `vendor/steam-vent/STEAMVENT_REV`.

It is vendored rather than depended on because PR #19 is still open upstream, so
that commit exists only as `refs/pull/19/head`. Cargo's git fetcher requests
`refs/heads/<sha>`, which does not exist for an unadvertised pull-request ref,
so a `rev = "<sha>"` git dependency fails to resolve. Publishing a mirror of a
third-party project was the alternative and was rejected.

Notes for anyone editing near this tree:

- It is third-party code, including its own `examples/`, `.gitignore` and
  `.forgejo/` CI config. Do not "fix" or tidy those files.
- Because it ships its own `.gitignore`, a `git add` inside `vendor/steam-vent`
  obeys *steam-vent's* rules, not this repository's.
- `tests/steam_vent_git_pin.rs` asserts the recorded revision matches and that
  the source contains PR #19's change. A re-vendor that drifts fails the build.

To refresh to a newer revision, archive from a clone of upstream steam-vent
(the vendored copy is not a git repository, so `git archive` cannot run here):

```bash
git clone https://codeberg.org/steam-vent/steam-vent /tmp/steam-vent
git -C /tmp/steam-vent fetch origin 'refs/pull/19/head:refs/pr19'
git -C /tmp/steam-vent archive <new-rev> | tar -x -C vendor/steam-vent
echo <new-rev> > vendor/steam-vent/STEAMVENT_REV
# update the expected revision in tests/steam_vent_git_pin.rs
```

`cargo test --test steam_vent_git_pin` then verifies the recorded revision and
the vendored source agree.

Once upstream merges PR #19 this can collapse back to a published version.

## Change workflow

- Keep changes focused and update relevant documentation when behavior or
  architecture changes.
- Before submitting a pull request, run formatting, tests, Clippy, and a
  release build when the change affects production code.
- Describe behavior changes and test coverage clearly in the pull request.
