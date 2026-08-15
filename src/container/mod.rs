//! Steam Linux Runtime container infrastructure (Phase 4.2 — `OnlineContainerized`).
//!
//! Building blocks for launching games inside Valve's official Steam Linux
//! Runtime (SLR) containers:
//!
//! - [`runtime`] — `RuntimeManager`: provisions SLR images (the `steamrt4`
//!   line, codename *sniper*, and its siblings) into
//!   `~/.local/share/SteamFlow/runtimes/<id>/`, verifies archive integrity
//!   (SHA256 and/or detached GPG signatures), extracts the runtime image,
//!   and parses `VERSIONS.txt` + per-component `manifest.json` files into a
//!   [`runtime::RuntimeDeploymentState`] the application can display and act on.
//! - [`pressure_vessel`] — a native Rust builder that programmatically
//!   constructs `pressure-vessel-wrap` / `bwrap` execution command lines:
//!   host Vulkan ICD / EGL vendor pass-through, `/dev/dri` + `/dev/nvidia*`
//!   device nodes, display sockets (Wayland / X11), user audio sockets
//!   (PulseAudio / PipeWire), and read-write mounts for game installs and
//!   per-game `compatdata` prefixes.

pub mod pressure_vessel;
pub mod runtime;
