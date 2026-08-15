//! Native Rust builder for `pressure-vessel-wrap` / `bwrap` commands
//! (Phase 4.2 — `OnlineContainerized`, corrected in Phase 4.3).
//!
//! [`PressureVesselBuilder`] programmatically constructs the argv for
//! launching a game inside a Steam Linux Runtime container:
//!
//! - **Storage & prefixes** — game install directories and per-game prefixes
//!   (`…/steamapps/compatdata/<appid>/pfx/`) mounted read-write via
//!   `--filesystem=`.
//! - **Conditional environment** — `--env-if-host=NAME=VALUE` flags so a host
//!   var is only applied when the container runs with the host `/usr`.
//!
//! Two command flavors are supported:
//!
//! - [`CommandKind::PressureVesselWrap`] — Valve's official launcher, invoked
//!   through the runtime's `run` entry point (which selects the runtime via
//!   `PRESSURE_VESSEL_RUNTIME*` env and execs `pressure-vessel-unruntime`):
//!   `pressure-vessel-wrap --filesystem=… --env-if-host=… -- <program> <args>`.
//!   GPU/display/audio pass-through is automatic (graphics provider + shared
//!   home/runtime dir), and forced env vars are carried on the process
//!   environment (`CommandSpec.env`) — the real `pressure-vessel-wrap` CLI has
//!   no `--runtime-path`/`--runtime-version`/`--device`/`--bind-mount`/`--env`
//!   flag.
//! - [`CommandKind::Bwrap`] — the underlying `bubblewrap` engine, for
//!   environments where pressure-vessel is not available:
//!   `bwrap --unshare-all --ro-bind / / --dev-bind … --setenv … -- <program>`.
//!   bwrap DOES have `--bind`/`--ro-bind`/`--dev-bind`/`--setenv`, so the
//!   explicit mounts and forced env are emitted for this flavor.

use std::path::{Path, PathBuf};

/// Which container engine the builder emits argv for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CommandKind {
    /// Valve's `pressure-vessel-wrap` (the Steam Linux Runtime launcher).
    #[default]
    PressureVesselWrap,
    /// `bubblewrap` directly (no pressure-vessel layer).
    Bwrap,
}

/// Whether a path refers to a unix socket (portable across stable Rust —
/// `Path::is_socket` is not yet stable).
fn is_socket(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    path.metadata()
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false)
}

/// The audio service whose socket is being passed through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioBackend {
    /// PulseAudio (or PipeWire's pulse-compat socket).
    PulseAudio,
    /// Native PipeWire.
    PipeWire,
}

/// A detected user audio socket on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioSocket {
    pub backend: AudioBackend,
    /// Host path of the socket (also used as the container path).
    pub socket: PathBuf,
}

/// Host resource discovery for container pass-through.
///
/// Construction with [`HostResourceDetector::detect`] reads the real system
/// (env vars, `/dev`, `/usr/share`, `/run/user`). Tests construct the struct
/// directly with temp dirs so detection logic stays deterministic.
#[derive(Debug, Clone)]
pub struct HostResourceDetector {
    /// Directories scanned for `*.json` Vulkan ICD manifests.
    pub vulkan_icd_dirs: Vec<PathBuf>,
    /// Directories scanned for `*.json` EGL vendor manifests.
    pub egl_vendor_dirs: Vec<PathBuf>,
    /// Root of device nodes (default `/dev`; overridable for tests).
    pub device_root: PathBuf,
    /// X11 socket directory (default `/tmp/.X11-unix`).
    pub x11_unix_dir: PathBuf,
    /// Per-user runtime dir (default `$XDG_RUNTIME_DIR` or `/run/user/<uid>`).
    pub runtime_dir: PathBuf,
    /// User home directory.
    pub home: PathBuf,
    /// Numeric uid of the invoking user.
    pub uid: u32,
    /// Host `WAYLAND_DISPLAY` value, if set.
    pub wayland_display: Option<String>,
    /// Host `DISPLAY` value, if set.
    pub display: Option<String>,
}

impl HostResourceDetector {
    /// Detect host resources from the current process environment.
    pub fn detect() -> Self {
        let uid = unsafe { libc::getuid() };
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/"));
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(format!("/run/user/{uid}")));
        Self {
            vulkan_icd_dirs: vec![
                PathBuf::from("/usr/share/vulkan/icd.d"),
                PathBuf::from("/etc/vulkan/icd.d"),
                home.join(".local/share/vulkan/icd.d"),
            ],
            egl_vendor_dirs: vec![
                PathBuf::from("/usr/share/glvnd/egl_vendor.d"),
                PathBuf::from("/etc/glvnd/egl_vendor.d"),
            ],
            device_root: PathBuf::from("/dev"),
            x11_unix_dir: PathBuf::from("/tmp/.X11-unix"),
            runtime_dir,
            home,
            uid,
            wayland_display: std::env::var("WAYLAND_DISPLAY").ok(),
            display: std::env::var("DISPLAY").ok(),
        }
    }

    /// Vulkan ICD manifest dirs that actually exist, in priority order.
    pub fn vulkan_icds(&self) -> Vec<PathBuf> {
        self.vulkan_icd_dirs
            .iter()
            .filter(|d| d.is_dir())
            .cloned()
            .collect()
    }

    /// EGL vendor manifest dirs that actually exist.
    pub fn egl_vendors(&self) -> Vec<PathBuf> {
        self.egl_vendor_dirs
            .iter()
            .filter(|d| d.is_dir())
            .cloned()
            .collect()
    }

    /// `/dev/dri` (bound as a unit) if it exists.
    pub fn dri_devices(&self) -> Vec<PathBuf> {
        let dri = self.device_root.join("dri");
        if dri.is_dir() {
            vec![dri]
        } else {
            Vec::new()
        }
    }

    /// Every `/dev/nvidia*` entry (nodes plus the `nvidia-caps` dir).
    pub fn nvidia_devices(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.device_root) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().starts_with("nvidia") {
                    out.push(entry.path());
                }
            }
        }
        out
    }

    /// The Wayland socket path, if `WAYLAND_DISPLAY` is set and the socket
    /// exists in the runtime dir.
    pub fn wayland_socket(&self) -> Option<PathBuf> {
        let name = self.wayland_display.as_ref()?;
        if name.starts_with('/') {
            let p = PathBuf::from(name);
            return is_socket(&p).then_some(p);
        }
        let p = self.runtime_dir.join(name);
        is_socket(&p).then_some(p)
    }

    /// The X11 socket directory, if it exists.
    pub fn x11_sockets(&self) -> Option<PathBuf> {
        self.x11_unix_dir
            .is_dir()
            .then_some(self.x11_unix_dir.clone())
    }

    /// The active user audio socket: `pulse/native` wins (PipeWire's
    /// pulse-compat socket speaks the pulse protocol, which is what most
    /// games use), otherwise the native PipeWire socket.
    pub fn audio_socket(&self) -> Option<AudioSocket> {
        let pulse = self.runtime_dir.join("pulse").join("native");
        if is_socket(&pulse) {
            return Some(AudioSocket {
                backend: AudioBackend::PulseAudio,
                socket: pulse,
            });
        }
        let pipewire = self.runtime_dir.join("pipewire-0");
        if is_socket(&pipewire) {
            return Some(AudioSocket {
                backend: AudioBackend::PipeWire,
                socket: pipewire,
            });
        }
        None
    }
}

/// Programmatic builder for container launch command lines.
#[derive(Debug, Clone, Default)]
pub struct PressureVesselBuilder {
    kind: CommandKind,
    filesystem_rw: Vec<PathBuf>,
    filesystem_ro: Vec<PathBuf>,
    bind_mounts: Vec<(PathBuf, PathBuf)>,
    devices: Vec<PathBuf>,
    env_if_host: Vec<(String, String)>,
    env_forced: Vec<(String, String)>,
    program: Option<PathBuf>,
    program_args: Vec<String>,
}

impl PressureVesselBuilder {
    /// A new builder for the given engine flavor.
    pub fn new(kind: CommandKind) -> Self {
        Self {
            kind,
            ..Default::default()
        }
    }

    /// Expose a host path read-write inside the container
    /// (`--filesystem=<path>` / `--bind <path> <path>`).
    pub fn filesystem(&mut self, path: PathBuf) -> &mut Self {
        self.filesystem_rw.push(path);
        self
    }

    /// Expose a host path read-only (`--filesystem-ro=<path>` /
    /// `--ro-bind <path> <path>`).
    pub fn filesystem_ro(&mut self, path: PathBuf) -> &mut Self {
        self.filesystem_ro.push(path);
        self
    }

    /// Bind-mount `host` at `container` (`--bind-mount=host:container` /
    /// `--bind host container`).
    pub fn bind_mount(&mut self, host: PathBuf, container: PathBuf) -> &mut Self {
        self.bind_mounts.push((host, container));
        self
    }

    /// Expose a device node (`--device=<path>` / `--dev-bind <path> <path>`).
    pub fn device(&mut self, path: PathBuf) -> &mut Self {
        self.devices.push(path);
        self
    }

    /// Pass a host env var through **only if it is set on the host**
    /// (`--env-if-host=NAME=VALUE`).
    pub fn env_if_host(&mut self, name: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.env_if_host.push((name.into(), value.into()));
        self
    }

    /// Force an env var inside the container regardless of the host
    /// (`--env=NAME=VALUE`).
    pub fn env(&mut self, name: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.env_forced.push((name.into(), value.into()));
        self
    }

    /// The program and arguments to run inside the container.
    pub fn command(&mut self, program: PathBuf, args: Vec<String>) -> &mut Self {
        self.program = Some(program);
        self.program_args = args;
        self
    }

    /// Wire everything [`HostResourceDetector`] found on the host into this
    /// builder in one call: Vulkan/EGL dirs read-only, `/dev/dri` +
    /// `/dev/nvidia*` devices, X11/Wayland display sockets, audio socket,
    /// and the display/runtime env vars.
    pub fn apply_host_resources(&mut self, detector: &HostResourceDetector) -> &mut Self {
        for dir in detector.vulkan_icds() {
            self.filesystem_ro(dir);
        }
        for dir in detector.egl_vendors() {
            self.filesystem_ro(dir);
        }
        for dev in detector.dri_devices() {
            self.device(dev);
        }
        for dev in detector.nvidia_devices() {
            self.device(dev);
        }
        if let Some(x11) = detector.x11_sockets() {
            self.filesystem(x11);
        }
        if let Some(display) = &detector.display {
            self.env_if_host("DISPLAY", display.clone());
        }
        if let Some(socket) = detector.wayland_socket() {
            self.bind_mount(socket.clone(), socket);
        }
        if let Some(name) = &detector.wayland_display {
            self.env_if_host("WAYLAND_DISPLAY", name.clone());
        }
        self.env(
            "XDG_RUNTIME_DIR",
            detector.runtime_dir.to_string_lossy().to_string(),
        );
        if let Some(audio) = detector.audio_socket() {
            let path = audio.socket.display().to_string();
            self.bind_mount(audio.socket.clone(), audio.socket);
            match audio.backend {
                AudioBackend::PulseAudio => {
                    self.env("PULSE_SERVER", format!("unix:{path}"));
                }
                AudioBackend::PipeWire => {
                    self.env("PIPEWIRE_RUNTIME_DIR", path.clone());
                }
            }
        }
        self
    }

    /// Assemble the full argv (including the program), ready for
    /// `std::process::Command`.
    pub fn build(&self) -> anyhow::Result<Vec<String>> {
        let program = self
            .program
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no program set — call .command() first"))?;
        match self.kind {
            CommandKind::PressureVesselWrap => self.build_pressure_vessel(program),
            CommandKind::Bwrap => self.build_bwrap(program),
        }
    }

    fn build_pressure_vessel(&self, program: &Path) -> anyhow::Result<Vec<String>> {
        // argv[0] is a placeholder ("pressure-vessel-wrap") — the caller
        // replaces it with the resolved engine path (the runtime's `run`
        // entry point, or a bundled/host `pressure-vessel-wrap`). The real
        // `pressure-vessel-wrap` CLI accepts only: `--filesystem` (rw),
        // `--env-if-host` (conditional env), and `--` COMMAND. There is NO
        // `--runtime-path`/`--runtime-version`/`--runtime-arch`/`--launcher`/
        // `--game-pid`/`--env`/`--bind-mount`/`--device`/`--filesystem-ro`
        // flag — runtime selection is done by the runtime's `run` entry point
        // (via `PRESSURE_VESSEL_RUNTIME*` env), GPU/display/audio pass-through
        // is automatic (graphics provider + shared home/runtime dir), and
        // forced env vars are carried on the process environment
        // (`CommandSpec.env`), which pressure-vessel forwards.
        let mut argv = vec!["pressure-vessel-wrap".to_string()];
        for path in &self.filesystem_rw {
            argv.push(format!("--filesystem={}", path.display()));
        }
        for (name, value) in &self.env_if_host {
            argv.push(format!("--env-if-host={name}={value}"));
        }
        argv.push("--".to_string());
        argv.push(program.display().to_string());
        argv.extend(self.program_args.iter().cloned());
        Ok(argv)
    }

    fn build_bwrap(&self, program: &Path) -> anyhow::Result<Vec<String>> {
        let mut argv = vec!["bwrap".to_string()];
        argv.extend(
            [
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--tmpfs",
                "/tmp",
            ]
            .map(str::to_string),
        );
        for path in &self.filesystem_rw {
            argv.push("--bind".to_string());
            argv.push(path.display().to_string());
            argv.push(path.display().to_string());
        }
        for path in &self.filesystem_ro {
            argv.push("--ro-bind".to_string());
            argv.push(path.display().to_string());
            argv.push(path.display().to_string());
        }
        for (host, container) in &self.bind_mounts {
            argv.push("--bind".to_string());
            argv.push(host.display().to_string());
            argv.push(container.display().to_string());
        }
        for dev in &self.devices {
            argv.push("--dev-bind".to_string());
            argv.push(dev.display().to_string());
            argv.push(dev.display().to_string());
        }
        for (name, value) in &self.env_if_host {
            // bubblewrap has no conditional env flag — only forward the var
            // when it is actually set on the host.
            if std::env::var(name).is_ok() {
                argv.push("--setenv".to_string());
                argv.push(name.clone());
                argv.push(value.clone());
            }
        }
        for (name, value) in &self.env_forced {
            argv.push("--setenv".to_string());
            argv.push(name.clone());
            argv.push(value.clone());
        }
        argv.push(program.display().to_string());
        argv.extend(self.program_args.iter().cloned());
        Ok(argv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// A fake host environment: temp dirs stand in for /usr/share,
    /// /dev, /run/user, /tmp/.X11-unix and the game/prefix paths.
    fn fake_detector(
        dir: &std::path::Path,
        with_pulse: bool,
        with_wayland: bool,
    ) -> HostResourceDetector {
        // Create a real unix socket file (S_IFSOCK) at `path`; dropping the
        // listener leaves the socket file in place, which is what the
        // detector checks.
        fn bind_socket(path: &std::path::Path) {
            let _listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        }

        let vulkan = dir.join("usr/share/vulkan/icd.d");
        let egl = dir.join("usr/share/glvnd/egl_vendor.d");
        let dev = dir.join("dev");
        let x11 = dir.join("tmp/.X11-unix");
        let runtime = dir.join("run/user/1000");
        std::fs::create_dir_all(&vulkan).unwrap();
        std::fs::create_dir_all(&egl).unwrap();
        std::fs::create_dir_all(dev.join("dri")).unwrap();
        std::fs::create_dir_all(&x11).unwrap();
        std::fs::create_dir_all(&runtime).unwrap();
        // Fake host artifacts.
        std::fs::write(vulkan.join("nvidia_icd.json"), "{}").unwrap();
        std::fs::write(egl.join("nvidia.json"), "{}").unwrap();
        std::fs::write(dev.join("dri/card0"), "").unwrap();
        std::fs::write(dev.join("nvidia0"), "").unwrap();
        std::fs::write(dev.join("nvidiactl"), "").unwrap();
        std::fs::write(x11.join("X0"), "").unwrap();
        if with_pulse {
            std::fs::create_dir_all(runtime.join("pulse")).unwrap();
            bind_socket(&runtime.join("pulse/native"));
        } else {
            bind_socket(&runtime.join("pipewire-0"));
        }
        if with_wayland {
            bind_socket(&runtime.join("wayland-1"));
        }
        HostResourceDetector {
            vulkan_icd_dirs: vec![vulkan.clone(), dir.join("etc/vulkan/icd.d")],
            egl_vendor_dirs: vec![egl.clone()],
            device_root: dev,
            x11_unix_dir: x11,
            runtime_dir: runtime,
            home: dir.to_path_buf(),
            uid: 1000,
            wayland_display: with_wayland.then(|| "wayland-1".to_string()),
            display: Some(":0".to_string()),
        }
    }

    #[test]
    fn test_host_resource_detection() {
        let dir = tempdir().unwrap();
        let d = fake_detector(dir.path(), true, true);

        // Vulkan/EGL dirs exist; the missing /etc one is filtered out.
        assert_eq!(d.vulkan_icds().len(), 1);
        assert!(d.vulkan_icds()[0].ends_with("vulkan/icd.d"));
        assert_eq!(d.egl_vendors().len(), 1);

        // Devices: /dev/dri unit + nvidia nodes.
        assert_eq!(d.dri_devices().len(), 1);
        let nvidia = d.nvidia_devices();
        assert_eq!(nvidia.len(), 2);
        assert!(nvidia
            .iter()
            .all(|p| p.to_string_lossy().contains("nvidia")));

        // Display sockets.
        assert!(d.x11_sockets().is_some());
        let wayland = d.wayland_socket().unwrap();
        assert!(wayland.ends_with("run/user/1000/wayland-1"));

        // Audio: pulse wins over pipewire when both exist.
        let audio = d.audio_socket().unwrap();
        assert_eq!(audio.backend, AudioBackend::PulseAudio);
        assert!(audio.socket.ends_with("pulse/native"));

        // PipeWire fallback (separate root so the pulse socket from the
        // first scenario does not leak into this one).
        let d2 = fake_detector(&dir.path().join("scn2"), false, false);
        let audio = d2.audio_socket().unwrap();
        assert_eq!(audio.backend, AudioBackend::PipeWire);
        assert!(audio.socket.ends_with("pipewire-0"));

        // No audio sockets at all.
        let mut d3 = fake_detector(&dir.path().join("scn3"), false, false);
        std::fs::remove_file(d3.runtime_dir.join("pipewire-0")).unwrap();
        d3.x11_unix_dir = dir.path().join("scn3/no-x11");
        assert_eq!(d3.audio_socket(), None);
        assert_eq!(d3.wayland_socket(), None);
        assert_eq!(d3.x11_sockets(), None);
    }

    #[test]
    fn test_pressure_vessel_command_builder() {
        let dir = tempdir().unwrap();
        let detector = fake_detector(dir.path(), true, true);
        let prefix = dir.path().join("steamapps/compatdata/620/pfx");
        let install = dir.path().join("steamapps/common/Portal 2");
        std::fs::create_dir_all(&prefix).unwrap();
        std::fs::create_dir_all(&install).unwrap();

        let mut builder = PressureVesselBuilder::new(CommandKind::PressureVesselWrap);
        builder
            .apply_host_resources(&detector)
            .filesystem(install.clone())
            .filesystem(prefix.clone())
            .command(
                PathBuf::from("/usr/bin/portal2_linux"),
                vec!["-novid".into()],
            );

        let argv = builder.build().unwrap();
        assert_eq!(argv[0], "pressure-vessel-wrap");

        // The real `pressure-vessel-wrap` CLI accepts only `--filesystem` (rw)
        // and `--env-if-host`, then a single `--` before the command. Runtime
        // selection, GPU/display/audio pass-through, and forced env are handled
        // by the runtime `run` entry point, the graphics provider, and the
        // process environment respectively — so no `--runtime*`/`--device`/
        // `--bind-mount`/`--env`/`--filesystem-ro` flags are emitted.
        let sep = argv
            .iter()
            .position(|a| a == "--")
            .expect("single `--` separator");
        let options = &argv[..sep];

        // RW mounts: game install + prefix + the X11 socket dir (from
        // apply_host_resources).
        assert!(options.contains(&format!("--filesystem={}", install.display())));
        assert!(options.contains(&format!("--filesystem={}", prefix.display())));
        assert!(options.contains(&format!("--filesystem={}", detector.x11_unix_dir.display())));
        // Conditional display env passthrough.
        assert!(options.iter().any(|a| a == "--env-if-host=DISPLAY=:0"));
        assert!(options
            .iter()
            .any(|a| a == "--env-if-host=WAYLAND_DISPLAY=wayland-1"));
        // No invented flags leak into the argv.
        for bad in [
            "--runtime",
            "--device=",
            "--bind-mount=",
            "--env=",
            "--filesystem-ro=",
        ] {
            assert!(
                !options.iter().any(|a| a.starts_with(bad)),
                "unexpected {bad} in {argv:?}"
            );
        }

        // Command section after the `--`.
        assert_eq!(argv[sep + 1], "/usr/bin/portal2_linux");
        assert_eq!(argv[sep + 2], "-novid");
        assert_eq!(argv.len(), sep + 3);

        // A builder without a program is a clear error, not a panic.
        let empty = PressureVesselBuilder::new(CommandKind::PressureVesselWrap);
        let err = empty.build().unwrap_err();
        assert!(err.to_string().contains("no program set"));
    }

    #[test]
    fn test_bwrap_command_builder() {
        let dir = tempdir().unwrap();
        let detector = fake_detector(dir.path(), true, false);
        let prefix = dir.path().join("steamapps/compatdata/620/pfx");
        std::fs::create_dir_all(&prefix).unwrap();

        let mut builder = PressureVesselBuilder::new(CommandKind::Bwrap);
        builder
            .apply_host_resources(&detector)
            .filesystem(prefix.clone())
            .env("STEAM_APPID", "620")
            .command(PathBuf::from("/bin/true"), vec![]);
        let argv = builder.build().unwrap();

        assert_eq!(argv[0], "bwrap");
        // Base isolation flags.
        assert!(argv.iter().any(|a| a == "--unshare-all"));
        assert!(argv.iter().any(|a| a == "--die-with-parent"));
        assert!(argv.iter().any(|a| a == "--ro-bind"));
        // Device nodes map to --dev-bind with host:container pairs.
        let dri = detector.device_root.join("dri");
        let pos = argv.iter().position(|a| a == "--dev-bind").unwrap();
        assert_eq!(argv[pos + 1], dri.display().to_string());
        assert_eq!(argv[pos + 2], dri.display().to_string());
        // RW prefix mount → --bind HOST CONT (search for the prefix bind
        // specifically — X11/audio binds also appear in the argv).
        let prefix_bind = argv
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == prefix.display().to_string())
            .unwrap();
        assert_eq!(argv[prefix_bind + 2], prefix.display().to_string());
        // Forced env → --setenv NAME VALUE (search for the specific pair —
        // host display env is also forwarded when the host has it set).
        let setenv_idx = argv
            .windows(3)
            .position(|w| w[0] == "--setenv" && w[1] == "STEAM_APPID")
            .unwrap();
        assert_eq!(argv[setenv_idx + 2], "620");
        // Program last.
        assert_eq!(argv.last().unwrap(), "/bin/true");
    }
}
