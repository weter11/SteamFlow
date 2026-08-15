//! Containerized launch orchestration (Phase 4.3 — `OnlineContainerized`).
//!
//! [`ContainerizedLaunch`] turns the already-resolved inputs of a game launch
//! into a `pressure-vessel-wrap` (via the runtime's `run` entry point) or
//! `bwrap` command that boots the game inside the Steam Linux Runtime
//! container:
//!
//! - the **pure-PE Proton** runner is the compatibility tool inside the
//!   container (`<proton>/proton run <game.exe> …`),
//! - the game install directory and the per-game prefix
//!   (`…/compatdata/<appid>/pfx/`) are mounted read-write,
//! - host GPU / display / audio resources are passed through via
//!   [`PressureVesselBuilder::apply_host_resources`] (automatic for
//!   pressure-vessel; explicit `--bind`/`--dev-bind`/`--setenv` for bwrap),
//! - the full game environment (incl. the `lsteamclient.dll` IPC bridge
//!   wiring) is carried on the process environment (`CommandSpec.env`), which
//!   the runtime's `run` script forwards into the container.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::pressure_vessel::{CommandKind, HostResourceDetector, PressureVesselBuilder};
use crate::infra::runners::CommandSpec;

/// Resolved inputs for one containerized launch, produced by the runner.
#[derive(Debug, Clone)]
pub struct ContainerizedLaunch {
    /// Proton runner root (the compatibility tool that runs in the container).
    pub proton_runner: PathBuf,
    /// Absolute path of the game executable on the host.
    pub game_exe: PathBuf,
    /// Game install directory (mounted read-write).
    pub install_dir: PathBuf,
    /// Per-game prefix `…/compatdata/<appid>/pfx/` (mounted read-write).
    pub prefix: PathBuf,
    /// Extra game launch args (manifest/fixup/user options), after the exe.
    pub launch_args: Vec<String>,
    /// The fully-resolved game environment (from the runner's `build_env`),
    /// including `STEAM_COMPAT_CLIENT_INSTALL_PATH`, `STEAM_COMPAT_DATA_PATH`
    /// and `WINEDLLOVERRIDES=lsteamclient=n,b`.
    pub env: HashMap<String, String>,
    /// Working directory for the game process.
    pub working_dir: PathBuf,
}

impl ContainerizedLaunch {
    /// Build the container `CommandSpec`. The container engine is resolved
    /// with the runtime tree first: the runtime's `run` entry point (the
    /// canonical Steam contract, which selects the runtime via
    /// `PRESSURE_VESSEL_RUNTIME*` env and execs `pressure-vessel-unruntime`),
    /// then a bundled/host `pressure-vessel-wrap`, then host `bwrap` as a
    /// degraded fallback.
    pub fn build_command_spec(&self, runtime_root: &Path) -> Result<CommandSpec> {
        let (kind, engine_path) = resolve_engine(runtime_root)?;
        let mut spec = self.build_command_spec_with_kind(kind)?;
        // Use the resolved absolute engine path so downstream preflight checks
        // (`spec.program.exists()`) and `Command::new()` find it regardless of
        // the working directory.
        spec.program = engine_path;
        Ok(spec)
    }

    /// Build the container `CommandSpec` with an explicit engine. Exposed for
    /// unit tests so the argv shape can be asserted without requiring
    /// `pressure-vessel-wrap` / `bwrap` on the test host.
    pub fn build_command_spec_with_kind(&self, kind: CommandKind) -> Result<CommandSpec> {
        let proton_script = self.proton_runner.join("proton");
        if !proton_script.is_file() {
            bail!(
                "Proton runner {} has no `proton` script — OnlineContainerized \
                 requires a Proton-kind compatibility tool (e.g. pure-PE Proton 11.0)",
                self.proton_runner.display()
            );
        }

        let mut builder = PressureVesselBuilder::new(kind);
        builder
            .filesystem(self.install_dir.clone())
            .filesystem(self.prefix.clone())
            .apply_host_resources(&HostResourceDetector::detect());

        // Force the full game environment into the container. For bwrap these
        // become `--setenv` flags (bwrap sanitizes the parent env); for
        // pressure-vessel they are carried on the process environment
        // (`CommandSpec.env`) and forwarded by the runtime's `run` script.
        for (name, value) in &self.env {
            builder.env(name.clone(), value.clone());
        }

        // Program = Proton's `proton` script; args = `run <exe> <launch_args>`.
        let mut program_args = vec![
            "run".to_string(),
            self.game_exe.to_string_lossy().to_string(),
        ];
        program_args.extend(self.launch_args.iter().cloned());
        builder.command(proton_script, program_args);

        let argv = builder
            .build()
            .with_context(|| format!("failed assembling {} command", command_kind_name(kind)))?;
        if argv.len() < 2 {
            bail!("container builder produced an empty command line");
        }

        let program = PathBuf::from(&argv[0]);
        let args = argv[1..].to_vec();
        Ok(CommandSpec {
            program,
            args,
            cwd: Some(self.working_dir.clone()),
            env: self.env.clone(),
        })
    }
}

/// Resolve the container engine to `(kind, absolute_path)`:
///   1. the runtime's `run` entry point (Steam's canonical contract — selects
///      the runtime and execs `pressure-vessel-unruntime`),
///   2. the runtime's `_v2-entry-point` (older SLR layouts),
///   3. the `pressure-vessel-wrap` bundled inside the runtime tree
///      (`pressure-vessel/bin/` or `files/bin/`),
///   4. a host `pressure-vessel-wrap` (steam-runtime-tools),
///   5. host `bwrap` (bubblewrap) as a degraded fallback.
///
/// Fails fast with remediation when none is available.
fn resolve_engine(runtime_root: &Path) -> Result<(CommandKind, PathBuf)> {
    // The `run` script is the canonical entry point: it sets
    // PRESSURE_VESSEL_RUNTIME/RUNTIME_BASE/COPY_RUNTIME/VARIABLE_DIR and execs
    // the runtime's own pressure-vessel-unruntime, so the SLR's merged /usr is
    // mounted correctly. `_v2-entry-point` is the older-SLR equivalent (empty
    // for some steamrt4 deployments, so check it is a non-empty file).
    for entry in ["run", "_v2-entry-point"] {
        let candidate = runtime_root.join(entry);
        if candidate.is_file() && candidate.metadata().map(|m| m.len() > 0).unwrap_or(false) {
            return Ok((CommandKind::PressureVesselWrap, candidate));
        }
    }
    for rel in [
        "pressure-vessel/bin/pressure-vessel-wrap",
        "files/bin/pressure-vessel-wrap",
    ] {
        let bundled = runtime_root.join(rel);
        if bundled.is_file() {
            return Ok((CommandKind::PressureVesselWrap, bundled));
        }
    }
    if let Some(p) = command_path("pressure-vessel-wrap") {
        return Ok((CommandKind::PressureVesselWrap, p));
    }
    if let Some(p) = command_path("bwrap") {
        return Ok((CommandKind::Bwrap, p));
    }
    bail!(
        "OnlineContainerized requires the Steam Linux Runtime's `run` entry \
         point, `pressure-vessel-wrap` (steam-runtime-tools), or `bwrap` \
         (bubblewrap) — none was found in the runtime tree nor on PATH"
    )
}

fn command_kind_name(kind: CommandKind) -> &'static str {
    match kind {
        CommandKind::PressureVesselWrap => "pressure-vessel-wrap",
        CommandKind::Bwrap => "bwrap",
    }
}

/// Resolve `bin` to its absolute path on the current `PATH`, if present.
fn command_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Build a fake Proton tree (`proton` script + a game exe) and assert the
    /// container argv shape for both engine flavors — no real pressure-vessel
    /// or bwrap needed since `build_command_spec_with_kind` is injected.
    fn fake_launch(dir: &Path) -> ContainerizedLaunch {
        let proton = dir.join("proton");
        fs::create_dir_all(&proton).unwrap();
        fs::write(proton.join("proton"), "#!/bin/sh\n").unwrap();

        let install = dir.join("steamapps/common/Portal 2");
        fs::create_dir_all(&install).unwrap();
        let exe = install.join("portal2.exe");
        fs::write(&exe, "dummy").unwrap();

        let prefix = dir.join("steamapps/compatdata/620/pfx");
        fs::create_dir_all(&prefix).unwrap();

        let mut env = HashMap::new();
        env.insert(
            "STEAM_COMPAT_CLIENT_INSTALL_PATH".to_string(),
            "/home/wer/.steam/steam".to_string(),
        );
        env.insert(
            "STEAM_COMPAT_DATA_PATH".to_string(),
            dir.join("steamapps/compatdata/620")
                .to_string_lossy()
                .to_string(),
        );
        env.insert(
            "WINEDLLOVERRIDES".to_string(),
            "lsteamclient=n,b;d3d11=n".to_string(),
        );

        ContainerizedLaunch {
            proton_runner: proton,
            game_exe: exe,
            install_dir: install,
            prefix,
            launch_args: vec!["-novid".to_string()],
            env,
            working_dir: dir.to_path_buf(),
        }
    }

    #[test]
    fn test_containerized_command_pressure_vessel_shape() {
        let dir = tempdir().unwrap();
        let launch = fake_launch(dir.path());

        let spec = launch
            .build_command_spec_with_kind(CommandKind::PressureVesselWrap)
            .unwrap();

        assert_eq!(spec.program, PathBuf::from("pressure-vessel-wrap"));
        let argv = {
            let mut v = vec![spec.program.to_string_lossy().to_string()];
            v.extend(spec.args.iter().cloned());
            v
        };

        // One `--` separator (the real pressure-vessel-wrap contract).
        assert_eq!(argv.iter().filter(|a| a.as_str() == "--").count(), 1);
        // Read-write mounts for the game dir and prefix.
        assert!(argv.iter().any(|a| {
            a.as_str() == format!("--filesystem={}", launch.install_dir.display()).as_str()
        }));
        assert!(argv.iter().any(|a| {
            a.as_str() == format!("--filesystem={}", launch.prefix.display()).as_str()
        }));
        // The lsteamclient bridge env is carried on the process env (not a
        // `--env=` flag, which pressure-vessel-wrap does not support).
        assert_eq!(
            spec.env.get("WINEDLLOVERRIDES").map(String::as_str),
            Some("lsteamclient=n,b;d3d11=n")
        );
        assert_eq!(
            spec.env
                .get("STEAM_COMPAT_CLIENT_INSTALL_PATH")
                .map(String::as_str),
            Some("/home/wer/.steam/steam")
        );
        // Tail = `--` + proton script + `run <exe> <args>`.
        let proton_script = launch.proton_runner.join("proton");
        let proton_str = proton_script.to_string_lossy().to_string();
        let exe_str = launch.game_exe.to_string_lossy().to_string();
        let pos = argv
            .iter()
            .position(|a| *a == proton_str)
            .expect("proton script must be the container program");
        let tail: Vec<&str> = argv[pos + 1..].iter().map(|s| s.as_str()).collect();
        assert_eq!(tail, vec!["run", exe_str.as_str(), "-novid"]);
        assert_eq!(argv.last().unwrap(), "-novid");
    }

    #[test]
    fn test_containerized_command_bwrap_shape() {
        let dir = tempdir().unwrap();
        let launch = fake_launch(dir.path());

        let spec = launch
            .build_command_spec_with_kind(CommandKind::Bwrap)
            .unwrap();

        assert_eq!(spec.program, PathBuf::from("bwrap"));
        let argv = {
            let mut v = vec![spec.program.to_string_lossy().to_string()];
            v.extend(spec.args.iter().cloned());
            v
        };
        assert!(argv.iter().any(|a| a == "--unshare-all"));
        assert!(argv.iter().any(|a| a == "--bind"));
        // bwrap has no `--env=`; forced env becomes `--setenv NAME VALUE`.
        assert!(argv
            .windows(3)
            .any(|w| w == ["--setenv", "WINEDLLOVERRIDES", "lsteamclient=n,b;d3d11=n"]));
    }

    #[test]
    fn test_containerized_command_requires_proton_script() {
        let dir = tempdir().unwrap();
        let mut launch = fake_launch(dir.path());
        // Break the proton tree: no `proton` script.
        fs::remove_file(launch.proton_runner.join("proton")).unwrap();
        launch.proton_runner = dir.path().join("plain-wine");

        let err = launch
            .build_command_spec_with_kind(CommandKind::PressureVesselWrap)
            .unwrap_err();
        assert!(format!("{err:#}").contains("no `proton` script"));
    }

    #[test]
    fn test_command_on_path_negative() {
        assert!(command_path("definitely-not-a-real-binary-xyz").is_none());
    }

    #[test]
    fn test_resolve_engine_prefers_runtime_entry_point_then_bundled_pv_wrap() {
        let dir = tempdir().unwrap();

        // A runtime with a `run` entry point is preferred (canonical Steam
        // contract). Even when a bundled pressure-vessel-wrap exists too.
        let rt = dir.path().join("rt");
        let run = rt.join("run");
        std::fs::create_dir_all(rt.join("pressure-vessel/bin")).unwrap();
        std::fs::write(&run, "#!/bin/sh\nexec pressure-vessel-unruntime \"$@\"\n").unwrap();
        let bundled = rt.join("pressure-vessel/bin/pressure-vessel-wrap");
        std::fs::write(&bundled, "#!/bin/sh\n").unwrap();

        let (kind, path) = resolve_engine(&rt).unwrap();
        assert_eq!(kind, CommandKind::PressureVesselWrap);
        assert_eq!(path, run, "`run` entry point must beat bundled pv-wrap");

        // A runtime without `run`/`_v2-entry-point` falls back to the bundled
        // pressure-vessel-wrap (`pressure-vessel/bin/` layout).
        let rt2 = dir.path().join("rt2");
        let bundled2 = rt2.join("pressure-vessel/bin/pressure-vessel-wrap");
        std::fs::create_dir_all(bundled2.parent().unwrap()).unwrap();
        std::fs::write(&bundled2, "#!/bin/sh\n").unwrap();
        let (kind2, path2) = resolve_engine(&rt2).unwrap();
        assert_eq!(kind2, CommandKind::PressureVesselWrap);
        assert_eq!(path2, bundled2);

        // `files/bin/pressure-vessel-wrap` layout is also accepted.
        let rt3 = dir.path().join("rt3");
        let alt = rt3.join("files/bin/pressure-vessel-wrap");
        std::fs::create_dir_all(alt.parent().unwrap()).unwrap();
        std::fs::write(&alt, "#!/bin/sh\n").unwrap();
        let (kind3, path3) = resolve_engine(&rt3).unwrap();
        assert_eq!(kind3, CommandKind::PressureVesselWrap);
        assert_eq!(path3, alt);
    }
}
