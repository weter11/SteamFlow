use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DllProvider {
    GameLocal,
    Runner,
    System,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllResolution {
    pub name: String,
    pub chosen_provider: DllProvider,
    pub chosen_path: Option<PathBuf>,
    pub candidates: Vec<DllCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllCandidate {
    pub provider: DllProvider,
    pub path: PathBuf,
    pub exists: bool,
}

pub struct DllProviderResolver {
    target_dlls: Vec<String>,
}

impl DllProviderResolver {
    pub fn new() -> Self {
        Self {
            target_dlls: vec![
                "d3d9".into(),
                "dxgi".into(),
                "d3d10".into(),
                "d3d10_1".into(),
                "d3d10core".into(),
                "d3d11".into(),
                "d3d12".into(),
                "d3d12core".into(),
            ],
        }
    }

    pub fn resolve(
        &self,
        game_exe_dir: &Path,
        runner_path: &Path,
        runner_components: &crate::utils::RunnerComponents,
    ) -> Vec<DllResolution> {
        self.target_dlls
            .iter()
            .map(|dll| self.resolve_single(dll, game_exe_dir, runner_path, runner_components))
            .collect()
    }

    fn resolve_single(
        &self,
        dll_name: &str,
        game_exe_dir: &Path,
        runner_path: &Path,
        runner_components: &crate::utils::RunnerComponents,
    ) -> DllResolution {
        let mut candidates = Vec::new();
        let dll_filename = format!("{}.dll", dll_name);

        // 1. GameLocal Priority
        let local_path = game_exe_dir.join(&dll_filename);
        candidates.push(DllCandidate {
            provider: DllProvider::GameLocal,
            path: local_path.clone(),
            exists: local_path.exists(),
        });

        // Also check 'bin' subdir common in some games
        let bin_path = game_exe_dir.join("bin").join(&dll_filename);
        candidates.push(DllCandidate {
            provider: DllProvider::GameLocal,
            path: bin_path.clone(),
            exists: bin_path.exists(),
        });

        // 2. Runner Priority
        if let Some(path) = self.get_runner_dll_path(dll_name, runner_path, runner_components) {
            candidates.push(DllCandidate {
                provider: DllProvider::Runner,
                path: path.clone(),
                exists: path.exists(),
            });
        }

        // 3. System Priority
        // For now, we use a simplified check for system paths
        let system_paths = match dll_name {
            "d3d11" | "dxgi" | "d3d9" | "d3d10" | "d3d10_1" | "d3d10core" => vec![
                "/usr/lib/dxvk/x64",
                "/usr/lib/x86_64-linux-gnu/dxvk",
            ],
            "d3d12" | "d3d12core" => vec![
                "/usr/lib/vkd3d-proton/x64",
                "/usr/lib/x86_64-linux-gnu/vkd3d-proton",
            ],
            _ => vec![],
        };

        for base in system_paths {
            let p = Path::new(base).join(&dll_filename);
            candidates.push(DllCandidate {
                provider: DllProvider::System,
                path: p.clone(),
                exists: p.exists(),
            });
        }

        let chosen = candidates.iter().find(|c| c.exists).cloned();

        DllResolution {
            name: dll_name.to_string(),
            chosen_provider: chosen.as_ref().map(|c| c.provider).unwrap_or(DllProvider::None),
            chosen_path: chosen.as_ref().map(|c| c.path.clone()),
            candidates,
        }
    }

    fn get_runner_dll_path(&self, dll_name: &str, runner_path: &Path, components: &crate::utils::RunnerComponents) -> Option<PathBuf> {
        let runner_root = if runner_path.is_file() {
            runner_path.parent()?.parent()?.to_path_buf()
        } else {
            runner_path.to_path_buf()
        };

        let dll_filename = format!("{}.dll", dll_name);

        // Match DLL to component and look for it in runner root
        let is_dxvk = matches!(dll_name, "d3d9" | "d3d10" | "d3d10_1" | "d3d10core" | "d3d11" | "dxgi");
        if is_dxvk && components.dxvk.is_some() {
            let relative_paths = [
                "files/lib/wine/dxvk",
                "dist/lib/wine/dxvk",
                "lib/wine/dxvk",
                "lib64/wine/dxvk",
            ];
            for rel in relative_paths {
                let p = runner_root.join(rel).join(&dll_filename);
                if p.exists() { return Some(p); }
            }
        }

        let is_vkd3d = matches!(dll_name, "d3d12" | "d3d12core");
        if is_vkd3d && components.vkd3d_proton.is_some() {
            let relative_paths = [
                "files/lib/wine/vkd3d-proton",
                "dist/lib/wine/vkd3d-proton",
                "lib/wine/vkd3d-proton",
                "lib64/wine/vkd3d-proton",
            ];
            for rel in relative_paths {
                let p = runner_root.join(rel).join(&dll_filename);
                if p.exists() { return Some(p); }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;

    #[test]
    fn test_dll_priority_game_local() {
        let tmp = tempdir().unwrap();
        let game_dir = tmp.path().to_path_buf();
        let d3d9_dll = game_dir.join("d3d9.dll");
        fs::write(&d3d9_dll, "local content").unwrap();

        let resolver = DllProviderResolver::new();
        let runner_path = Path::new("/tmp/fake_runner");
        let components = crate::utils::RunnerComponents::default();
        let resolutions = resolver.resolve(&game_dir, runner_path, &components);

        let d3d9_res = resolutions.iter().find(|r| r.name == "d3d9").unwrap();
        assert_eq!(d3d9_res.chosen_provider, DllProvider::GameLocal);
        assert_eq!(d3d9_res.chosen_path.as_ref().unwrap(), &d3d9_dll);
    }

    #[test]
    fn test_dll_priority_system_fallback() {
        // We can't easily test system paths because they are absolute and might not exist
        // But we can verify the logic correctly identifies 'None' when no tier matches.
        let tmp = tempdir().unwrap();
        let game_dir = tmp.path().to_path_buf();

        let resolver = DllProviderResolver::new();
        let runner_path = Path::new("/tmp/fake_runner");
        let components = crate::utils::RunnerComponents::default();
        let resolutions = resolver.resolve(&game_dir, runner_path, &components);

        for res in resolutions {
            if res.chosen_provider == DllProvider::System {
                // OK if system has them
            } else {
                assert_eq!(res.chosen_provider, DllProvider::None);
            }
        }
    }
}
