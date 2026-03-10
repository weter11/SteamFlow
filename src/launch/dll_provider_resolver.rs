use std::path::{Path, PathBuf};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentScanReport {
    pub runner_binary: PathBuf,
    pub runner_root: PathBuf,
    pub scan_roots: Vec<PathBuf>,
    pub components_found: HashMap<String, ComponentFoundInfo>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentFoundInfo {
    pub family: String,
    pub version: String,
    pub source: String,
    pub matched_dll: Option<PathBuf>,
}

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
    pub fallback_reason: Option<String>,
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
                "d3d8".into(),
                "d3d9".into(),
                "dxgi".into(),
                "d3d10".into(),
                "d3d10_1".into(),
                "d3d10core".into(),
                "d3d11".into(),
                "d3d12".into(),
                "d3d12core".into(),
                "libvkd3d-1".into(),
                "libvkd3d-shader-1".into(),
            ],
        }
    }

    pub fn resolve(
        &self,
        game_exe_dir: &Path,
        runner_path: &Path,
        runner_components: &crate::utils::RunnerComponents,
        d3d12_policy: &crate::models::D3D12ProviderPolicy,
    ) -> (Vec<DllResolution>, ComponentScanReport) {
        tracing::debug!("Resolving DLL providers. ExeDir: {}, Runner: {}", game_exe_dir.display(), runner_path.display());
        let runner_root = crate::utils::derive_runner_root(runner_path);

        let mut report = ComponentScanReport {
            runner_binary: runner_path.to_path_buf(),
            runner_root: runner_root.clone(),
            scan_roots: Vec::new(),
            components_found: HashMap::new(),
            warnings: Vec::new(),
        };

        if runner_root == PathBuf::from(".") || runner_root.to_string_lossy().is_empty() {
             report.warnings.push("Runner root derivation failed or resulted in empty path".into());
        } else {
             // Derive all potential runner scan roots
             let mut roots = Vec::new();
             let subdirs = [
                 "files/lib/wine/dxvk/x86_64-windows",
                 "files/lib/wine/dxvk/i386-windows",
                 "files/lib/wine/vkd3d/x86_64-windows",
                 "files/lib/wine/vkd3d/i386-windows",
                 "files/lib/wine/vkd3d-proton/x86_64-windows",
                 "files/lib/wine/vkd3d-proton/i386-windows",
                 "files/lib/wine/dxvk",
                 "files/lib/wine/vkd3d",
                 "files/lib/wine/vkd3d-proton",
                 "files/lib64/wine/dxvk",
                 "files/lib64/wine/vkd3d",
                 "files/lib64/wine/vkd3d-proton",
                 "dist/lib/wine/dxvk/x86_64-windows",
                 "dist/lib/wine/dxvk/i386-windows",
                 "dist/lib/wine/vkd3d/x86_64-windows",
                 "dist/lib/wine/vkd3d/i386-windows",
                 "dist/lib/wine/vkd3d-proton/x86_64-windows",
                 "dist/lib/wine/vkd3d-proton/i386-windows",
                 "dist/lib/wine/dxvk",
                 "dist/lib/wine/vkd3d",
                 "dist/lib/wine/vkd3d-proton",
                 "lib/wine/dxvk/x86_64-windows",
                 "lib/wine/dxvk/i386-windows",
                 "lib/wine/vkd3d/x86_64-windows",
                 "lib/wine/vkd3d/i386-windows",
                 "lib/wine/vkd3d-proton/x86_64-windows",
                 "lib/wine/vkd3d-proton/i386-windows",
                 "lib/wine/dxvk",
                 "lib/wine/vkd3d",
                 "lib/wine/vkd3d-proton",
                 "lib64/wine/dxvk",
                 "lib64/wine/vkd3d",
                 "lib64/wine/vkd3d-proton",
             ];
             for s in subdirs { roots.push(runner_root.join(s)); }
             report.scan_roots = roots;
        }

        let resolutions: Vec<DllResolution> = self.target_dlls
            .iter()
            .map(|dll| self.resolve_single(dll, game_exe_dir, runner_path, runner_components, d3d12_policy))
            .collect();

        if let Some(ref c) = runner_components.dxvk {
            report.components_found.insert("dxvk".into(), ComponentFoundInfo {
                family: "dxvk".into(),
                version: c.version.clone(),
                source: format!("{:?}", c.source),
                matched_dll: None,
            });
        }
        if let Some(ref c) = runner_components.vkd3d_proton {
            report.components_found.insert("vkd3d-proton".into(), ComponentFoundInfo {
                family: "vkd3d-proton".into(),
                version: c.version.clone(),
                source: format!("{:?}", c.source),
                matched_dll: None,
            });
        }
        if let Some(ref c) = runner_components.vkd3d {
            report.components_found.insert("vkd3d".into(), ComponentFoundInfo {
                family: "vkd3d".into(),
                version: c.version.clone(),
                source: format!("{:?}", c.source),
                matched_dll: None,
            });
        }

        for res in &resolutions {
            let game_local_count = res.candidates.iter().filter(|c| c.provider == DllProvider::GameLocal && c.exists).count();
            let runner_count = res.candidates.iter().filter(|c| c.provider == DllProvider::Runner && c.exists).count();
            let system_count = res.candidates.iter().filter(|c| c.provider == DllProvider::System && c.exists).count();

            tracing::debug!(
                "DLL {}: chosen={:?} (candidates: GameLocal={}, Runner={}, System={})",
                res.name, res.chosen_provider, game_local_count, runner_count, system_count
            );

            if res.chosen_provider == DllProvider::Runner {
                if let Some(ref path) = res.chosen_path {
                     // Try to match back to component
                     let family = if res.name.starts_with("d3d12") || res.name.contains("vkd3d") {
                         if path.to_string_lossy().contains("vkd3d-proton") { "vkd3d-proton" } else { "vkd3d" }
                     } else {
                         "dxvk"
                     };
                     if let Some(info) = report.components_found.get_mut(family) {
                         info.matched_dll = Some(path.clone());
                     }
                }
            }
        }

        (resolutions, report)
    }

    fn resolve_single(
        &self,
        dll_name: &str,
        game_exe_dir: &Path,
        runner_path: &Path,
        runner_components: &crate::utils::RunnerComponents,
        d3d12_policy: &crate::models::D3D12ProviderPolicy,
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
        if let Some(path) = self.get_runner_dll_path(dll_name, runner_path, runner_components, d3d12_policy) {
            candidates.push(DllCandidate {
                provider: DllProvider::Runner,
                path: path.clone(),
                exists: path.exists(),
            });
        }

        // 3. System Priority
        // For now, we use a simplified check for system paths
        let system_paths = match dll_name {
            "d3d8" | "d3d9" | "d3d10" | "d3d10_1" | "d3d10core" | "d3d11" | "dxgi" => vec![
                "/usr/lib/dxvk/x64",
                "/usr/lib/x86_64-linux-gnu/dxvk",
            ],
            "d3d12" | "d3d12core" | "libvkd3d-1" | "libvkd3d-shader-1" => vec![
                "/usr/lib/vkd3d-proton/x64",
                "/usr/lib/x86_64-linux-gnu/vkd3d-proton",
                "/usr/lib/x86_64-linux-gnu", // standard system vkd3d
                "/usr/lib64",
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
        let fallback_reason = if chosen.is_none() {
            Some("no candidate files found in GameLocal, Runner, or System paths".to_string())
        } else {
            None
        };

        DllResolution {
            name: dll_name.to_string(),
            chosen_provider: chosen.as_ref().map(|c| c.provider).unwrap_or(DllProvider::None),
            chosen_path: chosen.as_ref().map(|c| c.path.clone()),
            fallback_reason,
            candidates,
        }
    }

    fn get_runner_dll_path(
        &self,
        dll_name: &str,
        runner_path: &Path,
        components: &crate::utils::RunnerComponents,
        d3d12_policy: &crate::models::D3D12ProviderPolicy,
    ) -> Option<PathBuf> {
        let runner_root = crate::utils::derive_runner_root(runner_path);

        let dll_filename = format!("{}.dll", dll_name);

        // Match DLL to component and look for it in runner root
        let is_dxvk = matches!(dll_name, "d3d8" | "d3d9" | "d3d10" | "d3d10_1" | "d3d10core" | "d3d11" | "dxgi");
        if is_dxvk && components.dxvk.is_some() {
            let relative_paths = [
                "lib/wine/dxvk/x86_64-windows",
                "lib/wine/dxvk/i386-windows",
                "files/lib/wine/dxvk/x86_64-windows",
                "files/lib/wine/dxvk/i386-windows",
                "dist/lib/wine/dxvk/x86_64-windows",
                "dist/lib/wine/dxvk/i386-windows",
                "lib/wine/dxvk",
                "files/lib/wine/dxvk",
                "dist/lib/wine/dxvk",
                "files/lib64/wine/dxvk",
                "lib64/wine/dxvk",
                "dist/lib64/wine/dxvk",
            ];
            for rel in relative_paths {
                let root = runner_root.join(rel);
                let p = root.join(&dll_filename);
                if p.exists() {
                    tracing::trace!("Found runner component DLL at: {}", p.display());
                    return Some(p);
                }
            }
        }

        let is_vkd3d_any = matches!(dll_name, "d3d12" | "d3d12core" | "libvkd3d-1" | "libvkd3d-shader-1");
        if is_vkd3d_any {
            let use_proton = match d3d12_policy {
                crate::models::D3D12ProviderPolicy::Auto => true,
                crate::models::D3D12ProviderPolicy::Vkd3dProton => true,
                crate::models::D3D12ProviderPolicy::Vkd3dWine => false,
            };

            if use_proton && components.vkd3d_proton.is_some() {
                let relative_paths = [
                    "lib/wine/vkd3d-proton/x86_64-windows",
                    "files/lib/wine/vkd3d-proton/x86_64-windows",
                    "dist/lib/wine/vkd3d-proton/x86_64-windows",
                    "lib/wine/vkd3d-proton",
                    "files/lib/wine/vkd3d-proton",
                    "dist/lib/wine/vkd3d-proton",
                    "lib64/wine/vkd3d-proton",
                    "files/lib64/wine/vkd3d-proton",
                    "dist/lib64/wine/vkd3d-proton",
                ];
                for rel in relative_paths {
                    let root = runner_root.join(rel);
                    let p = root.join(&dll_filename);
                    if p.exists() {
                        tracing::trace!("Found runner component DLL at: {}", p.display());
                        return Some(p);
                    }
                }
            }

            if (!use_proton || d3d12_policy == &crate::models::D3D12ProviderPolicy::Auto) && components.vkd3d.is_some() {
                let relative_paths = [
                    "lib/wine/vkd3d/x86_64-windows",
                    "files/lib/wine/vkd3d/x86_64-windows",
                    "dist/lib/wine/vkd3d/x86_64-windows",
                    "lib/wine/vkd3d",
                    "files/lib/wine/vkd3d",
                    "dist/lib/wine/vkd3d",
                    "lib64/wine/vkd3d",
                    "files/lib64/wine/vkd3d",
                    "dist/lib64/wine/vkd3d",
                ];
                for rel in relative_paths {
                    let root = runner_root.join(rel);
                    let p = root.join(&dll_filename);
                    if p.exists() {
                        tracing::trace!("Found runner component DLL at: {}", p.display());
                        return Some(p);
                    }
                }
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
        let d3d12_policy = crate::models::D3D12ProviderPolicy::Auto;
        let (resolutions, _) = resolver.resolve(&game_dir, runner_path, &components, &d3d12_policy);

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
        let d3d12_policy = crate::models::D3D12ProviderPolicy::Auto;
        let (resolutions, _) = resolver.resolve(&game_dir, runner_path, &components, &d3d12_policy);

        for res in resolutions {
            if res.chosen_provider == DllProvider::System {
                // OK if system has them
            } else {
                assert_eq!(res.chosen_provider, DllProvider::None);
            }
        }
    }

    #[test]
    fn test_d3d12_provider_selection() {
        let tmp = tempdir().unwrap();
        let runner_root = tmp.path().to_path_buf();
        let proton_dir = runner_root.join("files/lib/wine/vkd3d-proton");
        let wine_dir = runner_root.join("files/lib/wine/vkd3d");
        fs::create_dir_all(&proton_dir).unwrap();
        fs::create_dir_all(&wine_dir).unwrap();

        let proton_dll = proton_dir.join("d3d12.dll");
        let wine_dll = wine_dir.join("d3d12.dll");
        fs::write(&proton_dll, "proton").unwrap();
        fs::write(&wine_dll, "wine").unwrap();

        let mut components = crate::utils::RunnerComponents::default();
        components.vkd3d_proton = Some(crate::utils::ComponentInfo {
            version: "2.10".into(),
            source: crate::utils::ComponentSource::BundledWithRunner,
        });
        components.vkd3d = Some(crate::utils::ComponentInfo {
            version: "1.8".into(),
            source: crate::utils::ComponentSource::BundledWithRunner,
        });

        let resolver = DllProviderResolver::new();
        let game_dir = Path::new("/tmp/game");

        // Case 1: Auto (Prefer Proton)
        let (res, _) = resolver.resolve(game_dir, &runner_root, &components, &crate::models::D3D12ProviderPolicy::Auto);
        let d3d12 = res.iter().find(|r| r.name == "d3d12").unwrap();
        assert_eq!(d3d12.chosen_path.as_ref().unwrap(), &proton_dll);

        // Case 2: Explicit Wine
        let (res, _) = resolver.resolve(game_dir, &runner_root, &components, &crate::models::D3D12ProviderPolicy::Vkd3dWine);
        let d3d12 = res.iter().find(|r| r.name == "d3d12").unwrap();
        assert_eq!(d3d12.chosen_path.as_ref().unwrap(), &wine_dll);

        // Case 3: Explicit Proton
        let (res, _) = resolver.resolve(game_dir, &runner_root, &components, &crate::models::D3D12ProviderPolicy::Vkd3dProton);
        let d3d12 = res.iter().find(|r| r.name == "d3d12").unwrap();
        assert_eq!(d3d12.chosen_path.as_ref().unwrap(), &proton_dll);
    }

    #[test]
    fn test_d3d8_coverage() {
        let resolver = DllProviderResolver::new();
        assert!(resolver.target_dlls.contains(&"d3d8".to_string()));
    }

    #[test]
    fn test_fallback_reason_populated() {
        let resolver = DllProviderResolver::new();
        let tmp = tempdir().unwrap();
        let (res, _) = resolver.resolve(tmp.path(), tmp.path(), &crate::utils::RunnerComponents::default(), &crate::models::D3D12ProviderPolicy::Auto);
        let d3d11 = res.iter().find(|r| r.name == "d3d11").unwrap();
        assert_eq!(d3d11.chosen_provider, DllProvider::None);
        assert!(d3d11.fallback_reason.is_some());
    }
}
