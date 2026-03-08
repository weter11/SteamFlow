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
    pub resolution_summary: HashMap<String, DllResolutionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllResolutionSummary {
    pub chosen_provider: DllProvider,
    pub count_gamelocal: usize,
    pub count_runner: usize,
    pub count_system: usize,
    pub count_runner_total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentFoundInfo {
    pub family: String,
    pub version: String,
    pub source: String,
    pub matched_dll: Option<PathBuf>,
    pub state: crate::utils::DetectionState,
    pub arches: Vec<crate::utils::Architecture>,
    pub reason: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
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
            resolution_summary: HashMap::new(),
        };

        if runner_root == PathBuf::from(".") || runner_root.to_string_lossy().is_empty() {
             report.warnings.push("Runner root derivation failed or resulted in empty path".into());
        } else {
             report.scan_roots = crate::utils::get_runner_layout_roots(&runner_root);
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
                state: c.state,
                arches: c.arches.clone(),
                reason: c.reason.clone(),
            });
        }
        if let Some(ref c) = runner_components.vkd3d_proton {
            report.components_found.insert("vkd3d-proton".into(), ComponentFoundInfo {
                family: "vkd3d-proton".into(),
                version: c.version.clone(),
                source: format!("{:?}", c.source),
                matched_dll: None,
                state: c.state,
                arches: c.arches.clone(),
                reason: c.reason.clone(),
            });
        }
        if let Some(ref c) = runner_components.vkd3d {
            report.components_found.insert("vkd3d".into(), ComponentFoundInfo {
                family: "vkd3d".into(),
                version: c.version.clone(),
                source: format!("{:?}", c.source),
                matched_dll: None,
                state: c.state,
                arches: c.arches.clone(),
                reason: c.reason.clone(),
            });
        }

        for res in &resolutions {
            let game_local_count = res.candidates.iter().filter(|c| c.provider == DllProvider::GameLocal && c.exists).count();
            let runner_count = res.candidates.iter().filter(|c| c.provider == DllProvider::Runner && c.exists).count();
            let system_count = res.candidates.iter().filter(|c| c.provider == DllProvider::System && c.exists).count();

            let runner_total = res.candidates.iter().filter(|c| c.provider == DllProvider::Runner).count();

            report.resolution_summary.insert(res.name.clone(), DllResolutionSummary {
                chosen_provider: res.chosen_provider,
                count_gamelocal: game_local_count,
                count_runner: runner_count,
                count_system: system_count,
                count_runner_total: runner_total,
            });

            tracing::debug!(
                "DLL {}: chosen={:?} (candidates: GameLocal={}, Runner={}/{}, System={})",
                res.name, res.chosen_provider, game_local_count, runner_count, runner_total, system_count
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
            rejection_reason: None,
        });

        // Also check 'bin' subdir common in some games
        let bin_path = game_exe_dir.join("bin").join(&dll_filename);
        candidates.push(DllCandidate {
            provider: DllProvider::GameLocal,
            path: bin_path.clone(),
            exists: bin_path.exists(),
            rejection_reason: None,
        });

        // 2. Runner Priority
        let runner_candidates = self.generate_runner_candidates(dll_name, runner_path, runner_components, d3d12_policy);
        candidates.extend(runner_candidates);

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
                rejection_reason: None,
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

    fn generate_runner_candidates(
        &self,
        dll_name: &str,
        runner_path: &Path,
        _components: &crate::utils::RunnerComponents,
        d3d12_policy: &crate::models::D3D12ProviderPolicy,
    ) -> Vec<DllCandidate> {
        let runner_root = crate::utils::derive_runner_root(runner_path);
        let dll_filename = format!("{}.dll", dll_name);
        let mut candidates = Vec::new();

        let mut layout_roots = crate::utils::get_runner_layout_roots(&runner_root);
        let is_vkd3d_any = matches!(dll_name, "d3d12" | "d3d12core" | "libvkd3d-1" | "libvkd3d-shader-1");

        // Reorder roots based on policy to ensure preferred one is chosen if multiple exist
        if is_vkd3d_any {
            layout_roots.sort_by_key(|r| {
                let s = r.to_string_lossy();
                let is_proton_path = s.contains("vkd3d-proton");
                let is_bundled = s.contains("/files/") || s.contains("/dist/");

                match d3d12_policy {
                    crate::models::D3D12ProviderPolicy::Vkd3dWine => {
                        // Prefer non-proton, then non-bundled
                        match (is_proton_path, is_bundled) {
                            (false, false) => 0,
                            (false, true) => 1,
                            (true, false) => 2,
                            (true, true) => 3,
                        }
                    }
                    _ => {
                        // Auto/Vkd3dProton: Prefer proton, then bundled
                        match (is_proton_path, is_bundled) {
                            (true, true) => 0,
                            (true, false) => 1,
                            (false, true) => 2,
                            (false, false) => 3,
                        }
                    }
                }
            });
        }

        // We scan both 64-bit and 32-bit directories.
        // Order: x86_64-windows > i386-windows > root
        let arch_subdirs = ["x86_64-windows", "i386-windows"];

        for root in layout_roots {
            for subdir in arch_subdirs {
                let path = root.join(subdir).join(&dll_filename);
                candidates.push(DllCandidate {
                    provider: DllProvider::Runner,
                    exists: path.exists(),
                    path,
                    rejection_reason: None,
                });
            }

            let path = root.join(&dll_filename);
            candidates.push(DllCandidate {
                provider: DllProvider::Runner,
                exists: path.exists(),
                path,
                rejection_reason: None,
            });
        }

        candidates
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

        // Use standard layout paths that get_runner_layout_roots understands
        let proton_dir = runner_root.join("files/lib64/wine/vkd3d-proton");
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
            path: None,
            state: crate::utils::DetectionState::Found,
            arches: vec![crate::utils::Architecture::X86_64, crate::utils::Architecture::I386],
            reason: None,
        });
        components.vkd3d = Some(crate::utils::ComponentInfo {
            version: "1.8".into(),
            source: crate::utils::ComponentSource::BundledWithRunner,
            path: None,
            state: crate::utils::DetectionState::Found,
            arches: vec![crate::utils::Architecture::X86_64, crate::utils::Architecture::I386],
            reason: None,
        });

        let resolver = DllProviderResolver::new();
        let game_dir = Path::new("/tmp/game");

        // Case 1: Auto (Prefer Proton)
        // Since we now generate ALL candidates and priority is first-found-exists,
        // and we scan vkd3d-proton before vkd3d in our root list, it should work.
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
    fn test_dll_candidate_rejection_reason_serialization() {
        let candidate = DllCandidate {
            provider: DllProvider::Runner,
            path: PathBuf::from("/tmp/test.dll"),
            exists: false,
            rejection_reason: Some("arch_mismatch".to_string()),
        };
        let json = serde_json::to_string(&candidate).unwrap();
        assert!(json.contains("\"rejection_reason\":\"arch_mismatch\""));

        let ok_candidate = DllCandidate {
            provider: DllProvider::Runner,
            path: PathBuf::from("/tmp/test.dll"),
            exists: true,
            rejection_reason: None,
        };
        let json = serde_json::to_string(&ok_candidate).unwrap();
        assert!(!json.contains("rejection_reason"));
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
