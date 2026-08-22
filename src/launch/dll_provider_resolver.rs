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
    Custom,
    Runner,
    System,
    Internal, // Satisfied via capability (e.g. DXVK D3D10 core)
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
                "d3d7".into(),
                "ddraw".into(),
                "d3d8".into(),
                "d3d9".into(),
                "dxgi".into(),
                "d3d10core".into(),
                "d3d11".into(),
                "d3d12".into(),
                "d3d12core".into(),
                "libvkd3d-1".into(),
                "libvkd3d-shader-1".into(),
                "nvapi".into(),
                "nvapi64".into(),
                "nvofapi64".into(),
            ],
        }
    }

    pub fn resolve(
        &self,
        game_exe_dir: &Path,
        runner_path: &Path,
        runner_components: &crate::utils::RunnerComponents,
        d3d12_policy: &crate::models::D3D12ProviderPolicy,
        target_arch: &crate::models::ExecutableArchitecture,
        custom_dxvk_path: Option<&Path>,
        custom_vkd3d_path: Option<&Path>,
        custom_vkd3d_proton_path: Option<&Path>,
        dxvk_enabled: bool,
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
             for lib_subdir in crate::proton::COMPONENT_LIB_SUBDIRS {
                 // Component families
                 for family in crate::proton::COMPONENT_FAMILIES {
                     if *family == "vkd3d" { continue; }
                     let family_root = runner_root.join(lib_subdir).join(family);
                     roots.push(family_root.clone());
                     for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                         roots.push(family_root.join(arch_dir));
                     }
                 }
                 // Direct architecture subdirs (Modern Unified Layout)
                 for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                     roots.push(runner_root.join(lib_subdir).join(arch_dir));
                 }
             }
             // vkd3d in modern Proton 11+ is under files/lib/ (BASE_LIB)
             for base_lib in crate::proton::UNIFIED_BASE_LIB_SUBDIRS {
                 let family_root = runner_root.join(base_lib).join("vkd3d");
                 roots.push(family_root.clone());
                 for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                     roots.push(family_root.join(arch_dir));
                     roots.push(runner_root.join(base_lib).join(arch_dir));
                 }
             }
             report.scan_roots = roots;
        }

        let resolutions: Vec<DllResolution> = self.target_dlls
            .iter()
            .map(|dll| self.resolve_single(
                dll,
                game_exe_dir,
                runner_path,
                runner_components,
                d3d12_policy,
                target_arch,
                custom_dxvk_path,
                custom_vkd3d_path,
                custom_vkd3d_proton_path,
                dxvk_enabled,
            ))
            .collect();

        if let Some(ref c) = runner_components.dxvk {
            report.components_found.insert("dxvk".into(), ComponentFoundInfo {
                family: "dxvk".into(),
                version: c.version.clone(),
                source: format!("{:?}", c.source),
                matched_dll: None,
            });
        }
        if let Some(ref c) = runner_components.d7vk {
            report.components_found.insert("d7vk".into(), ComponentFoundInfo {
                family: "d7vk".into(),
                version: c.version.clone(),
                source: format!("{:?}", c.source),
                matched_dll: None,
            });
        }
        if let Some(ref c) = runner_components.nvapi {
            report.components_found.insert("nvapi".into(), ComponentFoundInfo {
                family: "nvapi".into(),
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
                     } else if res.name.contains("nvapi") {
                         "nvapi"
                     } else if res.name == "d3d7" || res.name == "ddraw" {
                         "d7vk"
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
        target_arch: &crate::models::ExecutableArchitecture,
        custom_dxvk_path: Option<&Path>,
        custom_vkd3d_path: Option<&Path>,
        custom_vkd3d_proton_path: Option<&Path>,
        dxvk_enabled: bool,
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

        // 2. Custom Path Priority
        if let Some(path) = self.get_custom_dll_path(
            dll_name,
            target_arch,
            custom_dxvk_path,
            custom_vkd3d_path,
            custom_vkd3d_proton_path,
            dxvk_enabled,
        ) {
            candidates.push(DllCandidate {
                provider: DllProvider::Custom,
                path: path.clone(),
                exists: path.exists(),
            });
        }

        // 3. Runner Priority
        if let Some(path) = self.get_runner_dll_path(
            dll_name,
            runner_path,
            runner_components,
            d3d12_policy,
            target_arch,
            dxvk_enabled,
        ) {
            candidates.push(DllCandidate {
                provider: DllProvider::Runner,
                path: path.clone(),
                exists: path.exists(),
            });
        }

        // 3. System Priority
        // For now, we use a simplified check for system paths.
        // dxvk_enabled=false contract: system DXVK paths must not be listed
        // either — otherwise a runner lacking a builtin would fall back to
        // system DXVK, defeating the WineD3D selection.
        let system_paths = match dll_name {
            "d3d8" | "d3d9" | "d3d10core" | "d3d11" | "dxgi" if dxvk_enabled => vec![
                "/usr/lib/dxvk/x64",
                "/usr/lib/x86_64-linux-gnu/dxvk",
            ],
            "d3d8" | "d3d9" | "d3d10core" | "d3d11" | "dxgi" => vec![],
            "d3d12" | "d3d12core" | "libvkd3d-1" | "libvkd3d-shader-1" => vec![
                "/usr/lib/vkd3d-proton/x64",
                "/usr/lib/x86_64-linux-gnu/vkd3d-proton",
                "/usr/lib/x86_64-linux-gnu", // standard system vkd3d
                "/usr/lib64",
            ],
            "nvapi" | "nvapi64" | "nvofapi64" => vec![
                "/usr/lib/nvapi/x64",
                "/usr/lib/x86_64-linux-gnu/nvapi",
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
            Some("no candidate files found in GameLocal, Custom, Runner, or System paths".to_string())
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

    fn get_custom_dll_path(
        &self,
        dll_name: &str,
        target_arch: &crate::models::ExecutableArchitecture,
        custom_dxvk_path: Option<&Path>,
        custom_vkd3d_path: Option<&Path>,
        custom_vkd3d_proton_path: Option<&Path>,
        dxvk_enabled: bool,
    ) -> Option<PathBuf> {
        let dll_filename = format!("{}.dll", dll_name);
        let is_dxvk = matches!(dll_name, "d3d8" | "d3d9" | "d3d10core" | "d3d11" | "dxgi");
        let is_vkd3d_proton = matches!(dll_name, "d3d12" | "d3d12core");
        let is_vkd3d = matches!(dll_name, "libvkd3d-1" | "libvkd3d-shader-1");

        // dxvk_enabled=false contract: a custom DXVK path must NOT be used —
        // the user asked for WineD3D/builtin, not for a custom DXVK build.
        if is_dxvk && !dxvk_enabled {
            return None;
        }

        let custom_root = if is_dxvk {
            custom_dxvk_path
        } else if is_vkd3d_proton {
            custom_vkd3d_proton_path
        } else if is_vkd3d {
            custom_vkd3d_path
        } else {
            None
        };

        if let Some(root) = custom_root {
            let mut relative_paths = vec![
                "x86_64-windows",
                "i386-windows",
                "x64",
                "x32",
                "",
            ];

            // Strictly filter by architecture
            match target_arch {
                crate::models::ExecutableArchitecture::X86 => {
                    relative_paths.retain(|p| p.contains("i386") || p.contains("x32") || p.is_empty());
                }
                crate::models::ExecutableArchitecture::X86_64 => {
                    relative_paths.retain(|p| p.contains("x86_64") || p.contains("x64") || p.is_empty());
                }
                _ => {}
            }

            for rel in relative_paths {
                let p = root.join(rel).join(&dll_filename);
                if p.exists() {
                    return Some(p);
                }
            }
        }

        None
    }

    fn get_runner_dll_path(
        &self,
        dll_name: &str,
        runner_path: &Path,
        components: &crate::utils::RunnerComponents,
        d3d12_policy: &crate::models::D3D12ProviderPolicy,
        target_arch: &crate::models::ExecutableArchitecture,
        dxvk_enabled: bool,
    ) -> Option<PathBuf> {
        let runner_root = crate::utils::derive_runner_root(runner_path);

        let dll_filename = format!("{}.dll", dll_name);

        // Match DLL to component and look for it in runner root
        let is_d7vk = dll_name == "d3d7" || dll_name == "ddraw";
        if is_d7vk && components.d7vk.is_some() {
            let mut relative_paths = Vec::new();
            for lib_subdir in crate::proton::COMPONENT_LIB_SUBDIRS {
                relative_paths.push(format!("{}/d7vk", lib_subdir));
                for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                    relative_paths.push(format!("{}/d7vk/{}", lib_subdir, arch_dir));
                    relative_paths.push(format!("{}/{}", lib_subdir, arch_dir));
                }
            }

            match target_arch {
                crate::models::ExecutableArchitecture::X86 => {
                    relative_paths.retain(|p| p.contains("i386") || (!p.contains("x86_64") && !p.contains("-windows")));
                }
                crate::models::ExecutableArchitecture::X86_64 => {
                    relative_paths.retain(|p| p.contains("x86_64") || (!p.contains("i386") && !p.contains("-windows")));
                }
                _ => {}
            }

            for rel in relative_paths {
                let root = runner_root.join(rel);
                let p = root.join(&dll_filename);
                if p.exists() {
                    tracing::trace!("Found runner component DLL at: {}", p.display());
                    return Some(p);
                }
            }
        }

        let is_dxvk = matches!(dll_name, "d3d8" | "d3d9" | "d3d10core" | "d3d11" | "dxgi");
        if is_dxvk && components.dxvk.is_some() {
            let mut relative_paths = Vec::new();
            for lib_subdir in crate::proton::COMPONENT_LIB_SUBDIRS {
                if dxvk_enabled {
                    relative_paths.push(format!("{}/dxvk", lib_subdir));
                }
                for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                    if dxvk_enabled {
                        relative_paths.push(format!("{}/dxvk/{}", lib_subdir, arch_dir));
                    }
                    // Plain builtin dirs (WineD3D). When dxvk_enabled=false these
                    // are the ONLY runner paths that qualify: the DXVK subdirs
                    // must never be resolved or provisioned for such a game.
                    relative_paths.push(format!("{}/{}", lib_subdir, arch_dir));
                }
            }

            // Strictly filter by architecture
            match target_arch {
                crate::models::ExecutableArchitecture::X86 => {
                    relative_paths.retain(|p| p.contains("i386") || (!p.contains("x86_64") && !p.contains("-windows")));
                }
                crate::models::ExecutableArchitecture::X86_64 => {
                    relative_paths.retain(|p| p.contains("x86_64") || (!p.contains("i386") && !p.contains("-windows")));
                }
                _ => {}
            }

            for rel in relative_paths {
                let root = runner_root.join(rel);
                let p = root.join(&dll_filename);
                if p.exists() {
                    tracing::trace!("Found runner component DLL at: {}", p.display());
                    return Some(p);
                }
            }
        }

        let is_nvapi = matches!(dll_name, "nvapi" | "nvapi64" | "nvofapi64");
        if is_nvapi && components.nvapi.is_some() {
             let mut relative_paths = Vec::new();
             for lib_subdir in crate::proton::COMPONENT_LIB_SUBDIRS {
                 relative_paths.push(format!("{}/nvapi", lib_subdir));
                 for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                     relative_paths.push(format!("{}/nvapi/{}", lib_subdir, arch_dir));
                     relative_paths.push(format!("{}/{}", lib_subdir, arch_dir));
                 }
             }

            match target_arch {
                crate::models::ExecutableArchitecture::X86 => {
                    relative_paths.retain(|p| p.contains("i386") || (!p.contains("x86_64") && !p.contains("-windows")));
                }
                crate::models::ExecutableArchitecture::X86_64 => {
                    relative_paths.retain(|p| p.contains("x86_64") || (!p.contains("i386") && !p.contains("-windows")));
                }
                _ => {}
            }

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
                let mut relative_paths = Vec::new();
                for lib_subdir in crate::proton::COMPONENT_LIB_SUBDIRS {
                    relative_paths.push(format!("{}/vkd3d-proton", lib_subdir));
                    for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                        relative_paths.push(format!("{}/vkd3d-proton/{}", lib_subdir, arch_dir));
                        relative_paths.push(format!("{}/{}", lib_subdir, arch_dir));
                    }
                }

                match target_arch {
                    crate::models::ExecutableArchitecture::X86 => {
                        relative_paths.retain(|p| p.contains("i386") || (!p.contains("x86_64") && !p.contains("-windows")));
                    }
                    crate::models::ExecutableArchitecture::X86_64 => {
                        relative_paths.retain(|p| p.contains("x86_64") || (!p.contains("i386") && !p.contains("-windows")));
                    }
                    _ => {}
                }

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
                let mut relative_paths = Vec::new();
                // vkd3d in modern Proton 11+ is under files/lib/ (BASE_LIB)
                for lib_subdir in crate::proton::UNIFIED_BASE_LIB_SUBDIRS {
                    relative_paths.push(format!("{}/vkd3d", lib_subdir));
                    for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                        relative_paths.push(format!("{}/vkd3d/{}", lib_subdir, arch_dir));
                        relative_paths.push(format!("{}/{}", lib_subdir, arch_dir));
                    }
                }
                // Fallback for legacy vkd3d under lib/wine/
                for lib_subdir in crate::proton::COMPONENT_LIB_SUBDIRS {
                    relative_paths.push(format!("{}/vkd3d", lib_subdir));
                    for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                        relative_paths.push(format!("{}/vkd3d/{}", lib_subdir, arch_dir));
                        relative_paths.push(format!("{}/{}", lib_subdir, arch_dir));
                    }
                }

                match target_arch {
                    crate::models::ExecutableArchitecture::X86 => {
                        relative_paths.retain(|p| p.contains("i386") || (!p.contains("x86_64") && !p.contains("-windows")));
                    }
                    crate::models::ExecutableArchitecture::X86_64 => {
                        relative_paths.retain(|p| p.contains("x86_64") || (!p.contains("i386") && !p.contains("-windows")));
                    }
                    _ => {}
                }

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
        let arch = crate::models::ExecutableArchitecture::X86_64;
        let (resolutions, _) = resolver.resolve(&game_dir, runner_path, &components, &d3d12_policy, &arch, None, None, None, true);

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
        let arch = crate::models::ExecutableArchitecture::X86_64;
        let (resolutions, _) = resolver.resolve(&game_dir, runner_path, &components, &d3d12_policy, &arch, None, None, None, true);

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
            path: None,
        });
        components.vkd3d = Some(crate::utils::ComponentInfo {
            version: "1.8".into(),
            source: crate::utils::ComponentSource::BundledWithRunner,
            path: None,
        });

        let resolver = DllProviderResolver::new();
        let game_dir = Path::new("/tmp/game");
        let arch = crate::models::ExecutableArchitecture::X86_64;

        // Case 1: Auto (Prefer Proton)
        let (res, _) = resolver.resolve(game_dir, &runner_root, &components, &crate::models::D3D12ProviderPolicy::Auto, &arch, None, None, None, true);
        let d3d12 = res.iter().find(|r| r.name == "d3d12").unwrap();
        assert_eq!(d3d12.chosen_path.as_ref().unwrap(), &proton_dll);

        // Case 2: Explicit Wine
        let (res, _) = resolver.resolve(game_dir, &runner_root, &components, &crate::models::D3D12ProviderPolicy::Vkd3dWine, &arch, None, None, None, true);
        let d3d12 = res.iter().find(|r| r.name == "d3d12").unwrap();
        assert_eq!(d3d12.chosen_path.as_ref().unwrap(), &wine_dll);

        // Case 3: Explicit Proton
        let (res, _) = resolver.resolve(game_dir, &runner_root, &components, &crate::models::D3D12ProviderPolicy::Vkd3dProton, &arch, None, None, None, true);
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
        let arch = crate::models::ExecutableArchitecture::X86_64;
        let (res, _) = resolver.resolve(tmp.path(), tmp.path(), &crate::utils::RunnerComponents::default(), &crate::models::D3D12ProviderPolicy::Auto, &arch, None, None, None, true);
        let d3d11 = res.iter().find(|r| r.name == "d3d11").unwrap();
        assert_eq!(d3d11.chosen_provider, DllProvider::None);
        assert!(d3d11.fallback_reason.is_some());
    }

    #[test]
    fn test_modern_unified_layout_discovery() {
        let tmp = tempdir().unwrap();
        let runner_root = tmp.path().to_path_buf();

        // Modern Proton 11 / CachyOS layout: files/lib/wine/x86_64-windows/
        let unified_dir = runner_root.join("files/lib/wine/x86_64-windows");
        fs::create_dir_all(&unified_dir).unwrap();

        let d3d11_dll = unified_dir.join("d3d11.dll");
        let dxgi_dll = unified_dir.join("dxgi.dll");
        fs::write(&d3d11_dll, "d3d11 content").unwrap();
        fs::write(&dxgi_dll, "dxgi content").unwrap();

        let mut components = crate::utils::RunnerComponents::default();
        // Even if components.dxvk is Some, it should look in the new paths
        components.dxvk = Some(crate::utils::ComponentInfo {
            version: "2.3".into(),
            source: crate::utils::ComponentSource::BundledWithRunner,
            path: None,
        });

        let resolver = DllProviderResolver::new();
        let game_dir = Path::new("/tmp/game");
        let arch = crate::models::ExecutableArchitecture::X86_64;

        let (res, report) = resolver.resolve(game_dir, &runner_root, &components, &crate::models::D3D12ProviderPolicy::Auto, &arch, None, None, None, true);

        let d3d11_res = res.iter().find(|r| r.name == "d3d11").unwrap();
        assert_eq!(d3d11_res.chosen_provider, DllProvider::Runner);
        assert_eq!(d3d11_res.chosen_path.as_ref().unwrap(), &d3d11_dll);

        let dxgi_res = res.iter().find(|r| r.name == "dxgi").unwrap();
        assert_eq!(dxgi_res.chosen_provider, DllProvider::Runner);
        assert_eq!(dxgi_res.chosen_path.as_ref().unwrap(), &dxgi_dll);

        // Check if report scan roots include the new unified path
        assert!(report.scan_roots.iter().any(|p| p.to_string_lossy().contains("files/lib/wine/x86_64-windows")));
    }

    #[test]
    fn test_dxvk_disabled_resolves_builtin_not_dxvk() {
        // Classic layout: runner ships BOTH the DXVK build (dxvk/ subdir) and
        // the plain WineD3D builtin. dxvk_enabled=false must resolve to the
        // builtin; dxvk_enabled=true must resolve to the DXVK build.
        let tmp = tempdir().unwrap();
        let runner_root = tmp.path().to_path_buf();
        let dxvk_dir = runner_root.join("files/lib/wine/dxvk/i386-windows");
        let builtin_dir = runner_root.join("files/lib/wine/i386-windows");
        fs::create_dir_all(&dxvk_dir).unwrap();
        fs::create_dir_all(&builtin_dir).unwrap();
        let dxvk_dll = dxvk_dir.join("d3d9.dll");
        let builtin_dll = builtin_dir.join("d3d9.dll");
        fs::write(&dxvk_dll, "dxvk build").unwrap();
        fs::write(&builtin_dll, "wined3d builtin").unwrap();

        let mut components = crate::utils::RunnerComponents::default();
        components.dxvk = Some(crate::utils::ComponentInfo {
            version: "2.3".into(),
            source: crate::utils::ComponentSource::BundledWithRunner,
            path: None,
        });

        let resolver = DllProviderResolver::new();
        let game_dir = Path::new("/tmp/game");
        let arch = crate::models::ExecutableArchitecture::X86;
        let policy = crate::models::D3D12ProviderPolicy::Auto;

        // DXVK disabled → builtin WineD3D DLL, never the dxvk/ subdir.
        let (res, _) = resolver.resolve(game_dir, &runner_root, &components, &policy, &arch, None, None, None, false);
        let d3d9 = res.iter().find(|r| r.name == "d3d9").unwrap();
        assert_eq!(d3d9.chosen_provider, DllProvider::Runner);
        let chosen = d3d9.chosen_path.as_ref().unwrap().to_string_lossy().to_string();
        assert!(chosen.ends_with("files/lib/wine/i386-windows/d3d9.dll"), "expected builtin path, got {chosen}");
        assert!(!chosen.contains("/dxvk/"), "dxvk_enabled=false must not resolve the dxvk subdir: {chosen}");
        assert!(d3d9.candidates.iter().all(|c| !c.path.to_string_lossy().contains("/dxvk/")),
            "dxvk_enabled=false must not even list dxvk candidates");

        // DXVK enabled → DXVK build wins (regression guard).
        let (res, _) = resolver.resolve(game_dir, &runner_root, &components, &policy, &arch, None, None, None, true);
        let d3d9 = res.iter().find(|r| r.name == "d3d9").unwrap();
        let chosen = d3d9.chosen_path.as_ref().unwrap().to_string_lossy().to_string();
        assert!(chosen.contains("/dxvk/"), "dxvk_enabled=true should resolve the dxvk subdir, got {chosen}");
    }

    #[test]
    fn test_dxvk_disabled_ignores_custom_dxvk_path() {
        let tmp = tempdir().unwrap();
        // get_custom_dll_path expects arch subdirs directly under the custom
        // dxvk root (i386-windows / x86_64-windows / x64 / x32 / "").
        let custom = tmp.path().join("i386-windows");
        fs::create_dir_all(&custom).unwrap();
        let custom_dll = custom.join("d3d9.dll");
        fs::write(&custom_dll, "custom dxvk").unwrap();

        let resolver = DllProviderResolver::new();
        let game_dir = Path::new("/tmp/game");
        let runner_root = Path::new("/tmp/fake_runner");
        let arch = crate::models::ExecutableArchitecture::X86;
        let policy = crate::models::D3D12ProviderPolicy::Auto;
        let components = crate::utils::RunnerComponents::default();

        // dxvk_enabled=false: the custom DXVK path must be ignored entirely.
        let (res, _) = resolver.resolve(game_dir, runner_root, &components, &policy, &arch, Some(tmp.path()), None, None, false);
        let d3d9 = res.iter().find(|r| r.name == "d3d9").unwrap();
        assert_ne!(d3d9.chosen_provider, DllProvider::Custom, "custom dxvk path must be ignored when dxvk_enabled=false");
        assert!(d3d9.candidates.iter().all(|c| c.provider != DllProvider::Custom));

        // dxvk_enabled=true: custom path is honored as before.
        let (res, _) = resolver.resolve(game_dir, runner_root, &components, &policy, &arch, Some(tmp.path()), None, None, true);
        let d3d9 = res.iter().find(|r| r.name == "d3d9").unwrap();
        assert_eq!(d3d9.chosen_provider, DllProvider::Custom);
        assert_eq!(d3d9.chosen_path.as_ref().unwrap(), &custom_dll);
    }
}
