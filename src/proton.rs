pub const VALVE_PROTONS: &[(&str, &str)] = &[
    ("Proton - Experimental", "experimental"),
    ("Proton 11.0", "11.0"),
    ("Proton 10.0", "10.0"),
    ("Proton 9.0 (Beta)", "9.0"),
    ("Proton 8.0", "8.0"),
    ("Proton 7.0", "7.0"),
    ("Proton 6.3", "6.3"),
    ("Proton 5.13", "5.13"),
    ("Proton 5.0", "5.0"),
];

pub fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

pub const UNIFIED_LIB_SUBDIRS: &[&str] = &[
    "files/lib/wine",
    "files/lib64/wine",
    "lib/wine",
    "lib64/wine",
    "dist/lib/wine",
    "dist/lib64/wine",
];

pub const ARCH_SUBDIRS: &[(&str, &str)] = &[
    ("x86_64", "x86_64-windows"),
    ("i386", "i386-windows"),
];

pub const COMPONENT_FAMILIES: &[&str] = &[
    "dxvk",
    "vkd3d-proton",
    "vkd3d",
    "nvapi",
];
