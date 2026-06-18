pub const VALVE_PROTONS: &[(&str, &str)] = &[
    ("Proton - Experimental", "experimental"),
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
