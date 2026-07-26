#[cfg(feature = "desktop-shell")]
fn main() {
    tauri_build::build();
}

#[cfg(not(feature = "desktop-shell"))]
fn main() {}
