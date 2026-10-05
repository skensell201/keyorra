use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        build_touch_id();
    }
    tauri_build::build()
}

/// Compiles the Swift helpers (Touch ID, the sync folder) into a static library and links
/// the Swift runtime from the OS.
fn build_touch_id() {
    let sources = ["swift/TouchId.swift", "swift/SyncFolder.swift"];
    for source in sources {
        println!("cargo:rerun-if-changed={source}");
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64",
        other => other,
    }
    .to_owned();
    let lib = out.join("libkeyorra_touchid.a");
    let status = Command::new("xcrun")
        .args([
            "swiftc",
            "-emit-library",
            "-static",
            "-O",
            "-parse-as-library",
        ])
        .args(["-module-name", "KeyorraTouchId", "-target"])
        .arg(format!("{arch}-apple-macosx13.0"))
        .args(sources)
        .arg("-o")
        .arg(&lib)
        .status()
        .expect("xcrun swiftc (install Xcode or the Command Line Tools)");
    assert!(status.success(), "compiling {sources:?} failed");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=keyorra_touchid");
    println!("cargo:rustc-link-lib=framework=CoreServices");
    let swiftc = xcrun(&["--find", "swiftc"]);
    let toolchain = Path::new(&swiftc).parent().unwrap().parent().unwrap();
    println!(
        "cargo:rustc-link-search=native={}",
        toolchain.join("lib/swift/macosx").display()
    );
    let sdk = xcrun(&["--sdk", "macosx", "--show-sdk-path"]);
    println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
}

fn xcrun(args: &[&str]) -> String {
    let out = Command::new("xcrun").args(args).output().expect("xcrun");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}
