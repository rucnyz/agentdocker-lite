//! Cargo build script: compile the Go `nitrobox-core` binary so it ends up
//! bundled inside the Python wheel.
//!
//! The Python package looks for `nitrobox-core` in this order
//! (see `src/nitrobox/_gobin.py`):
//!   1. ``$NITROBOX_CORE_BIN`` env override
//!   2. ``<package>/_vendor/nitrobox-core``        ← built here
//!   3. ``<project_root>/go/nitrobox-core``        ← `make dev` layout
//!   4. ``nitrobox-core`` on ``PATH``
//!
//! Maturin auto-includes everything under ``src/nitrobox/`` into the wheel
//! (because of ``python-source = "src"``), so writing the binary into
//! ``src/nitrobox/_vendor/nitrobox-core`` is enough to ship it.
//!
//! If the Go toolchain isn't available, we emit a warning and skip — the
//! Python loader will fall back to PATH or ``NITROBOX_CORE_BIN``.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let go_dir = manifest_dir.join("go");
    let out_dir = manifest_dir.join("src/nitrobox/_vendor");
    let out_path = out_dir.join("nitrobox-core");

    // Trigger rebuild if any Go source changes.
    println!("cargo:rerun-if-changed=go/go.mod");
    println!("cargo:rerun-if-changed=go/go.sum");
    println!("cargo:rerun-if-changed=go/cmd");
    println!("cargo:rerun-if-changed=go/internal");
    println!("cargo:rerun-if-env-changed=NITROBOX_SKIP_GO_BUILD");

    // Allow opting out (e.g. CI builds Rust-only test wheels).
    if env::var_os("NITROBOX_SKIP_GO_BUILD").is_some() {
        println!("cargo:warning=NITROBOX_SKIP_GO_BUILD set; skipping Go build");
        return;
    }

    // If the Go directory isn't present (e.g. building from a stripped-down
    // sdist that excludes go/), there's nothing to build.
    if !go_dir.exists() {
        println!(
            "cargo:warning=go/ directory not found at {} — skipping nitrobox-core build",
            go_dir.display()
        );
        return;
    }

    // If `go` isn't on PATH, skip with a useful warning instead of failing the
    // whole crate build. The Python loader will then fall back to PATH lookup.
    let go_check = Command::new("go").arg("version").output();
    if !matches!(&go_check, Ok(o) if o.status.success()) {
        println!(
            "cargo:warning=Go toolchain not found; skipping nitrobox-core build. \
             Install Go (https://go.dev/dl/) and rebuild, or set NITROBOX_CORE_BIN \
             to a prebuilt binary."
        );
        return;
    }

    std::fs::create_dir_all(&out_dir)
        .unwrap_or_else(|e| panic!("failed to mkdir {}: {}", out_dir.display(), e));

    println!(
        "cargo:warning=building nitrobox-core Go binary -> {}",
        out_path.display()
    );

    let status = Command::new("go")
        .args([
            "build",
            "-tags",
            "exclude_graphdriver_btrfs containers_image_openpgp",
            "-trimpath",
            "-ldflags=-s -w", // strip debug + symbol table; ~32MB instead of 47MB
            "-o",
        ])
        .arg(&out_path)
        .arg("./cmd/nitrobox-core/")
        .current_dir(&go_dir)
        .env("CGO_ENABLED", "1")
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => panic!(
            "go build failed (exit code {:?}); see stderr above",
            s.code()
        ),
        Err(e) => panic!("failed to spawn `go build`: {}", e),
    }
}
