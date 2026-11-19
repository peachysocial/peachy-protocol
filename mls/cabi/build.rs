// SPDX-License-Identifier: MIT
//! Generate the C header, into `OUT_DIR` — never over the committed copy.
//!
//! The committed `include/peachy_mls.h` is what a Swift or Kotlin wrapper is
//! written against, and it has to be readable without a Rust toolchain in the
//! loop. A build script that overwrote it on every `cargo build` would keep it
//! honest but would also mutate a tracked file behind the developer's back, and
//! a cross-compile or a CI run would quietly dirty the tree.
//!
//! So this writes to `OUT_DIR` and hands the path to the crate as an env var;
//! `tests/header.rs` compares the two and fails with the copy command if they
//! differ. The header is then exactly as reviewable as any other diff.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    let crate_dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => return,
    };
    let out_dir = match std::env::var("OUT_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => return,
    };
    let header = out_dir.join("peachy_mls.h");

    let config = cbindgen::Config::from_file(crate_dir.join("cbindgen.toml"))
        .unwrap_or_else(|err| panic!("cbindgen.toml should parse: {err}"));

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            bindings.write_to_file(&header);
            // The only place the path goes: nothing is written into the source
            // tree, which may be read-only. `tests/header.rs` prints it in the
            // copy command when the committed header has drifted.
            println!(
                "cargo:rustc-env=PEACHY_MLS_GENERATED_HEADER={}",
                header.display()
            );
        }
        Err(err) => {
            // Not fatal. A header that could not be generated must not stop the
            // library from building — the committed one is still there, and
            // tests/header.rs is where the drift is reported.
            println!("cargo:warning=cbindgen could not generate the header: {err}");
            println!("cargo:rustc-env=PEACHY_MLS_GENERATED_HEADER=");
        }
    }
}
