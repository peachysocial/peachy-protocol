// swift-tools-version:5.9
// SPDX-License-Identifier: MIT
//
// PeachyMLS — the Swift binding over `mls/cabi`'s C door.
//
// BOTH of Peachy's Apple app targets link this package (docs/mls-core.md
// §Swift binding): `Peachy` and `PeachyMac` take the `PeachyMLS` product as a
// local package dependency, so a break in the binding is a compile error in the
// apps' own build rather than something discovered by whoever first tries to
// adopt it.
//
// ## Why the core target is a system library and not a binary target
//
// The obvious manifest declares `PeachyMLSCore` as a `.binaryTarget` pointing
// at `build/PeachyMLSCore.xcframework`. That is exactly what an app should
// link, and it is what `build-xcframework.sh` produces — but a `.binaryTarget`
// path has to exist when the MANIFEST is evaluated, so `swift test` (and, now
// that an app depends on this package, `xcodegen generate` and every Xcode
// package resolution) in a fresh checkout would fail while PARSING
// Package.swift, with a message that says nothing about the Rust build being
// the thing that was missing. Worse, the shipping xcframework is built WITHOUT
// the test-only features — as it must be, since a release app has no business
// carrying code that can mint a device credential, nor a JSON harness for
// replaying a test fixture — so the test suite could not mint the credential it
// needs to open a client at all.
//
// ## Who links the archive, and which one
//
// So `PeachyMLSCore` is header-only — a system library over the modulemap and
// a symlink to `mls/cabi/include/peachy_mls.h` — and `PeachyMLS` itself names
// NO library to link. A static Swift target with unresolved C symbols is a
// perfectly good archive; resolving them is the consumer's job, and there are
// two consumers wanting two different archives:
//
//   - `PeachyMLSTests` links `build/host/libpeachy_mls_cabi.a`, the macOS arm64
//     build WITH `test-issuer` and `fixture`, through the `-L` below. Run
//     `./build-xcframework.sh` first; it writes that file as well as the
//     xcframework.
//   - An app (Xcode, `xcodebuild`) links `build/PeachyMLSCore.xcframework` —
//     three slices, no test issuer and no fixture door — declared beside this
//     package in the app's project. The app targets carry a pre-build
//     script that names `build-xcframework.sh` if the framework is absent, so
//     the failure is a sentence rather than a page of undefined symbols.
//
// The alternative — leaving the `-L` on `PeachyMLS` — would put the host
// archive on an iOS app's link line, where it is the wrong architecture and the
// wrong feature set, and the error would arrive as a missing symbol in a
// slice nobody meant to use.
//
// The cost of the split, stated plainly: `swift test` exercises a different
// archive from the one an app links. The Swift code is identical, the C ABI is
// identical and the header is the same symlinked file; what differs is one
// cargo feature and the target triple. The thing this arrangement CANNOT catch
// is a break that only appears when cross-compiling to iOS, which is why
// `build-xcframework.sh` builds all three slices and link-checks each one, and
// why the apps' build runs it before compiling the apps.
//
// `.unsafeFlags` on the TEST target is why this package cannot be a dependency
// of another SwiftPM package, and it is deliberately confined there: an Xcode
// project may depend on a local package that uses them, another package may
// not, and an app is meant to take the xcframework anyway.

import PackageDescription

let packageDirectory = Context.packageDirectory

let package = Package(
    name: "PeachyMLS",
    platforms: [
        // iOS 17 / macOS 14 are floors below what the Peachy apps build
        // against (they deploy to 26.0); nothing here
        // needs a newer one, and a package floor above an app's is an error.
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "PeachyMLS", targets: ["PeachyMLS"])
    ],
    targets: [
        // The header only. See Sources/PeachyMLSCore/module.modulemap.
        .systemLibrary(name: "PeachyMLSCore", path: "Sources/PeachyMLSCore"),

        // No linkerSettings: see "Who links the archive, and which one" above.
        .target(
            name: "PeachyMLS",
            dependencies: ["PeachyMLSCore"]
        ),

        .testTarget(
            name: "PeachyMLSTests",
            dependencies: ["PeachyMLS", "PeachyMLSCore"],
            swiftSettings: [
                // The two test-only doors are `#if defined(…)` in the header,
                // matching the cargo features the host archive is built with
                // (`--features test-issuer,fixture` in build-xcframework.sh).
                // Only the tests define them, so a mistake that puts an issuer
                // call — or a golden-fixture call — in PeachyMLS itself does
                // not compile, and the xcframework an app links carries
                // neither symbol.
                .unsafeFlags([
                    "-Xcc", "-DPEACHY_MLS_TEST_ISSUER",
                    "-Xcc", "-DPEACHY_MLS_FIXTURE",
                ])
            ],
            linkerSettings: [
                // The host archive, with both test features.
                // `build-xcframework.sh` writes it; without it the link fails with
                // `ld: library 'peachy_mls_cabi' not found`, naming this
                // directory, which is the whole of the diagnosis.
                .unsafeFlags(["-L\(packageDirectory)/build/host"]),
                .linkedLibrary("peachy_mls_cabi"),
            ]
        ),
    ]
)
