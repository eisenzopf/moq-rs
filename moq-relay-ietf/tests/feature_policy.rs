// SPDX-FileCopyrightText: 2026 Bridgefu contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

const MANIFEST: &str = include_str!("../Cargo.toml");
const LIBRARY: &str = include_str!("../src/lib.rs");
const ADMISSION: &str = include_str!("../src/admission.rs");

#[test]
fn complete_runtime_remains_the_default_and_is_required_by_the_binary() {
    assert!(MANIFEST.contains("default = [\"runtime\"]"));
    assert!(MANIFEST.contains("required-features = [\"runtime\"]"));
    assert!(MANIFEST
        .contains("metrics-prometheus = [\"runtime\", \"dep:metrics-exporter-prometheus\"]"));
}

#[test]
fn runtime_dependencies_are_optional() {
    for dependency in [
        "moq-api",
        "web-transport",
        "url",
        "tokio-util",
        "futures",
        "axum",
        "hyper-serve",
        "tower-http",
        "serde",
        "serde_json",
        "fs2",
        "clap",
        "tracing",
        "tracing-subscriber",
        "metrics",
    ] {
        let declaration = MANIFEST
            .lines()
            .find(|line| line.starts_with(&format!("{dependency} =")))
            .unwrap_or_else(|| panic!("missing dependency declaration for {dependency}"));
        assert!(
            declaration.contains("optional = true"),
            "runtime dependency is not optional: {dependency}"
        );
    }
}

#[test]
fn admission_is_unconditional_and_relay_modules_are_runtime_gated() {
    assert!(LIBRARY.contains("\nmod admission;\n"));
    assert!(LIBRARY.contains("\npub use admission::*;\n"));

    for declaration in [
        "mod api;",
        "mod capacity;",
        "mod consumer;",
        "mod coordinator;",
        "mod diagnostics;",
        "mod local;",
        "pub mod metrics;",
        "mod producer;",
        "mod relay;",
        "mod remote;",
        "mod session;",
        "mod web;",
    ] {
        assert!(
            LIBRARY.contains(&format!("#[cfg(feature = \"runtime\")]\n{declaration}")),
            "runtime module is not feature-gated: {declaration}"
        );
    }
}

#[test]
fn admission_source_does_not_import_relay_runtime_dependencies() {
    for forbidden in [
        "axum",
        "hyper_serve",
        "hyper_util",
        "moq_api",
        "web_transport",
        "tower_http",
        "tokio_util",
        "futures::",
        "metrics::",
        "tracing::",
        "serde::",
        "serde_json",
        "fs2::",
        "url::",
    ] {
        assert!(
            !ADMISSION.contains(forbidden),
            "admission contract references runtime dependency: {forbidden}"
        );
    }

    assert_eq!(ADMISSION.matches("clap::").count(), 1);
    assert!(ADMISSION.contains("#[cfg_attr(feature = \"runtime\", derive(clap::ValueEnum))]"));
}
