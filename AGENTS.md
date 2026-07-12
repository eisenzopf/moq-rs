<!-- SPDX-FileCopyrightText: 2024-2026 Cloudflare Inc., Luke Curley, Mike English and contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Repository Guidance

## Scope And Constraints

- This fork targets MoQT `draft-ietf-moq-transport-19`.
- Core protocol code lives in `moq-transport`; relay behavior lives in `moq-relay-ietf`.
- `moq-relay-ietf` is production critical, so prefer small, tested changes over broad refactors.
- Avoid breaking public APIs, wire behavior, CLI flags, and operator workflows unless explicitly requested.
- Do not add `unsafe` code unless there is a clear performance or FFI need and the safety invariant is documented at the call site.
- Do not commit or directly edit draft spec text files (`docs/draft-*.txt`) unless explicitly requested; they are local protocol reference material.
- Avoid `unwrap()`, `expect()`, `panic!`, `todo!`, `unimplemented!`, and `dbg!` in production paths. Propagate errors or convert lock poisoning to an internal error instead.

## Commands

- Run `cargo fmt --all` after Rust changes.
- Run `cargo test -p moq-transport` for protocol changes.
- Run `cargo test -p moq-relay-ietf` or `cargo build -p moq-relay-ietf` for relay-only changes.
- Run `cargo build --workspace` when shared APIs, relay behavior, or test-client behavior changes.
- Consider `cargo clippy --workspace --all-targets` before larger changes or when review asks for lint coverage.
- When tests fail, diagnose from compiler/test output first and keep fixes scoped to the failing behavior.

## Draft-19 Terminology

- Use `PUBLISH_NAMESPACE` terminology in protocol code and docs; older docs and comments may call this Announce.
- `PublishedNamespace` represents an inbound `PUBLISH_NAMESPACE` received by a subscriber.
- `TrackNamespacePrefix` is for `SUBSCRIBE_NAMESPACE` prefixes and may be empty; `TrackNamespace` is full and non-empty.
- `SUBSCRIBE_NAMESPACE` discovers namespaces; `SUBSCRIBE_TRACKS` requests matching track publications.
- `REQUEST_OK`, `REQUEST_ERROR`, and `REQUEST_UPDATE` are shared request response/update messages.
- `PUBLISH_OK` type `0x1E` is reserved; successful `PUBLISH` requests use `REQUEST_OK`.
- Requests (SUBSCRIBE, PUBLISH_NAMESPACE, etc.) are sent on individual bidirectional streams; responses on the same stream omit the Request ID field.
- `MAX_REQUEST_ID` and `REQUESTS_BLOCKED` do not exist in draft-19.

## External Contributions

- Treat public GitHub mirror and community PRs with heightened scrutiny for protocol correctness, resource bounds, panic-free production paths, and safe peer-facing errors.
- Be careful with compatibility: do not rename public CLI flags or remove behavior solely for terminology cleanup without an explicit migration decision.
