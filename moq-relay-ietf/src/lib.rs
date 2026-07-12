// SPDX-FileCopyrightText: 2024-2026 Cloudflare Inc., Luke Curley, Mike English and contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! MoQ Relay library for building Media over QUIC relay servers.
//!
//! This crate provides the core relay functionality that can be embedded
//! into other applications. The relay handles:
//!
//! - Accepting QUIC connections from publishers and subscribers
//! - Routing media between local and remote endpoints
//! - Coordinating namespace/track registration across relay clusters
//!
//! The default `runtime` feature provides the complete relay and its binary.
//! Disable default features to depend only on the admission contract, including
//! [`SessionAdmission`], [`AdmissionLease`], and [`AdmissionSessionId`].
//!
//! # Example
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use moq_relay_ietf::{Relay, RelayConfig, FileCoordinator};
//!
//! // Create a coordinator (FileCoordinator for multi-relay deployments)
//! let coordinator = FileCoordinator::new("/path/to/coordination/file", "https://relay.example.com");
//!
//! // Configure and create the relay
//! let relay = Relay::new(RelayConfig {
//!     bind: "[::]:443".parse().unwrap(),
//!     tls: tls_config,
//!     coordinator,
//!     // ... other options
//! })?;
//!
//! // Run the relay
//! relay.run().await?;
//! ```

mod admission;
#[cfg(feature = "runtime")]
mod api;
#[cfg(feature = "runtime")]
mod capacity;
#[cfg(feature = "runtime")]
mod consumer;
#[cfg(feature = "runtime")]
mod coordinator;
#[cfg(feature = "runtime")]
mod diagnostics;
#[cfg(feature = "runtime")]
mod local;
#[cfg(feature = "runtime")]
pub mod metrics;
#[cfg(feature = "runtime")]
mod producer;
#[cfg(feature = "runtime")]
mod relay;
#[cfg(feature = "runtime")]
mod remote;
#[cfg(feature = "runtime")]
mod session;
#[cfg(feature = "runtime")]
mod web;

pub use admission::*;
#[cfg(feature = "runtime")]
pub use api::*;
#[cfg(feature = "runtime")]
pub use capacity::*;
#[cfg(feature = "runtime")]
pub use consumer::*;
#[cfg(feature = "runtime")]
pub use coordinator::*;
#[cfg(feature = "runtime")]
pub use diagnostics::*;
#[cfg(feature = "runtime")]
pub use local::*;
#[cfg(feature = "runtime")]
pub use producer::*;
#[cfg(feature = "runtime")]
pub use relay::*;
#[cfg(feature = "runtime")]
pub use remote::{
    RemoteCapacityError, RemoteCapacityResource, RemoteManager, RemoteManagerLimits,
    RemoteManagerLimitsError, RemoteManagerSnapshot,
};
#[cfg(feature = "runtime")]
pub use session::*;
#[cfg(feature = "runtime")]
pub use web::*;
