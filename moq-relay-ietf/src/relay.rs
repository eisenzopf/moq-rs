// SPDX-FileCopyrightText: 2024-2026 Cloudflare Inc., Luke Curley, Mike English and contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{future::Future, net, path::PathBuf, pin::Pin, sync::Arc, time::Duration};

use anyhow::Context;

use futures::{stream::FuturesUnordered, FutureExt, StreamExt};
use moq_native_ietf::quic::{self, Endpoint};
use url::Url;

use crate::{
    metrics::GaugeGuard, AdmissionDecision, AdmissionRequest, Consumer, Coordinator,
    ListenerSecurityPolicy, Locals, Producer, RelayCapacity, RelayCapacityLimits, RelayIdentity,
    RemoteManager, RemoteManagerLimits, Session, SessionAdmission,
};

// A type alias for boxed future
type ServerFuture = Pin<
    Box<
        dyn Future<
                Output = (
                    anyhow::Result<quic::SessionConnection>,
                    quic::Server,
                    Arc<tokio::sync::Semaphore>,
                    Arc<tokio::sync::Semaphore>,
                ),
            > + Send,
    >,
>;

/// Configuration for the relay.
pub struct RelayConfig {
    /// Listen on this address
    pub bind: Option<net::SocketAddr>,

    /// Optional list of endpoints if provided, we won't use bind
    pub endpoints: Vec<Endpoint>,

    /// The TLS configuration.
    pub tls: moq_native_ietf::tls::Config,

    /// Directory to write qlog files (one per connection)
    pub qlog_dir: Option<PathBuf>,

    /// Directory to write mlog files (one per connection)
    pub mlog_dir: Option<PathBuf>,

    /// Forward all PUBLISH_NAMESPACE messages to the (optional) upstream URL.
    pub announce: Option<Url>,

    /// Our hostname which we advertise to other origins.
    /// We use QUIC, so the certificate must be valid for this address.
    pub node: Option<Url>,

    /// The coordinator for namespace/track registration and discovery.
    pub coordinator: Arc<dyn Coordinator>,

    /// Admission policy evaluated before coordinator or media state mutation.
    pub admission: Arc<dyn SessionAdmission>,

    /// Explicitly enables development-only policies and anonymous TLS peers.
    pub development: bool,

    /// Security role shared by this relay process's inbound listeners.
    /// Deploy separate relay processes when publisher and browser listener
    /// roles require different TLS postures.
    pub listener_security: ListenerSecurityPolicy,

    pub setup_timeout: Duration,
    pub admission_timeout: Duration,
    pub cleanup_timeout: Duration,
    pub max_pending_admissions: usize,
    pub max_active_sessions: usize,
    pub token_revalidation_interval: Duration,

    /// Hierarchical limits for retained namespace, track, subscription, and
    /// track-status request state.
    pub capacity_limits: RelayCapacityLimits,

    /// Limits and idle eviction windows for retained upstream relay state.
    pub remote_limits: RemoteManagerLimits,

    /// Per-published-namespace track cache and pending request limits.
    pub tracks_limits: moq_transport::serve::TracksLimits,

    /// Process-shared transport request and retained-media limits.
    pub request_limits: moq_transport::session::RequestLimits,
}

/// MoQ Relay server.
pub struct Relay {
    quic_endpoints: Vec<Endpoint>,
    announce_url: Option<Url>,
    mlog_dir: Option<PathBuf>,
    locals: Locals,
    remotes: RemoteManager,
    coordinator: Arc<dyn Coordinator>,
    admission: Arc<dyn SessionAdmission>,
    listener_security: ListenerSecurityPolicy,
    setup_timeout: Duration,
    admission_timeout: Duration,
    cleanup_timeout: Duration,
    max_pending_admissions: usize,
    max_active_sessions: usize,
    production: bool,
    token_revalidation_interval: Duration,
    capacity: RelayCapacity,
    tracks_limits: moq_transport::serve::TracksLimits,
    request_capacity: moq_transport::session::RequestCapacity,
}

/// Cloneable aggregate diagnostics that can be retained while [`Relay::run`] owns the server.
#[derive(Clone)]
pub struct RelayDiagnostics {
    capacity: RelayCapacity,
    remotes: RemoteManager,
    request_capacity: moq_transport::session::RequestCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayDiagnosticsSnapshot {
    pub capacity: crate::RelayCapacitySnapshot,
    pub remotes: crate::RemoteManagerSnapshot,
    pub retained_process_bytes: usize,
    pub max_retained_process_bytes: usize,
}

impl RelayDiagnostics {
    pub async fn snapshot(&self) -> RelayDiagnosticsSnapshot {
        let retention = self.request_capacity.retention_stats();
        RelayDiagnosticsSnapshot {
            capacity: self.capacity.snapshot(),
            remotes: self.remotes.snapshot().await,
            retained_process_bytes: retention.process_bytes,
            max_retained_process_bytes: retention.max_process_bytes,
        }
    }
}

fn listener_decision_is_valid(
    policy: ListenerSecurityPolicy,
    peer_identity: &moq_native_ietf::tls::PeerIdentity,
    setup_authorization: Option<&moq_transport::session::SetupAuthorization>,
    decision: &AdmissionDecision,
    production: bool,
) -> bool {
    if decision.claims.validate().is_err() {
        return false;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(u64::MAX, |duration| duration.as_secs());
    match policy {
        ListenerSecurityPolicy::MutualTlsPublisher => {
            peer_identity.is_authenticated()
                && decision_matches_listener_role(policy, decision, production, now)
        }
        ListenerSecurityPolicy::TokenSubscriber => {
            setup_authorization.is_some_and(|token| !token.is_empty())
                && decision_matches_listener_role(policy, decision, production, now)
        }
        ListenerSecurityPolicy::Development => {
            decision_matches_listener_role(policy, decision, production, now)
        }
    }
}

fn decision_matches_listener_role(
    policy: ListenerSecurityPolicy,
    decision: &AdmissionDecision,
    production: bool,
    now: u64,
) -> bool {
    match policy {
        ListenerSecurityPolicy::MutualTlsPublisher => {
            decision.principal.method == crate::AuthenticationMethod::MutualTls
                && decision.claims.publish
                && !decision.claims.subscribe
                && decision.claims.scope.is_some()
        }
        ListenerSecurityPolicy::TokenSubscriber => {
            let base = decision.principal.method == crate::AuthenticationMethod::SetupToken
                && decision.claims.subscribe
                && !decision.claims.publish;
            if !base || !production {
                return base;
            }
            decision
                .claims
                .scope
                .as_ref()
                .is_some_and(|scope| !scope.is_empty())
                && decision
                    .claims
                    .token_id
                    .as_ref()
                    .is_some_and(|token_id| !token_id.is_empty())
                && decision
                    .claims
                    .expires_at_unix_seconds
                    .is_some_and(|expiry| expiry > now)
        }
        ListenerSecurityPolicy::Development => {
            decision.principal.method == crate::AuthenticationMethod::Development
        }
    }
}

fn resolved_scope_is_valid(scope_id: &str) -> bool {
    !scope_id.is_empty()
        && scope_id.len() <= crate::AdmissionClaims::MAX_SCOPE_BYTES
        && !scope_id.chars().any(char::is_control)
}

fn should_log_admission_warning() -> bool {
    static WARNINGS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = WARNINGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    sequence < 4 || sequence.is_multiple_of(128)
}

async fn report_retention_metrics(
    capacity: moq_transport::session::RequestCapacity,
) -> anyhow::Result<()> {
    loop {
        let stats = capacity.retention_stats();
        metrics::gauge!("moq_relay_retained_bytes", "scope" => "process")
            .set(stats.process_bytes as f64);
        metrics::gauge!("moq_relay_retained_bytes_limit", "scope" => "process")
            .set(stats.max_process_bytes as f64);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn close_and_wait(
    session: &web_transport::Session,
    code: moq_transport::session::SessionTerminationCode,
    reason: &str,
    timeout: Duration,
) {
    session.close(code.as_u32(), reason);
    if tokio::time::timeout(timeout, session.closed())
        .await
        .is_err()
    {
        tracing::debug!(
            code = code.as_u32(),
            "timed out waiting for pre-admission connection cleanup"
        );
    }
}

async fn monitor_token_lease(
    admission: &dyn SessionAdmission,
    decision: &AdmissionDecision,
    interval: Duration,
    validation_timeout: Duration,
) -> Result<(), crate::AdmissionError> {
    monitor_token_lease_with_clock(
        admission,
        decision,
        interval,
        validation_timeout,
        || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(u64::MAX, |duration| duration.as_secs())
        },
        tokio::time::sleep,
    )
    .await
}

async fn monitor_token_lease_with_clock<Now, Sleep, SleepFuture>(
    admission: &dyn SessionAdmission,
    decision: &AdmissionDecision,
    interval: Duration,
    validation_timeout: Duration,
    mut now: Now,
    mut sleep: Sleep,
) -> Result<(), crate::AdmissionError>
where
    Now: FnMut() -> u64,
    Sleep: FnMut(Duration) -> SleepFuture,
    SleepFuture: Future<Output = ()>,
{
    loop {
        let expiry = decision
            .claims
            .expires_at_unix_seconds
            .ok_or(crate::AdmissionError::PolicyDenied)?;
        let before_sleep = now();
        if expiry <= before_sleep {
            return Err(crate::AdmissionError::PolicyDenied);
        }
        let until_expiry = Duration::from_secs(expiry - before_sleep);
        sleep(interval.min(until_expiry)).await;

        // Expiry is an independent hard deadline. Re-check it immediately
        // after sleeping so an exact-boundary session cannot remain active
        // for an additional admission/revalidation timeout.
        if expiry <= now() {
            return Err(crate::AdmissionError::PolicyDenied);
        }
        tokio::time::timeout(validation_timeout, admission.revalidate(decision))
            .await
            .map_err(|_| crate::AdmissionError::PolicyDenied)??;
    }
}

async fn revalidate_token_before_activation(
    admission: &dyn SessionAdmission,
    decision: &AdmissionDecision,
    validation_timeout: Duration,
    now: u64,
) -> Result<(), crate::AdmissionError> {
    if decision
        .claims
        .expires_at_unix_seconds
        .is_none_or(|expiry| expiry <= now)
    {
        return Err(crate::AdmissionError::PolicyDenied);
    }
    tokio::time::timeout(validation_timeout, admission.revalidate(decision))
        .await
        .map_err(|_| crate::AdmissionError::PolicyDenied)??;
    Ok(())
}

impl Relay {
    pub fn new(config: RelayConfig) -> anyhow::Result<Self> {
        if config.bind.is_some() && !config.endpoints.is_empty() {
            anyhow::bail!("cannot specify both bind and endpoints");
        }

        if config.admission.development_only() && !config.development {
            anyhow::bail!("development-only admission requires explicit development mode");
        }
        if config.admission.allow_all()
            && config.listener_security != ListenerSecurityPolicy::Development
        {
            anyhow::bail!("allow-all admission is restricted to development listeners");
        }
        if !config.development {
            anyhow::ensure!(
                config.qlog_dir.is_none() && config.mlog_dir.is_none(),
                "per-session qlog/mlog files are development-only without bounded retention"
            );
            anyhow::ensure!(
                config
                    .endpoints
                    .iter()
                    .all(|endpoint| !endpoint.writes_per_connection_diagnostics()),
                "production relay endpoints cannot create unbounded per-session qlog files"
            );
            anyhow::ensure!(
                config.endpoints.iter().all(Endpoint::uses_stateless_retry),
                "production relay endpoints require QUIC stateless retry"
            );
            anyhow::ensure!(
                config
                    .endpoints
                    .iter()
                    .all(|endpoint| !endpoint.tls_key_logging_enabled()),
                "production relay endpoints cannot enable TLS key logging"
            );
        }
        anyhow::ensure!(
            !config.setup_timeout.is_zero(),
            "SETUP timeout must be positive"
        );
        anyhow::ensure!(
            !config.admission_timeout.is_zero(),
            "admission timeout must be positive"
        );
        anyhow::ensure!(
            !config.cleanup_timeout.is_zero(),
            "pre-admission cleanup timeout must be positive"
        );
        anyhow::ensure!(
            config.max_pending_admissions > 0,
            "pending admission limit must be positive"
        );
        anyhow::ensure!(
            config.max_pending_admissions <= tokio::sync::Semaphore::MAX_PERMITS,
            "pending admission limit exceeds the semaphore maximum"
        );
        anyhow::ensure!(
            config.max_active_sessions > 0,
            "active session limit must be positive"
        );
        anyhow::ensure!(
            config.max_active_sessions <= tokio::sync::Semaphore::MAX_PERMITS,
            "active session limit exceeds the semaphore maximum"
        );
        anyhow::ensure!(
            !config.token_revalidation_interval.is_zero(),
            "token revalidation interval must be positive"
        );
        let capacity = RelayCapacity::new(config.capacity_limits)?;
        config.tracks_limits.validate()?;
        let request_capacity = moq_transport::session::RequestCapacity::new(config.request_limits)?;

        if !config.development {
            anyhow::ensure!(
                config.listener_security != ListenerSecurityPolicy::Development,
                "development listener security cannot be used in production"
            );
            if config.listener_security == ListenerSecurityPolicy::TokenSubscriber {
                anyhow::ensure!(
                    config.admission.supports_production_token_leases(),
                    "production token listeners require an external replay- and lease-aware admission policy"
                );
            }
            anyhow::ensure!(
                config.admission.supports_bounded_session_leases(),
                "production admission policies must provide bounded principal/tenant session leases"
            );
            anyhow::ensure!(
                config.tls.verifies_server_certificates(),
                "production relay mode forbids --tls-disable-verify for outbound connections"
            );
            anyhow::ensure!(
                config
                    .endpoints
                    .iter()
                    .all(Endpoint::verifies_server_certificates),
                "all production relay endpoints must verify outbound server certificates"
            );
        }

        let required_client_auth = match config.listener_security {
            ListenerSecurityPolicy::MutualTlsPublisher => {
                moq_native_ietf::tls::ClientAuthMode::Required
            }
            ListenerSecurityPolicy::TokenSubscriber | ListenerSecurityPolicy::Development => {
                moq_native_ietf::tls::ClientAuthMode::Disabled
            }
        };
        anyhow::ensure!(
            config.tls.client_auth_mode() == required_client_auth,
            "listener TLS client-auth mode does not match its security policy"
        );
        anyhow::ensure!(
            config
                .endpoints
                .iter()
                .all(|endpoint| endpoint.client_auth_mode() == required_client_auth),
            "endpoint TLS client-auth mode does not match listener security policy"
        );

        let endpoints = if let Some(bind) = config.bind {
            let endpoint = quic::Endpoint::new(quic::Config::new(
                bind,
                config.qlog_dir.clone(),
                config.tls.clone(),
            )?)?;
            vec![endpoint]
        } else {
            config.endpoints
        };

        if endpoints.is_empty() {
            anyhow::bail!("no endpoints available to start the server");
        }

        // Validate mlog directory if provided
        if let Some(mlog_dir) = &config.mlog_dir {
            if !mlog_dir.exists() {
                anyhow::bail!("mlog directory does not exist: {}", mlog_dir.display());
            }
            if !mlog_dir.is_dir() {
                anyhow::bail!("mlog path is not a directory: {}", mlog_dir.display());
            }
            tracing::info!("mlog output enabled: {}", mlog_dir.display());
        }

        let locals = Locals::new();

        // FIXME(itzmanish): have a generic filter to find endpoints for forward, remote etc.
        let remote_clients = endpoints
            .iter()
            .map(|endpoint| endpoint.client.clone())
            .collect::<Vec<_>>();

        // Create remote manager - uses coordinator for namespace lookups
        let remotes = RemoteManager::with_limits_and_capacity(
            config.coordinator.clone(),
            remote_clients,
            config.remote_limits,
            request_capacity.clone(),
        )?;

        Ok(Self {
            quic_endpoints: endpoints,
            announce_url: config.announce,
            mlog_dir: config.mlog_dir,
            locals,
            remotes,
            coordinator: config.coordinator,
            admission: config.admission,
            listener_security: config.listener_security,
            setup_timeout: config.setup_timeout,
            admission_timeout: config.admission_timeout,
            cleanup_timeout: config.cleanup_timeout,
            max_pending_admissions: config.max_pending_admissions,
            max_active_sessions: config.max_active_sessions,
            production: !config.development,
            token_revalidation_interval: config.token_revalidation_interval,
            capacity,
            tracks_limits: config.tracks_limits,
            request_capacity,
        })
    }

    /// Return aggregate capacity diagnostics without principal or scope labels.
    pub fn capacity_snapshot(&self) -> crate::RelayCapacitySnapshot {
        self.capacity.snapshot()
    }

    pub async fn remote_snapshot(&self) -> crate::RemoteManagerSnapshot {
        self.remotes.snapshot().await
    }

    /// Return a diagnostics handle that remains usable after moving this relay into `run`.
    pub fn diagnostics(&self) -> RelayDiagnostics {
        RelayDiagnostics {
            capacity: self.capacity.clone(),
            remotes: self.remotes.clone(),
            request_capacity: self.request_capacity.clone(),
        }
    }

    /// Run the relay server.
    pub async fn run(self) -> anyhow::Result<()> {
        let Self {
            quic_endpoints,
            announce_url,
            mlog_dir,
            locals,
            remotes,
            coordinator,
            admission,
            listener_security,
            setup_timeout,
            admission_timeout,
            cleanup_timeout,
            max_pending_admissions,
            max_active_sessions,
            production,
            token_revalidation_interval,
            capacity,
            tracks_limits,
            request_capacity,
        } = self;

        let run_result: anyhow::Result<()> = async {
            let mut tasks = FuturesUnordered::new();
            tasks.push(report_retention_metrics(request_capacity.clone()).boxed());

            // Use the remote manager for routing to remote relays.
            let remote_manager = remotes.clone();

            // Start the forwarder, if any
            let forward_producer = if let Some(url) = &announce_url {
                tracing::info!(
                    remote_url = %crate::redact_url_for_logging(url),
                    "forwarding PUBLISH_NAMESPACE messages"
                );

                // Establish a QUIC connection to the forward URL
                let (target, policy) = quic::compatibility_target(url)?;
                let connection = quic_endpoints[0]
                    .client
                    .connect_target(&target, policy, None)
                    .await
                    .context("failed to establish forward connection")?;

                // Create the MoQ session over the connection
                let (session, publisher, subscriber) =
                    moq_transport::session::Session::connect_with_capacity(
                        connection.session,
                        None,
                        connection.negotiated,
                        &request_capacity,
                    )
                    .await
                    .context("failed to establish forward session")?;

                // Use the connection path already validated and stored by Session::connect().
                // The forward session is scoped to whatever path the announce URL specifies.
                //
                // Note: the forward connection intentionally does not call
                // coordinator.resolve_scope(). The announce URL is operator-configured
                // (via --announce), not client-supplied, so it doesn't need the same
                // auth/permission checks that incoming client connections get. The
                // forward session always gets both Producer and Consumer (full
                // read-write) since it's acting as a relay peer, not a client.
                //
                // Limitation: all incoming scopes are forwarded to this single upstream scope.
                // Multi-scope forwarding (routing different incoming scopes to different
                // upstream paths) would require per-scope forward connections.
                let forward_scope = session.connection_path().map(|s| s.to_string());
                let forward_identity = RelayIdentity::operator(forward_scope.clone());

                let forward_coordinator = coordinator.clone();
                let session = Session {
                    session,
                    producer: Some(Producer::new_admitted(
                        publisher,
                        locals.clone(),
                        remote_manager.clone(),
                        forward_identity.clone(),
                        capacity.clone(),
                    )),
                    consumer: Some(Consumer::new_admitted(
                        subscriber,
                        locals.clone(),
                        forward_coordinator,
                        None,
                        forward_identity,
                        capacity.clone(),
                        tracks_limits,
                    )),
                    // Forward connections are always full read-write relay peers,
                    // so no reject loops needed.
                    reject_publishes: None,
                    reject_subscribes: None,
                };

                let forward_producer = session.producer.clone();

                tasks.push(async move { session.run().await.context("forwarding failed") }.boxed());

                forward_producer
            } else {
                None
            };

            let servers: Vec<quic::Server> = quic_endpoints
                .into_iter()
                .map(|endpoint| endpoint.server.context("missing TLS certificate for server"))
                .collect::<anyhow::Result<_>>()?;

            // This will hold the futures for all our listening servers.
            let mut accepts: FuturesUnordered<ServerFuture> = FuturesUnordered::new();
            for mut server in servers {
                tracing::info!("listening on {}", server.local_addr()?);
                let pending_admissions = Arc::new(tokio::sync::Semaphore::new(
                    max_pending_admissions,
                ));
                let active_sessions =
                    Arc::new(tokio::sync::Semaphore::new(max_active_sessions));

                // Create a future, box it, and push it to the collection.
                accepts.push(
                    async move {
                        let conn = server.accept_connection().await.context("accept failed");
                        (conn, server, pending_admissions, active_sessions)
                    }
                    .boxed(),
                );
            }

            loop {
                tokio::select! {
                    // This branch polls all the `accept` futures concurrently.
                    Some((conn_result, mut server, pending_admissions, active_sessions)) = accepts.next() => {
                        // An accept operation has completed.
                        // First, immediately queue up the next accept() call for this server.
                        let next_pending_admissions = pending_admissions.clone();
                        let next_active_sessions = active_sessions.clone();
                        accepts.push(
                            async move {
                                let conn = server.accept_connection().await.context("accept failed");
                                (conn, server, next_pending_admissions, next_active_sessions)
                            }
                            .boxed(),
                        );

                        let connection = conn_result.context("failed to accept QUIC connection")?;
                        metrics::counter!("moq_relay_connections_total").increment(1);
                        let admission_permit = match pending_admissions.try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                let session = connection.session;
                                // Overload rejection is intentionally inline:
                                // `close` is nonblocking and we retain no
                                // per-connection cleanup future, so a flood
                                // cannot grow the relay task set.
                                session.close(
                                    moq_transport::session::SessionTerminationCode::InternalError.as_u32(),
                                    "pending admission capacity exhausted",
                                );
                                metrics::counter!("moq_relay_connection_errors_total", "stage" => "admission_capacity").increment(1);
                                metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                continue;
                            }
                        };

                        let connection_id = connection.connection_id;
                        let negotiated = connection.negotiated;
                        let peer_identity = connection.peer_identity;
                        let conn = connection.session;

                        // Construct mlog path from connection ID if mlog directory is configured
                        let mlog_path = mlog_dir.as_ref()
                            .map(|dir| dir.join(format!("{}_server.mlog", connection_id)));

                        let locals = locals.clone();
                        let remotes = remote_manager.clone();
                        let forward = forward_producer.clone();
                        let coordinator = coordinator.clone();
                        let admission = admission.clone();
                        let active_sessions = active_sessions.clone();
                        let capacity = capacity.clone();
                        let request_capacity = request_capacity.clone();

                        // Spawn a new task to handle the connection
                        tasks.push(async move {
                            let admission_permit = admission_permit;
                            // Track active connections - decrements when task completes
                            let _conn_guard = GaugeGuard::new("moq_relay_active_connections");

                            // Clone the raw connection so we can close it with a proper
                            // error code if scope resolution fails after the MoQ handshake.
                            let raw_conn = conn.clone();

                            // Create the MoQ session over the connection (setup handshake etc)
                            let (session, publisher, subscriber) = match tokio::time::timeout(
                                setup_timeout,
                                moq_transport::session::Session::accept_with_capacity(
                                    conn,
                                    mlog_path,
                                    negotiated,
                                    &request_capacity,
                                ),
                            ).await {
                                Ok(Ok(session)) => session,
                                Ok(Err(err)) => {
                                    tracing::warn!(error = %err, "failed to accept MoQ session: {}", err);
                                    metrics::counter!("moq_relay_connection_errors_total", "stage" => "session_accept").increment(1);
                                    close_and_wait(&raw_conn, moq_transport::session::SessionTerminationCode::ProtocolViolation, "invalid SETUP", cleanup_timeout).await;
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                    return Ok(());
                                }
                                Err(_) => {
                                    tracing::warn!("timed out waiting for peer SETUP");
                                    metrics::counter!("moq_relay_connection_errors_total", "stage" => "setup_timeout").increment(1);
                                    close_and_wait(&raw_conn, moq_transport::session::SessionTerminationCode::InternalError, "SETUP timeout", cleanup_timeout).await;
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                    return Ok(());
                                }
                            };

                            // Create our MoQ relay session
                            let mut moq_session = session;

                            let admission_request = AdmissionRequest {
                                peer_identity: &peer_identity,
                                target: moq_session.target(),
                                substrate: moq_session.transport(),
                                negotiated_protocol: moq_session.negotiated_transport().protocol,
                                setup_authorization: moq_session.peer_setup_authorization(),
                            };
                            let decision = match tokio::time::timeout(
                                admission_timeout,
                                admission.admit(admission_request),
                            ).await {
                                Ok(Ok(decision)) if listener_decision_is_valid(
                                    listener_security,
                                    &peer_identity,
                                    moq_session.peer_setup_authorization(),
                                    &decision,
                                    production,
                                ) => decision,
                                Ok(Ok(_)) => {
                                    if should_log_admission_warning() {
                                        tracing::warn!("admission decision violates listener security policy (warnings sampled)");
                                    }
                                    metrics::counter!("moq_relay_connection_errors_total", "stage" => "admission_claims").increment(1);
                                    close_and_wait(&raw_conn, moq_transport::session::SessionTerminationCode::Unauthorized, "session admission denied", cleanup_timeout).await;
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                    return Ok(());
                                }
                                Ok(Err(error)) => {
                                    if should_log_admission_warning() {
                                        tracing::warn!(
                                            peer = ?peer_identity,
                                            target = %moq_session.target().redacted_for_logging(),
                                            substrate = ?moq_session.transport(),
                                            protocol = moq_session.negotiated_transport().protocol,
                                            error = %error,
                                            "session admission denied (warnings sampled)"
                                        );
                                    }
                                    metrics::counter!("moq_relay_connection_errors_total", "stage" => "admission").increment(1);
                                    close_and_wait(&raw_conn, moq_transport::session::SessionTerminationCode::Unauthorized, "session admission denied", cleanup_timeout).await;
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                    return Ok(());
                                }
                                Err(_) => {
                                    if should_log_admission_warning() {
                                        tracing::warn!("session admission timed out (warnings sampled)");
                                    }
                                    metrics::counter!("moq_relay_connection_errors_total", "stage" => "admission_timeout").increment(1);
                                    close_and_wait(&raw_conn, moq_transport::session::SessionTerminationCode::Unauthorized, "session admission timeout", cleanup_timeout).await;
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                    return Ok(());
                                }
                            };
                            moq_session.clear_peer_setup_authorization();

                            // Bound all admitted sessions independently from
                            // the short pre-admission queue. This permit stays
                            // alive until Session::run and all teardown paths
                            // have completed.
                            let _active_session_permit = match active_sessions.try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    metrics::counter!("moq_relay_connection_errors_total", "stage" => "session_capacity").increment(1);
                                    close_and_wait(&raw_conn, moq_transport::session::SessionTerminationCode::InternalError, "active session capacity exhausted", cleanup_timeout).await;
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                    return Ok(());
                                }
                            };

                            // Give embedding applications a per-tenant/account
                            // RAII capacity seam. The guard is retained for the
                            // same lifetime as the relay's global permit.
                            let _policy_lease = match tokio::time::timeout(
                                admission_timeout,
                                admission.acquire_session_lease(&decision),
                            ).await {
                                Ok(Ok(lease)) => lease,
                                Ok(Err(error)) => {
                                    tracing::warn!(error = %error, "session admission capacity denied");
                                    metrics::counter!("moq_relay_connection_errors_total", "stage" => "policy_capacity").increment(1);
                                    close_and_wait(&raw_conn, moq_transport::session::SessionTerminationCode::InternalError, "session capacity exhausted", cleanup_timeout).await;
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                    return Ok(());
                                }
                                Err(_) => {
                                    tracing::warn!("session admission capacity timed out");
                                    metrics::counter!("moq_relay_connection_errors_total", "stage" => "policy_capacity_timeout").increment(1);
                                    close_and_wait(&raw_conn, moq_transport::session::SessionTerminationCode::InternalError, "session capacity timeout", cleanup_timeout).await;
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                    return Ok(());
                                }
                            };
                            // Resolve the connection path to a scope (identity + permissions).
                            // This translates the raw transport-level path into an application-level
                            // scope_id and determines what the connection is allowed to do.
                            let scope_info = match tokio::time::timeout(
                                admission_timeout,
                                coordinator.resolve_admitted_scope(&decision, moq_session.connection_path()),
                            ).await {
                                Ok(Ok(info)) => info,
                                Ok(Err(err)) => {
                                    tracing::warn!(
                                        connection_target = %moq_session.target().redacted_for_logging(),
                                        query_present = moq_session.target().query().is_some(),
                                        error = %err,
                                        "scope resolution failed, rejecting session"
                                    );
                                    close_and_wait(&raw_conn, moq_transport::session::SessionTerminationCode::Unauthorized, "scope resolution failed", cleanup_timeout).await;
                                    metrics::counter!("moq_relay_connection_errors_total", "stage" => "scope_resolve").increment(1);
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                    return Ok(());
                                }
                                Err(_) => {
                                    tracing::warn!("scope resolution timed out");
                                    close_and_wait(&raw_conn, moq_transport::session::SessionTerminationCode::Unauthorized, "scope resolution timeout", cleanup_timeout).await;
                                    metrics::counter!("moq_relay_connection_errors_total", "stage" => "scope_timeout").increment(1);
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                    return Ok(());
                                }
                            };
                            if decision.claims.scope.is_some() && scope_info.is_none() {
                                tracing::warn!(
                                    connection_target = %moq_session.target().redacted_for_logging(),
                                    query_present = moq_session.target().query().is_some(),
                                    "scoped admission did not resolve to a coordinator scope"
                                );
                                close_and_wait(&raw_conn, moq_transport::session::SessionTerminationCode::Unauthorized, "admitted scope not found", cleanup_timeout).await;
                                metrics::counter!("moq_relay_connection_errors_total", "stage" => "scope_missing").increment(1);
                                metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                return Ok(());
                            }
                            if scope_info
                                .as_ref()
                                .is_some_and(|scope| !resolved_scope_is_valid(&scope.scope_id))
                            {
                                tracing::warn!("coordinator returned an invalid scope identity");
                                close_and_wait(&raw_conn, moq_transport::session::SessionTerminationCode::Unauthorized, "invalid resolved scope", cleanup_timeout).await;
                                metrics::counter!("moq_relay_connection_errors_total", "stage" => "scope_invalid").increment(1);
                                metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                return Ok(());
                            }
                            if listener_security == ListenerSecurityPolicy::TokenSubscriber
                                && production
                            {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map_or(u64::MAX, |duration| duration.as_secs());
                                if let Err(error) = revalidate_token_before_activation(
                                    admission.as_ref(),
                                    &decision,
                                    admission_timeout,
                                    now,
                                ).await {
                                    tracing::warn!(error = %error, "token lease expired or was revoked before activation");
                                    close_and_wait(&raw_conn, moq_transport::session::SessionTerminationCode::Unauthorized, "token admission expired before activation", cleanup_timeout).await;
                                    metrics::counter!("moq_relay_connection_errors_total", "stage" => "admission_activation").increment(1);
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                    return Ok(());
                                }
                            }
                            drop(admission_permit);

                            let scope_id = scope_info.as_ref().map(|s| s.scope_id.clone());
                            let identity = RelayIdentity::admitted(&decision, scope_id.clone());
                            let can_publish = decision.claims.publish
                                && scope_info.as_ref().is_none_or(|s| s.permissions.can_publish());
                            let can_subscribe = decision.claims.subscribe
                                && scope_info.as_ref().is_none_or(|s| s.permissions.can_subscribe());

                            if let Some(ref info) = scope_info {
                                tracing::debug!(
                                    connection_target = %moq_session.target().redacted_for_logging(),
                                    query_present = moq_session.target().query().is_some(),
                                    scope_bound = !info.scope_id.is_empty(),
                                    permissions = ?info.permissions,
                                    "scope resolved"
                                );
                            }

                            // Gate Producer/Consumer creation on permissions.
                            // Note the intentional inversion:
                            // - Producer serves SUBSCRIBEs → gated on can_subscribe
                            // - Consumer handles PUBLISH_NAMESPACEs → gated on can_publish
                            //
                            // When a half is disabled, we pass its transport counterpart
                            // to the Session's reject fields so unauthorized messages get
                            // an explicit error response instead of being silently ignored.
                            let (producer, reject_subscribes) = if can_subscribe {
                                (publisher.map(|publisher| Producer::new_admitted(publisher, locals.clone(), remotes, identity.clone(), capacity.clone())), None)
                            } else {
                                (None, publisher)
                            };

                            let (consumer, reject_publishes) = if can_publish {
                                (subscriber.map(|subscriber| Consumer::new_admitted(subscriber, locals, coordinator, forward, identity, capacity, tracks_limits)), None)
                            } else {
                                (None, subscriber)
                            };

                            let session = Session {
                                session: moq_session,
                                producer,
                                consumer,
                                reject_publishes,
                                reject_subscribes,
                            };

                            let session_result = if listener_security
                                == ListenerSecurityPolicy::TokenSubscriber
                                && production
                            {
                                let session_run = session.run();
                                tokio::pin!(session_run);
                                tokio::select! {
                                    result = &mut session_run => Some(result),
                                    lease = monitor_token_lease(
                                        admission.as_ref(),
                                        &decision,
                                        token_revalidation_interval,
                                        admission_timeout,
                                    ) => {
                                        tracing::warn!(error = ?lease.err(), "token admission lease expired or was revoked");
                                        close_and_wait(
                                            &raw_conn,
                                            moq_transport::session::SessionTerminationCode::Unauthorized,
                                            "token admission lease expired",
                                            cleanup_timeout,
                                        ).await;
                                        metrics::counter!("moq_relay_connection_errors_total", "stage" => "admission_revalidation").increment(1);
                                        if tokio::time::timeout(cleanup_timeout, &mut session_run).await.is_err() {
                                            tracing::debug!("timed out waiting for session tasks after token lease closure");
                                        }
                                        None
                                    }
                                }
                            } else {
                                Some(session.run().await)
                            };

                            match session_result {
                                None => {
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                }
                                Some(Ok(())) => {
                                    // Session ended cleanly (uncommon - usually ends via close)
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                }
                                Some(Err(err)) if err.is_graceful_close() => {
                                    // Graceful close - peer sent APPLICATION_CLOSE with code 0
                                    tracing::debug!("MoQ session closed gracefully");
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                }
                                Some(Err(err)) => {
                                    // Actual error - protocol violation, timeout, etc.
                                    tracing::warn!(error = %err, "MoQ session error: {}", err);
                                    metrics::counter!("moq_relay_connection_errors_total", "stage" => "session_run").increment(1);
                                    metrics::counter!("moq_relay_connections_closed_total").increment(1);
                                }
                            }

                            Ok(())
                        }.boxed());
                    },
                    res = tasks.next(), if !tasks.is_empty() => res.unwrap()?,
                }
            }
        }
        .await;

        remotes.shutdown().await;
        if let Err(error) = coordinator.shutdown().await {
            if run_result.is_ok() {
                return Err(anyhow::Error::new(error).context("coordinator shutdown failed"));
            }
            tracing::warn!(%error, "coordinator shutdown failed after relay error");
        }
        run_result
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use moq_native_ietf::tls;
    use moq_transport::{coding::TrackNamespace, session::SetupAuthorization};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use time::OffsetDateTime;

    use crate::{
        AdmissionClaims, AdmissionError, AdmissionLease, AdmissionPrincipal, AuthenticationMethod,
        CoordinatorError, CoordinatorResult, NamespaceOrigin, NamespaceRegistration,
    };

    #[derive(Default)]
    struct CountingCoordinator {
        resolve_calls: AtomicUsize,
        mutation_calls: AtomicUsize,
        resolved_scope: Option<&'static str>,
    }

    #[async_trait]
    impl Coordinator for CountingCoordinator {
        async fn resolve_scope(
            &self,
            _connection_path: Option<&str>,
        ) -> CoordinatorResult<Option<crate::ScopeInfo>> {
            self.resolve_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.resolved_scope.map(|scope_id| crate::ScopeInfo {
                scope_id: scope_id.to_string(),
                permissions: crate::ScopePermissions::ReadWrite,
            }))
        }

        async fn register_namespace(
            &self,
            _scope: Option<&str>,
            _namespace: &TrackNamespace,
        ) -> CoordinatorResult<NamespaceRegistration> {
            self.mutation_calls.fetch_add(1, Ordering::SeqCst);
            Ok(NamespaceRegistration::new(()))
        }

        async fn unregister_namespace(
            &self,
            _scope: Option<&str>,
            _namespace: &TrackNamespace,
        ) -> CoordinatorResult<()> {
            self.mutation_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn lookup(
            &self,
            _scope: Option<&str>,
            _namespace: &TrackNamespace,
        ) -> CoordinatorResult<(NamespaceOrigin, Option<quic::Client>)> {
            Err(CoordinatorError::NamespaceNotFound)
        }
    }

    struct RecordingAdmission {
        calls: AtomicUsize,
        context_valid: AtomicBool,
        delay: Duration,
        allow: bool,
    }

    impl RecordingAdmission {
        fn deny() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                context_valid: AtomicBool::new(false),
                delay: Duration::ZERO,
                allow: false,
            })
        }

        fn slow(delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                context_valid: AtomicBool::new(false),
                delay,
                allow: false,
            })
        }
    }

    #[async_trait]
    impl SessionAdmission for RecordingAdmission {
        async fn admit(
            &self,
            request: AdmissionRequest<'_>,
        ) -> Result<AdmissionDecision, AdmissionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.context_valid.store(
                request.target.routing_path() == Some("/secure")
                    && request.substrate == moq_transport::session::Transport::RawQuic
                    && request.negotiated_protocol == "moqt-19"
                    && request
                        .setup_authorization
                        .is_some_and(|token| token.as_bytes() == b"test-token")
                    && matches!(request.peer_identity, tls::PeerIdentity::Anonymous),
                Ordering::SeqCst,
            );
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if !self.allow {
                return Err(AdmissionError::PolicyDenied);
            }
            AdmissionDecision::new(
                AdmissionPrincipal::new("development-test", AuthenticationMethod::Development)
                    .map_err(|_| AdmissionError::PolicyDenied)?,
                AdmissionClaims {
                    scope: None,
                    publish: true,
                    subscribe: true,
                    expires_at_unix_seconds: None,
                    token_id: None,
                },
            )
            .map_err(|_| AdmissionError::PolicyDenied)
        }
    }

    #[derive(Default)]
    struct LeaseAdmission {
        revalidation_calls: AtomicUsize,
    }

    #[async_trait]
    impl SessionAdmission for LeaseAdmission {
        async fn admit(
            &self,
            _request: AdmissionRequest<'_>,
        ) -> Result<AdmissionDecision, AdmissionError> {
            Err(AdmissionError::PolicyDenied)
        }

        fn supports_production_token_leases(&self) -> bool {
            true
        }

        async fn revalidate(&self, _decision: &AdmissionDecision) -> Result<(), AdmissionError> {
            self.revalidation_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct ScopedDevelopmentAdmission;

    #[async_trait]
    impl SessionAdmission for ScopedDevelopmentAdmission {
        async fn admit(
            &self,
            _request: AdmissionRequest<'_>,
        ) -> Result<AdmissionDecision, AdmissionError> {
            AdmissionDecision::new(
                AdmissionPrincipal::new("scoped-test", AuthenticationMethod::Development)
                    .map_err(|_| AdmissionError::PolicyDenied)?,
                AdmissionClaims {
                    scope: Some("/unknown-scope".into()),
                    publish: true,
                    subscribe: true,
                    expires_at_unix_seconds: None,
                    token_id: None,
                },
            )
            .map_err(|_| AdmissionError::PolicyDenied)
        }
    }

    struct CapacityAdmission {
        calls: AtomicUsize,
        leases: Arc<AtomicUsize>,
    }

    impl CapacityAdmission {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                leases: Arc::new(AtomicUsize::new(0)),
            })
        }
    }

    struct CapacityLease(Arc<AtomicUsize>);

    impl AdmissionLease for CapacityLease {}

    impl Drop for CapacityLease {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl SessionAdmission for CapacityAdmission {
        async fn admit(
            &self,
            _request: AdmissionRequest<'_>,
        ) -> Result<AdmissionDecision, AdmissionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            AdmissionDecision::new(
                AdmissionPrincipal::new("capacity-test", AuthenticationMethod::Development)
                    .map_err(|_| AdmissionError::PolicyDenied)?,
                AdmissionClaims {
                    scope: None,
                    publish: true,
                    subscribe: true,
                    expires_at_unix_seconds: None,
                    token_id: None,
                },
            )
            .map_err(|_| AdmissionError::PolicyDenied)
        }

        async fn acquire_session_lease(
            &self,
            _decision: &AdmissionDecision,
        ) -> Result<Box<dyn AdmissionLease>, AdmissionError> {
            self.leases.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(CapacityLease(self.leases.clone())))
        }
    }

    fn token_decision(
        expires_at_unix_seconds: Option<u64>,
        scope: Option<&str>,
        token_id: Option<&str>,
    ) -> AdmissionDecision {
        AdmissionDecision::new(
            AdmissionPrincipal::new("token-test", AuthenticationMethod::SetupToken).unwrap(),
            AdmissionClaims {
                scope: scope.map(str::to_owned),
                publish: false,
                subscribe: true,
                expires_at_unix_seconds,
                token_id: token_id.map(str::to_owned),
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn exact_token_expiry_boundary_skips_revalidation() {
        let admission = LeaseAdmission::default();
        let decision = token_decision(Some(101), Some("tenant/broadcast"), Some("jti-1"));
        let clock = Arc::new(AtomicU64::new(100));
        let sleep_clock = clock.clone();

        let result = monitor_token_lease_with_clock(
            &admission,
            &decision,
            Duration::from_secs(10),
            Duration::from_secs(30),
            || clock.load(Ordering::SeqCst),
            move |duration| {
                let sleep_clock = sleep_clock.clone();
                async move {
                    assert_eq!(duration, Duration::from_secs(1));
                    sleep_clock.store(101, Ordering::SeqCst);
                }
            },
        )
        .await;

        assert_eq!(result, Err(AdmissionError::PolicyDenied));
        assert_eq!(admission.revalidation_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn token_expiring_during_admission_is_rejected_before_activation() {
        let admission = LeaseAdmission::default();
        let decision = token_decision(Some(101), Some("tenant/broadcast"), Some("jti-1"));
        let result =
            revalidate_token_before_activation(&admission, &decision, Duration::from_secs(30), 101)
                .await;
        assert_eq!(result, Err(AdmissionError::PolicyDenied));
        assert_eq!(admission.revalidation_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn production_token_claims_fail_closed() {
        let authorization = SetupAuthorization::new(b"test-token").unwrap();
        let identity = tls::PeerIdentity::Anonymous;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid = token_decision(Some(now + 60), Some("tenant/broadcast"), Some("jti-1"));

        assert!(listener_decision_is_valid(
            ListenerSecurityPolicy::TokenSubscriber,
            &identity,
            Some(&authorization),
            &valid,
            true,
        ));
        for invalid in [
            token_decision(None, Some("tenant/broadcast"), Some("jti-1")),
            token_decision(Some(now + 60), None, Some("jti-1")),
            token_decision(Some(now + 60), Some("tenant/broadcast"), None),
            token_decision(Some(now), Some("tenant/broadcast"), Some("jti-1")),
        ] {
            assert!(!listener_decision_is_valid(
                ListenerSecurityPolicy::TokenSubscriber,
                &identity,
                Some(&authorization),
                &invalid,
                true,
            ));
        }

        let malformed = AdmissionDecision {
            principal: AdmissionPrincipal::new("malformed", AuthenticationMethod::SetupToken)
                .unwrap(),
            claims: AdmissionClaims {
                scope: Some(String::new()),
                publish: false,
                subscribe: true,
                expires_at_unix_seconds: Some(now + 60),
                token_id: Some("jti-malformed".into()),
            },
        };
        assert!(!listener_decision_is_valid(
            ListenerSecurityPolicy::TokenSubscriber,
            &identity,
            Some(&authorization),
            &malformed,
            true,
        ));
    }

    #[test]
    fn mtls_publisher_role_rejects_custom_subscribe_claim() {
        let principal =
            || AdmissionPrincipal::new("custom-mtls", AuthenticationMethod::MutualTls).unwrap();
        let publisher = AdmissionDecision::new(
            principal(),
            AdmissionClaims {
                scope: Some("/tenant/live".into()),
                publish: true,
                subscribe: false,
                expires_at_unix_seconds: None,
                token_id: None,
            },
        )
        .unwrap();
        assert!(decision_matches_listener_role(
            ListenerSecurityPolicy::MutualTlsPublisher,
            &publisher,
            true,
            0,
        ));

        let bidirectional = AdmissionDecision::new(
            principal(),
            AdmissionClaims {
                subscribe: true,
                ..publisher.claims.clone()
            },
        )
        .unwrap();
        assert!(!decision_matches_listener_role(
            ListenerSecurityPolicy::MutualTlsPublisher,
            &bidirectional,
            true,
            0,
        ));
    }

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("moq-native-ietf")
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    struct ProductionPki {
        _directory: tempfile::TempDir,
        ca: PathBuf,
        server_cert: PathBuf,
        server_key: PathBuf,
        client_cert: PathBuf,
        client_key: PathBuf,
        client_fingerprint: String,
    }

    fn production_pki() -> anyhow::Result<ProductionPki> {
        let directory = tempfile::tempdir()?;
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        ca_params.not_before = OffsetDateTime::now_utc() - time::Duration::days(1);
        ca_params.not_after = OffsetDateTime::now_utc() + time::Duration::days(30);
        let ca_key = KeyPair::generate()?;
        let ca = ca_params.self_signed(&ca_key)?;
        let ca_path = directory.path().join("ca.pem");
        fs::write(&ca_path, ca.pem())?;

        let identity = |name: &str,
                        dns_name: &str,
                        usage: ExtendedKeyUsagePurpose|
         -> anyhow::Result<(PathBuf, PathBuf, Vec<u8>)> {
            let mut params = CertificateParams::new(vec![dns_name.to_string()])?;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![usage];
            params.not_before = OffsetDateTime::now_utc() - time::Duration::days(1);
            params.not_after = OffsetDateTime::now_utc() + time::Duration::days(1);
            let key = KeyPair::generate()?;
            let certificate = params.signed_by(&key, &ca, &ca_key)?;
            let cert_path = directory.path().join(format!("{name}-cert.pem"));
            let key_path = directory.path().join(format!("{name}-key.pem"));
            fs::write(&cert_path, certificate.pem())?;
            fs::write(&key_path, key.serialize_pem())?;
            Ok((cert_path, key_path, certificate.der().as_ref().to_vec()))
        };
        let (server_cert, server_key, _) =
            identity("server", "localhost", ExtendedKeyUsagePurpose::ServerAuth)?;
        let (client_cert, client_key, client_der) =
            identity("client", "client.test", ExtendedKeyUsagePurpose::ClientAuth)?;
        let fingerprint = ring::digest::digest(&ring::digest::SHA256, &client_der);

        Ok(ProductionPki {
            _directory: directory,
            ca: ca_path,
            server_cert,
            server_key,
            client_cert,
            client_key,
            client_fingerprint: hex::encode(fingerprint.as_ref()),
        })
    }

    fn development_tls() -> anyhow::Result<tls::Config> {
        tls::Args {
            cert: vec![fixture("localhost-cert.pem")],
            key: vec![fixture("localhost-key.pem")],
            disable_verify: true,
            ..Default::default()
        }
        .load()
    }

    struct RunningRelay {
        client: quic::Client,
        target: moq_transport::session::SessionTarget,
        task: tokio::task::JoinHandle<anyhow::Result<()>>,
        coordinator: Arc<CountingCoordinator>,
    }

    async fn start_development_relay(
        admission: Arc<dyn SessionAdmission>,
        setup_timeout: Duration,
        admission_timeout: Duration,
        max_pending_admissions: usize,
        max_active_sessions: usize,
    ) -> anyhow::Result<RunningRelay> {
        start_development_relay_with_coordinator(
            admission,
            setup_timeout,
            admission_timeout,
            max_pending_admissions,
            max_active_sessions,
            Arc::new(CountingCoordinator::default()),
        )
        .await
    }

    async fn start_development_relay_with_coordinator(
        admission: Arc<dyn SessionAdmission>,
        setup_timeout: Duration,
        admission_timeout: Duration,
        max_pending_admissions: usize,
        max_active_sessions: usize,
        coordinator: Arc<CountingCoordinator>,
    ) -> anyhow::Result<RunningRelay> {
        let tls = development_tls()?;
        let endpoint = Endpoint::new(quic::Config::new(
            "127.0.0.1:0".parse()?,
            None,
            tls.clone(),
        )?)?;
        let address = endpoint
            .server
            .as_ref()
            .context("test endpoint did not expose a server")?
            .local_addr()?;
        let client = endpoint.client.clone();
        let target = format!("moqt://localhost:{}/secure", address.port()).parse()?;
        let relay = Relay::new(RelayConfig {
            bind: None,
            endpoints: vec![endpoint],
            tls,
            qlog_dir: None,
            mlog_dir: None,
            announce: None,
            node: None,
            coordinator: coordinator.clone(),
            admission,
            development: true,
            listener_security: ListenerSecurityPolicy::Development,
            setup_timeout,
            admission_timeout,
            cleanup_timeout: Duration::from_millis(200),
            max_pending_admissions,
            max_active_sessions,
            token_revalidation_interval: Duration::from_millis(50),
            capacity_limits: RelayCapacityLimits::default(),
            remote_limits: RemoteManagerLimits::default(),
            tracks_limits: moq_transport::serve::TracksLimits::default(),
            request_limits: moq_transport::session::RequestLimits::default(),
        })?;
        Ok(RunningRelay {
            client,
            target,
            task: tokio::spawn(relay.run()),
            coordinator,
        })
    }

    async fn connect_with_setup(
        client: &quic::Client,
        target: &moq_transport::session::SessionTarget,
    ) -> anyhow::Result<()> {
        let connection = client
            .connect_target(target, quic::SubstratePolicy::RawQuic, None)
            .await?;
        let setup = moq_transport::session::Session::connect_with_authorization(
            connection.session,
            None,
            connection.negotiated,
            Some(SetupAuthorization::new(b"test-token")?),
        )
        .await;
        if let Ok((session, _publisher, _subscriber)) = setup {
            let _ = tokio::time::timeout(Duration::from_secs(2), session.run())
                .await
                .context("denied session did not close")?;
        }
        Ok(())
    }

    async fn establish_with_setup(
        client: &quic::Client,
        target: &moq_transport::session::SessionTarget,
    ) -> anyhow::Result<(
        web_transport::Session,
        tokio::task::JoinHandle<Result<(), moq_transport::session::SessionError>>,
    )> {
        let connection = client
            .connect_target(target, quic::SubstratePolicy::RawQuic, None)
            .await?;
        let raw = connection.session.clone();
        let (session, _publisher, _subscriber) =
            moq_transport::session::Session::connect_with_authorization(
                connection.session,
                None,
                connection.negotiated,
                Some(SetupAuthorization::new(b"test-token")?),
            )
            .await?;
        Ok((raw, tokio::spawn(session.run())))
    }

    async fn start_production_mtls_relay() -> anyhow::Result<(RunningRelay, quic::Client)> {
        let pki = production_pki()?;
        let tls = tls::Args {
            cert: vec![pki.server_cert.clone()],
            key: vec![pki.server_key.clone()],
            root: vec![pki.ca.clone()],
            client_auth: tls::ClientAuthMode::Required,
            client_ca: vec![pki.ca.clone()],
            ..Default::default()
        }
        .load()?;
        let endpoint = Endpoint::new(quic::Config::new(
            "127.0.0.1:0".parse()?,
            None,
            tls.clone(),
        )?)?;
        let address = endpoint
            .server
            .as_ref()
            .context("test endpoint did not expose a server")?
            .local_addr()?;
        let target = format!("moqt://localhost:{}/secure", address.port()).parse()?;
        let coordinator = Arc::new(CountingCoordinator {
            resolved_scope: Some("/secure"),
            ..Default::default()
        });
        let admission = crate::CertificateFingerprintAdmission::new_bindings_with_limit(
            [format!("{}=/secure", pki.client_fingerprint)],
            4,
        )?;
        let relay = Relay::new(RelayConfig {
            bind: None,
            endpoints: vec![endpoint],
            tls,
            qlog_dir: None,
            mlog_dir: None,
            announce: None,
            node: None,
            coordinator: coordinator.clone(),
            admission,
            development: false,
            listener_security: ListenerSecurityPolicy::MutualTlsPublisher,
            setup_timeout: Duration::from_secs(1),
            admission_timeout: Duration::from_secs(1),
            cleanup_timeout: Duration::from_millis(200),
            max_pending_admissions: 4,
            max_active_sessions: 8,
            token_revalidation_interval: Duration::from_secs(1),
            capacity_limits: RelayCapacityLimits::default(),
            remote_limits: RemoteManagerLimits::default(),
            tracks_limits: moq_transport::serve::TracksLimits::default(),
            request_limits: moq_transport::session::RequestLimits::default(),
        })?;

        let client_tls = tls::Args {
            root: vec![pki.ca],
            client_cert: Some(pki.client_cert),
            client_key: Some(pki.client_key),
            ..Default::default()
        }
        .load()?;
        let client =
            Endpoint::new(quic::Config::new("127.0.0.1:0".parse()?, None, client_tls)?)?.client;
        Ok((
            RunningRelay {
                client: client.clone(),
                target,
                task: tokio::spawn(relay.run()),
                coordinator,
            },
            client,
        ))
    }

    async fn connect_production_session(
        client: &quic::Client,
        target: &moq_transport::session::SessionTarget,
        policy: quic::SubstratePolicy,
    ) -> anyhow::Result<(
        web_transport::Session,
        tokio::task::JoinHandle<Result<(), moq_transport::session::SessionError>>,
    )> {
        let connection = client.connect_target(target, policy, None).await?;
        let raw = connection.session.clone();
        let (session, _publisher, _subscriber) = moq_transport::session::Session::connect(
            connection.session,
            None,
            connection.negotiated,
        )
        .await?;
        Ok((raw, tokio::spawn(session.run())))
    }

    #[tokio::test]
    async fn admission_denial_precedes_coordinator_mutation_and_cleans_up() -> anyhow::Result<()> {
        let admission = RecordingAdmission::deny();
        let relay = start_development_relay(
            admission.clone(),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
            100,
        )
        .await?;

        connect_with_setup(&relay.client, &relay.target).await?;
        connect_with_setup(&relay.client, &relay.target).await?;

        assert_eq!(admission.calls.load(Ordering::SeqCst), 2);
        assert!(admission.context_valid.load(Ordering::SeqCst));
        assert_eq!(relay.coordinator.resolve_calls.load(Ordering::SeqCst), 0);
        assert_eq!(relay.coordinator.mutation_calls.load(Ordering::SeqCst), 0);
        assert!(!relay.task.is_finished(), "denial terminated the listener");
        relay.task.abort();
        let _ = relay.task.await;
        Ok(())
    }

    #[tokio::test]
    async fn production_mtls_scope_is_enforced_on_raw_quic_and_webtransport() -> anyhow::Result<()>
    {
        let (relay, client) = start_production_mtls_relay().await?;

        for (expected_resolves, policy) in [
            (1, quic::SubstratePolicy::RawQuic),
            (2, quic::SubstratePolicy::WebTransport),
        ] {
            let (raw, task) = connect_production_session(&client, &relay.target, policy).await?;
            tokio::time::timeout(Duration::from_secs(1), async {
                while relay.coordinator.resolve_calls.load(Ordering::SeqCst) != expected_resolves {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            raw.close(0, "production mTLS substrate test complete");
            let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        }

        let cross_scope: moq_transport::session::SessionTarget = format!(
            "moqt://localhost:{}/other-tenant",
            relay.target.port().unwrap()
        )
        .parse()?;
        let connection = client
            .connect_target(&cross_scope, quic::SubstratePolicy::RawQuic, None)
            .await?;
        let setup = moq_transport::session::Session::connect(
            connection.session,
            None,
            connection.negotiated,
        )
        .await;
        if let Ok((session, _publisher, _subscriber)) = setup {
            let _ = tokio::time::timeout(Duration::from_secs(2), session.run()).await;
        }
        assert_eq!(relay.coordinator.resolve_calls.load(Ordering::SeqCst), 2);
        assert_eq!(relay.coordinator.mutation_calls.load(Ordering::SeqCst), 0);

        relay.task.abort();
        let _ = relay.task.await;
        Ok(())
    }

    #[tokio::test]
    async fn setup_deadline_releases_the_pending_admission_permit() -> anyhow::Result<()> {
        let admission = RecordingAdmission::deny();
        let relay = start_development_relay(
            admission.clone(),
            Duration::from_millis(75),
            Duration::from_secs(1),
            1,
            100,
        )
        .await?;

        let connection = relay
            .client
            .connect_target(&relay.target, quic::SubstratePolicy::RawQuic, None)
            .await?;
        tokio::time::timeout(Duration::from_secs(2), connection.session.closed())
            .await
            .context("SETUP-less connection was not closed")?;

        connect_with_setup(&relay.client, &relay.target).await?;
        assert_eq!(admission.calls.load(Ordering::SeqCst), 1);
        assert_eq!(relay.coordinator.resolve_calls.load(Ordering::SeqCst), 0);
        relay.task.abort();
        let _ = relay.task.await;
        Ok(())
    }

    #[tokio::test]
    async fn admission_timeout_and_capacity_do_not_leak_slots() -> anyhow::Result<()> {
        let admission = RecordingAdmission::slow(Duration::from_secs(1));
        let relay = start_development_relay(
            admission.clone(),
            Duration::from_secs(1),
            Duration::from_millis(75),
            1,
            100,
        )
        .await?;

        let first_client = relay.client.clone();
        let first_target = relay.target.clone();
        let first =
            tokio::spawn(async move { connect_with_setup(&first_client, &first_target).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while admission.calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        connect_with_setup(&relay.client, &relay.target).await?;
        first.await??;
        connect_with_setup(&relay.client, &relay.target).await?;
        assert_eq!(admission.calls.load(Ordering::SeqCst), 2);
        assert_eq!(relay.coordinator.resolve_calls.load(Ordering::SeqCst), 0);
        relay.task.abort();
        let _ = relay.task.await;
        Ok(())
    }

    #[tokio::test]
    async fn overload_flood_is_rejected_inline_and_listener_recovers() -> anyhow::Result<()> {
        let admission = RecordingAdmission::slow(Duration::from_secs(5));
        let relay = start_development_relay(
            admission.clone(),
            Duration::from_secs(1),
            Duration::from_millis(500),
            1,
            100,
        )
        .await?;

        let first_client = relay.client.clone();
        let first_target = relay.target.clone();
        let first =
            tokio::spawn(async move { connect_with_setup(&first_client, &first_target).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while admission.calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        let flood = (0..32).map(|_| {
            let client = relay.client.clone();
            let target = relay.target.clone();
            tokio::spawn(async move { connect_with_setup(&client, &target).await })
        });
        let results =
            tokio::time::timeout(Duration::from_secs(3), futures::future::join_all(flood))
                .await
                .context("overload flood retained unbounded cleanup work")?;
        for result in results {
            result??;
        }
        first.await??;
        assert_eq!(admission.calls.load(Ordering::SeqCst), 1);

        connect_with_setup(&relay.client, &relay.target).await?;
        assert_eq!(admission.calls.load(Ordering::SeqCst), 2);
        assert!(!relay.task.is_finished());
        relay.task.abort();
        let _ = relay.task.await;
        Ok(())
    }

    #[tokio::test]
    async fn scoped_admission_rejects_unknown_coordinator_scope() -> anyhow::Result<()> {
        let relay = start_development_relay(
            Arc::new(ScopedDevelopmentAdmission),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
            10,
        )
        .await?;

        connect_with_setup(&relay.client, &relay.target).await?;
        assert_eq!(relay.coordinator.resolve_calls.load(Ordering::SeqCst), 1);
        assert_eq!(relay.coordinator.mutation_calls.load(Ordering::SeqCst), 0);
        assert!(!relay.task.is_finished());
        relay.task.abort();
        let _ = relay.task.await;
        Ok(())
    }

    #[tokio::test]
    async fn scoped_admission_rejects_malformed_coordinator_scope() -> anyhow::Result<()> {
        assert!(!resolved_scope_is_valid(
            &"x".repeat(AdmissionClaims::MAX_SCOPE_BYTES + 1)
        ));
        for malformed in ["", "tenant\nsmuggled"] {
            let coordinator = Arc::new(CountingCoordinator {
                resolved_scope: Some(malformed),
                ..Default::default()
            });
            let relay = start_development_relay_with_coordinator(
                Arc::new(ScopedDevelopmentAdmission),
                Duration::from_secs(1),
                Duration::from_secs(1),
                1,
                10,
                coordinator,
            )
            .await?;
            connect_with_setup(&relay.client, &relay.target).await?;
            assert_eq!(relay.coordinator.resolve_calls.load(Ordering::SeqCst), 1);
            assert_eq!(relay.coordinator.mutation_calls.load(Ordering::SeqCst), 0);
            relay.task.abort();
            let _ = relay.task.await;
        }
        Ok(())
    }

    #[tokio::test]
    async fn active_capacity_and_policy_leases_release_for_reconnect() -> anyhow::Result<()> {
        let admission = CapacityAdmission::new();
        let relay = start_development_relay(
            admission.clone(),
            Duration::from_secs(1),
            Duration::from_secs(1),
            4,
            1,
        )
        .await?;

        let (first_raw, first_task) = establish_with_setup(&relay.client, &relay.target).await?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while admission.leases.load(Ordering::SeqCst) != 1
                || relay.coordinator.resolve_calls.load(Ordering::SeqCst) != 1
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        connect_with_setup(&relay.client, &relay.target).await?;
        assert_eq!(admission.leases.load(Ordering::SeqCst), 1);
        assert_eq!(relay.coordinator.resolve_calls.load(Ordering::SeqCst), 1);

        first_raw.close(0, "capacity test reconnect");
        let _ = tokio::time::timeout(Duration::from_secs(2), first_task).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while admission.leases.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .context("policy capacity lease was not released")?;

        let (third_raw, third_task) = establish_with_setup(&relay.client, &relay.target).await?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while admission.leases.load(Ordering::SeqCst) != 1
                || relay.coordinator.resolve_calls.load(Ordering::SeqCst) != 2
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        third_raw.close(0, "capacity test complete");
        let _ = tokio::time::timeout(Duration::from_secs(2), third_task).await;

        assert_eq!(admission.calls.load(Ordering::SeqCst), 3);
        relay.task.abort();
        let _ = relay.task.await;
        Ok(())
    }

    #[tokio::test]
    async fn production_rejects_disable_verify_optional_mtls_and_development_allow_all() {
        fn config(
            tls: tls::Config,
            admission: Arc<dyn SessionAdmission>,
            listener_security: ListenerSecurityPolicy,
        ) -> RelayConfig {
            RelayConfig {
                bind: Some("127.0.0.1:0".parse().unwrap()),
                endpoints: Vec::new(),
                tls,
                qlog_dir: None,
                mlog_dir: None,
                announce: None,
                node: None,
                coordinator: Arc::new(CountingCoordinator::default()),
                admission,
                development: false,
                listener_security,
                setup_timeout: Duration::from_secs(1),
                admission_timeout: Duration::from_secs(1),
                cleanup_timeout: Duration::from_millis(100),
                max_pending_admissions: 1,
                max_active_sessions: 1,
                token_revalidation_interval: Duration::from_secs(1),
                capacity_limits: RelayCapacityLimits::default(),
                remote_limits: RemoteManagerLimits::default(),
                tracks_limits: moq_transport::serve::TracksLimits::default(),
                request_limits: moq_transport::session::RequestLimits::default(),
            }
        }

        let mut diagnostics = config(
            development_tls().unwrap(),
            Arc::new(crate::DenyAllAdmission),
            ListenerSecurityPolicy::MutualTlsPublisher,
        );
        diagnostics.mlog_dir = Some(PathBuf::from("."));
        let error = Relay::new(diagnostics)
            .err()
            .expect("production per-session diagnostics must fail");
        assert!(error.to_string().contains("development-only"));

        let keylog_tls = development_tls().unwrap();
        let keylog_endpoint = Endpoint::new(
            quic::Config::new("127.0.0.1:0".parse().unwrap(), None, keylog_tls.clone())
                .unwrap()
                .with_tls_key_log(true),
        )
        .unwrap();
        let mut keylog = config(
            keylog_tls,
            Arc::new(crate::DenyAllAdmission),
            ListenerSecurityPolicy::MutualTlsPublisher,
        );
        keylog.bind = None;
        keylog.endpoints = vec![keylog_endpoint];
        let error = Relay::new(keylog)
            .err()
            .expect("production TLS key logging must fail");
        assert!(error.to_string().contains("TLS key logging"));

        let insecure = development_tls().unwrap();
        let error = Relay::new(config(
            insecure,
            Arc::new(crate::DenyAllAdmission),
            ListenerSecurityPolicy::MutualTlsPublisher,
        ))
        .err()
        .expect("production disable-verify must fail");
        assert!(error.to_string().contains("tls-disable-verify"));

        let cert = fixture("localhost-cert.pem");
        let optional = tls::Args {
            cert: vec![cert.clone()],
            key: vec![fixture("localhost-key.pem")],
            root: vec![cert.clone()],
            client_auth: tls::ClientAuthMode::Optional,
            client_ca: vec![cert],
            ..Default::default()
        }
        .load()
        .unwrap();
        assert!(Relay::new(config(
            optional,
            Arc::new(crate::DenyAllAdmission),
            ListenerSecurityPolicy::MutualTlsPublisher,
        ))
        .is_err());

        let development = development_tls().unwrap();
        assert!(Relay::new(config(
            development,
            crate::DevelopmentAllowAllAdmission::explicitly_enabled(),
            ListenerSecurityPolicy::Development,
        ))
        .is_err());
    }
}
