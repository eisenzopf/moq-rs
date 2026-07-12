# moq-relay

A server that connects publishing clients to subscribing clients.
All subscriptions are deduplicated and cached, so that a single publisher can serve many subscribers.

## Usage

The publisher must choose a unique name for their broadcast, sent as the WebTransport path when connecting to the server.
Connection paths are normalized and validated: trailing slashes are trimmed, dot segments and percent-encoded characters are rejected, and empty segments are not allowed. Capitalization matters.

For example: `CONNECT https://relay.quic.video/BigBuckBunny`

The MoqTransport handshake includes a `role` parameter, which must be `publisher` or `subscriber`.
The specification allows a `both` role but you'll get an error.

You can have one publisher and any number of subscribers connected to the same path.
If the publisher disconnects, then all subscribers receive an error and will not get updates, even if a new publisher reuses the path.

## Secure embedding and migration

The security-bearing rustls fields in `moq_native_ietf::tls::Config` are intentionally private. Embedders, including rvoip, should construct TLS through `tls::Args::load()` so the resulting configuration retains trustworthy evidence about server verification and inbound client authentication:

```rust,ignore
let tls = moq_native_ietf::tls::Args {
    root: vec![relay_ca],
    client_cert: Some(origin_cert),
    client_key: Some(origin_key),
    cert: vec![listener_cert],
    key: vec![listener_key],
    client_auth: moq_native_ietf::tls::ClientAuthMode::Required,
    client_ca: vec![origin_ca],
    ..Default::default()
}.load()?;
let endpoint = moq_native_ietf::quic::Endpoint::new(
    moq_native_ietf::quic::Config::new(bind, None, tls)?
)?;
```

Legacy `Server::accept`, `Client::connect`, and `SessionConnection::into_parts` retain their three-element tuples. Identity-aware applications use `accept_connection`, `connect_target`, or `into_parts_with_identity`.

Production relay embedders must now configure:

- explicit listener security and a `SessionAdmission` policy;
- fingerprint-to-scope mappings such as `SHA256=/tenant/live`, not independent fingerprint and scope lists;
- a bounded `max_active_sessions` and policy-owned `AdmissionLease` capacity;
- setup, admission, cleanup, and token-revalidation deadlines.

The built-in fingerprint policy supports `new_bindings_with_limit`. Production token listeners require an external replay-, expiry-, revocation-, and capacity-aware policy. Per-session qlog/mlog, TLS key logging, disabled stateless retry, anonymous development admission, and `--insecure-development` are rejected or explicitly local-only in production.

Raw `SessionTarget` values retain queries for trusted routing and canonical serialization. Logs must use `SessionTarget::redacted_for_logging()` or `redact_url_for_logging()`; bearer query values and authorization parameters are never diagnostic output.

## Retained-state limits

Production relays must also configure bounded request and cache retention. `RelayConfig` exposes:

- `capacity_limits`: process, authenticated-principal, and resolved-scope totals plus independent PUBLISH_NAMESPACE, PUBLISH, SUBSCRIBE, TRACK_STATUS, and FETCH limits;
- `remote_limits`: global upstream connection/track caps and 30-second track/60-second connection idle defaults;
- `tracks_limits`: per-published-namespace cached-track and pending-request caps.
- `request_limits`: transport request queues plus per-session and process-wide retained FETCH byte budgets.

The relay CLI exposes each limit explicitly; use `moq-relay-ietf --help` for the full flag set. Limits are validated at startup. Admission is fail-fast and occurs before coordinator/media mutation. Every admitted request retains an RAII permit until its task completes, so cancellation, failure, and panic release capacity. Saturation is returned as retryable `EXCESSIVE_LOAD` with a 1001 ms retry interval rather than being reported as missing media.

The built-in API coordinator supervises one bounded refresh/cleanup task per registration. The file coordinator limits both total entries and serialized bytes and validates a write before truncating existing state. Upstream caches are keyed by resolved scope, and active calls to one scope cannot reuse another scope's authenticated session.

Prometheus metrics use only fixed `level`, `resource`, and `kind` labels. Principal, scope, namespace, track, and request IDs are intentionally omitted. Retain `Relay::diagnostics()` before moving the server into `run` to query aggregate runtime snapshots; component snapshots remain available from `RelayCapacity` and `RemoteManager`.

Direct embedders should construct `Consumer` and `Producer` with `new_admitted`, retaining the authenticated `RelayIdentity` and sharing one process-wide `RelayCapacity`. The shorter `new` constructors are compatibility helpers with isolated operator capacity and are not production admission boundaries.
