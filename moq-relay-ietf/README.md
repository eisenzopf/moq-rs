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
