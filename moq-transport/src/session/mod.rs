// SPDX-FileCopyrightText: 2024-2026 Cloudflare Inc., Luke Curley, Mike English and contributors
// SPDX-FileCopyrightText: 2023-2024 Luke Curley and contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

mod error;
mod publish_namespace;
mod publish_received;
mod published;
mod published_namespace;
mod publisher;
mod reader;
mod request_id;
mod request_updates;
mod subscribe;
mod subscribed;
mod subscriber;
mod track_status_requested;
mod writer;

pub use error::*;
pub use publish_namespace::*;
pub use publish_received::*;
pub use published::*;
pub use published_namespace::*;
pub use publisher::*;
pub use request_id::RequestId;
pub use subscribe::*;
pub use subscribed::*;
pub use subscriber::*;
pub use track_status_requested::*;

use reader::*;
use request_updates::{RequestKind, RequestUpdateCredits};
use writer::*;

use futures::{stream::FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use crate::coding::{Encode, KeyValuePairs, Value};
use crate::message::Message;
use crate::mlog;
use crate::watch::Queue;
use crate::{message, setup};
use std::path::PathBuf;

/// Registry mapping bidi-request IDs to a channel for forwarding responses.
/// When `run_send` pops a response message from the outgoing queue, it checks
/// this map: if the response's target request ID has a registered sender, the
/// response is forwarded to the bidi handler task that owns the Writer.
pub(super) enum BidiCommand {
    Send(Message),
    Cancel(u32),
    RequestUpdate {
        update: message::RequestUpdate,
        forward: bool,
        completion: tokio::sync::oneshot::Sender<Result<(), SessionError>>,
    },
}

struct PendingReverseUpdate {
    id: u64,
    forward: bool,
    completion: tokio::sync::oneshot::Sender<Result<(), SessionError>>,
}

#[derive(Clone, Copy)]
struct RequestUpdateLimits {
    incoming: u64,
    outgoing: u64,
}

struct SessionConfig {
    transport: Transport,
    connection_path: Option<String>,
    peer_max_request_updates: u64,
}

type BidiResponseMap = Arc<Mutex<HashMap<u64, tokio::sync::mpsc::UnboundedSender<BidiCommand>>>>;

/// Channel for spawned bidi response reader tasks. Publisher/Subscriber send
/// handles here; `Session::run` collects and polls them.
///
/// A wrapper is used instead of exposing Tokio's sender directly so a task
/// raced against session shutdown is aborted even when the caller ignores the
/// send error. Dropping a bare `JoinHandle` would detach the task.
#[derive(Clone)]
pub(super) struct BidiTaskSender(tokio::sync::mpsc::UnboundedSender<tokio::task::JoinHandle<()>>);

struct BidiTaskSendError(Option<tokio::task::JoinHandle<()>>);

impl Drop for BidiTaskSendError {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

impl BidiTaskSendError {
    async fn abort_and_wait(mut self) {
        let Some(task) = self.0.take() else {
            return;
        };
        task.abort();
        match task.await {
            Err(error) if !error.is_cancelled() => {
                tracing::warn!(%error, "request-stream task failed while joining raced shutdown");
            }
            _ => {}
        }
    }
}

impl BidiTaskSender {
    fn channel() -> (
        Self,
        tokio::sync::mpsc::UnboundedReceiver<tokio::task::JoinHandle<()>>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Self(tx), rx)
    }

    fn send(&self, task: tokio::task::JoinHandle<()>) -> Result<(), BidiTaskSendError> {
        self.0
            .send(task)
            .map_err(|error| BidiTaskSendError(Some(error.0)))
    }
}

/// Process-wide and per-session admission limits for peer-opened data streams.
///
/// QUIC's transport stream limit controls how many streams the peer may have
/// open on the wire, while this separate bound controls how many application
/// futures we retain and poll.
struct DataStreamTaskLimits {
    global: Arc<tokio::sync::Semaphore>,
    per_session: usize,
}

impl DataStreamTaskLimits {
    fn production() -> Self {
        Self {
            global: GLOBAL_DATA_STREAM_TASKS.clone(),
            per_session: Session::MAX_CONCURRENT_DATA_STREAMS_PER_SESSION,
        }
    }

    fn try_admit(&self, active_for_session: usize) -> Option<tokio::sync::OwnedSemaphorePermit> {
        if active_for_session >= self.per_session {
            return None;
        }

        self.global.clone().try_acquire_owned().ok()
    }
}

static GLOBAL_DATA_STREAM_TASKS: LazyLock<Arc<tokio::sync::Semaphore>> = LazyLock::new(|| {
    Arc::new(tokio::sync::Semaphore::new(
        Session::MAX_CONCURRENT_DATA_STREAMS_GLOBAL,
    ))
});

/// The transport protocol negotiated for this MoQT connection.
///
/// MoQT can run over either WebTransport (HTTP/3 + QUIC) or raw QUIC.
/// The transport type affects protocol behavior — for example, the PATH
/// parameter is only sent in SETUP for raw QUIC connections,
/// since WebTransport carries the path in the HTTP/3 CONNECT URL.
///
/// This enum is intentionally extensible for future transport options
/// (e.g., QMUX, WebSocket fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// WebTransport over HTTP/3 (RFC 9220).
    /// ALPN: "h3". Path carried in HTTP/3 CONNECT :path pseudo-header.
    WebTransport,
    /// Raw QUIC with MoQT framing directly on QUIC streams.
    /// ALPN: "moqt-16". Path carried in SETUP PATH parameter.
    RawQuic,
}

/// Session object for managing all communications in a single QUIC connection.
#[must_use = "run() must be called"]
pub struct Session {
    webtransport: web_transport::Session,

    /// Control Stream Reader and Writer (QUIC bi-directional stream)
    sender: Writer, // Control Stream Sender
    recver: Reader, // Control Stream Receiver

    publisher: Option<Publisher>, // Contains Publisher side logic, uses outgoing message queue to send control messages
    subscriber: Option<Subscriber>, // Contains Subscriber side logic, uses outgoing message queue to send control messages

    /// Queue used by Publisher and Subscriber for sending Control Messages
    outgoing: Queue<Message>,

    /// Session-level request ID manager.
    /// Publisher and Subscriber share one outbound request ID sequence.
    request_id: RequestId,

    /// Optional mlog writer for MoQ Transport events
    /// Wrapped in Arc<Mutex<>> to share across send/recv tasks when enabled
    mlog: Option<Arc<Mutex<mlog::MlogWriter>>>,

    /// The transport protocol negotiated for this connection.
    transport: Transport,

    /// The connection path, derived from the WebTransport URL path or SETUP PATH parameter.
    /// For incoming connections: extracted during accept() from the WebTransport CONNECT URL
    /// (takes precedence) or the SETUP PATH parameter (key 0x1).
    /// For outgoing connections: auto-extracted from the session URL in connect().
    connection_path: Option<String>,

    /// Receiver for spawned bidi reader task handles.
    /// Polled by Session::run; dropping FuturesUnordered aborts all tasks.
    bidi_task_rx: tokio::sync::mpsc::UnboundedReceiver<tokio::task::JoinHandle<()>>,

    /// Maps bidi-request IDs to their response stream writers (draft-19).
    bidi_response_map: BidiResponseMap,

    /// Per-request-stream update concurrency advertised to the peer.
    max_request_updates: u64,

    /// Maximum concurrent reverse-direction REQUEST_UPDATEs advertised by the peer.
    peer_max_request_updates: u64,
}

impl Session {
    const MAX_CONNECTION_PATH_LEN: usize = 1024;
    const DEFAULT_MAX_REQUEST_UPDATES: u64 = 16;
    pub(super) const REQUEST_STREAM_CANCELLED: u32 = 0x1;

    /// Application-level bounds for peer-opened unidirectional data stream
    /// handlers. These are deliberately independent from the negotiated QUIC
    /// stream count so peer behavior cannot create an unbounded task set.
    const MAX_CONCURRENT_DATA_STREAMS_PER_SESSION: usize = 256;
    const MAX_CONCURRENT_DATA_STREAMS_GLOBAL: usize = 4096;

    /// Draft-19 stream reset code used when data-stream admission is exhausted.
    const DATA_STREAM_EXCESSIVE_LOAD: u32 = 0x9;

    /// Normalize and validate a connection path.
    ///
    /// Returns `Ok(None)` for empty or root-only paths. Returns `Err` for
    /// paths that are too long, don't start with `/`, contain empty,
    /// dot, or percent-encoded segments, or are otherwise malformed.
    ///
    /// Percent-encoded characters are rejected rather than decoded because
    /// scope identity must be unambiguous: `/foo%2Fbar` and `/foo/bar`
    /// must not silently map to different scopes, and `%2E%2E` must not
    /// bypass the dot-segment check.
    ///
    /// This is used internally by `accept()` and `connect()`, but is also
    /// available for callers that need to validate paths from other sources
    /// (e.g., announce URLs used for forward connections).
    pub fn normalize_connection_path(raw: &str) -> Result<Option<String>, SessionError> {
        if raw.is_empty() || raw == "/" {
            return Ok(None);
        }

        if raw.len() > Self::MAX_CONNECTION_PATH_LEN {
            return Err(SessionError::InvalidPath("path too long".to_string()));
        }

        if !raw.starts_with('/') {
            return Err(SessionError::InvalidPath(
                "path must start with '/'".to_string(),
            ));
        }

        let trimmed = raw.trim_end_matches('/');
        if trimmed.is_empty() {
            return Ok(None);
        }

        let mut segments = trimmed.split('/');
        let _ = segments.next();
        for segment in segments {
            if segment.is_empty() {
                return Err(SessionError::InvalidPath(
                    "path contains empty segment".to_string(),
                ));
            }
            if segment.contains('%') {
                return Err(SessionError::InvalidPath(
                    "path must not contain percent-encoded characters".to_string(),
                ));
            }
            if segment == "." || segment == ".." {
                return Err(SessionError::InvalidPath(
                    "path contains invalid segment".to_string(),
                ));
            }
        }

        Ok(Some(trimmed.to_string()))
    }

    fn decode_client_setup_path(params: &KeyValuePairs) -> Result<Option<String>, SessionError> {
        let Some(kvp) = params.get(setup::ParameterType::Path.into()) else {
            return Ok(None);
        };

        let bytes = match &kvp.value {
            Value::BytesValue(bytes) => bytes,
            _ => {
                return Err(SessionError::InvalidPath(
                    "PATH parameter must be bytes-encoded".to_string(),
                ))
            }
        };

        if bytes.len() > Self::MAX_CONNECTION_PATH_LEN {
            return Err(SessionError::InvalidPath("path too long".to_string()));
        }

        let path = std::str::from_utf8(bytes)
            .map_err(|_| SessionError::InvalidPath("path must be UTF-8".to_string()))?;

        Self::normalize_connection_path(path)
    }

    /// Returns the negotiated transport protocol for this connection.
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// Returns the connection path, if one was present on the incoming connection.
    ///
    /// For server-side sessions (created via `accept()`), this is derived from:
    /// 1. The WebTransport CONNECT URL path (takes precedence), or
    /// 2. The SETUP PATH parameter (key 0x1), used for raw QUIC connections.
    ///
    /// Returns `None` if no path was present or if the path was just "/".
    pub fn connection_path(&self) -> Option<&str> {
        self.connection_path.as_deref()
    }

    /// Log a control message with structured fields for observability.
    /// Uses target "moq_transport::control" so it can be filtered independently.
    fn log_control_message(msg: &Message, direction: &str) {
        match msg {
            Message::Subscribe(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "SUBSCRIBE",
                    subscribe_id = m.id,
                    namespace = %m.track_namespace,
                    track_name = %m.track_name,
                    "MoQT control message"
                );
            }
            Message::SubscribeOk(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "SUBSCRIBE_OK",
                    subscribe_id = m.id,
                    track_alias = m.track_alias,
                    "MoQT control message"
                );
            }
            Message::PublishNamespace(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "PUBLISH_NAMESPACE",
                    request_id = m.id,
                    namespace = %m.track_namespace,
                    "MoQT control message"
                );
            }
            Message::Namespace(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "NAMESPACE",
                    namespace_suffix = %m.track_namespace_suffix,
                    "MoQT control message"
                );
            }
            Message::NamespaceDone(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "NAMESPACE_DONE",
                    namespace_suffix = %m.track_namespace_suffix,
                    "MoQT control message"
                );
            }
            Message::TrackStatus(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "TRACK_STATUS",
                    request_id = m.id,
                    namespace = %m.track_namespace,
                    track_name = %m.track_name,
                    "MoQT control message"
                );
            }
            Message::SubscribeNamespace(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "SUBSCRIBE_NAMESPACE",
                    request_id = m.id,
                    namespace_prefix = %m.track_namespace_prefix,
                    "MoQT control message"
                );
            }
            Message::SubscribeTracks(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "SUBSCRIBE_TRACKS",
                    request_id = m.id,
                    namespace_prefix = %m.track_namespace_prefix,
                    "MoQT control message"
                );
            }
            Message::Fetch(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "FETCH",
                    request_id = m.id,
                    fetch_type = ?m.fetch_type,
                    "MoQT control message"
                );
            }
            Message::FetchOk(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "FETCH_OK",
                    request_id = m.id,
                    end_of_track = m.end_of_track,
                    "MoQT control message"
                );
            }
            Message::Publish(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "PUBLISH",
                    request_id = m.id,
                    namespace = %m.track_namespace,
                    track_name = %m.track_name,
                    track_alias = m.track_alias,
                    "MoQT control message"
                );
            }
            Message::PublishSkipped(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "PUBLISH_SKIPPED",
                    namespace_suffix = %m.track_namespace_suffix,
                    track_name = %m.track_name,
                    "MoQT control message"
                );
            }
            Message::PublishDone(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "PUBLISH_DONE",
                    request_id = m.id,
                    status_code = m.status_code,
                    stream_count = m.stream_count,
                    "MoQT control message"
                );
            }
            Message::GoAway(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "GOAWAY",
                    uri = %m.uri.0,
                    timeout_ms = m.timeout,
                    "MoQT control message"
                );
            }
            Message::RequestOk(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "REQUEST_OK",
                    request_id = m.id,
                    "MoQT control message"
                );
            }
            Message::RequestError(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "REQUEST_ERROR",
                    request_id = m.id,
                    error_code = m.error_code,
                    retry_interval = m.retry_interval,
                    "MoQT control message"
                );
            }
            Message::RequestUpdate(m) => {
                tracing::debug!(
                    target: "moq_transport::control",
                    direction,
                    msg_type = "REQUEST_UPDATE",
                    request_id = m.id,
                    "MoQT control message"
                );
            }
        }
    }

    fn new(
        webtransport: web_transport::Session,
        sender: Writer,
        recver: Reader,
        mlog: Option<mlog::MlogWriter>,
        request_id: RequestId,
        config: SessionConfig,
    ) -> (Self, Option<Publisher>, Option<Subscriber>) {
        let outgoing = Queue::default().split();

        // Wrap mlog in Arc<Mutex<>> for sharing across tasks
        let mlog_shared = mlog.map(|m| Arc::new(Mutex::new(m)));

        let (bidi_task_tx, bidi_task_rx) = BidiTaskSender::channel();
        let bidi_response_map = Arc::new(Mutex::new(HashMap::new()));

        let publisher = Some(Publisher::new(
            outgoing.0.clone(),
            webtransport.clone(),
            mlog_shared.clone(),
            request_id.clone(),
            bidi_task_tx.clone(),
            bidi_response_map.clone(),
        ));
        let subscriber = Some(Subscriber::new(
            outgoing.0,
            webtransport.clone(),
            mlog_shared.clone(),
            request_id.clone(),
            bidi_task_tx,
            bidi_response_map.clone(),
        ));

        let session = Self {
            webtransport,
            sender,
            recver,
            publisher: publisher.clone(),
            subscriber: subscriber.clone(),
            outgoing: outgoing.1,
            request_id,
            mlog: mlog_shared,
            transport: config.transport,
            connection_path: config.connection_path,
            bidi_task_rx,
            bidi_response_map,
            max_request_updates: Self::DEFAULT_MAX_REQUEST_UPDATES,
            peer_max_request_updates: config.peer_max_request_updates,
        };

        (session, publisher, subscriber)
    }

    /// Create an outbound/client QUIC connection.
    ///
    /// Opens a unidirectional control stream, sends SETUP with
    /// parameters only (version is agreed via ALPN), and waits for SETUP.
    ///
    /// For native `moqt://` connections the PATH and AUTHORITY parameters are
    /// sent automatically.  For WebTransport the path is carried in the HTTP/3
    /// CONNECT URL so PATH is not sent.
    pub async fn connect(
        session: web_transport::Session,
        mlog_path: Option<PathBuf>,
        transport: Transport,
    ) -> Result<(Session, Publisher, Subscriber), SessionError> {
        let url = session.url().clone();
        let url_path = url.path();
        let path = Self::normalize_connection_path(url_path)?;

        let mlog = mlog_path.and_then(|p| {
            mlog::MlogWriter::new(p)
                .map_err(|e| tracing::warn!("Failed to create mlog: {}", e))
                .ok()
        });

        // Open our unidirectional control send stream.
        let send_stream = session.open_uni().await?;
        let mut sender = Writer::new(send_stream);

        let mut params = KeyValuePairs::default();
        params.set_intvalue(
            setup::ParameterType::MaxRequestUpdates.into(),
            Self::DEFAULT_MAX_REQUEST_UPDATES,
        );

        if transport == Transport::RawQuic {
            // Draft-16 §9.3.1.1: send AUTHORITY for native QUIC.
            if let Some(host) = url.host_str() {
                let authority = if let Some(port) = url.port() {
                    format!("{}:{}", host, port)
                } else {
                    host.to_string()
                };
                params.set_bytesvalue(
                    setup::ParameterType::Authority.into(),
                    authority.into_bytes(),
                );
            }

            // Draft-16 §9.3.1.2: send PATH (path + optional query) for native QUIC.
            let path_and_query = match url.query() {
                Some(q) => format!("{}?{}", url_path, q),
                None => url_path.to_string(),
            };
            if !path_and_query.is_empty() && path_and_query != "/" {
                params.set_bytesvalue(
                    setup::ParameterType::Path.into(),
                    path_and_query.into_bytes(),
                );
            }
        }

        let client = setup::Setup { params };

        tracing::debug!(
            target: "moq_transport::control",
            direction = "sent",
            msg_type = "SETUP",
            ?transport,
            path = path.as_deref(),
            "MoQT control message"
        );
        sender.encode(&client).await?;

        // Accept the peer's unidirectional control stream.
        let recv_stream = session.accept_uni().await?;
        let mut recver = Reader::new(recv_stream);
        let server: setup::Setup = recver.decode().await?;
        let peer_max_request_updates = server.max_request_updates()?;
        tracing::debug!(
            target: "moq_transport::control",
            direction = "recv",
            msg_type = "SETUP (recv)",
            "MoQT control message"
        );

        // Client sends even IDs (0); peer server sends odd IDs (1).
        let request_id = RequestId::new(0, 1);
        let session = Session::new(
            session,
            sender,
            recver,
            mlog,
            request_id,
            SessionConfig {
                transport,
                connection_path: path,
                peer_max_request_updates,
            },
        );
        Ok((session.0, session.1.unwrap(), session.2.unwrap()))
    }

    /// Accept an inbound server connection.
    ///
    /// Opens a unidirectional control stream and accepts the peer.s, decodes SETUP,
    /// sends SETUP with parameters only.  Version is already agreed
    /// via ALPN before this is called.
    pub async fn accept(
        session: web_transport::Session,
        mlog_path: Option<PathBuf>,
        transport: Transport,
    ) -> Result<(Session, Option<Publisher>, Option<Subscriber>), SessionError> {
        let mut mlog = mlog_path.and_then(|p| {
            mlog::MlogWriter::new(p)
                .map_err(|e| tracing::warn!("Failed to create mlog: {}", e))
                .ok()
        });

        // Open our unidirectional control send stream.
        let send_stream = session.open_uni().await?;
        let mut sender = Writer::new(send_stream);

        // Accept the peer's unidirectional control stream.
        let recv_stream = session.accept_uni().await?;
        let mut recver = Reader::new(recv_stream);

        let client: setup::Setup = recver.decode().await?;
        let peer_max_request_updates = client.max_request_updates()?;
        tracing::debug!(
            target: "moq_transport::control",
            direction = "recv",
            msg_type = "SETUP",
            "MoQT control message"
        );

        // For WebTransport the path arrives in the HTTP/3 CONNECT :path.
        // For raw QUIC the PATH setup parameter carries it instead.
        let wt_url_path = session.url().path();
        let wt_path = Self::normalize_connection_path(wt_url_path)?;

        let client_setup_path = if wt_path.is_none() {
            Self::decode_client_setup_path(&client.params)?
        } else {
            None
        };

        let connection_path = wt_path.or(client_setup_path);

        if connection_path.is_some() {
            tracing::debug!(
                connection_path = connection_path.as_deref(),
                "Connection path resolved"
            );
        }

        if let Some(ref mut mlog) = mlog {
            let event = mlog::events::client_setup_parsed(mlog.elapsed_ms(), 0, &client);
            let _ = mlog.add_event(event);
        }

        let mut params = KeyValuePairs::default();
        params.set_intvalue(
            setup::ParameterType::MaxRequestUpdates.into(),
            Self::DEFAULT_MAX_REQUEST_UPDATES,
        );

        let server = setup::Setup { params };

        tracing::debug!(
            target: "moq_transport::control",
            direction = "sent",
            msg_type = "SETUP (recv)",
            "MoQT control message"
        );

        if let Some(ref mut mlog) = mlog {
            let event = mlog::events::server_setup_created(mlog.elapsed_ms(), 0, &server);
            let _ = mlog.add_event(event);
        }

        sender.encode(&server).await?;

        // Server sends odd IDs (1); peer client sends even IDs (0).
        let request_id = RequestId::new(1, 0);
        Ok(Session::new(
            session,
            sender,
            recver,
            mlog,
            request_id,
            SessionConfig {
                transport,
                connection_path,
                peer_max_request_updates,
            },
        ))
    }

    /// Run Tasks for the session, including sending of control messages, receiving and processing
    /// inbound control messages, receiving and processing new inbound uni-directional QUIC streams,
    /// and receiving and processing QUIC datagrams received
    pub async fn run(self) -> Result<(), SessionError> {
        let mut bidi_task_rx = self.bidi_task_rx;
        let mut reader_tasks = FuturesUnordered::new();

        let result = tokio::select! {
            res = Self::run_recv(self.recver, self.publisher.clone(), self.subscriber.clone(), self.mlog.clone(), self.request_id.clone(), self.outgoing.clone()) => res,
            res = Self::run_send(self.sender, self.outgoing, self.mlog.clone(), self.bidi_response_map.clone()) => res,
            res = Self::run_bidi_requests(self.webtransport.clone(), self.publisher.clone(), self.subscriber.clone(), self.request_id.clone(), self.bidi_response_map.clone(), self.max_request_updates, self.peer_max_request_updates) => res,
            res = Self::run_streams(self.webtransport.clone(), self.subscriber.clone()) => res,
            res = Self::run_datagrams(self.webtransport, self.subscriber) => res,
            // Collect bidi reader task handles and poll them to completion.
            () = async {
                loop {
                    tokio::select! {
                        handle = bidi_task_rx.recv() => {
                            match handle {
                                Some(h) => reader_tasks.push(h),
                                None => break, // all senders dropped
                            }
                        }
                        Some(_) = reader_tasks.next() => {}
                    }
                }
            } => Ok(()),
        };

        Self::shutdown_bidi_tasks(&mut bidi_task_rx, &mut reader_tasks).await;

        result
    }

    /// Stop and join every request-stream task owned by the session.
    ///
    /// Closing the receiver first creates a linearization point with racing
    /// senders: a send either completed before the close and is drained below,
    /// or it fails and `BidiTaskSendError` aborts the returned handle. Every
    /// handle accepted by this collector is explicitly awaited after abort so
    /// no request-stream task can outlive `Session::run`.
    async fn shutdown_bidi_tasks(
        bidi_task_rx: &mut tokio::sync::mpsc::UnboundedReceiver<tokio::task::JoinHandle<()>>,
        reader_tasks: &mut FuturesUnordered<tokio::task::JoinHandle<()>>,
    ) {
        bidi_task_rx.close();
        while let Some(task) = bidi_task_rx.recv().await {
            reader_tasks.push(task);
        }

        for task in reader_tasks.iter() {
            task.abort();
        }

        while let Some(result) = reader_tasks.next().await {
            if let Err(error) = result {
                if !error.is_cancelled() {
                    tracing::warn!(%error, "request-stream task failed during session shutdown");
                }
            }
        }
    }

    /// Processes the outgoing control message queue. Response messages targeting
    /// a bidi request stream are redirected there (draft-19); everything else
    /// goes to the control stream.
    async fn run_send(
        mut sender: Writer,
        mut outgoing: Queue<message::Message>,
        mlog: Option<Arc<Mutex<mlog::MlogWriter>>>,
        bidi_response_map: BidiResponseMap,
    ) -> Result<(), SessionError> {
        while let Some(msg) = outgoing.pop().await {
            Self::log_control_message(&msg, "sent");

            if let Some(ref mlog) = mlog {
                if let Ok(mut mlog_guard) = mlog.lock() {
                    let time = mlog_guard.elapsed_ms();
                    // Draft-18: Subscribe and PublishNamespace travel on bidi
                    // request streams, not the control stream. Use the request
                    // ID as the stream identifier for mlog; only GoAway still
                    // uses stream 0 (control).
                    let event = match &msg {
                        Message::Subscribe(m) => {
                            Some(mlog::events::subscribe_created(time, m.id, m))
                        }
                        Message::SubscribeOk(m) => {
                            Some(mlog::events::subscribe_ok_created(time, m.id, m))
                        }
                        Message::PublishNamespace(m) => {
                            Some(mlog::events::publish_namespace_created(time, m.id, m))
                        }
                        Message::GoAway(m) => Some(mlog::events::go_away_created(time, 0, m)),
                        _ => None,
                    };
                    if let Some(event) = event {
                        let _ = mlog_guard.add_event(event);
                    }
                }
            }

            // Draft-18: response messages with a target request ID belong on
            // the bidi stream, never the control stream.
            if let Some(target_id) = msg.response_target_id() {
                let tx_opt = bidi_response_map
                    .lock()
                    .map_err(|_| SessionError::Internal)?
                    .get(&target_id)
                    .cloned();
                if let Some(tx) = tx_opt {
                    if tx.send(BidiCommand::Send(msg)).is_err() {
                        tracing::warn!(target_id, "bidi response channel closed, dropping message");
                    }
                } else {
                    tracing::warn!(
                        target_id,
                        "bidi response map entry gone, dropping late response"
                    );
                }
                continue; // never fall through to control stream for bidi-only messages
            }

            // Only control-stream messages (no response_target_id) reach here.
            sender.encode(&msg).await?;
        }

        Ok(())
    }

    /// Accept incoming bidirectional request streams (draft-19 §10).
    /// Each peer-initiated bidi stream carries one request message followed
    /// by responses/follow-ups on the same stream.
    /// Maximum number of bidi request handler tasks running concurrently.
    /// Provides back-pressure when a peer opens many streams at once.
    const MAX_CONCURRENT_BIDI_STREAMS: usize = 128;

    async fn run_bidi_requests(
        webtransport: web_transport::Session,
        publisher: Option<Publisher>,
        subscriber: Option<Subscriber>,
        request_id: RequestId,
        bidi_response_map: BidiResponseMap,
        max_request_updates: u64,
        peer_max_request_updates: u64,
    ) -> Result<(), SessionError> {
        let mut tasks = FuturesUnordered::new();

        loop {
            tokio::select! {
                res = webtransport.accept_bi(), if tasks.len() < Self::MAX_CONCURRENT_BIDI_STREAMS => {
                    let (send_stream, recv_stream) = res?;
                    let mut pub_clone = publisher.clone();
                    let mut sub_clone = subscriber.clone();
                    let rid = request_id.clone();
                    let map = bidi_response_map.clone();

                    tasks.push(async move {
                        Self::handle_bidi_request(
                            send_stream, recv_stream,
                            &mut pub_clone, &mut sub_clone, &rid, &map,
                            RequestUpdateLimits {
                                incoming: max_request_updates,
                                outgoing: peer_max_request_updates,
                            },
                        ).await
                    });
                }
                Some(result) = tasks.next() => match result {
                    Err(error) if error.is_request_stream_cancelled() => {
                        tracing::debug!(%error, "peer cancelled request stream");
                    }
                    other => other?,
                },
            }
        }
    }

    /// Handle a single bidi request stream: decode the request, dispatch
    /// to handlers, then wait for responses and write them back on the
    /// same stream (without Request ID, per draft-19).
    async fn handle_bidi_request(
        send_stream: web_transport::SendStream,
        recv_stream: web_transport::RecvStream,
        publisher: &mut Option<Publisher>,
        subscriber: &mut Option<Subscriber>,
        request_id: &RequestId,
        bidi_response_map: &BidiResponseMap,
        update_limits: RequestUpdateLimits,
    ) -> Result<(), SessionError> {
        let mut reader = Reader::new(recv_stream);
        let mut writer = Writer::new(send_stream);

        // Read the first (request) message from the bidi stream.
        let msg: Message = reader.decode().await?;
        let request_kind = RequestKind::from_first_message(&msg)?;
        let initial_id = msg.sequenced_request_id().ok_or_else(|| {
            SessionError::ProtocolViolation(
                "first request-stream message did not consume a Request ID".to_string(),
            )
        })?;

        request_id.validate_incoming(initial_id)?;

        let (response_tx, mut response_rx) = tokio::sync::mpsc::unbounded_channel::<BidiCommand>();
        bidi_response_map
            .lock()
            .map_err(|_| SessionError::Internal)?
            .insert(initial_id, response_tx.clone());

        // Dispatch to the appropriate role handler (same as run_recv).
        // Capture the result so cleanup runs unconditionally on error.
        let dispatch_result = (|| -> Result<(), SessionError> {
            let msg = match TryInto::<message::Publisher>::try_into(msg) {
                Ok(msg) => {
                    subscriber
                        .as_mut()
                        .ok_or(SessionError::RoleViolation)?
                        .recv_message(msg)?;
                    return Ok(());
                }
                Err(msg) => msg,
            };
            match TryInto::<message::Subscriber>::try_into(msg) {
                Ok(msg) => {
                    publisher
                        .as_mut()
                        .ok_or(SessionError::RoleViolation)?
                        .recv_message(msg)?;
                }
                Err(msg) => {
                    tracing::warn!(
                        msg_type = msg.name(),
                        "unexpected message on bidi request stream"
                    );
                }
            }
            Ok(())
        })();
        if let Err(error) = dispatch_result {
            if let Ok(mut map) = bidi_response_map.lock() {
                map.remove(&initial_id);
            }
            return Err(error);
        }

        let mut requester_open = true;
        let mut update_ids = std::collections::HashSet::new();
        let mut update_credits = RequestUpdateCredits::new(update_limits.incoming);
        let mut reverse_updates: std::collections::VecDeque<PendingReverseUpdate> =
            std::collections::VecDeque::new();

        let result = async {
            loop {
                tokio::select! {
                incoming = Self::decode_requester_followup(
                    &mut reader,
                    initial_id,
                    request_kind,
                    reverse_updates.front().map(|update| update.id),
                ), if requester_open => {
                    match incoming? {
                        Some(Message::RequestUpdate(update)) => {
                            if !request_kind.accepts_request_updates() {
                                break Err(SessionError::ProtocolViolation(format!(
                                    "unexpected REQUEST_UPDATE on {:?} request stream",
                                    request_kind
                                )));
                            }

                            request_id.validate_incoming(update.id)?;
                            update_credits.receive()?;

                            let update_id = update.id;
                            let previous = bidi_response_map
                                .lock()
                                .map_err(|_| SessionError::Internal)?
                                .insert(update_id, response_tx.clone());
                            if previous.is_some() || !update_ids.insert(update_id) {
                                break Err(SessionError::InvalidRequestId);
                            }

                            let dispatch = if request_kind.is_publisher_message() {
                                subscriber
                                    .as_mut()
                                    .ok_or(SessionError::RoleViolation)?
                                    .recv_request_update(initial_id, update)
                            } else {
                                publisher
                                    .as_mut()
                                    .ok_or(SessionError::RoleViolation)?
                                    .recv_request_update(initial_id, update)
                            };
                            if let Err(error) = dispatch {
                                break Err(error);
                            }
                        }
                        Some(Message::PublishDone(done)) if request_kind == RequestKind::Publish => {
                            let subscriber = subscriber
                                .as_mut()
                                .ok_or(SessionError::RoleViolation)?;
                            subscriber.recv_message(message::Publisher::PublishDone(done))?;
                            subscriber.await_publish_done_cleanup(initial_id).await;
                            break Ok(());
                        }
                        Some(Message::RequestOk(ok)) if request_kind == RequestKind::Publish => {
                            let Some(update) = reverse_updates.pop_front() else {
                                break Err(SessionError::ProtocolViolation(
                                    "PUBLISH requester sent REQUEST_OK without a pending reverse update"
                                        .to_string(),
                                ));
                            };
                            debug_assert_eq!(ok.id, update.id);
                            Self::validate_response_for_request(request_kind, true, &Message::RequestOk(ok))?;
                            let result = subscriber
                                .as_mut()
                                .ok_or(SessionError::RoleViolation)?
                                .set_publish_forward(initial_id, update.forward);
                            let completion_result = result.clone();
                            let _ = update.completion.send(completion_result);
                            result?;
                        }
                        Some(Message::RequestError(error)) if request_kind == RequestKind::Publish => {
                            let Some(update) = reverse_updates.pop_front() else {
                                break Err(SessionError::ProtocolViolation(
                                    "PUBLISH requester sent REQUEST_ERROR without a pending reverse update"
                                        .to_string(),
                                ));
                            };
                            debug_assert_eq!(error.id, update.id);
                            let _ = update.completion.send(Err(SessionError::Serve(
                                crate::serve::ServeError::Closed(error.error_code),
                            )));
                        }
                        Some(other) => {
                            break Err(SessionError::ProtocolViolation(format!(
                                "unexpected {} after first request-stream message",
                                other.name()
                            )));
                        }
                        None => {
                            if request_kind == RequestKind::Publish {
                                break Err(SessionError::ProtocolViolation(
                                    "PUBLISH requester sent FIN while its request remained established"
                                        .to_string(),
                                ));
                            }
                            requester_open = false;
                        }
                    }
                }
                command = response_rx.recv() => {
                    let Some(command) = command else {
                        break Err(SessionError::Internal);
                    };
                    let response = match command {
                        BidiCommand::Cancel(code) => {
                            reader.stop(code);
                            writer.reset(code);
                            break Ok(());
                        }
                        BidiCommand::RequestUpdate { update, forward, completion } => {
                            if request_kind != RequestKind::Publish {
                                let _ = completion.send(Err(SessionError::ProtocolViolation(
                                    "reverse REQUEST_UPDATE is only valid for PUBLISH".to_string(),
                                )));
                                continue;
                            }
                            if update_limits.outgoing != 0
                                && reverse_updates.len() as u64 >= update_limits.outgoing
                            {
                                let _ = completion.send(Err(SessionError::TooManyRequestUpdates));
                                continue;
                            }
                            writer.encode(&Message::RequestUpdate(update.clone())).await?;
                            reverse_updates.push_back(PendingReverseUpdate {
                                id: update.id,
                                forward,
                                completion,
                            });
                            continue;
                        }
                        BidiCommand::Send(response) => response,
                    };
                    let response_id = response.response_target_id().ok_or_else(|| {
                        SessionError::ProtocolViolation(format!(
                            "{} is not valid on a request response stream",
                            response.name()
                        ))
                    })?;
                    let is_update_response = update_ids.remove(&response_id);

                    Self::validate_response_for_request(
                        request_kind,
                        is_update_response,
                        &response,
                    )?;
                    Self::encode_bidi_response(&mut writer, &response).await?;

                    if is_update_response {
                        if let Ok(mut map) = bidi_response_map.lock() {
                            map.remove(&response_id);
                        }
                        update_credits.respond();
                    }

                    let request_error_is_terminal = matches!(&response, Message::RequestError(_))
                        && !(is_update_response
                            && matches!(request_kind, RequestKind::Subscribe | RequestKind::Publish));
                    let terminal = request_error_is_terminal
                        || matches!(&response, Message::PublishDone(_))
                        || (request_kind == RequestKind::TrackStatus
                            && matches!(&response, Message::RequestOk(_)));
                    if terminal {
                        break Ok(());
                    }
                }
                }
            }
        }
        .await;

        if let Ok(mut map) = bidi_response_map.lock() {
            map.remove(&initial_id);
            for update_id in update_ids {
                map.remove(&update_id);
            }
        }
        for update in reverse_updates {
            let _ = update
                .completion
                .send(Err(SessionError::Serve(crate::serve::ServeError::Cancel)));
        }

        if request_kind == RequestKind::Publish {
            if let Err(error) = &result {
                if let Some(subscriber) = subscriber.as_mut() {
                    let serve_error = if error.is_request_stream_cancelled() {
                        crate::serve::ServeError::Cancel
                    } else {
                        crate::serve::ServeError::internal_ctx(error.to_string())
                    };
                    subscriber.fail_publish_received(initial_id, serve_error);
                }
            }
        }

        // Explicitly finish the stream and yield for Quinn to flush.
        writer.finish();
        tokio::task::yield_now().await;

        result
    }

    /// Decode a message sent after the first request-stream message.
    ///
    /// `PUBLISH_DONE` omits its Request ID because the request stream already
    /// identifies the publication. Other requester-side follow-ups currently
    /// use their regular encoding (`REQUEST_UPDATE` carries its own new ID).
    async fn decode_requester_followup(
        reader: &mut Reader,
        initial_id: u64,
        request_kind: RequestKind,
        pending_reverse_update: Option<u64>,
    ) -> Result<Option<Message>, SessionError> {
        if request_kind == RequestKind::Publish {
            if reader.done().await? {
                return Ok(None);
            }
            let (msg_type, payload) = Self::read_bidi_frame(reader).await?;
            let response_id =
                Self::publish_followup_request_id(msg_type, initial_id, pending_reverse_update)?;
            return Self::decode_bidi_response_payload(
                msg_type,
                payload,
                response_id,
                request_kind,
            )
            .map(Some);
        }
        reader.decode_optional::<Message>().await
    }

    fn publish_followup_request_id(
        msg_type: u64,
        initial_id: u64,
        pending_reverse_update: Option<u64>,
    ) -> Result<u64, SessionError> {
        match msg_type {
            message::wire_id::PublishDone => Ok(initial_id),
            message::wire_id::RequestOk | message::wire_id::RequestError => pending_reverse_update
                .ok_or_else(|| {
                    SessionError::ProtocolViolation(
                        "PUBLISH response arrived without a pending reverse update".to_string(),
                    )
                }),
            _ => Ok(initial_id),
        }
    }

    fn validate_response_for_request(
        request_kind: RequestKind,
        is_update_response: bool,
        response: &Message,
    ) -> Result<(), SessionError> {
        match response {
            Message::RequestOk(ok) => {
                let properties_allowed =
                    !is_update_response && request_kind == RequestKind::TrackStatus;
                if !properties_allowed && !ok.track_properties.is_empty() {
                    return Err(SessionError::ProtocolViolation(
                        "Track Properties are only valid in TRACK_STATUS_OK".to_string(),
                    ));
                }
            }
            Message::RequestError(error) => {
                if let Some(redirect) = &error.redirect {
                    if request_kind.is_namespace_scoped()
                        && !redirect.track_name.as_bytes().is_empty()
                    {
                        return Err(SessionError::ProtocolViolation(
                            "namespace-scoped redirect contained a Track Name".to_string(),
                        ));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Encode a response message to a bidi stream, omitting the Request ID
    /// field per draft-19 (the stream identity provides the association).
    /// Build the wire frame for a bidi response message (type + length +
    /// payload with Request ID omitted). Separated from the async writer
    /// so tests can verify the encoding without a QUIC stream.
    fn encode_bidi_response_frame(msg: &Message) -> Result<bytes::BytesMut, SessionError> {
        use bytes::BufMut;

        // Encode the payload (all fields EXCEPT Request ID, which is
        // implicit from the bidi stream identity in draft-19).
        let mut payload = bytes::BytesMut::new();
        match msg {
            Message::RequestOk(m) => {
                m.params.encode(&mut payload)?;
                m.track_properties.encode(&mut payload)?;
            }
            Message::RequestError(m) => {
                m.error_code.encode(&mut payload)?;
                m.retry_interval.encode(&mut payload)?;
                m.reason.encode(&mut payload)?;
                match (
                    m.error_code == message::RequestErrorCode::Redirect as u64,
                    &m.redirect,
                ) {
                    (true, Some(redirect)) => redirect.encode(&mut payload)?,
                    (true, None) => {
                        return Err(SessionError::ProtocolViolation(
                            "REDIRECT REQUEST_ERROR omitted Redirect".to_string(),
                        ));
                    }
                    (false, Some(_)) => {
                        return Err(SessionError::ProtocolViolation(
                            "non-REDIRECT REQUEST_ERROR contained Redirect".to_string(),
                        ));
                    }
                    (false, None) => {}
                }
            }
            Message::SubscribeOk(m) => {
                m.track_alias.encode(&mut payload)?;
                m.params.encode(&mut payload)?;
                m.track_extensions.encode(&mut payload)?;
            }
            Message::PublishDone(m) => {
                m.status_code.encode(&mut payload)?;
                m.stream_count.encode(&mut payload)?;
                m.reason.encode(&mut payload)?;
            }
            Message::FetchOk(m) => {
                m.end_of_track.encode(&mut payload)?;
                m.end_location.encode(&mut payload)?;
                m.params.encode(&mut payload)?;
                m.track_extensions.encode(&mut payload)?;
            }
            other => {
                tracing::warn!(
                    msg_type = other.name(),
                    "unexpected message type in encode_bidi_response — not a bidi response message"
                );
                return Err(SessionError::Internal);
            }
        };

        let msg_type = msg.id();

        if payload.len() > u16::MAX as usize {
            return Err(crate::coding::EncodeError::MsgBoundsExceeded.into());
        }
        let mut frame = bytes::BytesMut::new();
        msg_type.encode(&mut frame)?;
        (payload.len() as u16).encode(&mut frame)?;
        frame.put(payload);
        Ok(frame)
    }

    async fn encode_bidi_response(writer: &mut Writer, msg: &Message) -> Result<(), SessionError> {
        let frame = Self::encode_bidi_response_frame(msg)?;
        writer.write(&frame).await?;
        Ok(())
    }

    /// Decode a response message from a bidi request stream (draft-19).
    ///
    /// Response messages omit the Request ID field — the stream identity
    /// provides the association. The caller supplies the known `request_id`
    /// which is injected into the decoded `Message`.
    pub(super) async fn decode_bidi_response(
        reader: &mut Reader,
        request_id: u64,
        request_kind: RequestKind,
    ) -> Result<Message, SessionError> {
        let (msg_type, payload) = Self::read_bidi_frame(reader).await?;
        Self::decode_bidi_response_payload(msg_type, payload, request_id, request_kind)
    }

    async fn read_bidi_frame(reader: &mut Reader) -> Result<(u64, bytes::BytesMut), SessionError> {
        use crate::coding::DecodeError;
        let msg_type: u64 = reader.decode().await?;
        let msg_len: u16 = reader.decode().await?;
        let len = usize::from(msg_len);
        let mut payload = bytes::BytesMut::new();
        while payload.len() < len {
            let remaining = len - payload.len();
            match reader.read_chunk(remaining).await? {
                Some(chunk) => payload.extend_from_slice(&chunk),
                None => return Err(DecodeError::More(remaining).into()),
            }
        }
        Ok((msg_type, payload))
    }

    fn decode_bidi_response_payload(
        msg_type: u64,
        payload: bytes::BytesMut,
        request_id: u64,
        request_kind: RequestKind,
    ) -> Result<Message, SessionError> {
        use crate::coding::{Decode, ReasonPhrase};
        use bytes::Buf as _;
        let mut buf = &payload[..];

        use message::wire_id;

        let message = match msg_type {
            wire_id::RequestError => {
                let error_code = u64::decode(&mut buf)?;
                let retry_interval = u64::decode(&mut buf)?;
                let reason = ReasonPhrase::decode(&mut buf)?;
                let redirect = if error_code == message::RequestErrorCode::Redirect as u64 {
                    Some(message::Redirect::decode(&mut buf)?)
                } else {
                    None
                };
                Ok(Message::RequestError(message::RequestError {
                    id: request_id,
                    error_code,
                    retry_interval,
                    reason,
                    redirect,
                }))
            }
            wire_id::RequestOk => {
                let params = crate::coding::KeyValuePairs::decode(&mut buf)?;
                let track_properties = message::TrackProperties::decode(&mut buf)?;
                Ok(Message::RequestOk(message::RequestOk {
                    id: request_id,
                    params,
                    track_properties,
                }))
            }
            wire_id::SubscribeOk => {
                let track_alias = u64::decode(&mut buf)?;
                let params = crate::coding::KeyValuePairs::decode(&mut buf)?;
                let track_extensions = message::TrackExtensions::decode(&mut buf)?;
                Ok(Message::SubscribeOk(message::SubscribeOk {
                    id: request_id,
                    track_alias,
                    params,
                    track_extensions,
                }))
            }
            wire_id::PublishDone => {
                let status_code = u64::decode(&mut buf)?;
                let stream_count = u64::decode(&mut buf)?;
                let reason = ReasonPhrase::decode(&mut buf)?;
                Ok(Message::PublishDone(message::PublishDone {
                    id: request_id,
                    status_code,
                    stream_count,
                    reason,
                }))
            }
            wire_id::FetchOk => {
                let end_of_track = bool::decode(&mut buf)?;
                let end_location = crate::coding::Location::decode(&mut buf)?;
                let params = crate::coding::KeyValuePairs::decode(&mut buf)?;
                let track_extensions = message::TrackExtensions::decode(&mut buf)?;
                Ok(Message::FetchOk(message::FetchOk {
                    id: request_id,
                    end_of_track,
                    end_location,
                    params,
                    track_extensions,
                }))
            }
            other => {
                tracing::warn!(msg_type = other, "unexpected bidi response message type");
                Err(SessionError::unimplemented(&format!(
                    "bidi response type 0x{:x}",
                    other
                )))
            }
        }?;

        if buf.has_remaining() {
            return Err(SessionError::ProtocolViolation(format!(
                "response type 0x{:x} left {} unparsed body bytes",
                msg_type,
                buf.remaining()
            )));
        }
        Self::validate_response_for_request(request_kind, false, &message)?;
        Ok(message)
    }

    pub(super) async fn decode_publish_response(
        reader: &mut Reader,
        request_id: u64,
    ) -> Result<Message, SessionError> {
        let (msg_type, payload) = Self::read_bidi_frame(reader).await?;
        Self::decode_publish_response_payload(msg_type, payload, request_id)
    }

    fn decode_publish_response_payload(
        msg_type: u64,
        payload: bytes::BytesMut,
        request_id: u64,
    ) -> Result<Message, SessionError> {
        use crate::coding::Decode;
        use bytes::Buf as _;

        if msg_type != message::wire_id::RequestUpdate {
            return Self::decode_bidi_response_payload(
                msg_type,
                payload,
                request_id,
                RequestKind::Publish,
            );
        }

        let mut body = &payload[..];
        let update = message::RequestUpdate::decode(&mut body)?;
        if body.has_remaining() {
            return Err(SessionError::ProtocolViolation(format!(
                "REQUEST_UPDATE left {} unparsed body bytes",
                body.remaining()
            )));
        }
        Ok(Message::RequestUpdate(update))
    }

    /// Receives inbound messages from the control stream reader/receiver.
    /// Handles session-level messages (GOAWAY) directly and routes
    /// role-specific messages to Publisher or Subscriber.
    async fn run_recv(
        mut recver: Reader,
        mut publisher: Option<Publisher>,
        mut subscriber: Option<Subscriber>,
        mlog: Option<Arc<Mutex<mlog::MlogWriter>>>,
        request_id: RequestId,
        _outgoing: Queue<Message>,
    ) -> Result<(), SessionError> {
        let mut goaway_received = false;

        loop {
            let msg: message::Message = recver.decode().await?;

            // Emit structured tracing log for received control messages
            Self::log_control_message(&msg, "recv");

            // Emit mlog event for received control messages
            if let Some(ref mlog) = mlog {
                if let Ok(mut mlog_guard) = mlog.lock() {
                    let time = mlog_guard.elapsed_ms();
                    let stream_id = 0; // Control stream is always stream 0

                    // Emit events based on message type
                    let event = match &msg {
                        Message::Subscribe(m) => {
                            Some(mlog::events::subscribe_parsed(time, stream_id, m))
                        }
                        Message::SubscribeOk(m) => {
                            Some(mlog::events::subscribe_ok_parsed(time, stream_id, m))
                        }
                        Message::PublishNamespace(m) => {
                            Some(mlog::events::publish_namespace_parsed(time, stream_id, m))
                        }
                        Message::GoAway(m) => {
                            Some(mlog::events::go_away_parsed(time, stream_id, m))
                        }
                        _ => None, // TODO: Add other message types
                    };

                    if let Some(event) = event {
                        let _ = mlog_guard.add_event(event);
                    }
                }
            }

            if let Some(id) = msg.sequenced_request_id() {
                request_id.validate_incoming(id)?;
            }

            let msg = match TryInto::<message::Publisher>::try_into(msg) {
                Ok(msg) => {
                    subscriber
                        .as_mut()
                        .ok_or(SessionError::RoleViolation)?
                        .recv_message(msg)?;
                    continue;
                }
                Err(msg) => msg,
            };

            let msg = match TryInto::<message::Subscriber>::try_into(msg) {
                Ok(msg) => {
                    publisher
                        .as_mut()
                        .ok_or(SessionError::RoleViolation)?
                        .recv_message(msg)?;
                    continue;
                }
                Err(msg) => msg,
            };

            // Session-level messages handled here (not role-specific).
            match msg {
                Message::GoAway(ref m) => {
                    // Draft-16 §9.4: receiving a second GOAWAY is PROTOCOL_VIOLATION.
                    if goaway_received {
                        return Err(SessionError::ProtocolViolation(
                            "received multiple GOAWAY messages".to_string(),
                        ));
                    }
                    goaway_received = true;
                    tracing::info!(
                        target: "moq_transport::control",
                        new_uri = %m.uri.0,
                        "received GOAWAY"
                    );
                    // TODO(itzmanish): trigger session migration.
                }
                other => {
                    tracing::warn!(msg_type = other.name(), "received unhandled message type");
                    return Err(SessionError::unimplemented(&format!(
                        "message type {}",
                        other.name()
                    )));
                }
            }
        }
    }

    /// Accepts uni-directional quic streams and starts handling for them.
    /// Will read stream header to know what type of stream it is and create
    /// the appropriate stream handlers.
    async fn run_streams(
        webtransport: web_transport::Session,
        subscriber: Option<Subscriber>,
    ) -> Result<(), SessionError> {
        let mut tasks = FuturesUnordered::new();
        let limits = DataStreamTaskLimits::production();

        loop {
            tokio::select! {
                // Reap completed handlers before accepting more streams. This
                // keeps normal streams progressing even under an excess-open
                // flood from the peer.
                biased;
                _ = tasks.next(), if !tasks.is_empty() => {},
                res = webtransport.accept_uni() => {
                    let mut stream = res?;
                    let subscriber = subscriber.clone().ok_or(SessionError::RoleViolation)?;
                    let Some(global_permit) = limits.try_admit(tasks.len()) else {
                        stream.stop(Self::DATA_STREAM_EXCESSIVE_LOAD);
                        tracing::warn!(
                            active_for_session = tasks.len(),
                            per_session_limit = limits.per_session,
                            global_available = limits.global.available_permits(),
                            error_code = Self::DATA_STREAM_EXCESSIVE_LOAD,
                            "rejecting peer data stream: handler capacity exhausted"
                        );
                        continue;
                    };

                    tasks.push(async move {
                        let _global_permit = global_permit;
                        if let Err(err) = Subscriber::recv_stream(subscriber, stream).await {
                            tracing::warn!("failed to serve stream: {}", err);
                        };
                    });
                },
            };
        }
    }

    /// Receives QUIC datagrams and processes them using the Subscriber logic
    async fn run_datagrams(
        webtransport: web_transport::Session,
        mut subscriber: Option<Subscriber>,
    ) -> Result<(), SessionError> {
        loop {
            let datagram = webtransport.recv_datagram().await?;
            subscriber
                .as_mut()
                .ok_or(SessionError::RoleViolation)?
                .recv_datagram(datagram)
                .await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TaskDropCounter(Arc<AtomicUsize>);

    impl Drop for TaskDropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn pending_task(dropped: Arc<AtomicUsize>) -> tokio::task::JoinHandle<()> {
        let drop_counter = TaskDropCounter(dropped);
        tokio::spawn(async move {
            let _drop_counter = drop_counter;
            futures::future::pending::<()>().await;
        })
    }

    // ========================================================================
    // normalize_connection_path
    // ========================================================================

    #[test]
    fn normalize_empty_and_root() {
        assert_eq!(Session::normalize_connection_path("").unwrap(), None);
        assert_eq!(Session::normalize_connection_path("/").unwrap(), None);
        assert_eq!(Session::normalize_connection_path("///").unwrap(), None);
    }

    #[test]
    fn normalize_valid_paths() {
        assert_eq!(
            Session::normalize_connection_path("/app").unwrap(),
            Some("/app".to_string())
        );
        assert_eq!(
            Session::normalize_connection_path("/tenant/stream-1").unwrap(),
            Some("/tenant/stream-1".to_string())
        );
        // Trailing slash is trimmed
        assert_eq!(
            Session::normalize_connection_path("/app/").unwrap(),
            Some("/app".to_string())
        );
    }

    #[test]
    fn normalize_rejects_missing_leading_slash() {
        assert!(Session::normalize_connection_path("app").is_err());
    }

    #[test]
    fn normalize_rejects_empty_segments() {
        assert!(Session::normalize_connection_path("/app//stream").is_err());
    }

    #[test]
    fn normalize_rejects_dot_segments() {
        assert!(Session::normalize_connection_path("/app/./stream").is_err());
        assert!(Session::normalize_connection_path("/app/../secret").is_err());
        assert!(Session::normalize_connection_path("/..").is_err());
    }

    #[test]
    fn normalize_rejects_percent_encoded_characters() {
        // %2F = '/' — would create scope ambiguity
        assert!(Session::normalize_connection_path("/foo%2Fbar").is_err());
        // %2E%2E = '..' — would bypass dot-segment check
        assert!(Session::normalize_connection_path("/%2E%2E/secret").is_err());
        // %00 = null — general injection risk
        assert!(Session::normalize_connection_path("/app/%00").is_err());
        // Uppercase hex digits
        assert!(Session::normalize_connection_path("/app/%2e%2e").is_err());
    }

    #[test]
    fn normalize_rejects_too_long_path() {
        let long_path = format!("/{}", "a".repeat(Session::MAX_CONNECTION_PATH_LEN));
        assert!(Session::normalize_connection_path(&long_path).is_err());
    }

    #[test]
    fn normalize_accepts_max_length_path() {
        // Exactly at the limit (1024 total including leading slash)
        let path = format!("/{}", "a".repeat(Session::MAX_CONNECTION_PATH_LEN - 1));
        assert!(Session::normalize_connection_path(&path).is_ok());
    }

    // ========================================================================
    // task admission and shutdown
    // ========================================================================

    #[test]
    fn data_stream_admission_enforces_per_session_and_global_limits() {
        let per_session = DataStreamTaskLimits {
            global: Arc::new(tokio::sync::Semaphore::new(8)),
            per_session: 1,
        };
        let permit = per_session.try_admit(0).expect("first stream admitted");
        assert!(per_session.try_admit(1).is_none());
        drop(permit);

        let global = Arc::new(tokio::sync::Semaphore::new(2));
        let first_session = DataStreamTaskLimits {
            global: global.clone(),
            per_session: 8,
        };
        let second_session = DataStreamTaskLimits {
            global,
            per_session: 8,
        };
        let first = first_session.try_admit(0).expect("first global permit");
        let second = second_session.try_admit(0).expect("second global permit");
        assert!(first_session.try_admit(1).is_none());
        drop(first);
        assert!(first_session.try_admit(1).is_some());
        drop(second);

        assert_eq!(Session::DATA_STREAM_EXCESSIVE_LOAD, 0x9);
    }

    #[tokio::test]
    async fn bidi_task_shutdown_drains_aborts_and_awaits_all_accepted_handles() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let (sender, mut receiver) = BidiTaskSender::channel();
        let mut collected = FuturesUnordered::new();

        collected.push(pending_task(dropped.clone()));
        assert!(sender.send(pending_task(dropped.clone())).is_ok());
        assert!(sender.send(pending_task(dropped.clone())).is_ok());

        Session::shutdown_bidi_tasks(&mut receiver, &mut collected).await;

        assert!(collected.is_empty());
        assert_eq!(dropped.load(Ordering::SeqCst), 3);
        assert!(receiver.is_closed());
    }

    #[tokio::test]
    async fn bidi_task_sender_aborts_handle_raced_after_collector_close() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let (sender, mut receiver) = BidiTaskSender::channel();
        receiver.close();

        let result = sender.send(pending_task(dropped.clone()));
        assert!(result.is_err());
        drop(result);

        for _ in 0..100 {
            if dropped.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn bidi_task_send_error_can_abort_and_join_raced_handle() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let (sender, mut receiver) = BidiTaskSender::channel();
        receiver.close();

        let Err(error) = sender.send(pending_task(dropped.clone())) else {
            panic!("closed task collector accepted a handle");
        };
        error.abort_and_wait().await;

        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    // ========================================================================
    // encode_bidi_response — verify wire format (no Request ID)
    // ========================================================================

    /// Helper: calls the production `encode_bidi_response_frame` and
    /// returns the raw bytes. No duplicate encoding logic.
    fn encode_bidi_response_bytes(msg: &Message) -> Vec<u8> {
        Session::encode_bidi_response_frame(msg).unwrap().to_vec()
    }

    #[test]
    fn encode_bidi_request_ok_omits_request_id() {
        use message::wire_id;
        let msg = Message::RequestOk(message::RequestOk {
            id: 42, // should NOT appear on the wire
            params: crate::coding::KeyValuePairs::default(),
            track_properties: Default::default(),
        });
        let bytes = encode_bidi_response_bytes(&msg);
        // type (1 byte) + length 0x0001 (2 bytes) + params_count=0 (1 byte) = 4 bytes
        assert_eq!(bytes[0], wire_id::RequestOk as u8);
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn encode_bidi_request_error_omits_request_id() {
        use message::wire_id;
        let msg = Message::RequestError(message::RequestError {
            id: 99, // should NOT appear on the wire
            error_code: 0x10,
            retry_interval: 0,
            reason: crate::coding::ReasonPhrase("nf".to_string()),
            redirect: None,
        });
        let bytes = encode_bidi_response_bytes(&msg);
        assert_eq!(bytes[0], wire_id::RequestError as u8);
        // No 99 (0x63) anywhere in the output
        assert!(
            !bytes.contains(&99),
            "Request ID must not appear in bidi encoding"
        );
    }

    #[test]
    fn response_target_id_covers_responses_only() {
        // Response messages should return Some(id)
        assert!(Message::RequestOk(message::RequestOk {
            id: 1,
            params: Default::default(),
            track_properties: Default::default(),
        })
        .response_target_id()
        .is_some());
        assert!(Message::RequestError(message::RequestError {
            id: 1,
            error_code: 0,
            retry_interval: 0,
            reason: Default::default(),
            redirect: None,
        })
        .response_target_id()
        .is_some());

        // Request messages should return None
        assert!(Message::Subscribe(message::Subscribe {
            id: 1,
            track_namespace: crate::coding::TrackNamespace::from_utf8_path("t"),
            track_name: "n".into(),
            params: Default::default(),
        })
        .response_target_id()
        .is_none());
        assert!(Message::GoAway(message::GoAway {
            uri: crate::coding::SessionUri(String::new()),
            timeout: 0,
        })
        .response_target_id()
        .is_none());
    }

    #[test]
    fn request_ok_properties_are_rejected_outside_track_status() {
        let mut properties = message::TrackProperties::default();
        properties.set_int_extension(0x78, 1);
        let response = Message::RequestOk(message::RequestOk {
            id: 2,
            params: Default::default(),
            track_properties: properties,
        });

        assert!(matches!(
            Session::validate_response_for_request(RequestKind::Subscribe, false, &response),
            Err(SessionError::ProtocolViolation(_))
        ));
        assert!(
            Session::validate_response_for_request(RequestKind::TrackStatus, false, &response)
                .is_ok()
        );
        assert!(matches!(
            Session::validate_response_for_request(RequestKind::TrackStatus, true, &response),
            Err(SessionError::ProtocolViolation(_))
        ));
    }

    #[test]
    fn namespace_redirect_rejects_track_name() {
        let response = Message::RequestError(message::RequestError {
            id: 2,
            error_code: message::RequestErrorCode::Redirect as u64,
            retry_interval: 0,
            reason: Default::default(),
            redirect: Some(message::Redirect {
                connect_uri: Default::default(),
                track_namespace: Default::default(),
                track_name: "audio".into(),
            }),
        });

        assert!(matches!(
            Session::validate_response_for_request(RequestKind::PublishNamespace, false, &response),
            Err(SessionError::ProtocolViolation(_))
        ));
    }

    #[test]
    fn encode_bidi_publish_done_omits_request_id() {
        use message::wire_id;
        let msg = Message::PublishDone(message::PublishDone {
            id: 77,
            status_code: 0,
            stream_count: 3,
            reason: crate::coding::ReasonPhrase("done".to_string()),
        });
        let bytes = encode_bidi_response_bytes(&msg);
        assert_eq!(bytes[0], wire_id::PublishDone as u8);
        assert!(
            !bytes.contains(&77),
            "Request ID must not appear in bidi encoding"
        );
    }

    #[test]
    fn encode_bidi_fetch_ok_omits_request_id() {
        use message::wire_id;
        let msg = Message::FetchOk(message::FetchOk {
            id: 88,
            end_of_track: true,
            end_location: crate::coding::Location::new(5, 10),
            params: crate::coding::KeyValuePairs::default(),
            track_extensions: Default::default(),
        });
        let bytes = encode_bidi_response_bytes(&msg);
        assert_eq!(bytes[0], wire_id::FetchOk as u8);
        assert!(
            !bytes.contains(&88),
            "Request ID must not appear in bidi encoding"
        );
    }

    #[test]
    fn publish_followups_keep_terminal_and_update_response_associations_distinct() {
        assert_eq!(
            Session::publish_followup_request_id(message::wire_id::PublishDone, 10, Some(12))
                .unwrap(),
            10
        );
        assert_eq!(
            Session::publish_followup_request_id(message::wire_id::RequestOk, 10, Some(12))
                .unwrap(),
            12
        );
        assert!(matches!(
            Session::publish_followup_request_id(message::wire_id::RequestError, 10, None),
            Err(SessionError::ProtocolViolation(_))
        ));
    }

    #[test]
    fn publish_response_direction_decodes_full_request_update_id_and_forward() {
        let mut params = KeyValuePairs::default();
        params.set_forward(false);
        let update = message::RequestUpdate { id: 14, params };
        let mut payload = bytes::BytesMut::new();
        update.encode(&mut payload).unwrap();

        let decoded =
            Session::decode_publish_response_payload(message::wire_id::RequestUpdate, payload, 10)
                .unwrap();
        let Message::RequestUpdate(decoded) = decoded else {
            panic!("expected REQUEST_UPDATE");
        };
        assert_eq!(decoded.id, 14);
        assert_eq!(decoded.params.forward().unwrap(), Some(false));
    }
}
