// SPDX-FileCopyrightText: 2024-2026 Cloudflare Inc., Luke Curley, Mike English and contributors
// SPDX-FileCopyrightText: 2023-2024 Luke Curley and contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{collections::HashSet, ops};

use bytes::BytesMut;

use crate::{
    coding::{Encode, KeyValuePairs, Location, TrackName, TrackNamespace},
    data,
    message::{self, FilterType, GroupOrder, SubscriptionFilter},
    serve::{self, ServeError, TrackWriter, TrackWriterMode},
};

use crate::watch::State;

use super::SessionError;
use super::Subscriber;

#[derive(Debug, Clone, Copy)]
pub struct DeliveryFilter {
    pub forward: bool,
    pub start_location: Option<Location>,
    pub end_group_id: Option<u64>,
}

impl DeliveryFilter {
    pub fn allows(&self, group_id: u64, object_id: u64) -> bool {
        if !self.forward {
            return false;
        }

        let location = Location::new(group_id, object_id);
        if let Some(start) = self.start_location {
            if location < start {
                return false;
            }
        }

        if let Some(end_group_id) = self.end_group_id {
            if group_id > end_group_id {
                return false;
            }
        }

        true
    }
}

/// Transport-owned configuration for an outbound SUBSCRIBE request.
///
/// `None` leaves a typed parameter off the wire and therefore uses its MOQT
/// default. This keeps [`Subscriber::subscribe_open`] wire-compatible while
/// allowing callers to explicitly send values such as `Forward=1`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubscribeOptions {
    pub forward: Option<bool>,
    pub filter: Option<SubscriptionFilter>,
    pub group_order: Option<GroupOrder>,
    pub subscriber_priority: Option<u8>,
    /// Additional request parameters, such as authorization or delivery
    /// policy. Typed fields above may not also appear here.
    pub request_parameters: KeyValuePairs,
}

impl SubscribeOptions {
    pub fn with_forward(mut self, forward: bool) -> Self {
        self.forward = Some(forward);
        self
    }

    pub fn with_filter(mut self, filter: SubscriptionFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    pub fn with_group_order(mut self, group_order: GroupOrder) -> Self {
        self.group_order = Some(group_order);
        self
    }

    pub fn with_subscriber_priority(mut self, subscriber_priority: u8) -> Self {
        self.subscriber_priority = Some(subscriber_priority);
        self
    }

    pub fn with_request_parameters(mut self, request_parameters: KeyValuePairs) -> Self {
        self.request_parameters = request_parameters;
        self
    }

    /// Validate and merge typed and additional parameters without dropping or
    /// overwriting either source.
    pub fn to_request_parameters(&self) -> Result<KeyValuePairs, SubscribeOptionsError> {
        if let Some(filter) = &self.filter {
            validate_subscription_filter(filter)?;
        }
        if self.group_order == Some(GroupOrder::Publisher) {
            return Err(SubscribeOptionsError::InvalidGroupOrder);
        }

        for forbidden in [
            message::parameter_type::EXPIRES,
            message::parameter_type::LARGEST_OBJECT,
        ] {
            if self.request_parameters.has(forbidden) {
                return Err(SubscribeOptionsError::ParameterNotAllowed(forbidden));
            }
        }

        for (present, parameter) in [
            (self.forward.is_some(), message::parameter_type::FORWARD),
            (
                self.filter.is_some(),
                message::parameter_type::SUBSCRIPTION_FILTER,
            ),
            (
                self.group_order.is_some(),
                message::parameter_type::GROUP_ORDER,
            ),
            (
                self.subscriber_priority.is_some(),
                message::parameter_type::SUBSCRIBER_PRIORITY,
            ),
        ] {
            if present && self.request_parameters.has(parameter) {
                return Err(SubscribeOptionsError::ConflictingParameter(parameter));
            }
        }

        let mut parameters = self.request_parameters.clone();
        if let Some(forward) = self.forward {
            parameters.set_forward(forward);
        }
        if let Some(filter) = &self.filter {
            parameters
                .set_subscription_filter(filter)
                .map_err(|_| SubscribeOptionsError::InvalidRequestParameters)?;
        }
        if let Some(group_order) = self.group_order {
            parameters.set_group_order(group_order);
        }
        if let Some(priority) = self.subscriber_priority {
            parameters.set_subscriber_priority(priority);
        }

        validate_request_parameters(&parameters)?;
        Ok(parameters)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubscribeOptionsError {
    #[error("Publisher group order is an omission sentinel and cannot be sent")]
    InvalidGroupOrder,
    #[error("invalid fields for subscription filter {0:?}")]
    InvalidFilter(FilterType),
    #[error("typed option conflicts with request parameter 0x{0:x}")]
    ConflictingParameter(u64),
    #[error("request parameter 0x{0:x} is not allowed on SUBSCRIBE")]
    ParameterNotAllowed(u64),
    #[error("request parameters are not valid MOQT parameters")]
    InvalidRequestParameters,
}

impl From<SubscribeOptionsError> for ServeError {
    fn from(error: SubscribeOptionsError) -> Self {
        ServeError::Internal(error.to_string())
    }
}

fn validate_subscription_filter(filter: &SubscriptionFilter) -> Result<(), SubscribeOptionsError> {
    let valid = match filter.filter_type {
        FilterType::NextGroupStart | FilterType::LargestObject => {
            filter.start_location.is_none() && filter.end_group_id.is_none()
        }
        FilterType::AbsoluteStart => {
            filter.start_location.is_some() && filter.end_group_id.is_none()
        }
        FilterType::AbsoluteRange => {
            filter.start_location.is_some() && filter.end_group_id.is_some()
        }
    };

    if valid {
        Ok(())
    } else {
        Err(SubscribeOptionsError::InvalidFilter(filter.filter_type))
    }
}

fn validate_request_parameters(parameters: &KeyValuePairs) -> Result<(), SubscribeOptionsError> {
    let mut encoded = BytesMut::new();
    parameters
        .encode(&mut encoded)
        .map_err(|_| SubscribeOptionsError::InvalidRequestParameters)?;
    parameters
        .forward()
        .map_err(|_| SubscribeOptionsError::InvalidRequestParameters)?;
    parameters
        .subscriber_priority()
        .map_err(|_| SubscribeOptionsError::InvalidRequestParameters)?;
    parameters
        .group_order()
        .map_err(|_| SubscribeOptionsError::InvalidRequestParameters)?;
    if let Some(filter) = parameters
        .subscription_filter()
        .map_err(|_| SubscribeOptionsError::InvalidRequestParameters)?
    {
        validate_subscription_filter(&filter)?;
    }

    Ok(())
}

// TODO rename to SubscriptionInfo when used for Publishes as well?
#[derive(Debug, Clone)]
pub struct SubscribeInfo {
    pub id: u64,
    pub track_namespace: TrackNamespace,
    pub track_name: TrackName,

    /// Subscriber Priority
    pub subscriber_priority: u8,
    pub group_order: GroupOrder,

    /// Forward Flag
    pub forward: bool,

    /// Filter type
    pub filter_type: FilterType,

    /// The starting location for this subscription. Only present for "AbsoluteStart" and "AbsoluteRange" filter types.
    pub start_location: Option<Location>,
    /// End group id, inclusive, for the subscription, if applicable. Only present for "AbsoluteRange" filter type.
    pub end_group_id: Option<u64>,

    /// None means the SUBSCRIPTION_FILTER parameter was omitted and the
    /// subscription is unfiltered per draft-16 §9.2.2.5.
    pub filter: Option<SubscriptionFilter>,

    /// Optional parameters
    pub params: KeyValuePairs,

    // Set to true if this is a track_status request only
    pub track_status: bool,
}

impl SubscribeInfo {
    pub fn new_from_subscribe(msg: &message::Subscribe) -> Result<Self, SessionError> {
        let filter = msg.params.subscription_filter()?;
        let filter_type = filter
            .as_ref()
            .map(|filter| filter.filter_type)
            .unwrap_or(FilterType::AbsoluteStart);
        let start_location = filter.as_ref().and_then(|filter| filter.start_location);
        let end_group_id = filter.as_ref().and_then(|filter| filter.end_group_id);

        Ok(Self {
            id: msg.id,
            track_namespace: msg.track_namespace.clone(),
            track_name: msg.track_name.clone(),
            subscriber_priority: msg.params.subscriber_priority()?.unwrap_or(128),
            group_order: msg.params.group_order()?.unwrap_or(GroupOrder::Publisher),
            forward: msg.params.forward()?.unwrap_or(true),
            filter_type,
            start_location,
            end_group_id,
            filter,
            params: msg.params.clone(),
            track_status: false,
        })
    }

    pub fn delivery_filter(&self, largest_location: Option<Location>) -> DeliveryFilter {
        let Some(filter) = &self.filter else {
            return DeliveryFilter {
                forward: self.forward,
                start_location: None,
                end_group_id: None,
            };
        };

        let start_location = match filter.filter_type {
            FilterType::LargestObject => Some(next_object_location(largest_location)),
            FilterType::NextGroupStart => Some(next_group_location(largest_location)),
            FilterType::AbsoluteStart | FilterType::AbsoluteRange => filter.start_location,
        };

        DeliveryFilter {
            forward: self.forward,
            start_location,
            end_group_id: filter.end_group_id,
        }
    }
}

fn next_object_location(largest_location: Option<Location>) -> Location {
    let Some(location) = largest_location else {
        return Location::new(0, 0);
    };

    if let Some(object_id) = location.object_id.checked_add(1) {
        Location::new(location.group_id, object_id)
    } else {
        next_group_location(Some(location))
    }
}

fn next_group_location(largest_location: Option<Location>) -> Location {
    let Some(location) = largest_location else {
        return Location::new(0, 0);
    };

    Location::new(location.group_id.saturating_add(1), 0)
}

struct SubscribeState {
    ok: bool,
    track_alias: Option<u64>,
    closed: Result<(), ServeError>,
}

impl Default for SubscribeState {
    fn default() -> Self {
        Self {
            ok: Default::default(),
            track_alias: None,
            closed: Ok(()),
        }
    }
}

// Held by the application
#[must_use = "unsubscribe on drop"]
pub struct Subscribe {
    state: State<SubscribeState>,
    subscriber: Subscriber,

    pub info: SubscribeInfo,
}

impl Subscribe {
    fn build_info(
        request_id: u64,
        track: &TrackWriter,
        options: &SubscribeOptions,
    ) -> Result<SubscribeInfo, SubscribeOptionsError> {
        let subscribe_message = message::Subscribe {
            id: request_id,
            track_namespace: track.namespace.clone(),
            track_name: track.name.clone(),
            params: options.to_request_parameters()?,
        };
        SubscribeInfo::new_from_subscribe(&subscribe_message)
            .map_err(|_| SubscribeOptionsError::InvalidRequestParameters)
    }

    /// Create a configured Subscribe without sending on the control stream.
    /// The caller sends it via a bidirectional request stream.
    pub(super) fn new_with_options(
        subscriber: Subscriber,
        request_id: u64,
        track: TrackWriter,
        options: SubscribeOptions,
    ) -> Result<(Subscribe, SubscribeRecv), SubscribeOptionsError> {
        let info = Self::build_info(request_id, &track, &options)?;
        Ok(Self::from_parts(subscriber, info, track))
    }

    /// Return the wire message to send on the request stream.
    pub(super) fn wire_message(&self) -> message::Subscribe {
        message::Subscribe {
            id: self.info.id,
            track_namespace: self.info.track_namespace.clone(),
            track_name: self.info.track_name.clone(),
            params: self.info.params.clone(),
        }
    }

    fn from_parts(
        subscriber: Subscriber,
        info: SubscribeInfo,
        track: TrackWriter,
    ) -> (Subscribe, SubscribeRecv) {
        let (send, recv) = State::default().split();

        let send = Subscribe {
            state: send,
            subscriber,
            info,
        };

        let recv = SubscribeRecv {
            state: recv,
            writer: Some(track.into()),
            info: send.info.clone(),
            delivery_filter: None,
            seen_objects: HashSet::new(),
        };

        (send, recv)
    }

    pub async fn closed(&self) -> Result<(), ServeError> {
        loop {
            {
                let state = self.state.lock();
                state.closed.clone()?;

                match state.modified() {
                    Some(notify) => notify,
                    None => return Ok(()),
                }
            }
            .await;
        }
    }

    pub async fn ok(&self) -> Result<(), ServeError> {
        loop {
            {
                let state = self.state.lock();
                state.closed.clone()?;

                if state.ok {
                    return Ok(());
                }

                match state.modified() {
                    Some(notify) => notify,
                    None => return Err(ServeError::Done),
                }
            }
            .await;
        }
    }
}

impl Drop for Subscribe {
    fn drop(&mut self) {
        // Draft-19 removed UNSUBSCRIBE. The owning request stream is the
        // cancellation boundary; dropping the handle releases local state.
        self.subscriber.remove_subscribe(self.info.id);
    }
}

impl ops::Deref for Subscribe {
    type Target = SubscribeInfo;

    fn deref(&self) -> &SubscribeInfo {
        &self.info
    }
}

pub(super) struct SubscribeRecv {
    state: State<SubscribeState>,
    writer: Option<TrackWriterMode>,
    info: SubscribeInfo,
    delivery_filter: Option<DeliveryFilter>,
    seen_objects: HashSet<(u64, u64)>,
}

impl SubscribeRecv {
    pub fn ok(&mut self, msg: &message::SubscribeOk) -> Result<(), ServeError> {
        let state = self.state.lock();
        if state.ok {
            return Err(ServeError::Duplicate);
        }

        if let Some(mut state) = state.into_mut() {
            state.ok = true;
            state.track_alias = Some(msg.track_alias);
        }
        self.delivery_filter = Some(self.info.delivery_filter(
            msg.params.largest_object().map_err(|err| {
                ServeError::internal_ctx(format!("invalid largest object: {err}"))
            })?,
        ));

        Ok(())
    }

    pub fn full_name(&self) -> serve::FullTrackName {
        serve::FullTrackName {
            namespace: self.info.track_namespace.clone(),
            name: self.info.track_name.clone(),
        }
    }

    pub fn allows(&self, group_id: u64, object_id: u64) -> bool {
        self.delivery_filter
            .unwrap_or_else(|| self.info.delivery_filter(None))
            .allows(group_id, object_id)
    }

    /// Claim an Object for this subscription, applying its filter and
    /// suppressing duplicate wire copies caused by shared Track Aliases.
    pub fn claim_object(&mut self, group_id: u64, object_id: u64) -> bool {
        self.allows(group_id, object_id) && self.seen_objects.insert((group_id, object_id))
    }

    pub fn track_alias(&self) -> Option<u64> {
        let state = self.state.lock();
        state.track_alias
    }

    pub fn error(mut self, err: ServeError) -> Result<(), ServeError> {
        if let Some(writer) = self.writer.take() {
            writer.close(err.clone())?;
        }

        let state = self.state.lock();
        state.closed.clone()?;

        let mut state = state.into_mut().ok_or(ServeError::Cancel)?;
        state.closed = Err(err);

        Ok(())
    }

    pub fn subgroup(
        &mut self,
        header: data::SubgroupHeader,
    ) -> Result<serve::SubgroupWriter, ServeError> {
        let writer = self.writer.take().ok_or(ServeError::Done)?;

        let mut subgroups = match writer {
            // TODO SLG - understand why both of these are needed, clock demo won't run if I comment out TrackWriteMode::Track
            TrackWriterMode::Track(track) => track.subgroups()?,
            TrackWriterMode::Subgroups(subgroups) => subgroups,
            _ => return Err(ServeError::Mode),
        };

        let subgroup_id = header
            .resolved_subgroup_id()
            .map_err(|err| ServeError::internal_ctx(format!("invalid subgroup id: {err}")))?
            .ok_or_else(|| {
                ServeError::internal_ctx(
                    "FIRST_OBJECT subgroup id was not resolved before creating the subgroup",
                )
            })?;
        let writer = subgroups.create(serve::Subgroup {
            group_id: header.group_id,
            subgroup_id,
            priority: header.publisher_priority,
            first_object: header.header_type.is_first_object(),
        })?;

        self.writer = Some(subgroups.into());

        Ok(writer)
    }

    pub fn datagram(&mut self, datagram: data::Datagram) -> Result<(), ServeError> {
        let writer = self.writer.take().ok_or(ServeError::Done)?;

        match writer {
            TrackWriterMode::Track(track) => {
                // convert Track -> Datagrams writer, write, then put Datagrams back
                let mut datagrams = track.datagrams()?;
                datagrams.write(serve::Datagram {
                    group_id: datagram.group_id,
                    object_id: datagram.object_id.unwrap_or(0),
                    priority: datagram.publisher_priority,
                    payload: datagram.payload.unwrap_or_default(),
                    extension_headers: datagram.extension_headers.unwrap_or_default(),
                })?;
                self.writer = Some(TrackWriterMode::Datagrams(datagrams));
                Ok(())
            }
            TrackWriterMode::Datagrams(mut datagrams) => {
                datagrams.write(serve::Datagram {
                    group_id: datagram.group_id,
                    object_id: datagram.object_id.unwrap_or(0),
                    priority: datagram.publisher_priority,
                    payload: datagram.payload.unwrap_or_default(),
                    extension_headers: datagram.extension_headers.unwrap_or_default(),
                })?;
                self.writer = Some(TrackWriterMode::Datagrams(datagrams));
                Ok(())
            }
            other => {
                // preserve whatever unexpected mode was present, then report error
                self.writer = Some(other);
                Err(ServeError::Mode)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn track_writer() -> TrackWriter {
        let (writer, _reader) =
            serve::Track::new(TrackNamespace::from_utf8_path("test/session"), "audio").produce();
        writer
    }

    fn subscribe_info_with(params: KeyValuePairs) -> SubscribeInfo {
        SubscribeInfo::new_from_subscribe(&message::Subscribe {
            id: 0,
            track_namespace: TrackNamespace::from_utf8_path("test"),
            track_name: "track".into(),
            params,
        })
        .unwrap()
    }

    #[test]
    fn omitted_subscription_filter_is_unfiltered() {
        let info = subscribe_info_with(KeyValuePairs::default());
        let filter = info.delivery_filter(Some(Location::new(10, 20)));

        assert!(info.filter.is_none());
        assert!(filter.allows(0, 0));
        assert!(filter.allows(10, 20));
        assert!(filter.allows(100, 0));
    }

    #[test]
    fn largest_object_filter_starts_after_largest_object() {
        let mut params = KeyValuePairs::default();
        params
            .set_subscription_filter(&SubscriptionFilter::largest_object())
            .unwrap();
        let info = subscribe_info_with(params);
        let filter = info.delivery_filter(Some(Location::new(2, 3)));

        assert!(!filter.allows(2, 3));
        assert!(filter.allows(2, 4));
        assert!(filter.allows(3, 0));
    }

    #[test]
    fn absolute_range_filter_limits_start_and_end_group() {
        let mut params = KeyValuePairs::default();
        params
            .set_subscription_filter(&SubscriptionFilter {
                filter_type: FilterType::AbsoluteRange,
                start_location: Some(Location::new(2, 3)),
                end_group_id: Some(4),
            })
            .unwrap();
        let info = subscribe_info_with(params);
        let filter = info.delivery_filter(None);

        assert!(!filter.allows(2, 2));
        assert!(filter.allows(2, 3));
        assert!(filter.allows(4, 10));
        assert!(!filter.allows(5, 0));
    }

    #[test]
    fn forward_false_blocks_delivery() {
        let mut params = KeyValuePairs::default();
        params.set_forward(false);
        let info = subscribe_info_with(params);
        let filter = info.delivery_filter(None);

        assert!(!filter.allows(0, 0));
        assert!(!filter.allows(100, 100));
    }

    #[test]
    fn explicit_forward_one_and_largest_object_have_stable_wire_and_model() {
        let options = SubscribeOptions::default()
            .with_forward(true)
            .with_filter(SubscriptionFilter::largest_object());
        let parameters = options.to_request_parameters().unwrap();
        let mut wire = BytesMut::new();
        parameters.encode(&mut wire).unwrap();

        // count=2, FORWARD(type=0x10,value=1), then LOCATION_FILTER
        // (delta=0x11,length=1,LargestObject=0x2).
        assert_eq!(wire.as_ref(), &[0x02, 0x10, 0x01, 0x11, 0x01, 0x02]);
        let info = Subscribe::build_info(8, &track_writer(), &options).unwrap();
        assert_eq!(info.id, 8);
        assert!(info.forward);
        assert_eq!(info.filter, Some(SubscriptionFilter::largest_object()));
        assert_eq!(info.params, parameters);
    }

    #[test]
    fn default_options_preserve_legacy_empty_parameters_and_semantics() {
        let options = SubscribeOptions::default();
        assert!(options.to_request_parameters().unwrap().0.is_empty());

        let info = Subscribe::build_info(10, &track_writer(), &options).unwrap();
        assert!(info.params.0.is_empty());
        assert!(info.forward);
        assert_eq!(info.subscriber_priority, 128);
        assert_eq!(info.group_order, GroupOrder::Publisher);
        assert_eq!(info.filter, None);
    }

    #[test]
    fn explicit_priority_and_group_order_round_trip_into_model() {
        let options = SubscribeOptions::default()
            .with_subscriber_priority(7)
            .with_group_order(GroupOrder::Descending);
        let parameters = options.to_request_parameters().unwrap();
        assert_eq!(parameters.subscriber_priority().unwrap(), Some(7));
        assert_eq!(
            parameters.group_order().unwrap(),
            Some(GroupOrder::Descending)
        );

        let info = Subscribe::build_info(12, &track_writer(), &options).unwrap();
        assert_eq!(info.subscriber_priority, 7);
        assert_eq!(info.group_order, GroupOrder::Descending);
    }

    #[test]
    fn invalid_option_combinations_are_rejected_before_wire_encoding() {
        assert_eq!(
            SubscribeOptions::default()
                .with_group_order(GroupOrder::Publisher)
                .to_request_parameters(),
            Err(SubscribeOptionsError::InvalidGroupOrder)
        );

        for filter in [
            SubscriptionFilter {
                filter_type: FilterType::LargestObject,
                start_location: Some(Location::new(1, 0)),
                end_group_id: None,
            },
            SubscriptionFilter {
                filter_type: FilterType::AbsoluteStart,
                start_location: None,
                end_group_id: None,
            },
            SubscriptionFilter {
                filter_type: FilterType::AbsoluteRange,
                start_location: Some(Location::new(1, 0)),
                end_group_id: None,
            },
        ] {
            let filter_type = filter.filter_type;
            assert_eq!(
                SubscribeOptions::default()
                    .with_filter(filter)
                    .to_request_parameters(),
                Err(SubscribeOptionsError::InvalidFilter(filter_type))
            );
        }

        let mut collision = KeyValuePairs::default();
        collision.set_forward(false);
        assert_eq!(
            SubscribeOptions::default()
                .with_forward(true)
                .with_request_parameters(collision)
                .to_request_parameters(),
            Err(SubscribeOptionsError::ConflictingParameter(
                message::parameter_type::FORWARD
            ))
        );

        let mut response_only = KeyValuePairs::default();
        response_only.set_intvalue(message::parameter_type::EXPIRES, 1);
        assert_eq!(
            SubscribeOptions::default()
                .with_request_parameters(response_only)
                .to_request_parameters(),
            Err(SubscribeOptionsError::ParameterNotAllowed(
                message::parameter_type::EXPIRES
            ))
        );

        let invalid_wire = KeyValuePairs(vec![crate::coding::KeyValuePair::new_bytes(
            message::parameter_type::DELIVERY_TIMEOUT,
            vec![1],
        )]);
        assert_eq!(
            SubscribeOptions::default()
                .with_request_parameters(invalid_wire)
                .to_request_parameters(),
            Err(SubscribeOptionsError::InvalidRequestParameters)
        );
    }

    #[test]
    fn additional_request_parameters_are_preserved_without_silent_overwrite() {
        let mut request_parameters = KeyValuePairs::default();
        request_parameters.set_intvalue(message::parameter_type::DELIVERY_TIMEOUT, 250);
        request_parameters.set_bytesvalue(0x41, vec![1, 2, 3]);
        let original = request_parameters.clone();

        let merged = SubscribeOptions::default()
            .with_forward(true)
            .with_subscriber_priority(9)
            .with_request_parameters(request_parameters)
            .to_request_parameters()
            .unwrap();

        assert_eq!(
            merged.get(message::parameter_type::DELIVERY_TIMEOUT),
            original.get(message::parameter_type::DELIVERY_TIMEOUT)
        );
        assert_eq!(merged.get(0x41), original.get(0x41));
        assert_eq!(merged.forward().unwrap(), Some(true));
        assert_eq!(merged.subscriber_priority().unwrap(), Some(9));
        assert_eq!(merged.0.len(), original.0.len() + 2);
    }

    #[test]
    fn valid_typed_request_parameter_is_preserved_when_option_is_omitted() {
        let mut request_parameters = KeyValuePairs::default();
        request_parameters.set_forward(false);
        let parameters = SubscribeOptions::default()
            .with_request_parameters(request_parameters)
            .to_request_parameters()
            .unwrap();
        assert_eq!(parameters.forward().unwrap(), Some(false));

        let info = Subscribe::build_info(
            14,
            &track_writer(),
            &SubscribeOptions::default().with_request_parameters(parameters),
        )
        .unwrap();
        assert!(!info.forward);
    }
}
