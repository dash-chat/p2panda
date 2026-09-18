// SPDX-License-Identifier: MIT OR Apache-2.0

use futures_util::Stream;
use futures_util::stream::{SelectAll, StreamExt};
use p2panda_net::discovery::DiscoveryEvent;
use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tokio_stream::wrappers::BroadcastStream;

/// System event.
///
/// System events encompass all network-related events which are not directly associated with a
/// topic.
#[derive(Clone, Debug, PartialEq)]
pub enum SystemEvent {
    Discovery(DiscoveryEvent),
}

/// Merge the provided event streams into a single, unified system event stream.
pub(crate) fn event_stream(
    discovery_events: Option<BroadcastReceiver<DiscoveryEvent>>,
) -> impl Stream<Item = SystemEvent> + Send + Unpin + 'static {
    let mut stream_set = SelectAll::new();

    // An offline node has no discovery source, so `discovery_events` is omitted in that case.
    if let Some(discovery_events) = discovery_events {
        let discovery_broadcast_stream = BroadcastStream::new(discovery_events);

        let discovery_stream = Box::pin(
            discovery_broadcast_stream
                .filter_map(|event| async { event.ok().map(SystemEvent::Discovery) }),
        );

        stream_set.push(discovery_stream);
    }

    Box::pin(stream_set)
}
