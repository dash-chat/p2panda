// SPDX-License-Identifier: MIT OR Apache-2.0

//! Discover nodes on our local-area network right away.
//!
//! Random walkers pick the next node at random from the whole address book. The more nodes it
//! holds, and the more of them are unreachable, the longer it takes a walker to come across the
//! few nodes right next to us, and until one does we don't learn which topics we share with them.
//! With a few hundred nodes in the address book two nodes on the same local-area network could go
//! many minutes without syncing.
//!
//! mDNS tells us exactly which nodes are next to us, so we initiate a discovery session with each
//! of them as soon as it is found, and again with all of them whenever we subscribe to new topics,
//! since we might share those with them too.
use std::collections::HashSet;

use ractor::ActorRef;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::NodeId;
use crate::address_book::{AddressBook, AddressBookError};
use crate::discovery::actors::ToDiscoveryManager;
use crate::iroh_mdns::LocalNodeEvent;

pub(crate) async fn spawn(
    my_node_id: NodeId,
    address_book: AddressBook,
    mut local_node_events_rx: broadcast::Receiver<LocalNodeEvent>,
    manager_ref: ActorRef<ToDiscoveryManager>,
) -> Result<JoinHandle<()>, AddressBookError> {
    let mut topics_rx = address_book.watch_node_topics(my_node_id, true).await?;

    let handle = tokio::task::spawn(async move {
        let mut local_nodes = HashSet::new();
        loop {
            let nodes_to_discover: Vec<NodeId> = tokio::select! {
                event = local_node_events_rx.recv() => match event {
                    Ok(LocalNodeEvent::Found(node_id)) => {
                        local_nodes.insert(node_id);
                        vec![node_id]
                    }
                    Ok(LocalNodeEvent::Lost(node_id)) => {
                        local_nodes.remove(&node_id);
                        continue;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                Some(event) = topics_rx.recv() => {
                    // Ignore removed topics, we can't share anything new with anyone through them.
                    let difference = event.difference.unwrap_or_default();
                    if difference.is_empty() || !difference.is_subset(&event.value) {
                        continue;
                    }
                    local_nodes.iter().copied().collect()
                }
                else => break,
            };

            for node_id in nodes_to_discover {
                if manager_ref
                    .send_message(ToDiscoveryManager::InitiateLocalSession(node_id))
                    .is_err()
                {
                    return;
                }
            }
        }
    });

    Ok(handle)
}
