// SPDX-License-Identifier: MIT OR Apache-2.0

//! Two nodes on one store, as an app and its push notification extension run on iOS: same
//! credentials, same database, both subscribed to the same space under their own cursor.
//!
//! Opening a stream resets the orderer state of every operation past its cursor and replays them.
//! If that state were shared between the nodes, the second node's reset would wipe the first
//! node's record that its latest message was processed, the first node would park its next
//! message on that dependency, and the second node's replay would release it into the second
//! node's pipeline instead: the first node would never process its own message.

use std::path::PathBuf;
use std::time::Duration;

use p2panda::node::AckPolicy;
use p2panda::streams::StreamEvent;
use p2panda::{Credentials, Hash, Node, Topic};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::StreamExt;

/// Enough unacknowledged messages that the second node's replay takes a while to reach the first
/// node's latest one.
const BACKLOG: usize = 300;

async fn spawn_node(credentials: &Credentials, url: &str) -> Node {
    p2panda::builder()
        .credentials(credentials.clone())
        .database_url(url)
        .ack_policy(AckPolicy::Explicit)
        .offline()
        .spawn()
        .await
        .unwrap()
}

/// The hash of every message `subscription` processes, none of them acknowledged, and a signal
/// for when its replay starts.
fn watch<S>(mut subscription: S) -> (mpsc::UnboundedReceiver<Hash>, oneshot::Receiver<()>)
where
    S: tokio_stream::Stream<Item = StreamEvent<String>> + Unpin + Send + 'static,
{
    let (processed_tx, processed_rx) = mpsc::unbounded_channel();
    let (replay_tx, replay_rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut replay_tx = Some(replay_tx);
        while let Some(event) = subscription.next().await {
            match event {
                StreamEvent::ReplayStarted { .. } => {
                    if let Some(replay_tx) = replay_tx.take() {
                        let _ = replay_tx.send(());
                    }
                }
                StreamEvent::Processed { operation, .. } => {
                    let _ = processed_tx.send(operation.id());
                }
                _ => {}
            }
        }
    });
    (processed_rx, replay_rx)
}

async fn processed(processed: &mut mpsc::UnboundedReceiver<Hash>, hash: Hash) -> bool {
    tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(processed) = processed.recv().await {
            if processed == hash {
                return;
            }
        }
        std::future::pending::<()>().await
    })
    .await
    .is_ok()
}

/// A database file only this test uses, removed when dropped.
struct TempDatabase(PathBuf);

impl TempDatabase {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("p2panda-shared-store-{}.db", Topic::random())))
    }

    fn url(&self) -> String {
        format!("sqlite://{}?mode=rwc", self.0.display())
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

#[tokio::test]
async fn nodes_on_one_store_each_process_their_own_space_messages() {
    let database = TempDatabase::new();
    let credentials = Credentials::generate();

    let app = spawn_node(&credentials, &database.url()).await;
    let (space, app_subscription) = app
        .create_space_with_id::<String>(Topic::random())
        .await
        .unwrap();
    let (mut app_processed, _) = watch(app_subscription);

    // Nothing is acknowledged, as when the app has processed its messages but not yet persisted
    // its cursor past them.
    for i in 0..BACKLOG {
        space
            .publish(format!("message {i}"))
            .await
            .unwrap()
            .await
            .unwrap();
    }

    let extension = spawn_node(&credentials, &database.url()).await;
    let (_pending, extension_subscription) = extension
        .space_from::<String>(
            space.id(),
            p2panda::streams::StreamFrom::Frontier,
            Some("extension".to_string()),
        )
        .await
        .unwrap();
    let (_extension_processed, replay_started) = watch(extension_subscription);
    // The replay starts once the reset has gone through.
    replay_started.await.unwrap();

    let next = space.publish("the next message".to_string()).await.unwrap();
    let hash = next.hash();
    next.await.unwrap();

    assert!(
        processed(&mut app_processed, hash).await,
        "the first node never processed its own message"
    );
}
