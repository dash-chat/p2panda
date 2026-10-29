// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reproduction of a space-group takeover by an outsider who only knows a space id.
//!
//! # The hole
//!
//! A space's auth group id is derived deterministically from its space id
//! ([`crate::space::space_group_id`]). Anyone who learns a space id can therefore forge their own
//! "create" operation for the very same auth group, with no prior state and hence empty
//! dependencies. The existing members merge that second create as a second, concurrent *root* of
//! the group's history.
//!
//! Two layers react differently to the forged create, and the split between them is the heart of
//! the bug:
//!
//! * **Auth layer (membership & access).** The group CRDT merges both roots. Per-member access
//!   conflicts between the two roots are resolved by "take the lower access level" (see
//!   `p2panda_auth`'s `group::crdt::state::merge`). So the attacker, by naming the real manager as
//!   a mere writer in the forged create, *demotes* them: their own `Manage` and the attacker's
//!   `Write` for that member conflict, and `Write` wins. The attacker names only themselves as
//!   `Manage`, so they become a manager. This converges on every node.
//!
//! * **Encryption layer (who can read/write messages).** A node that has already established its
//!   encryption group for the space rejects the forged create with `GroupAlreadyEstablished`, so
//!   its *space-local* membership and message stream are untouched. The result is a split brain:
//!   the global auth state says the attacker took over, while the victim's space state does not.
//!
//! The encryption guard is only skin deep: it depends purely on *delivery order*. A member who
//! processes the attacker's create *before* the legitimate one locks into the attacker's
//! encryption group instead, and can then exchange encrypted messages with the attacker
//! (see [`delivery_order_decides_encryption_group`]).
//!
//! The common cast in every test: Alice creates a space with Bobby (who gets `write` access),
//! leaving herself as the only manager. Carol was never a member and only knows the space id.
//!
//! NOTE: the assertions below pin the *current, vulnerable* behaviour so the reproduction runs
//! green. Lines marked `VULNERABILITY:` encode attacker-favourable outcomes that a fix is expected
//! to change; when the hole is closed these assertions should be flipped to assert the secure
//! outcome.

use std::collections::BTreeMap;

use p2panda_auth::Access;

use crate::event::Event;
use crate::space::space_group_id;
use crate::test_utils::{TestConditions, TestOperation, TestPeer};
use crate::{ActorId, SpaceId};

const SPACE_LABEL: &[u8] = b"hijack";

/// Let every peer learn every other peer's key bundle.
async fn exchange_key_bundles(peers: &[&TestPeer]) {
    let mut bundles = Vec::new();
    for peer in peers {
        bundles.push(peer.manager.key_bundle_message().await.unwrap());
    }
    for peer in peers {
        for bundle in &bundles {
            peer.manager.process(bundle).await.unwrap();
        }
    }
}

/// Flatten a space output into just its forged messages.
fn messages(
    output: crate::space::SpaceOutput<TestConditions, TestOperation>,
) -> Vec<TestOperation> {
    output.messages.into_iter().map(|(msg, _)| msg).collect()
}

/// Persist and process every message on `peer`, asserting each one is accepted.
async fn process_ok(peer: &TestPeer, msgs: &[TestOperation]) -> Vec<Event<TestConditions>> {
    let mut events = Vec::new();
    for msg in msgs {
        peer.persist_operation(msg).await.unwrap();
        events.extend(
            peer.manager
                .process(msg)
                .await
                .expect("message should be accepted"),
        );
    }
    events
}

/// Persist and process every message on `peer`, returning the error text of any that are rejected.
async fn process_collecting_errors(peer: &TestPeer, msgs: &[TestOperation]) -> Vec<String> {
    let mut errors = Vec::new();
    for msg in msgs {
        peer.persist_operation(msg).await.unwrap();
        if let Err(err) = peer.manager.process(msg).await {
            errors.push(format!("{err:?}"));
        }
    }
    errors
}

/// Space-local membership (what the space's own state reports), keyed by actor.
async fn space_members(
    peer: &TestPeer,
    space_id: SpaceId,
) -> BTreeMap<ActorId, Access<TestConditions>> {
    peer.manager
        .space(space_id)
        .created()
        .await
        .unwrap()
        .members()
        .await
        .unwrap()
        .into_iter()
        .collect()
}

/// Global auth-group membership for the space's group (the authorization view), keyed by actor.
async fn auth_members(
    peer: &TestPeer,
    space_id: SpaceId,
) -> BTreeMap<ActorId, Access<TestConditions>> {
    peer.manager
        .get_global_groups_state()
        .await
        .unwrap()
        .members(space_group_id(space_id))
        .into_iter()
        .collect()
}

/// Decrypted application payloads carried by `events`.
fn application_payloads(events: &[Event<TestConditions>]) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Application { data, .. } => Some(data.clone()),
            _ => None,
        })
        .collect()
}

/// Carol's forged "create" for the space, naming herself manager and the originals as writers.
async fn forge_outsider_create(
    carol: &TestPeer,
    space_id: SpaceId,
    alice_id: ActorId,
    bobby_id: ActorId,
) -> Vec<TestOperation> {
    let (_space, output) = carol
        .manager
        .create_space(
            space_id,
            &[
                (carol.manager.id(), Access::manage()),
                (alice_id, Access::write()),
                (bobby_id, Access::write()),
            ],
        )
        .await
        .unwrap();
    messages(output)
}

/// # Minimal reproduction (the simplest case)
///
/// Alice and Bobby are the original members, Alice the only manager. Carol, knowing only the space
/// id, publishes her own create. Afterwards every node's global authorization state says Carol is
/// the manager and Alice is a mere writer: Carol has taken over the group and Alice is no longer a
/// manager.
#[tokio::test]
async fn outsider_second_create_hijacks_auth_group() {
    let alice = TestPeer::new(0).await;
    let bobby = TestPeer::new(1).await;
    let carol = TestPeer::new(2).await;

    let alice_id = alice.manager.id();
    let bobby_id = bobby.manager.id();
    let carol_id = carol.manager.id();

    exchange_key_bundles(&[&alice, &bobby, &carol]).await;

    // Alice creates the space with Bobby as a writer; Alice is the sole manager.
    let space_id = SpaceId::digest(SPACE_LABEL);
    let (_alice_space, output) = alice
        .manager
        .create_space(space_id, &[(bobby_id, Access::write())])
        .await
        .unwrap();
    let alice_create = messages(output);
    process_ok(&bobby, &alice_create).await;

    // Original, healthy state: Alice manages, Bobby writes - in both the auth and space views.
    let healthy = BTreeMap::from([(alice_id, Access::manage()), (bobby_id, Access::write())]);
    assert_eq!(auth_members(&alice, space_id).await, healthy);
    assert_eq!(space_members(&alice, space_id).await, healthy);
    assert_eq!(auth_members(&bobby, space_id).await, healthy);
    assert_eq!(space_members(&bobby, space_id).await, healthy);

    // Carol forges her own create for the same space id and ships it to Alice and Bobby.
    let carol_create = forge_outsider_create(&carol, space_id, alice_id, bobby_id).await;

    // The forged create is two operations: [0] the auth-group "create", [1] the space membership
    // message that drives encryption. The auth create is accepted; the space message is rejected
    // because the encryption group is already established.
    let (auth_create, space_message) = (&carol_create[0..1], &carol_create[1..2]);
    for victim in [&alice, &bobby] {
        assert!(
            process_collecting_errors(victim, auth_create)
                .await
                .is_empty(),
            "the forged auth create is accepted as a concurrent root",
        );
        let errors = process_collecting_errors(victim, space_message).await;
        assert!(
            errors.iter().any(|e| e.contains("GroupAlreadyEstablished")),
            "the forged space/encryption message is rejected, got: {errors:?}",
        );
    }

    // VULNERABILITY: Carol has taken over the authorization state on every node. She is now the
    // manager and Alice has been silently demoted from Manage to Write (the CRDT resolves the
    // Manage-vs-Write conflict between the two roots in favour of the lower level).
    let hijacked = BTreeMap::from([
        (alice_id, Access::write()),
        (bobby_id, Access::write()),
        (carol_id, Access::manage()),
    ]);
    assert_eq!(auth_members(&alice, space_id).await, hijacked);
    assert_eq!(auth_members(&bobby, space_id).await, hijacked);
    assert_eq!(auth_members(&carol, space_id).await, hijacked);
    assert!(
        auth_members(&alice, space_id).await[&alice_id].level
            != Access::<TestConditions>::manage().level,
        "VULNERABILITY: Alice is no longer a manager in the authorization state",
    );

    // The split brain: the encryption guard kept the victims' *space* membership intact, so the
    // auth state and the space state now disagree.
    assert_eq!(
        space_members(&alice, space_id).await,
        healthy,
        "Alice's space state still shows the original, healthy membership (encryption guard)",
    );
    assert_eq!(space_members(&bobby, space_id).await, healthy);
    assert_ne!(
        space_members(&alice, space_id).await,
        auth_members(&alice, space_id).await,
        "auth state and space state disagree: the takeover is a split brain",
    );
}

/// # Can Carol finish the job against the original members?
///
/// Following on from the takeover: Carol is an auth manager, so she can *author* a removal of
/// Alice and can encrypt messages in her own encryption group. But because Alice and Bobby already
/// established their encryption group from Alice's create, Carol's follow-up operations never land
/// on them. The two groups cannot talk: the takeover is contained to the authorization view.
#[tokio::test]
async fn outsider_takeover_does_not_reach_established_members() {
    let alice = TestPeer::new(0).await;
    let bobby = TestPeer::new(1).await;
    let carol = TestPeer::new(2).await;

    let alice_id = alice.manager.id();
    let bobby_id = bobby.manager.id();

    exchange_key_bundles(&[&alice, &bobby, &carol]).await;

    let space_id = SpaceId::digest(SPACE_LABEL);
    let (_alice_space, output) = alice
        .manager
        .create_space(space_id, &[(bobby_id, Access::write())])
        .await
        .unwrap();
    let alice_create = messages(output);
    process_ok(&bobby, &alice_create).await;

    let carol_create = forge_outsider_create(&carol, space_id, alice_id, bobby_id).await;
    process_collecting_errors(&alice, &carol_create).await;
    process_collecting_errors(&bobby, &carol_create).await;
    process_collecting_errors(&carol, &alice_create).await;

    // Carol, an auth manager, authors a removal of Alice. The call succeeds on her node...
    let carol_space = carol.manager.space(space_id).joined().await.unwrap();
    let removal = carol_space.remove(alice_id).await;
    assert!(
        removal.is_ok(),
        "Carol is a manager in auth, so she may author a removal"
    );
    let removal_msgs = messages(removal.unwrap());

    // ...but the victims cannot apply it: it depends on Carol's rejected create.
    let alice_errors = process_collecting_errors(&alice, &removal_msgs).await;
    let bobby_errors = process_collecting_errors(&bobby, &removal_msgs).await;
    assert!(
        alice_errors
            .iter()
            .any(|e| e.contains("MissingDependencies")),
        "Alice cannot apply Carol's removal: {alice_errors:?}",
    );
    assert!(
        bobby_errors
            .iter()
            .any(|e| e.contains("MissingDependencies"))
    );

    // Alice is still a manager of her own space and still present.
    let alice_space = space_members(&alice, space_id).await;
    assert_eq!(
        alice_space[&alice_id].level,
        Access::<TestConditions>::manage().level
    );

    // The two encryption states are isolated: a message from one side cannot be read by the other.
    let bobby_space = bobby.manager.space(space_id).joined().await.unwrap();
    let (bobby_msg, _) = bobby_space
        .publish(b"bobby to the original group")
        .await
        .unwrap();
    let carol_sees = process_collecting_errors(&carol, &[bobby_msg]).await;
    assert!(
        !carol_sees.is_empty(),
        "Carol cannot even process Bobby's message - different encryption group",
    );

    // Carol's message is authored against a group where the victims are unknown writers.
    let (carol_msg, _) = carol_space
        .publish(b"carol to her shadow group")
        .await
        .unwrap();
    let bobby_sees_errors = process_collecting_errors(&bobby, &[carol_msg]).await;
    assert!(
        !bobby_sees_errors.is_empty(),
        "Bobby rejects Carol's message - he is locked to Alice's encryption group",
    );
}

/// # Exploration: "since there are two encryption states, can Bobby do something interesting?"
///
/// Yes - and it is worse than the contained split brain above. The encryption guard only protects
/// a node that already established the *legitimate* group. Whichever create a member processes
/// first decides which encryption group they lock into. A Bobby who receives Carol's forged create
/// before Alice's legitimate one ends up in *Carol's* group, rejects Alice's create as a
/// duplicate, and can exchange encrypted messages with Carol in both directions.
#[tokio::test]
async fn delivery_order_decides_encryption_group() {
    let alice = TestPeer::new(0).await;
    let carol = TestPeer::new(2).await;

    let alice_id = alice.manager.id();
    let carol_id = carol.manager.id();
    // Bobby's identity/key material is deterministic from his peer seed.
    let bobby_id = TestPeer::new(1).await.manager.id();

    exchange_key_bundles(&[&alice, &carol]).await;

    // Register Bobby's (deterministic) key bundle on Alice and Carol so both can address him in a
    // create. A freshly constructed TestPeer::new(1) reproduces exactly this bundle.
    let bobby_seed = TestPeer::new(1).await;
    let bobby_bundle = bobby_seed.manager.key_bundle_message().await.unwrap();
    alice.manager.process(&bobby_bundle).await.unwrap();
    carol.manager.process(&bobby_bundle).await.unwrap();
    drop(bobby_seed);

    let space_id = SpaceId::digest(SPACE_LABEL);
    let (_as, aout) = alice
        .manager
        .create_space(space_id, &[(bobby_id, Access::write())])
        .await
        .unwrap();
    let alice_create = messages(aout);
    let carol_create = forge_outsider_create(&carol, space_id, alice_id, bobby_id).await;

    // A fresh Bobby (same identity, empty state) who hears Carol's create FIRST.
    let bobby = TestPeer::new(1).await;
    exchange_key_bundles(&[&bobby]).await;
    for src in [&alice, &carol] {
        let bundle = src.manager.key_bundle_message().await.unwrap();
        bobby.manager.process(&bundle).await.unwrap();
    }

    process_ok(&bobby, &carol_create).await;
    // Alice's legitimate create is now rejected as a duplicate establishment.
    let alice_errors = process_collecting_errors(&bobby, &alice_create).await;
    assert!(
        alice_errors
            .iter()
            .any(|e| e.contains("GroupAlreadyEstablished")),
        "VULNERABILITY: Bobby rejects the LEGITIMATE create as the duplicate: {alice_errors:?}",
    );

    // VULNERABILITY: Bobby's space is Carol's group - Carol manages, Alice demoted to writer.
    let bobby_view = space_members(&bobby, space_id).await;
    assert_eq!(
        bobby_view[&carol_id].level,
        Access::<TestConditions>::manage().level
    );
    assert_eq!(
        bobby_view[&alice_id].level,
        Access::<TestConditions>::write().level
    );

    // VULNERABILITY: Carol and this Bobby now exchange encrypted messages in both directions.
    let carol_space = carol.manager.space(space_id).joined().await.unwrap();
    let (c2b, _) = carol_space
        .publish(b"hello bobby from carol")
        .await
        .unwrap();
    let bobby_got = process_ok(&bobby, &[c2b]).await;
    assert_eq!(
        application_payloads(&bobby_got),
        vec![b"hello bobby from carol".to_vec()],
        "Bobby decrypts Carol's message",
    );

    let bobby_space = bobby.manager.space(space_id).joined().await.unwrap();
    let (b2c, _) = bobby_space
        .publish(b"hello carol from bobby")
        .await
        .unwrap();
    let carol_got = process_ok(&carol, &[b2c]).await;
    assert_eq!(
        application_payloads(&carol_got),
        vec![b"hello carol from bobby".to_vec()],
        "Carol decrypts Bobby's message - the outsider shares an encryption state with a victim",
    );
}

/// # Exploration: "what happens if Alice is invited back?"
///
/// Carol, the new auth manager, removes Alice and then invites her back (as a writer) inside her
/// own encryption partition. Both operations succeed on Carol's node but neither reaches the
/// established members - they depend on Carol's rejected create. Meanwhile Alice, still a manager
/// inside her own un-hijacked space partition, keeps managing that partition. "Inviting Alice
/// back" is a no-op across the split; the two worlds never reconcile through the auth layer alone.
#[tokio::test]
async fn invited_back_does_not_cross_the_split() {
    let alice = TestPeer::new(0).await;
    let bobby = TestPeer::new(1).await;
    let carol = TestPeer::new(2).await;
    let dave = TestPeer::new(3).await;

    let alice_id = alice.manager.id();
    let bobby_id = bobby.manager.id();
    let dave_id = dave.manager.id();

    exchange_key_bundles(&[&alice, &bobby, &carol, &dave]).await;

    let space_id = SpaceId::digest(SPACE_LABEL);
    let (alice_space, output) = alice
        .manager
        .create_space(space_id, &[(bobby_id, Access::write())])
        .await
        .unwrap();
    let alice_create = messages(output);
    process_ok(&bobby, &alice_create).await;

    let carol_create = forge_outsider_create(&carol, space_id, alice_id, bobby_id).await;
    process_collecting_errors(&alice, &carol_create).await;
    process_collecting_errors(&bobby, &carol_create).await;
    process_collecting_errors(&carol, &alice_create).await;

    // Carol removes Alice, then invites her back - both only within Carol's own partition.
    let carol_space = carol.manager.space(space_id).joined().await.unwrap();
    let removal = messages(carol_space.remove(alice_id).await.unwrap());
    let readd = messages(carol_space.add(alice_id, Access::write()).await.unwrap());

    let mut alice_errors = process_collecting_errors(&alice, &removal).await;
    alice_errors.extend(process_collecting_errors(&alice, &readd).await);
    assert!(
        alice_errors
            .iter()
            .all(|e| e.contains("MissingDependencies")),
        "neither Carol's removal nor her re-invite of Alice can reach Alice: {alice_errors:?}",
    );
    assert!(
        !alice_errors.is_empty(),
        "Carol's operations were rejected by Alice (they depend on the rejected create)",
    );

    // VULNERABILITY: worse than a passive split brain - Alice can no longer manage her OWN space.
    // Membership changes are authorized against the global auth state, where Carol's create
    // demoted Alice to a writer, so Alice's attempt to add Dave is now unauthorized.
    let add_dave_result = alice_space.add(dave_id, Access::read()).await;
    assert!(
        add_dave_result.is_err(),
        "VULNERABILITY: the takeover strips Alice of manage rights even over her own space",
    );
    assert!(!space_members(&alice, space_id).await.contains_key(&dave_id));
    // Carol never sees Dave either: her shadow group is a separate world.
    assert!(!space_members(&carol, space_id).await.contains_key(&dave_id));
}

/// # Exploration: "what if Alice creates a 3rd Create, taking the group back over?"
///
/// Alice cannot. The attack worked precisely because the attacker had *no* prior state, so their
/// create carried no dependencies and merged as a fresh concurrent root. An existing member like
/// Alice already holds the group's state, so the normal `create_space` path refuses to forge a
/// competing root for a space she already has - it fails with `MissingDependencies`. The door only
/// opens one way: for a stateless outsider, not for a member trying to reclaim the group.
#[tokio::test]
async fn existing_member_cannot_issue_a_third_create() {
    let alice = TestPeer::new(0).await;
    let bobby = TestPeer::new(1).await;
    let carol = TestPeer::new(2).await;

    let alice_id = alice.manager.id();
    let bobby_id = bobby.manager.id();
    let carol_id = carol.manager.id();

    exchange_key_bundles(&[&alice, &bobby, &carol]).await;

    let space_id = SpaceId::digest(SPACE_LABEL);
    let (_alice_space, output) = alice
        .manager
        .create_space(space_id, &[(bobby_id, Access::write())])
        .await
        .unwrap();
    let alice_create = messages(output);
    process_ok(&bobby, &alice_create).await;

    let carol_create = forge_outsider_create(&carol, space_id, alice_id, bobby_id).await;
    process_collecting_errors(&alice, &carol_create).await;

    // Alice tries to fight back with her own second create, reinstating herself as manager.
    let third_create = alice
        .manager
        .create_space(
            space_id,
            &[
                (alice_id, Access::manage()),
                (bobby_id, Access::write()),
                (carol_id, Access::read()),
            ],
        )
        .await;
    assert!(
        third_create.is_err(),
        "an existing member cannot forge a competing root create to reclaim the group",
    );
    let err = format!("{:?}", third_create.err().unwrap());
    assert!(
        err.contains("MissingDependencies"),
        "unexpected error: {err}"
    );

    // Alice is still demoted in the authorization view; the takeover stands.
    assert_eq!(
        auth_members(&alice, space_id).await[&alice_id].level,
        Access::<TestConditions>::write().level,
    );
}
