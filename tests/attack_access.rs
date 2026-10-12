//! Scenario B — "read = holding a key" (§2, principle 2).
//!
//! A user with limited rights writes their own client (not the CLI) and has the whole vault file
//! plus their own unlocked identity. This test plays that attacker with direct library access:
//! Jane holds a grant on `/shared` but none on `/infra/db/prod`. It asserts that no path through
//! the public crypto recovers the target's node key or plaintext, while the master still can.

mod common;

use common::{password_for, Env};

use nepomuk::crypto::{self, Sealed};
use nepomuk::format::{from_cbor, CheckpointBody, VaultFile};
use nepomuk::identity::{unlock_password_user, IdentityFile, Keys, Unlocked};
use nepomuk::keyring::{aad_content, aad_grant, aad_name, aad_node_key, blob_key, wrap_key, Access};
use nepomuk::model::{Content, Id, Principal, State};
use nepomuk::verify::{user_fp, verify_file};

const TARGET_PLAINTEXT: &str = "TOP-SECRET-prod-db-pw-7781";

fn jane_pass() -> String {
    password_for("jane@example.com")
}

/// Build a vault: master, Jane (password identity), a secret Jane cannot access and one she can.
fn setup() -> Env {
    let e = Env::new("attack-access");
    e.add_password_user("jane@example.com");
    e.m(&["mkdir", "-p", "/infra/db"]).ok();
    e.m(&["mkdir", "-p", "/shared"]).ok();
    e.m_in(&["put", "/infra/db/prod", "-"], format!("{TARGET_PLAINTEXT}\n").as_bytes())
        .ok();
    e.m_in(&["put", "/shared/note", "-"], b"shared-value-ok-for-jane\n")
        .ok();
    e.m(&["grant", "user:jane@example.com", "read", "/shared"]).ok();
    e
}

/// Load and verify the vault, pinning its own current master (rollback is out of scope here).
fn load(e: &Env) -> State {
    let bytes = std::fs::read(&e.vault).unwrap();
    let probe = VaultFile::parse(&bytes).expect("parse");
    let cp: CheckpointBody = from_cbor(&probe.entries[0].envelope.body).unwrap();
    let master = cp.state.users.get(&cp.state.master).unwrap();
    let pinned = user_fp(master);
    let file = VaultFile::parse(&bytes).unwrap();
    verify_file(file, &pinned).expect("verify").state
}

fn unlock_master(e: &Env) -> Unlocked {
    let text = std::fs::read_to_string(e.master_identity()).unwrap();
    IdentityFile::parse(&text)
        .unwrap()
        .unlock(common::MASTER_PASS)
        .unwrap()
}

fn unlock_jane(state: &State) -> Unlocked {
    let jane = state.user_by_name("jane@example.com").unwrap();
    unlock_password_user(jane, &jane_pass()).unwrap()
}

/// True if any node key the identity can legitimately derive opens `sealed` under any of `aads`.
fn opens_with_reachable_keys(acc: &Access, sealed: &Sealed, aads: &[Vec<u8>]) -> bool {
    acc.nodes.values().any(|v| {
        let bk = blob_key(&v.key);
        aads.iter().any(|aad| crypto::open_padded(&bk, sealed, aad).is_ok())
    })
}

#[test]
fn jane_cannot_read_a_secret_she_has_no_grant_for() {
    let e = setup();
    let state = load(&e);
    let vault = state.vault_id;

    // Locate the target as the master would (Jane cannot even name it).
    let master = unlock_master(&e);
    let macc = Access::build(&state, state.master, &master);
    let target = macc.resolve("/infra/db/prod").expect("master sees target");
    let target_node = state.nodes.get(&target).unwrap().clone();

    // The attacker: Jane, fully unlocked, with her own keys and the whole state.
    let jane_id: Id = state.user_by_name("jane@example.com").unwrap().id;
    let jane = unlock_jane(&state);
    let jacc = Access::build(&state, jane_id, &jane);

    // (1) The capability view does not include the target, and content() refuses it.
    assert!(
        jacc.resolve("/infra/db/prod").is_none(),
        "Jane must not resolve a path she has no grant for"
    );
    assert!(
        !jacc.nodes.contains_key(&target),
        "the target node must be outside Jane's access view"
    );
    assert!(jacc.content(&state, target).is_err(), "content() must deny the target");
    // She sees nothing under /infra.
    assert!(
        jacc.nodes.values().all(|v| !v.path.starts_with("/infra")),
        "Jane must not see any node under /infra"
    );

    // (2) No node key Jane can derive opens the target's content or name — under the correct
    //     AAD or any other AAD in the vault (guards against an AAD-transplant shortcut).
    let aads = vec![
        aad_content(vault, target),
        aad_name(vault, target),
        aad_content(vault, state.root),
        Vec::new(),
    ];
    assert!(
        !opens_with_reachable_keys(&jacc, &target_node.content, &aads),
        "no key in Jane's view may decrypt the target content"
    );
    assert!(
        !opens_with_reachable_keys(&jacc, &target_node.name, &aads),
        "no key in Jane's view may decrypt the target name"
    );

    // (3) The target's node-key wrap is only under its parent's wrap_key. None of Jane's
    //     reachable keys, used as a wrapping key, open it.
    let wrap = target_node.wrapped_key.expect("non-root node has a wrapped key");
    let aad_nk = aad_node_key(vault, target);
    let any = jacc.nodes.values().any(|v| {
        crypto::open(&wrap_key(&v.key), &wrap, &aad_nk).is_ok()
            || crypto::open(&blob_key(&v.key), &wrap, &aad_nk).is_ok()
    });
    assert!(!any, "Jane cannot unwrap the target node key from any key she holds");

    // (4) Of every grant in the file, Jane's KEM secret unwraps only grants addressed to her
    //     (or a group she is in). The master-only grant on the target never opens for her,
    //     and not under a transplanted AAD either.
    for g in state.grants.values() {
        let correct = aad_grant(vault, g.node, g.to);
        let ok = jane.unwrap(&g.wrapped, &correct).is_ok();
        let addressed_to_jane = matches!(g.to, Principal::User(u) if u == jane_id)
            || matches!(g.to, Principal::Group(gid)
                if state.groups.get(&gid).is_some_and(|grp| grp.members.contains_key(&jane_id)));
        assert_eq!(
            ok, addressed_to_jane,
            "Jane may unwrap a grant iff it is addressed to her; node {}",
            g.node.short()
        );
        if g.node == target {
            for g2 in state.grants.values() {
                let aad = aad_grant(vault, g2.node, g2.to);
                assert!(
                    jane.unwrap(&g.wrapped, &aad).is_err(),
                    "the target grant must not open for Jane under any AAD"
                );
            }
        }
    }

    // Control: the master recovers the exact plaintext, so the secret is intact and it is the
    // access control — not a broken vault — that stops Jane.
    match &macc.content(&state, target).unwrap().content {
        Content::Text { value } => assert_eq!(value, TARGET_PLAINTEXT, "master reads the real secret"),
        other => common::fail(&format!("unexpected content type: {}", other.type_name())),
    }

    // Positive control: the very same detector fires for a secret Jane IS allowed to read, so
    // the negative results above are not vacuous. Her reachable keys open /shared/note, and her
    // own grant unwraps.
    let shared = jacc.resolve("/shared/note").expect("Jane keeps her legitimate access");
    let shared_node = state.nodes.get(&shared).unwrap();
    assert!(
        opens_with_reachable_keys(&jacc, &shared_node.content, &[aad_content(vault, shared)]),
        "detector must open a secret Jane can read (guards against a vacuous test)"
    );
    assert!(
        state.grants.values().any(|g| matches!(g.to, Principal::User(u) if u == jane_id)
            && jane.unwrap(&g.wrapped, &aad_grant(vault, g.node, g.to)).is_ok()),
        "Jane's own grant must unwrap"
    );
}
