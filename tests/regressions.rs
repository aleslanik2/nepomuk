//! Regression tests for the findings of the October 2026 security review. Each test builds the
//! attack a malicious client could produce and checks that every client rejects it.

use nepomuk::crypto;
use nepomuk::error::Code;
use nepomuk::format::{
    CheckpointBody, CommitBody, Envelope, RawEntry, VaultFile, from_cbor, to_cbor,
};
use nepomuk::identity::{Request, Unlocked};
use nepomuk::keyring::{self, Access, PathProof};
use nepomuk::model::*;
use nepomuk::tx::{self, Tx};
use nepomuk::verify::{Verified, verify_file, verify_file_with};

fn sign_commit(file: &mut VaultFile, signer: &Unlocked, author: Id, seq: u64, ops: Vec<Op>) {
    let body = to_cbor(&CommitBody {
        vault_id: file.vault_id,
        seq,
        prev_hash: file.entries.last().unwrap().hash(),
        author,
        time: tx::now(),
        ops,
    });
    let sig = signer.sig.sign("commit", &body);
    file.entries
        .push(RawEntry::from_envelope(Envelope { body, sig }));
}

fn new_vault(master: &Unlocked) -> Verified {
    verify_file(tx::genesis(master).unwrap(), &master.fingerprint()).unwrap()
}

fn text(acc: &Access, v: &Verified, path: &str) -> String {
    let id = acc
        .resolve(path)
        .unwrap_or_else(|| panic!("{path} not visible"));
    match &acc.content(&v.state, id).unwrap().content {
        Content::Text { value } => value.to_string(),
        _ => panic!("not text"),
    }
}

/// K1: a vault signed by someone else, whose log "transfers" the master role to the pinned
/// key, must not verify against the pin.
#[test]
fn forged_checkpoint_with_transfer_to_pinned_master_is_rejected() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let ci = Unlocked::generate("ci", IdentityKind::Local);
    let fp = master.fingerprint();
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&ci, None)).unwrap();
    let (real, rv, _, _) = t.commit().unwrap();
    let real_master = rv.state.users[&rv.state.master].clone();
    let ci_rec = rv.state.user_by_name("ci").unwrap().clone();

    let evil = Unlocked::generate("evil", IdentityKind::Local);
    let g = tx::genesis(&evil).unwrap();
    let mut cp: CheckpointBody = from_cbor(&g.entries[0].envelope.body).unwrap();
    let vid = real.vault_id;
    let nk = crypto::random_key();
    let root = cp.state.root;
    cp.vault_id = vid;
    cp.state.vault_id = vid;
    cp.seq = 1_000;
    cp.state.grants.clear();
    let name = keyring::seal_name(vid, root, &nk, "");
    let rn = cp.state.nodes.get_mut(&root).unwrap();
    rn.name = name.sealed;
    rn.name_commit = name.commit;
    cp.state.users.insert(real_master.id, real_master.clone());
    cp.state.users.insert(ci_rec.id, ci_rec.clone());
    let body = to_cbor(&cp);
    let sig = evil.sig.sign("checkpoint", &body);
    let mut forged = VaultFile {
        vault_id: vid,
        entries: vec![RawEntry::from_envelope(Envelope { body, sig })],
    };
    let gr = keyring::make_grant(
        &cp.state,
        Id::random(),
        root,
        Principal::User(ci_rec.id),
        Right::Read,
        &nk,
        &PathProof::root(),
    )
    .unwrap();
    let evil_id = cp.state.master;
    sign_commit(
        &mut forged,
        &evil,
        evil_id,
        1_001,
        vec![
            Op::Grant { grant: gr },
            Op::TransferMaster {
                user: real_master.id,
            },
        ],
    );
    let err = verify_file(forged, &fp).unwrap_err();
    assert_eq!(err.code, Code::UntrustedRoot);
}

/// A real master transfer still works: the client that pinned the former master accepts it,
/// a fresh client needs the new master to compact first.
#[test]
fn master_transfer_needs_former_pin_or_compact() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let heir = Unlocked::generate("heir", IdentityKind::Local);
    let old_fp = master.fingerprint();
    let new_fp = heir.fingerprint();
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&heir, None)).unwrap();
    let h = t.user_named("heir").unwrap();
    t.transfer_master(h, false).unwrap();
    let (file, _, _, _) = t.commit().unwrap();

    assert_eq!(
        verify_file(file.clone(), &new_fp).unwrap_err().code,
        Code::UntrustedRoot
    );
    let v = verify_file_with(file, &new_fp, &[old_fp]).unwrap();
    assert_eq!(v.master_fp, new_fp);
    let compacted = tx::compact(&v, &heir).unwrap();
    verify_file(compacted, &new_fp).unwrap();
}

/// V1: a grant whose encrypted path does not match the node's place in the tree is ignored, so
/// a user with `share` on their own folder cannot shadow a path elsewhere.
#[test]
fn spoofed_grant_path_is_ignored() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let mallory = Unlocked::generate("mallory", IdentityKind::Local);
    let ci = Unlocked::generate("ci", IdentityKind::Local);
    let fp = master.fingerprint();
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&mallory, None)).unwrap();
    t.user_add(&Request::new(&ci, None)).unwrap();
    t.mkdir("/projects/eshop/signing", true).unwrap();
    t.put(
        "/projects/eshop/signing/release",
        Content::Text {
            value: "REAL".into(),
        },
        None,
    )
    .unwrap();
    // A folder of Mallory's at the same depth as the target, with a node of the same name.
    t.mkdir("/teams/mallory/x", true).unwrap();
    let m = t.user_named("mallory").unwrap();
    let c = t.user_named("ci").unwrap();
    t.grant(Principal::User(m), Right::Share, "/teams").unwrap();
    t.grant(Principal::User(c), Right::Read, "/projects/eshop/signing")
        .unwrap();
    let (mut f, v, _, _) = t.commit().unwrap();

    let macc = Access::build(&v.state, m, &mallory);
    let parent = macc.resolve("/teams/mallory/x").unwrap();
    let pk = macc.key(parent).unwrap().clone();
    let id = Id([0u8; 16]);
    let nk = crypto::random_key();
    let vid = v.state.vault_id;
    let name = keyring::seal_name(vid, id, &nk, "release");
    let node = Node {
        id,
        parent: Some(parent),
        wrapped_key: Some(keyring::seal_node_key(vid, id, &pk, &nk)),
        name: name.sealed,
        name_commit: name.commit,
        content: keyring::seal_content(
            vid,
            id,
            &nk,
            &NodeContent {
                content: Content::Text {
                    value: "EVIL".into(),
                },
                meta: Meta::default(),
            },
        ),
    };
    let mut st = v.state.clone();
    st.nodes.insert(id, node.clone());
    // Mallory's real salts for the four levels, but a path elsewhere.
    let mut salts = macc.proof(parent).unwrap().salts;
    salts.push(keyring::name_salt(&nk));
    let spoof = PathProof {
        path: "/projects/eshop/signing/release".into(),
        salts,
    };
    let gr = keyring::make_grant(
        &st,
        Id::random(),
        id,
        Principal::User(c),
        Right::Read,
        &nk,
        &spoof,
    )
    .unwrap();
    let gid = gr.id;
    sign_commit(
        &mut f,
        &mallory,
        m,
        v.seq + 1,
        vec![Op::CreateNode { node }, Op::Grant { grant: gr }],
    );
    let v2 = verify_file(f, &fp).unwrap();
    let acc = Access::build(&v2.state, c, &ci);
    assert_eq!(text(&acc, &v2, "/projects/eshop/signing/release"), "REAL");
    assert!(acc.unproven.contains(&gid));
    assert!(acc.path(id).is_none());
}

/// V1, write side: a grant labelled with another path cannot make someone write into it.
#[test]
fn write_through_spoofed_path_lands_in_the_real_folder() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let eve = Unlocked::generate("eve", IdentityKind::Local);
    let bob = Unlocked::generate("bob", IdentityKind::Local);
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&eve, None)).unwrap();
    t.user_add(&Request::new(&bob, None)).unwrap();
    t.mkdir("/public", false).unwrap();
    t.mkdir("/secret", false).unwrap();
    t.put("/public/db", Content::Text { value: "x".into() }, None)
        .unwrap();
    let eve_id = t.user_named("eve").unwrap();
    let bob_id = t.user_named("bob").unwrap();
    t.grant(Principal::User(eve_id), Right::Share, "/public")
        .unwrap();
    t.grant(Principal::User(bob_id), Right::Write, "/secret")
        .unwrap();
    let (_, v, _, _) = t.commit().unwrap();

    let mut t = Tx::new(&v, &eve).unwrap();
    let x = t.resolve("/public/db").unwrap();
    let nk = t.access().key(x).unwrap().clone();
    let mut proof = t.access().proof(x).unwrap();
    proof.path = "/secret/db".into();
    let g = keyring::make_grant(
        &v.state,
        Id::random(),
        x,
        Principal::User(bob_id),
        Right::Write,
        &nk,
        &proof,
    )
    .unwrap();
    t.push(Op::Grant { grant: g }).unwrap();
    let (_, v2, _, _) = t.commit().unwrap();

    let mut t = Tx::new(&v2, &bob).unwrap();
    assert_ne!(t.resolve("/secret/db").ok(), Some(x));
    t.put(
        "/secret/db",
        Content::Text {
            value: "NEW-PROD-PASSWORD".into(),
        },
        None,
    )
    .unwrap();
    let (_, v3, _, _) = t.commit().unwrap();
    let eacc = Access::build(&v3.state, eve_id, &eve);
    assert_eq!(text(&eacc, &v3, "/public/db"), "x");
    assert!(eacc.resolve("/secret/db").is_none());
}

/// Paths of grants deep in the tree stay provable after renames, moves and rekeys above them.
#[test]
fn deep_grant_paths_survive_tree_changes() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let ci = Unlocked::generate("ci", IdentityKind::Local);
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&ci, None)).unwrap();
    t.mkdir("/a/b/c", true).unwrap();
    t.put("/a/b/c/key", Content::Text { value: "k".into() }, None)
        .unwrap();
    let c = t.user_named("ci").unwrap();
    t.grant(Principal::User(c), Right::Read, "/a/b/c").unwrap();
    let (_, mut v, _, _) = t.commit().unwrap();
    let check = |v: &Verified, path: &str| {
        let acc = Access::build(&v.state, c, &ci);
        assert!(acc.unproven.is_empty(), "unproven grant at {path}");
        assert_eq!(text(&acc, v, path), "k");
    };
    check(&v, "/a/b/c/key");

    type Step = Box<dyn Fn(&mut Tx) -> nepomuk::error::Result<()>>;
    let steps: Vec<(&str, Step)> = vec![
        ("/z/b/c/key", Box::new(|t: &mut Tx| t.mv("/a", "/z"))),
        ("/y/c/key", Box::new(|t: &mut Tx| t.mv("/z/b", "/y"))),
        (
            "/y/c/key",
            Box::new(|t: &mut Tx| {
                let n = t.resolve("/y")?;
                t.rekey(n)
            }),
        ),
        (
            "/y/c/key",
            Box::new(|t: &mut Tx| {
                let n = t.resolve("/y/c")?;
                t.rekey(n)
            }),
        ),
        (
            "/y/c/key",
            Box::new(|t: &mut Tx| {
                let root = t.state.root;
                t.rekey(root)
            }),
        ),
        ("/y/d/key", Box::new(|t: &mut Tx| t.mv("/y/c", "/y/d"))),
    ];
    for (path, step) in steps {
        let mut t = Tx::new(&v, &master).unwrap();
        step(&mut t).unwrap();
        v = t.commit().unwrap().1;
        check(&v, path);
    }
}

/// V3: replacing an identity removes its system rights and cannot revive a disabled user.
#[test]
fn replace_identity_does_not_hand_over_system_rights() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let it = Unlocked::generate("it", IdentityKind::Local);
    let bob = Unlocked::generate("bob", IdentityKind::Local);
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&it, None)).unwrap();
    t.user_add(&Request::new(&bob, None)).unwrap();
    let i = t.user_named("it").unwrap();
    let b = t.user_named("bob").unwrap();
    t.sysgrant(i, SysRight::Users, false).unwrap();
    t.sysgrant(b, SysRight::Groups, true).unwrap();
    let (_, v, _, _) = t.commit().unwrap();

    let fake_bob = Unlocked::generate("bob", IdentityKind::Local);
    let mut t = Tx::new(&v, &it).unwrap();
    t.user_replace(b, &Request::new(&fake_bob, None)).unwrap();
    assert!(t.tasks.iter().any(|x| x.contains("groups")));
    let (_, v, _, _) = t.commit().unwrap();
    assert_eq!(v.state.sys_right(b, SysRight::Groups), None);

    // Keys of another user cannot be taken over.
    let mut t = Tx::new(&v, &it).unwrap();
    assert!(t.user_replace(b, &Request::new(&it, None)).is_err());

    // A disabled user comes back with nothing: no grants, groups or system rights.
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_disable(b).unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    let again = Unlocked::generate("bob", IdentityKind::Local);
    let mut t = Tx::new(&v, &it).unwrap();
    t.user_replace(b, &Request::new(&again, None)).unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    assert!(v.state.active(b));
    assert!(v.state.sysrights.get(&b).is_none_or(|m| m.is_empty()));
    assert!(!v.state.grants.values().any(|g| g.to == Principal::User(b)));
}

/// Format v2: an entry with trailing bytes (same signature, different encoding) is rejected.
#[test]
fn non_canonical_entry_is_rejected() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let f = tx::genesis(&master).unwrap();
    let mut bytes = f.serialize();
    let hl = 34;
    let len = u32::from_be_bytes(bytes[hl..hl + 4].try_into().unwrap());
    bytes[hl..hl + 4].copy_from_slice(&(len + 1).to_be_bytes());
    bytes.push(0x00);
    assert!(VaultFile::parse(&bytes).is_err());
}

/// S1: credentials with weak Argon2id parameters are refused by every client.
#[test]
fn weak_kdf_credential_is_rejected() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let alice = Unlocked::generate("alice@example.com", IdentityKind::Password);
    let weak = crypto::KdfParams {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };
    let salt = vec![7u8; 16];
    let key = crypto::argon2id(b"pw", &salt, &weak).unwrap();
    let cred = crypto::PasswordSealed {
        kdf: weak,
        salt,
        sealed: crypto::seal(
            &key,
            alice.seed.as_ref(),
            &nepomuk::identity::credential_aad("alice@example.com"),
        ),
    };
    let req = Request::new(&alice, Some(cred));
    assert!(req.verify().is_err());

    let v = new_vault(&master);
    let user = User {
        id: Id::random(),
        name: req.name.clone(),
        kind: req.kind,
        kem: req.kem.clone(),
        sig: req.sig.clone(),
        credential: req.credential.clone(),
        proof: req.proof.clone(),
        disabled: false,
    };
    let mut f = v.file.clone();
    let me = v.state.master;
    sign_commit(&mut f, &master, me, v.seq + 1, vec![Op::AddUser { user }]);
    assert_eq!(
        verify_file(f, &master.fingerprint()).unwrap_err().code,
        Code::UnauthorizedOperation
    );
}

/// F3: whoever relays a request cannot swap its credential.
#[test]
fn request_proof_covers_the_credential() {
    let alice = Unlocked::generate("alice@example.com", IdentityKind::Password);
    let other = Unlocked::generate("alice@example.com", IdentityKind::Password);
    let ps = |id: &Unlocked| crypto::PasswordSealed {
        kdf: crypto::KdfParams::default_params(),
        salt: vec![1u8; 16],
        sealed: crypto::seal(&crypto::random_key(), id.seed.as_ref(), b""),
    };
    let mut req = Request::new(&alice, Some(ps(&alice)));
    req.verify().unwrap();
    req.credential = Some(ps(&other));
    assert!(req.verify().is_err());
}

/// V4: crash cleanup never follows symlinks and never touches directories it does not own
/// privately, so a planted directory in the shared temp dir cannot be used to wipe files.
#[cfg(unix)]
#[test]
fn exec_cleanup_does_not_follow_symlinks() {
    use std::os::unix::fs::PermissionsExt;
    let base = std::env::temp_dir().join(format!("nepomuk-test-{}", Id::random().hex()));
    std::fs::create_dir(&base).unwrap();
    let victim = base.join("victim");
    std::fs::write(&victim, b"precious").unwrap();

    // A world-readable directory is not ours to clean.
    let open_dir = base.join("open");
    std::fs::create_dir(&open_dir).unwrap();
    std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink(&victim, open_dir.join("link")).unwrap();
    nepomuk::exec::remove_dir(&open_dir);
    assert!(open_dir.exists());

    // In a private directory the symlink is removed, not followed.
    let private = base.join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&victim, private.join("link")).unwrap();
    std::fs::write(private.join("secret"), b"s3cret").unwrap();
    nepomuk::exec::remove_dir(&private);
    assert!(!private.exists());
    assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
    std::fs::remove_dir_all(&base).unwrap();
}

/// A former master cannot use its old key to forge the vault for clients that remember it: a
/// checkpoint signed by a former master is accepted only when it continues the seen history.
#[test]
fn former_master_cannot_forge_after_transfer() {
    use nepomuk::config::VaultMemory;
    let alice = Unlocked::generate("alice", IdentityKind::Local);
    let bob = Unlocked::generate("bob", IdentityKind::Local);
    let (a_fp, b_fp) = (alice.fingerprint(), bob.fingerprint());
    let v = new_vault(&alice);
    let mut t = Tx::new(&v, &alice).unwrap();
    t.user_add(&Request::new(&bob, None)).unwrap();
    let b = t.user_named("bob").unwrap();
    t.transfer_master(b, false).unwrap();
    let (file, seen, _, _) = t.commit().unwrap();
    let mut mem = VaultMemory {
        pin: Some(b_fp.clone()),
        former: vec![a_fp.clone()],
        seq: Some(seen.seq),
        head: Some(hex::encode(seen.head)),
        ..Default::default()
    };

    // The real continuation (still Alice's checkpoint) is accepted.
    let mut t = Tx::new(&seen, &bob).unwrap();
    t.mkdir("/x", false).unwrap();
    let (next, _, _, _) = t.commit().unwrap();
    let v2 = verify_file_with(next, &b_fp, &mem.former).unwrap();
    nepomuk::app::check_former_signer(&v2, &mut mem, &b_fp).unwrap();

    // Alice forges a fresh history ending with a transfer to Bob.
    let g = tx::genesis(&alice).unwrap();
    let mut cp: CheckpointBody = from_cbor(&g.entries[0].envelope.body).unwrap();
    let vid = file.vault_id;
    let root = cp.state.root;
    let nk = crypto::random_key();
    cp.vault_id = vid;
    cp.state.vault_id = vid;
    cp.seq = 1_000;
    cp.folded_head = Some(seen.head);
    cp.state.grants.clear();
    let name = keyring::seal_name(vid, root, &nk, "");
    let rn = cp.state.nodes.get_mut(&root).unwrap();
    rn.name = name.sealed;
    rn.name_commit = name.commit;
    let bob_rec = seen.state.users[&b].clone();
    cp.state.users.insert(b, bob_rec);
    let body = to_cbor(&cp);
    let sig = alice.sig.sign("checkpoint", &body);
    let mut forged = VaultFile {
        vault_id: vid,
        entries: vec![RawEntry::from_envelope(Envelope { body, sig })],
    };
    let a = cp.state.master;
    sign_commit(
        &mut forged,
        &alice,
        a,
        1_001,
        vec![Op::TransferMaster { user: b }],
    );
    let fv = verify_file_with(forged, &b_fp, &mem.former).unwrap();
    let err = nepomuk::app::check_former_signer(&fv, &mut mem, &b_fp).unwrap_err();
    assert_eq!(err.code, Code::UntrustedRoot);

    // After Bob compacts, Alice is no longer trusted at all.
    let compacted = tx::compact(&v2, &bob).unwrap();
    let v3 = verify_file_with(compacted, &b_fp, &mem.former).unwrap();
    nepomuk::app::check_former_signer(&v3, &mut mem, &b_fp).unwrap();
    assert!(mem.former.is_empty());
}

/// Proven paths must be canonical; anything else is ignored.
#[test]
fn non_canonical_grant_path_is_not_proven() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let ci = Unlocked::generate("ci", IdentityKind::Local);
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&ci, None)).unwrap();
    t.mkdir("/a/b", true).unwrap();
    let c = t.user_named("ci").unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    let mut t = Tx::new(&v, &master).unwrap();
    let n = t.resolve("/a/b").unwrap();
    let nk = t.access().key(n).unwrap().clone();
    let mut proof = t.access().proof(n).unwrap();
    for bad in ["//a/b", "/a//b", "/a/b/"] {
        proof.path = bad.into();
        let g = keyring::make_grant(
            &v.state,
            Id::random(),
            n,
            Principal::User(c),
            Right::Read,
            &nk,
            &proof,
        )
        .unwrap();
        assert!(!keyring::check_path(&v.state, n, bad, &proof.salts));
        let _ = g;
    }
    assert!(keyring::check_path(&v.state, n, "/a/b", &proof.salts));
}

/// `mv` into a folder that already holds that name is refused instead of creating a duplicate,
/// and a node the author cannot read does not block moving its ancestors.
#[test]
fn mv_refuses_duplicates_and_ignores_unreadable_nodes() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let eve = Unlocked::generate("eve", IdentityKind::Local);
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&eve, None)).unwrap();
    t.mkdir("/x/a", true).unwrap();
    t.mkdir("/y/a", true).unwrap();
    t.mkdir("/w/e", true).unwrap();
    let e = t.user_named("eve").unwrap();
    t.grant(Principal::User(e), Right::Write, "/w/e").unwrap();
    let (mut f, v, _, _) = t.commit().unwrap();
    let mut t = Tx::new(&v, &master).unwrap();
    assert_eq!(t.mv("/x/a", "/y").unwrap_err().code, Code::AlreadyExists);

    // Eve plants a node with a commitment that does not match its name.
    let eacc = Access::build(&v.state, e, &eve);
    let parent = eacc.resolve("/w/e").unwrap();
    let pk = eacc.key(parent).unwrap().clone();
    let id = Id::random();
    let nk = crypto::random_key();
    let vid = v.state.vault_id;
    let node = Node {
        id,
        parent: Some(parent),
        wrapped_key: Some(keyring::seal_node_key(vid, id, &pk, &nk)),
        name: keyring::seal_name(vid, id, &nk, "junk").sealed,
        name_commit: [0u8; 32],
        content: keyring::seal_content(
            vid,
            id,
            &nk,
            &NodeContent {
                content: Content::Folder,
                meta: Meta::default(),
            },
        ),
    };
    sign_commit(&mut f, &eve, e, v.seq + 1, vec![Op::CreateNode { node }]);
    let v = verify_file(f, &master.fingerprint()).unwrap();
    let mut t = Tx::new(&v, &master).unwrap();
    t.mv("/w", "/v").unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    let eacc = Access::build(&v.state, e, &eve);
    assert!(eacc.unproven.is_empty());
    assert!(eacc.resolve("/v/e").is_some());
}

/// A client that last saw the vault right after a compact (no commits yet) still accepts the
/// former master's checkpoint followed by the transfer: it is the very checkpoint it saw.
#[test]
fn transfer_right_after_compact_is_accepted() {
    use nepomuk::config::VaultMemory;
    let alice = Unlocked::generate("alice", IdentityKind::Local);
    let bob = Unlocked::generate("bob", IdentityKind::Local);
    let b_fp = bob.fingerprint();
    let v = new_vault(&alice);
    let mut t = Tx::new(&v, &alice).unwrap();
    t.user_add(&Request::new(&bob, None)).unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    let compacted = verify_file(tx::compact(&v, &alice).unwrap(), &alice.fingerprint()).unwrap();
    let mut mem = VaultMemory {
        pin: Some(alice.fingerprint()),
        seq: Some(compacted.seq),
        head: Some(hex::encode(compacted.head)),
        checkpoint: Some(hex::encode(compacted.file.entries[0].hash())),
        ..Default::default()
    };
    let mut t = Tx::new(&compacted, &alice).unwrap();
    let b = t.user_named("bob").unwrap();
    t.transfer_master(b, false).unwrap();
    let (file, _, _, _) = t.commit().unwrap();
    mem.former = vec![alice.fingerprint()];
    mem.pin = Some(b_fp.clone());
    let v = verify_file_with(file, &b_fp, &mem.former).unwrap();
    nepomuk::app::check_former_signer(&v, &mut mem, &b_fp).unwrap();
}

/// A share-holder's grant on a node nobody else can read does not block moving its ancestors.
#[test]
fn unreadable_granted_node_does_not_block_mv() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let eve = Unlocked::generate("eve", IdentityKind::Local);
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&eve, None)).unwrap();
    t.mkdir("/a/w", true).unwrap();
    let e = t.user_named("eve").unwrap();
    t.grant(Principal::User(e), Right::Share, "/a/w").unwrap();
    let (mut f, v, _, _) = t.commit().unwrap();
    let eacc = Access::build(&v.state, e, &eve);
    let parent = eacc.resolve("/a/w").unwrap();
    let pk = eacc.key(parent).unwrap().clone();
    let id = Id::random();
    let nk = crypto::random_key();
    let vid = v.state.vault_id;
    let node = Node {
        id,
        parent: Some(parent),
        wrapped_key: Some(keyring::seal_node_key(vid, id, &pk, &nk)),
        name: keyring::seal_name(vid, id, &nk, "junk").sealed,
        name_commit: [0u8; 32],
        content: keyring::seal_content(
            vid,
            id,
            &nk,
            &NodeContent {
                content: Content::Folder,
                meta: Meta::default(),
            },
        ),
    };
    let mut st = v.state.clone();
    st.nodes.insert(id, node.clone());
    let mut proof = eacc.proof(parent).unwrap();
    proof = proof.child("junk", keyring::name_salt(&nk));
    let g = keyring::make_grant(
        &st,
        Id::random(),
        id,
        Principal::User(e),
        Right::Write,
        &nk,
        &proof,
    )
    .unwrap();
    sign_commit(
        &mut f,
        &eve,
        e,
        v.seq + 1,
        vec![Op::CreateNode { node }, Op::Grant { grant: g }],
    );
    let v = verify_file(f, &master.fingerprint()).unwrap();
    let mut t = Tx::new(&v, &master).unwrap();
    t.mv("/a", "/b").unwrap();
    assert!(!t.tasks.is_empty());
    t.commit().unwrap();
}

/// A vault where Eve has `write` on /team and her own client has added a node nobody can open
/// with the folder's key (`junk`), plus a real secret of Alice's next to it.
fn vault_with_junk() -> (Unlocked, Unlocked, Verified, Id) {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let eve = Unlocked::generate("eve", IdentityKind::Local);
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&eve, None)).unwrap();
    t.mkdir("/team/sub", true).unwrap();
    t.put("/team/sub/key", Content::Text { value: "k".into() }, None)
        .unwrap();
    let e = t.user_named("eve").unwrap();
    t.grant(Principal::User(e), Right::Write, "/team").unwrap();
    let (mut file, v, _, _) = t.commit().unwrap();

    // Eve's client: a child of /team whose key is wrapped under a key only she knows.
    let acc = Access::build(&v.state, e, &eve);
    let team = acc.resolve("/team").unwrap();
    let (vid, junk) = (v.state.vault_id, Id::random());
    let (own, nk) = (crypto::random_key(), crypto::random_key());
    let name = keyring::seal_name(vid, junk, &nk, "junk");
    let node = Node {
        id: junk,
        parent: Some(team),
        wrapped_key: Some(keyring::seal_node_key(vid, junk, &own, &nk)),
        name: name.sealed,
        name_commit: name.commit,
        content: keyring::seal_content(
            vid,
            junk,
            &nk,
            &NodeContent {
                content: Content::Folder,
                meta: Meta {
                    created: 0,
                    updated: 0,
                    not_after: None,
                    description: None,
                },
            },
        ),
    };
    let seq = v.seq + 1;
    sign_commit(&mut file, &eve, e, seq, vec![Op::CreateNode { node }]);
    // Every client accepts it: Eve may write there, and nobody can check what she sealed.
    let v = verify_file(file, &master.fingerprint()).unwrap();
    (master, eve, v, junk)
}

/// Audit finding 2: a node the admin cannot read must not block rekey or offboarding.
#[test]
fn unreadable_node_does_not_block_offboarding() {
    let (master, _eve, v, junk) = vault_with_junk();
    let mut t = Tx::new(&v, &master).unwrap();
    let e = t.user_named("eve").unwrap();
    t.offboard(e).unwrap();
    assert!(
        t.warnings.iter().any(|w| w.contains(&junk.hex())),
        "{:?}",
        t.warnings
    );
    assert!(t.tasks.is_empty(), "{:?}", t.tasks);
    let (file, v2, _, _) = t.commit().unwrap();
    verify_file(file, &master.fingerprint()).unwrap();
    assert!(!v2.state.nodes.contains_key(&junk));
    assert!(!v2.state.active(e));
    let acc = Access::build(&v2.state, v2.state.master, &master);
    assert_eq!(text(&acc, &v2, "/team/sub/key"), "k");
}

#[test]
fn unreadable_node_does_not_block_rekey_of_ancestors() {
    let (master, _eve, v, junk) = vault_with_junk();
    let mut t = Tx::new(&v, &master).unwrap();
    let root = t.state.root;
    t.rekey(root).unwrap();
    let (_, v2, _, _) = t.commit().unwrap();
    assert!(!v2.state.nodes.contains_key(&junk));
    let acc = Access::build(&v2.state, v2.state.master, &master);
    assert_eq!(text(&acc, &v2, "/team/sub/key"), "k");
}

/// A readable folder whose content Eve replaced with garbage: rekey keeps it (and the secret
/// below it) instead of failing or deleting someone else's data.
#[test]
fn folder_with_garbled_content_is_resealed_by_rekey() {
    let (master, eve, v, _) = vault_with_junk();
    let e = v.state.user_by_name("eve").unwrap().id;
    let acc = Access::build(&v.state, e, &eve);
    let sub = acc.resolve("/team/sub").unwrap();
    let mut file = v.file.clone();
    let garbage = keyring::seal_content(
        v.state.vault_id,
        sub,
        &crypto::random_key(),
        &NodeContent {
            content: Content::Folder,
            meta: Meta {
                created: 0,
                updated: 0,
                not_after: None,
                description: None,
            },
        },
    );
    sign_commit(
        &mut file,
        &eve,
        e,
        v.seq + 1,
        vec![Op::UpdateNode {
            id: sub,
            content: garbage,
        }],
    );
    let v = verify_file(file, &master.fingerprint()).unwrap();
    let mut t = Tx::new(&v, &master).unwrap();
    let team = t.resolve("/team").unwrap();
    t.rekey(team).unwrap();
    let (_, v2, _, _) = t.commit().unwrap();
    let acc = Access::build(&v2.state, v2.state.master, &master);
    assert_eq!(text(&acc, &v2, "/team/sub/key"), "k");
    let sub = acc.resolve("/team/sub").unwrap();
    assert!(matches!(
        acc.content(&v2.state, sub).unwrap().content,
        Content::Folder
    ));
}

#[test]
fn unreadable_node_can_be_removed_by_id() {
    let (master, _eve, v, junk) = vault_with_junk();
    let mut t = Tx::new(&v, &master).unwrap();
    t.rm_node(junk).unwrap();
    let (_, v2, _, _) = t.commit().unwrap();
    assert!(!v2.state.nodes.contains_key(&junk));
}

/// Audit finding 1: a bare repository committed into a project, with a config that runs
/// commands, must never be used by git on nepomuk's behalf.
#[test]
fn embedded_bare_repository_is_refused() {
    use nepomuk::store::Location;
    use std::process::Command;
    let dir = std::env::temp_dir().join(format!(
        "nepomuk-embedded-{}-{}",
        std::process::id(),
        tx::now()
    ));
    let git = |args: &[&str]| {
        assert!(
            Command::new("git")
                .args(args)
                .output()
                .unwrap()
                .status
                .success(),
            "git {args:?}"
        )
    };
    let proj = dir.join("proj");
    let repo = proj.join("evil/repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&["init", "-q", proj.to_str().unwrap()]);
    git(&["init", "-q", "--bare", repo.to_str().unwrap()]);
    let pwned = dir.join("PWNED");
    let cfg = |k: &str, v: &str| git(&["-C", repo.to_str().unwrap(), "config", k, v]);
    cfg("core.bare", "false");
    cfg("core.worktree", "..");
    cfg("protocol.ext.allow", "always");
    cfg(
        "remote.origin.url",
        &format!("ext::sh -c touch% {}", pwned.display()),
    );
    cfg(
        "core.fsmonitor",
        &format!("touch {}; false", pwned.display()),
    );
    let res = Location::detect(&repo.join("vault.npk"), None);
    if let Ok(loc) = res {
        let _ = loc.load(true);
        panic!("embedded repository accepted: git = {:?}", loc.git);
    }
    assert!(
        !pwned.exists(),
        "git ran a command from the embedded config"
    );

    // A vault in an ordinary repository with a remote still uses git.
    let ok = dir.join("ok");
    git(&["init", "-q", ok.to_str().unwrap()]);
    git(&[
        "-C",
        ok.to_str().unwrap(),
        "remote",
        "add",
        "origin",
        "/nonexistent",
    ]);
    std::fs::create_dir_all(ok.join("sub")).unwrap();
    let loc = Location::detect(&ok.join("sub/vault.npk"), None).unwrap();
    assert!(loc.is_git());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Audit finding 3: a key rotation may only touch the author's own grants and memberships.
#[test]
fn rotate_own_keys_rules() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let eve = Unlocked::generate("eve", IdentityKind::Local);
    let bob = Unlocked::generate("bob", IdentityKind::Local);
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&eve, None)).unwrap();
    t.user_add(&Request::new(&bob, None)).unwrap();
    t.mkdir("/x", false).unwrap();
    t.put("/x/s", Content::Text { value: "v".into() }, None)
        .unwrap();
    let (e, b) = (t.user_named("eve").unwrap(), t.user_named("bob").unwrap());
    t.grant(Principal::User(e), Right::Read, "/x").unwrap();
    t.grant(Principal::User(b), Right::Read, "/x").unwrap();
    let (file, v, _, _) = t.commit().unwrap();
    let fp = master.fingerprint();
    let bob_grant = v
        .state
        .grants
        .values()
        .find(|g| g.to == Principal::User(b))
        .unwrap()
        .clone();
    let new = Unlocked::generate("eve", IdentityKind::Local);
    let rotate = |grants: Vec<Grant>, kem: &crypto::KemPublic, sig: &crypto::SigPublic| {
        let mut f = file.clone();
        sign_commit(
            &mut f,
            &eve,
            e,
            v.seq + 1,
            vec![Op::RotateOwnKeys {
                kem: kem.clone(),
                sig: sig.clone(),
                credential: None,
                proof: new.proof(IdentityKind::Local, None),
                grants,
                memberships: Default::default(),
            }],
        );
        verify_file(f, &fp)
    };
    let (nk, ns) = (new.kem.public(), new.sig.public());
    // Someone else's grant cannot be "re-wrapped".
    assert_eq!(
        rotate(vec![bob_grant], nk, ns).unwrap_err().code,
        Code::UnauthorizedOperation
    );
    // Another user's keys cannot be taken over.
    assert_eq!(
        rotate(vec![], bob.kem.public(), bob.sig.public())
            .unwrap_err()
            .code,
        Code::UnauthorizedOperation
    );
    // Without a matching proof of possession the keys are refused.
    let other = Unlocked::generate("eve", IdentityKind::Local);
    assert_eq!(
        rotate(vec![], other.kem.public(), ns).unwrap_err().code,
        Code::UnauthorizedOperation
    );

    // The real thing: Eve keeps her access under the new keys, the old keys are dead.
    let mut t = Tx::new(&v, &eve).unwrap();
    t.rotate_own_keys(
        nk.clone(),
        ns.clone(),
        None,
        new.proof(IdentityKind::Local, None),
    )
    .unwrap();
    let (f2, _, _, _) = t.commit().unwrap();
    let v2 = verify_file(f2.clone(), &fp).unwrap();
    let acc = Access::build(&v2.state, e, &new);
    assert_eq!(text(&acc, &v2, "/x/s"), "v");
    assert!(tx::find_me(&v2.state, &eve).is_err());
    // The old keys cannot sign any more.
    let mut f3 = f2;
    sign_commit(
        &mut f3,
        &eve,
        e,
        v2.seq + 1,
        vec![Op::DeleteNode {
            id: acc.resolve("/x/s").unwrap(),
        }],
    );
    assert_eq!(
        verify_file(f3, &fp).unwrap_err().code,
        Code::SignatureInvalid
    );

    // The master's keys are pinned: no rotation.
    let mut f4 = v2.file.clone();
    let m2 = Unlocked::generate("master", IdentityKind::Local);
    sign_commit(
        &mut f4,
        &master,
        v2.state.master,
        v2.seq + 1,
        vec![Op::RotateOwnKeys {
            kem: m2.kem.public().clone(),
            sig: m2.sig.public().clone(),
            credential: None,
            proof: m2.proof(IdentityKind::Local, None),
            grants: vec![],
            memberships: Default::default(),
        }],
    );
    assert_eq!(
        verify_file(f4, &fp).unwrap_err().code,
        Code::UnauthorizedOperation
    );
}

/// Audit finding 5: the former master gives up its access, and the vault remembers that the
/// root has to be rekeyed until the new master does it.
#[test]
fn master_transfer_steps_down_and_asks_for_root_rekey() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let heir = Unlocked::generate("heir", IdentityKind::Local);
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&heir, None)).unwrap();
    t.put("/s", Content::Text { value: "v".into() }, None)
        .unwrap();
    let h = t.user_named("heir").unwrap();
    let old = t.me;
    t.transfer_master(h, false).unwrap();
    assert!(!t.tasks.is_empty());
    let (_, v, _, _) = t.commit().unwrap();
    assert_eq!(v.state.former_master, Some(old));
    assert!(!v.state.has_right(old, v.state.root, Right::Admin));
    assert!(
        Access::build(&v.state, old, &master)
            .resolve("/s")
            .is_none()
    );
    let w = nepomuk::queries::state_warnings(&v.state);
    assert!(w.iter().any(|w| w.contains("rekey /")), "{w:?}");

    let mut t = Tx::new(&v, &heir).unwrap();
    let root = t.state.root;
    t.rekey(root).unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    assert_eq!(v.state.former_master, None);
    assert!(nepomuk::queries::state_warnings(&v.state).is_empty());
    let acc = Access::build(&v.state, h, &heir);
    assert_eq!(text(&acc, &v, "/s"), "v");

    // With --keep-access the former master stays admin and nothing nags.
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&heir, None)).unwrap();
    let h = t.user_named("heir").unwrap();
    let old = t.me;
    t.transfer_master(h, true).unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    assert!(v.state.has_right(old, v.state.root, Right::Admin));
    assert!(nepomuk::queries::state_warnings(&v.state).is_empty());
}

/// NPK-01: replacing an identity gives new keys to everything the replaced keys could read,
/// so content written afterwards is out of their reach; what the author cannot rekey stays
/// pending in the vault, even after the new keys are granted access again.
#[test]
fn replaced_keys_cannot_read_later_content() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let bob = Unlocked::generate("bob", IdentityKind::Local);
    let it = Unlocked::generate("it", IdentityKind::Local);
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&bob, None)).unwrap();
    t.user_add(&Request::new(&it, None)).unwrap();
    t.mkdir("/team", false).unwrap();
    t.put("/team/db", Content::Text { value: "v1".into() }, None)
        .unwrap();
    let g = t.group_create("devs").unwrap();
    let b = t.user_named("bob").unwrap();
    let i = t.user_named("it").unwrap();
    t.group_add(g, b).unwrap();
    t.grant(Principal::User(b), Right::Read, "/team").unwrap();
    t.mkdir("/grp", false).unwrap();
    t.put("/grp/s", Content::Text { value: "g1".into() }, None)
        .unwrap();
    t.grant(Principal::Group(g), Right::Read, "/grp").unwrap();
    t.sysgrant(i, SysRight::Users, false).unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    // What the old keys know, from the history.
    let old = Access::build(&v.state, b, &bob);
    assert_eq!(text(&old, &v, "/team/db"), "v1");
    assert_eq!(text(&old, &v, "/grp/s"), "g1");

    // The master replaces Bob's keys: everything is rekeyed, nothing is left pending.
    let new_bob = Unlocked::generate("bob", IdentityKind::Local);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_replace(b, &Request::new(&new_bob, None)).unwrap();
    assert!(t.tasks.is_empty(), "{:?}", t.tasks);
    let (_, v2, _, _) = t.commit().unwrap();
    assert!(v2.state.rekey_pending.is_empty());
    let mut t = Tx::new(&v2, &master).unwrap();
    t.put("/team/db", Content::Text { value: "v2".into() }, None)
        .unwrap();
    t.put("/grp/s", Content::Text { value: "g2".into() }, None)
        .unwrap();
    let (_, v3, _, _) = t.commit().unwrap();
    for (id, n) in &old.nodes {
        assert!(
            old.content(&v3.state, *id).is_err(),
            "the replaced keys still read {}",
            n.path
        );
    }
    // The old group key does not open the group's new grants.
    let (_, old_group) = old.groups.get(&g).unwrap();
    for gr in v3
        .state
        .grants
        .values()
        .filter(|x| x.to == Principal::Group(g))
    {
        let aad = keyring::aad_grant(v3.state.vault_id, gr.node, gr.to);
        assert!(crypto::unwrap(old_group, &gr.wrapped, &aad).is_err());
    }
    // The new keys read everything again.
    let acc = Access::build(&v3.state, b, &new_bob);
    assert_eq!(text(&acc, &v3, "/team/db"), "v2");
    assert_eq!(text(&acc, &v3, "/grp/s"), "g2");

    // Someone with only `users` can neither rekey nor give the group a new key: the vault
    // keeps both marked, also after the master grants the new keys access again.
    let old2 = Access::build(&v3.state, b, &new_bob);
    let newer = Unlocked::generate("bob", IdentityKind::Local);
    let mut t = Tx::new(&v3, &it).unwrap();
    t.user_replace(b, &Request::new(&newer, None)).unwrap();
    assert!(
        t.tasks.iter().any(|x| x.contains("group remove devs bob")),
        "{:?}",
        t.tasks
    );
    let (_, v4, _, _) = t.commit().unwrap();
    assert!(v4.state.stale_groups.contains(&g));
    let mut t = Tx::new(&v4, &master).unwrap();
    t.grant(Principal::User(b), Right::Read, "/team").unwrap();
    t.group_add(g, b).unwrap();
    let (_, v5, _, _) = t.commit().unwrap();
    let macc = Access::build(&v5.state, v5.state.master, &master);
    let (team, grp) = (
        macc.resolve("/team").unwrap(),
        macc.resolve("/grp").unwrap(),
    );
    assert!(v5.state.stale_keys.contains_key(&team));
    assert!(v5.state.stale_keys.contains_key(&grp));
    // A rekey alone does not help /grp while the group key is stale.
    let mut t = Tx::new(&v5, &master).unwrap();
    t.rekey_pending().unwrap();
    let (_, v6, _, _) = t.commit().unwrap();
    assert!(!v6.state.stale_keys.contains_key(&team));
    assert!(v6.state.stale_keys.contains_key(&grp));
    // `group remove devs bob` by a member and admin gives the group a new key (bob is a member
    // again here; it works too when he is not), then `rekey --pending` clears the rest.
    let mut t = Tx::new(&v6, &master).unwrap();
    t.group_remove(g, b).unwrap();
    let (_, v7, _, _) = t.commit().unwrap();
    assert!(v7.state.stale_groups.is_empty());
    let mut t = Tx::new(&v7, &master).unwrap();
    if !v7.state.stale_keys.is_empty() || !v7.state.rekey_pending.is_empty() {
        t.rekey_pending().unwrap();
    }
    t.put("/team/db", Content::Text { value: "v3".into() }, None)
        .unwrap();
    t.put("/grp/s", Content::Text { value: "g3".into() }, None)
        .unwrap();
    let (_, v8, _, _) = t.commit().unwrap();
    assert!(v8.state.stale_keys.is_empty() && v8.state.rekey_pending.is_empty());
    for (id, n) in &old2.nodes {
        assert!(
            old2.content(&v8.state, *id).is_err(),
            "the replaced keys still read {}",
            n.path
        );
    }
}

/// A stale group can be given a new key after the replaced user is no longer its member.
#[test]
fn stale_group_gets_a_new_key_without_the_replaced_member() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let bob = Unlocked::generate("bob", IdentityKind::Local);
    let it = Unlocked::generate("it", IdentityKind::Local);
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&bob, None)).unwrap();
    t.user_add(&Request::new(&it, None)).unwrap();
    let g = t.group_create("devs").unwrap();
    let b = t.user_named("bob").unwrap();
    let i = t.user_named("it").unwrap();
    t.group_add(g, b).unwrap();
    t.mkdir("/grp", false).unwrap();
    t.grant(Principal::Group(g), Right::Read, "/grp").unwrap();
    t.sysgrant(i, SysRight::Users, false).unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    let old = Access::build(&v.state, b, &bob);
    let mut t = Tx::new(&v, &it).unwrap();
    t.user_replace(
        b,
        &Request::new(&Unlocked::generate("bob", IdentityKind::Local), None),
    )
    .unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    assert!(v.state.stale_groups.contains(&g));
    assert!(!v.state.groups[&g].members.contains_key(&b));
    // A new grant for the stale group is readable by the replaced keys: marked.
    let mut t = Tx::new(&v, &master).unwrap();
    t.mkdir("/grp2", false).unwrap();
    t.grant(Principal::Group(g), Right::Read, "/grp2").unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    let grp2 = Access::build(&v.state, v.state.master, &master)
        .resolve("/grp2")
        .unwrap();
    assert!(v.state.stale_keys[&grp2].contains(&g));
    // Only operations every client accepts: add the user back, remove (new key), add again.
    let mut t = Tx::new(&v, &master).unwrap();
    assert!(t.group_remove(g, b).is_err(), "bob is not a member");
    t.group_add(g, b).unwrap();
    t.group_remove(g, b).unwrap();
    t.group_add(g, b).unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    assert!(v.state.stale_groups.is_empty());
    let (_, old_group) = old.groups.get(&g).unwrap();
    for gr in v
        .state
        .grants
        .values()
        .filter(|x| x.to == Principal::Group(g))
    {
        let aad = keyring::aad_grant(v.state.vault_id, gr.node, gr.to);
        assert!(crypto::unwrap(old_group, &gr.wrapped, &aad).is_err());
    }
}

/// Marks follow a folder moved out of a folder whose key is known to replaced keys, and
/// pending rekeys of a group follow its members when one is removed.
#[test]
fn stale_and_pending_marks_survive_moves_and_group_changes() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let bob = Unlocked::generate("bob", IdentityKind::Local);
    let it = Unlocked::generate("it", IdentityKind::Local);
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&bob, None)).unwrap();
    t.user_add(&Request::new(&it, None)).unwrap();
    let b = t.user_named("bob").unwrap();
    let i = t.user_named("it").unwrap();
    t.mkdir("/team/sub", true).unwrap();
    t.mkdir("/other", false).unwrap();
    t.mkdir("/n", false).unwrap();
    t.grant(Principal::User(b), Right::Read, "/team").unwrap();
    let g = t.group_create("devs").unwrap();
    t.group_add(g, b).unwrap();
    t.grant(Principal::Group(g), Right::Read, "/n").unwrap();
    t.sysgrant(i, SysRight::Users, false).unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    // The group loses /n without a rekey: pending under the group.
    let mut t = Tx::new(&v, &master).unwrap();
    t.revoke(Principal::Group(g), "/n", true).unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    // `it` replaces bob (no rights to rekey anything).
    let mut t = Tx::new(&v, &it).unwrap();
    t.user_replace(
        b,
        &Request::new(&Unlocked::generate("bob", IdentityKind::Local), None),
    )
    .unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    // The master moves a folder out of /team and gives the group /n back.
    let mut t = Tx::new(&v, &master).unwrap();
    t.mv("/team/sub", "/other/sub").unwrap();
    t.grant(Principal::Group(g), Right::Read, "/n").unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    let macc = Access::build(&v.state, v.state.master, &master);
    let (sub, n) = (
        macc.resolve("/other/sub").unwrap(),
        macc.resolve("/n").unwrap(),
    );
    assert!(
        v.state.stale_keys.contains_key(&sub),
        "moved folder lost its mark"
    );
    assert!(
        v.state.stale_keys.contains_key(&n),
        "group's pending rekey was lost"
    );
    // A rekey clears the moved folder; /n waits for the group's new key.
    let mut t = Tx::new(&v, &master).unwrap();
    t.rekey_pending().unwrap();
    let (_, v, _, _) = t.commit().unwrap();
    assert!(!v.state.stale_keys.contains_key(&sub));
    assert_eq!(v.state.stale_keys.get(&n), Some(&[g].into()));
    let mut t = Tx::new(&v, &master).unwrap();
    t.group_add(g, b).unwrap();
    t.group_remove(g, b).unwrap();
    t.group_add(g, b).unwrap();
    // `group remove` also rekeys what the group reads.
    let (_, v, _, _) = t.commit().unwrap();
    assert!(v.state.stale_keys.is_empty() && v.state.rekey_pending.is_empty());
    assert!(v.state.stale_groups.is_empty());
}

/// "Removing" a member while keeping the group key does not count as a new key.
#[test]
fn group_removal_must_change_the_key() {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let bob = Unlocked::generate("bob", IdentityKind::Local);
    let v = new_vault(&master);
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&bob, None)).unwrap();
    let b = t.user_named("bob").unwrap();
    let g = t.group_create("devs").unwrap();
    t.group_add(g, b).unwrap();
    let (mut f, v, _, _) = t.commit().unwrap();
    let group = v.state.groups[&g].clone();
    let me = v.state.master;
    let members = group
        .members
        .iter()
        .filter(|(m, _)| **m != b)
        .map(|(m, w)| (*m, w.clone()))
        .collect();
    sign_commit(
        &mut f,
        &master,
        me,
        v.seq + 1,
        vec![Op::RemoveMember {
            group: g,
            user: b,
            kem: group.kem.clone(),
            members,
            grants: vec![],
        }],
    );
    assert_eq!(
        verify_file(f, &master.fingerprint()).unwrap_err().code,
        Code::UnauthorizedOperation
    );
}
