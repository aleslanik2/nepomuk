//! A user with limited rights writes their own client (§2): every forged operation must be
//! rejected by `verify_file`, whatever the CLI would have allowed.

use nepomuk::crypto;
use nepomuk::error::Code;
use nepomuk::format::{CommitBody, Envelope, RawEntry, VaultFile, to_cbor};
use nepomuk::identity::{Request, Unlocked};
use nepomuk::keyring::{self, Access};
use nepomuk::model::*;
use nepomuk::tx::{self, Tx};
use nepomuk::verify::{Verified, verify_file};

struct World {
    master: Unlocked,
    eve: Unlocked,
    file: VaultFile,
    fp: String,
}

fn setup() -> World {
    let master = Unlocked::generate("master", IdentityKind::Local);
    let eve = Unlocked::generate("eve", IdentityKind::Local);
    let file = tx::genesis(&master).unwrap();
    let fp = master.fingerprint();
    let v = verify_file(file, &fp).unwrap();
    let mut t = Tx::new(&v, &master).unwrap();
    t.user_add(&Request::new(&eve, None)).unwrap();
    t.mkdir("/public", false).unwrap();
    t.mkdir("/secret", false).unwrap();
    t.put(
        "/secret/key",
        Content::Text {
            value: "top".into(),
        },
        None,
    )
    .unwrap();
    t.put(
        "/public/doc",
        Content::Text {
            value: "hello".into(),
        },
        None,
    )
    .unwrap();
    let eve_id = t.user_named("eve").unwrap();
    t.grant(Principal::User(eve_id), Right::Read, "/public")
        .unwrap();
    let (file, _, _, _) = t.commit().unwrap();
    World {
        master,
        eve,
        file,
        fp,
    }
}

fn verified(w: &World) -> Verified {
    verify_file(w.file.clone(), &w.fp).unwrap()
}

/// Appends a commit signed by `signer`, claiming `author`, without any client-side checks.
fn forge(w: &World, signer: &Unlocked, author: Id, ops: Vec<Op>) -> VaultFile {
    let v = verified(w);
    let body = to_cbor(&CommitBody {
        vault_id: v.file.vault_id,
        seq: v.seq + 1,
        prev_hash: v.file.entries.last().unwrap().hash(),
        author,
        time: tx::now(),
        ops,
    });
    let sig = signer.sig.sign("commit", &body);
    let mut f = v.file.clone();
    f.entries
        .push(RawEntry::from_envelope(Envelope { body, sig }));
    f
}

fn eve_id(v: &Verified) -> Id {
    v.state.user_by_name("eve").unwrap().id
}

fn rejected(w: &World, file: VaultFile, code: Code) {
    match verify_file(file, &w.fp) {
        Ok(_) => panic!("forged file was accepted"),
        Err(e) => assert_eq!(e.code, code, "{}", e.message),
    }
}

fn node_by_path(w: &World, who: &Unlocked, path: &str) -> (Id, Access) {
    let v = verified(w);
    let me = tx::find_me(&v.state, who).unwrap();
    let acc = Access::build(&v.state, me, who);
    (acc.resolve(path).unwrap(), acc)
}

#[test]
fn honest_file_verifies() {
    let w = setup();
    let v = verified(&w);
    assert_eq!(v.seq, 1);
    // Eve sees only /public.
    let acc = Access::build(&v.state, eve_id(&v), &w.eve);
    assert!(acc.resolve("/public/doc").is_some());
    assert!(acc.resolve("/secret/key").is_none());
}

#[test]
fn reader_cannot_modify_content() {
    let w = setup();
    let v = verified(&w);
    let (doc, acc) = node_by_path(&w, &w.eve, "/public/doc");
    let nk = acc.key(doc).unwrap().clone();
    let c = NodeContent {
        content: Content::Text {
            value: "evil".into(),
        },
        meta: Meta::default(),
    };
    let content = keyring::seal_content(v.state.vault_id, doc, &nk, &c);
    let f = forge(
        &w,
        &w.eve,
        eve_id(&v),
        vec![Op::UpdateNode { id: doc, content }],
    );
    rejected(&w, f, Code::UnauthorizedOperation);
}

#[test]
fn reader_cannot_escalate() {
    let w = setup();
    let v = verified(&w);
    let (public, acc) = node_by_path(&w, &w.eve, "/public");
    let nk = acc.key(public).unwrap().clone();
    let g = keyring::make_grant(
        &v.state,
        Id::random(),
        public,
        Principal::User(eve_id(&v)),
        Right::Admin,
        &nk,
        &acc.proof(public).unwrap(),
    )
    .unwrap();
    rejected(
        &w,
        forge(&w, &w.eve, eve_id(&v), vec![Op::Grant { grant: g }]),
        Code::UnauthorizedOperation,
    );
    let f = forge(
        &w,
        &w.eve,
        eve_id(&v),
        vec![Op::GrantSystemRight {
            user: eve_id(&v),
            right: SysRight::Users,
            delegate: true,
        }],
    );
    rejected(&w, f, Code::UnauthorizedOperation);
    let f = forge(
        &w,
        &w.eve,
        eve_id(&v),
        vec![Op::TransferMaster { user: eve_id(&v) }],
    );
    rejected(&w, f, Code::UnauthorizedOperation);
}

#[test]
fn reader_cannot_delete_or_revoke() {
    let w = setup();
    let v = verified(&w);
    let (doc, _) = node_by_path(&w, &w.eve, "/public/doc");
    rejected(
        &w,
        forge(&w, &w.eve, eve_id(&v), vec![Op::DeleteNode { id: doc }]),
        Code::UnauthorizedOperation,
    );
    let master_grant = v
        .state
        .grants
        .values()
        .find(|g| g.node == v.state.root)
        .unwrap()
        .id;
    rejected(
        &w,
        forge(
            &w,
            &w.eve,
            eve_id(&v),
            vec![Op::Revoke {
                grant: master_grant,
            }],
        ),
        Code::UnauthorizedOperation,
    );
    rejected(
        &w,
        forge(
            &w,
            &w.eve,
            eve_id(&v),
            vec![Op::DisableUser {
                user: v.state.master,
            }],
        ),
        Code::UnauthorizedOperation,
    );
}

#[test]
fn cannot_add_users_or_groups_without_rights() {
    let w = setup();
    let v = verified(&w);
    let mallory = Unlocked::generate("mallory", IdentityKind::Local);
    let user = User {
        id: Id::random(),
        name: "mallory".into(),
        kind: IdentityKind::Local,
        kem: mallory.kem.public().clone(),
        sig: mallory.sig.public().clone(),
        credential: None,
        proof: mallory.proof(IdentityKind::Local, None),
        disabled: false,
    };
    rejected(
        &w,
        forge(&w, &w.eve, eve_id(&v), vec![Op::AddUser { user }]),
        Code::UnauthorizedOperation,
    );
    let seed = [1u8; 64];
    let kem = crypto::KemSecret::from_seed(&seed, "group");
    let group = Group {
        id: Id::random(),
        name: "g".into(),
        kem: kem.public().clone(),
        members: Default::default(),
    };
    rejected(
        &w,
        forge(&w, &w.eve, eve_id(&v), vec![Op::CreateGroup { group }]),
        Code::UnauthorizedOperation,
    );
}

#[test]
fn cannot_create_nodes_under_foreign_folders() {
    let w = setup();
    let v = verified(&w);
    let secret = v
        .state
        .nodes
        .values()
        .find(|n| n.parent == Some(v.state.root) && n.id != node_by_path(&w, &w.eve, "/public").0)
        .unwrap()
        .id;
    let nk = crypto::random_key();
    let id = Id::random();
    let name = keyring::seal_name(v.state.vault_id, id, &nk, "planted");
    let node = Node {
        id,
        parent: Some(secret),
        wrapped_key: Some(crypto::seal(&[0u8; 32], nk.as_ref(), b"")),
        name: name.sealed,
        name_commit: name.commit,
        content: keyring::seal_content(
            v.state.vault_id,
            id,
            &nk,
            &NodeContent {
                content: Content::Folder,
                meta: Meta::default(),
            },
        ),
    };
    rejected(
        &w,
        forge(&w, &w.eve, eve_id(&v), vec![Op::CreateNode { node }]),
        Code::UnauthorizedOperation,
    );
}

#[test]
fn impersonation_and_bad_signatures() {
    let w = setup();
    let v = verified(&w);
    // Eve signs but claims to be the master.
    let f = forge(
        &w,
        &w.eve,
        v.state.master,
        vec![Op::MarkRotation { node: v.state.root }],
    );
    rejected(&w, f, Code::SignatureInvalid);
    // An unknown key.
    let x = Unlocked::generate("x", IdentityKind::Local);
    let f = forge(&w, &x, Id::random(), vec![]);
    rejected(&w, f, Code::UnauthorizedOperation);
    // A valid master commit whose operations are altered after signing.
    let mut f = forge(
        &w,
        &w.master,
        v.state.master,
        vec![Op::MarkRotation { node: v.state.root }],
    );
    let last = f.entries.last_mut().unwrap();
    let mut env = last.envelope.clone();
    let n = env.body.len();
    env.body[n - 3] ^= 1;
    *last = RawEntry::from_envelope(env);
    assert!(verify_file(f, &w.fp).is_err());
}

#[test]
fn broken_chain_and_transplanted_commits() {
    let w = setup();
    let v = verified(&w);
    // Dropping a commit in the middle breaks the hash chain.
    let f1 = forge(
        &w,
        &w.master,
        v.state.master,
        vec![Op::MarkRotation { node: v.state.root }],
    );
    let w2 = World {
        master: Unlocked::from_seed(
            nepomuk::memory::LockedSeed::from_slice(w.master.seed.as_ref()).unwrap(),
            "master",
            IdentityKind::Local,
        ),
        eve: Unlocked::generate("e", IdentityKind::Local),
        file: f1.clone(),
        fp: w.fp.clone(),
    };
    let v2 = verified(&w2);
    let f2 = forge(
        &w2,
        &w.master,
        v2.state.master,
        vec![Op::ClearRotation {
            node: v2.state.root,
        }],
    );
    let mut gap = f2.clone();
    gap.entries.remove(gap.entries.len() - 2);
    rejected(&w, gap, Code::SignatureInvalid);

    // A commit from another vault cannot be transplanted.
    let other = setup();
    let ov = verified(&other);
    let foreign = forge(&other, &other.master, ov.state.master, vec![]);
    let mut f = w.file.clone();
    f.entries.push(foreign.entries.last().unwrap().clone());
    assert!(verify_file(f, &w.fp).is_err());
}

#[test]
fn disabled_user_cannot_sign() {
    let w = setup();
    let v = verified(&w);
    let mut t = Tx::new(&v, &w.master).unwrap();
    let eve = t.user_named("eve").unwrap();
    t.user_disable(eve).unwrap();
    let (file, _, _, _) = t.commit().unwrap();
    let w2 = World { file, ..w };
    let v2 = verified(&w2);
    let (public, _) = (v2.state.nodes.keys().next().copied().unwrap(), ());
    let f = forge(&w2, &w2.eve, eve, vec![Op::MarkRotation { node: public }]);
    rejected(&w2, f, Code::UnauthorizedOperation);
}

#[test]
fn grants_bind_to_vault_node_and_recipient() {
    let w = setup();
    let v = verified(&w);
    // Move Eve's grant onto /secret: the AAD no longer matches, nothing decrypts.
    let mut state = v.state.clone();
    let secret = Access::build(&v.state, v.state.master, &w.master)
        .resolve("/secret")
        .unwrap();
    for g in state.grants.values_mut() {
        if g.to == Principal::User(eve_id(&v)) {
            g.node = secret;
        }
    }
    let acc = Access::build(&state, eve_id(&v), &w.eve);
    assert!(acc.nodes.is_empty());
}

#[test]
fn revoked_reader_keeps_only_old_keys() {
    let w = setup();
    let v = verified(&w);
    let (doc, acc) = node_by_path(&w, &w.eve, "/public/doc");
    let old_key = acc.key(doc).unwrap().clone();
    let mut t = Tx::new(&v, &w.master).unwrap();
    let eve = t.user_named("eve").unwrap();
    t.revoke(Principal::User(eve), "/public", false).unwrap();
    t.put(
        "/public/doc",
        Content::Text {
            value: "new secret".into(),
        },
        None,
    )
    .unwrap();
    let (file, v2, _, _) = t.commit().unwrap();
    let _ = file;
    // The old node key does not open the new content.
    let n = &v2.state.nodes[&doc];
    assert!(
        crypto::open_padded(
            &keyring::blob_key(&old_key),
            &n.content,
            &keyring::aad_content(v2.state.vault_id, doc)
        )
        .is_err()
    );
    assert!(Access::build(&v2.state, eve, &w.eve).nodes.is_empty());
}
