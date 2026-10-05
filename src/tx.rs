//! Building signed commits (§8): every high-level action becomes one or more operations that
//! are checked against the working state exactly as every other client will check them.

use std::collections::{BTreeMap, BTreeSet};

use crate::crypto::{self, KemSecret, Key32};
use crate::error::{Code, Error, Result};
use crate::format::{CheckpointBody, CommitBody, Envelope, RawEntry, VaultFile, to_cbor};
use crate::identity::{Keys, Request, Unlocked};
use crate::keyring::{self, Access};
use crate::memory::LockedSeed;
use crate::model::*;
use crate::verify::{Verified, apply_op, verify_file_with};

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

// ---------------------------------------------------------------- Paths

pub fn normalize_path(p: &str) -> Result<String> {
    if !p.starts_with('/') {
        return Err(Error::usage(format!("path must be absolute: {p}")));
    }
    let parts: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    for part in &parts {
        validate_name(part)?;
    }
    Ok(if parts.is_empty() {
        "/".into()
    } else {
        format!("/{}", parts.join("/"))
    })
}

/// Characters that change how text around them is shown: control characters, and the
/// invisible and bidirectional formatting characters that can make one name look like another.
pub fn is_deceptive(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '#'])
        || name.chars().any(is_deceptive)
    {
        return Err(Error::usage(format!("invalid name: {name:?}")));
    }
    if name.len() > 255 {
        return Err(Error::usage("name too long"));
    }
    Ok(())
}

pub const MAX_DESCRIPTION: usize = 2000;

/// Trims a description; an empty one means none.
pub fn normalize_description(d: Option<&str>) -> Result<Option<String>> {
    let Some(d) = d.map(str::trim).filter(|d| !d.is_empty()) else {
        return Ok(None);
    };
    if d.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err(Error::usage("invalid description: control characters"));
    }
    if d.chars().count() > MAX_DESCRIPTION {
        return Err(Error::usage(format!(
            "description too long (at most {MAX_DESCRIPTION} characters)"
        )));
    }
    Ok(Some(d.to_string()))
}

pub fn split_parent(path: &str) -> Result<(String, String)> {
    let path = normalize_path(path)?;
    if path == "/" {
        return Err(Error::usage("the root folder has no parent"));
    }
    let idx = path.rfind('/').unwrap();
    let parent = if idx == 0 {
        "/".to_string()
    } else {
        path[..idx].to_string()
    };
    Ok((parent, path[idx + 1..].to_string()))
}

/// Names are encrypted: "not found" can only be told apart from "no access" when the reader can
/// see an existing ancestor folder.
pub fn missing(acc: &Access, path: &str) -> Error {
    if acc.ambiguous(path) {
        return Error::new(
            Code::Conflict,
            format!("ambiguous path: more than one item is named {path}"),
        )
        .with("path", path.to_string());
    }
    let mut p = path.to_string();
    while let Ok((parent, _)) = split_parent(&p) {
        if acc.resolve(&parent).is_some() {
            return Error::not_found(path);
        }
        p = parent;
    }
    Error::access_denied(path)
}

// ---------------------------------------------------------------- Genesis

/// Creates a new vault: checkpoint 0 with the master user, the root folder and the master's
/// grant on the root, signed by the master.
pub fn genesis(master: &Unlocked) -> Result<VaultFile> {
    let vault_id = Id::random();
    let master_id = Id::random();
    let root = Id::random();
    let nk = crypto::random_key();
    let user = User {
        id: master_id,
        name: master.name.clone(),
        kind: IdentityKind::Local,
        kem: master.kem.public().clone(),
        sig: master.sig.public().clone(),
        credential: None,
        proof: master.proof(IdentityKind::Local, None),
        disabled: false,
    };
    let content = NodeContent {
        content: Content::Folder,
        meta: Meta {
            created: now(),
            updated: now(),
            not_after: None,
            description: None,
        },
    };
    let name = keyring::seal_name(vault_id, root, &nk, "");
    let node = Node {
        id: root,
        parent: None,
        wrapped_key: None,
        name: name.sealed,
        name_commit: name.commit,
        content: keyring::seal_content(vault_id, root, &nk, &content),
    };
    let mut state = State {
        vault_id,
        master: master_id,
        root,
        ..Default::default()
    };
    state.users.insert(master_id, user);
    state.nodes.insert(root, node);
    let grant = keyring::make_grant(
        &state,
        Id::random(),
        root,
        Principal::User(master_id),
        Right::Admin,
        &nk,
        &keyring::PathProof::root(),
    )?;
    state.grants.insert(grant.id, grant);
    let body = to_cbor(&CheckpointBody {
        vault_id,
        seq: 0,
        folded_head: None,
        time: now(),
        state,
    });
    let sig = master.sig.sign("checkpoint", &body);
    Ok(VaultFile {
        vault_id,
        entries: vec![RawEntry::from_envelope(Envelope { body, sig })],
    })
}

/// Folds the log into a new checkpoint signed by the master (§7.3).
pub fn compact(v: &Verified, master: &Unlocked) -> Result<VaultFile> {
    if !master.matches(&v.state.users[&v.state.master]) {
        return Err(Error::unauthorized("only the master can compact the vault"));
    }
    let body = to_cbor(&CheckpointBody {
        vault_id: v.file.vault_id,
        seq: v.seq,
        folded_head: Some(v.head),
        time: now(),
        state: v.state.clone(),
    });
    let sig = master.sig.sign("checkpoint", &body);
    Ok(VaultFile {
        vault_id: v.file.vault_id,
        entries: vec![RawEntry::from_envelope(Envelope { body, sig })],
    })
}

// ---------------------------------------------------------------- Transactions

pub struct Tx<'a> {
    pub base: &'a Verified,
    pub state: State,
    pub me: Id,
    pub id: &'a dyn Keys,
    pub ops: Vec<Op>,
    access: Option<Access>,
    pub warnings: Vec<String>,
    /// Work the author could not do (missing keys or rights), for other admins.
    pub tasks: Vec<String>,
}

/// Finds the vault user matching an unlocked identity.
pub fn find_me(state: &State, id: &dyn Keys) -> Result<Id> {
    let u = state
        .users
        .values()
        .find(|u| id.matches(u))
        .ok_or_else(|| {
            Error::new(
                Code::AccessDenied,
                "this identity is not a user of the vault",
            )
        })?;
    if u.disabled {
        return Err(Error::new(
            Code::IdentityDisabled,
            "this identity has been disabled",
        ));
    }
    Ok(u.id)
}

impl<'a> Tx<'a> {
    pub fn new(base: &'a Verified, id: &'a dyn Keys) -> Result<Tx<'a>> {
        let me = find_me(&base.state, id)?;
        Ok(Tx {
            base,
            state: base.state.clone(),
            me,
            id,
            ops: Vec::new(),
            access: None,
            warnings: Vec::new(),
            tasks: Vec::new(),
        })
    }

    pub fn access(&mut self) -> &Access {
        if self.access.is_none() {
            self.access = Some(Access::build(&self.state, self.me, self.id));
        }
        self.access.as_ref().unwrap()
    }

    pub fn push(&mut self, op: Op) -> Result<()> {
        apply_op(&mut self.state, self.me, &op).map_err(|e| match e.code {
            Code::UnauthorizedOperation => Error::new(Code::AccessDenied, e.message),
            _ => e,
        })?;
        self.ops.push(op);
        self.access = None;
        Ok(())
    }

    fn vault(&self) -> Id {
        self.state.vault_id
    }

    /// Signs the operations and returns the new file (verified end to end).
    pub fn commit(self) -> Result<(VaultFile, Verified, Vec<String>, Vec<String>)> {
        if self.ops.is_empty() {
            return Err(Error::general("nothing to commit"));
        }
        let body = to_cbor(&CommitBody {
            vault_id: self.vault(),
            seq: self.base.seq + 1,
            prev_hash: self.base.file.entries.last().unwrap().hash(),
            author: self.me,
            time: now(),
            ops: self.ops,
        });
        let sig = self.id.sign("commit", &body)?;
        let mut file = self.base.file.clone();
        file.entries
            .push(RawEntry::from_envelope(Envelope { body, sig }));
        // The base was verified against the pin; the new file must verify from the same root.
        let master_fp = crate::verify::user_fp(&self.state.users[&self.state.master]);
        let signer: Vec<String> = crate::verify::checkpoint_master_fp(&file)
            .into_iter()
            .collect();
        let verified = verify_file_with(file.clone(), &master_fp, &signer)?;
        Ok((file, verified, self.warnings, self.tasks))
    }

    // ------------------------------------------------------------ Lookups

    pub fn resolve(&mut self, path: &str) -> Result<Id> {
        let path = normalize_path(path)?;
        let acc = self.access();
        acc.resolve(&path).ok_or_else(|| missing(acc, &path))
    }

    fn key(&mut self, node: Id) -> Result<Key32> {
        let path = node.hex();
        self.access()
            .key(node)
            .cloned()
            .ok_or_else(|| Error::access_denied(&path))
    }

    fn proof(&mut self, node: Id) -> Result<keyring::PathProof> {
        let path = node.hex();
        self.access()
            .proof(node)
            .ok_or_else(|| Error::access_denied(&path))
    }

    fn path_of(&mut self, node: Id) -> String {
        self.access()
            .path(node)
            .map(str::to_string)
            .unwrap_or_else(|| format!("<{}>", node.short()))
    }

    pub fn is_folder(&mut self, node: Id) -> Result<bool> {
        let acc = Access::build(&self.state, self.me, self.id);
        Ok(matches!(
            acc.content(&self.state, node)?.content,
            Content::Folder
        ))
    }

    pub fn user_named(&self, name: &str) -> Result<Id> {
        self.state
            .user_by_name(name)
            .map(|u| u.id)
            .ok_or_else(|| Error::not_found(&format!("user {name}")))
    }

    pub fn group_named(&self, name: &str) -> Result<Id> {
        self.state
            .group_by_name(name)
            .map(|g| g.id)
            .ok_or_else(|| Error::not_found(&format!("group {name}")))
    }

    pub fn principal(&self, who: &str) -> Result<Principal> {
        if let Some(g) = who.strip_prefix("group:") {
            Ok(Principal::Group(self.group_named(g)?))
        } else {
            let u = who.strip_prefix("user:").unwrap_or(who);
            Ok(Principal::User(self.user_named(u)?))
        }
    }

    pub fn principal_name(&self, p: Principal) -> String {
        principal_name(&self.state, p)
    }

    // ------------------------------------------------------------ Tree

    pub fn create_node(
        &mut self,
        parent: Id,
        name: &str,
        content: Content,
        not_after: Option<i64>,
        description: Option<String>,
    ) -> Result<Id> {
        validate_name(name)?;
        let parent_path = self.path_of(parent);
        if !self.is_folder(parent)? {
            return Err(Error::usage(format!("{parent_path} is not a folder")));
        }
        let target = keyring::join(&parent_path, name);
        if self.access().exists(&target) {
            return Err(
                Error::new(Code::AlreadyExists, format!("already exists: {target}"))
                    .with("path", target),
            );
        }
        let pk = self.key(parent)?;
        let id = Id::random();
        let nk = crypto::random_key();
        let vault = self.vault();
        let c = NodeContent {
            content,
            meta: Meta {
                created: now(),
                updated: now(),
                not_after,
                description,
            },
        };
        let sealed_name = keyring::seal_name(vault, id, &nk, name);
        let node = Node {
            id,
            parent: Some(parent),
            wrapped_key: Some(keyring::seal_node_key(vault, id, &pk, &nk)),
            name: sealed_name.sealed,
            name_commit: sealed_name.commit,
            content: keyring::seal_content(vault, id, &nk, &c),
        };
        self.push(Op::CreateNode { node })?;
        Ok(id)
    }

    pub fn mkdir(&mut self, path: &str, parents: bool) -> Result<Id> {
        self.mkdir_with(path, parents, None)
    }

    /// Creates a folder with a description; with `parents`, an existing folder gets it.
    pub fn mkdir_with(
        &mut self,
        path: &str,
        parents: bool,
        description: Option<&str>,
    ) -> Result<Id> {
        let path = normalize_path(path)?;
        let description = normalize_description(description)?;
        if let Some(id) = self.access().resolve(&path) {
            if parents && self.is_folder(id)? {
                if description.is_some() {
                    self.set_description(&path, description.as_deref())?;
                }
                return Ok(id);
            }
            return Err(
                Error::new(Code::AlreadyExists, format!("already exists: {path}"))
                    .with("path", path),
            );
        }
        let (parent, name) = split_parent(&path)?;
        let pid = match self.access().resolve(&parent) {
            Some(p) => p,
            None if parents => self.mkdir(&parent, true)?,
            None => return Err(missing(self.access(), &parent)),
        };
        self.create_node(pid, &name, Content::Folder, None, description)
    }

    /// Creates or replaces a secret.
    pub fn put(&mut self, path: &str, content: Content, not_after: Option<i64>) -> Result<Id> {
        self.put_with(path, content, not_after, None)
    }

    /// Creates or replaces a secret; `description: None` keeps the current one.
    pub fn put_with(
        &mut self,
        path: &str,
        content: Content,
        not_after: Option<i64>,
        description: Option<&str>,
    ) -> Result<Id> {
        let path = normalize_path(path)?;
        let new_description = match description {
            Some(d) => Some(normalize_description(Some(d))?),
            None => None,
        };
        if let Some(id) = self.access().resolve(&path) {
            let acc = Access::build(&self.state, self.me, self.id);
            let old = acc.content(&self.state, id)?;
            if matches!(old.content, Content::Folder) {
                return Err(Error::usage(format!("{path} is a folder")));
            }
            let c = NodeContent {
                content,
                meta: Meta {
                    created: old.meta.created,
                    updated: now(),
                    not_after,
                    description: new_description.unwrap_or_else(|| old.meta.description.clone()),
                },
            };
            let nk = self.key(id)?;
            let sealed = keyring::seal_content(self.vault(), id, &nk, &c);
            self.push(Op::UpdateNode {
                id,
                content: sealed,
            })?;
            return Ok(id);
        }
        let (parent, name) = split_parent(&path)?;
        let pid = self.resolve(&parent)?;
        self.create_node(pid, &name, content, not_after, new_description.flatten())
    }

    /// Sets or clears the description of a folder or secret (`write` on the node).
    pub fn set_description(&mut self, path: &str, description: Option<&str>) -> Result<()> {
        let path = normalize_path(path)?;
        let description = normalize_description(description)?;
        let id = self.resolve(&path)?;
        let acc = Access::build(&self.state, self.me, self.id);
        let old = acc.content(&self.state, id)?;
        if old.meta.description == description {
            return Ok(());
        }
        let c = NodeContent {
            content: old.content.clone(),
            meta: Meta {
                description,
                ..old.meta.clone()
            },
        };
        let nk = self.key(id)?;
        let sealed = keyring::seal_content(self.vault(), id, &nk, &c);
        self.push(Op::UpdateNode {
            id,
            content: sealed,
        })
    }

    pub fn rm(&mut self, path: &str) -> Result<()> {
        let id = self.resolve(path)?;
        if id == self.state.root {
            return Err(Error::usage("the root folder cannot be removed"));
        }
        self.push(Op::DeleteNode { id })
    }

    /// Removes a node by its id: the only way to delete a node whose name cannot be decrypted
    /// (or that shares its path with a sibling). The verifier still requires `write` on the
    /// parent.
    pub fn rm_node(&mut self, id: Id) -> Result<()> {
        if !self.state.nodes.contains_key(&id) {
            return Err(Error::not_found(&format!("node {}", id.hex())));
        }
        if id == self.state.root {
            return Err(Error::usage("the root folder cannot be removed"));
        }
        self.push(Op::DeleteNode { id })
    }

    /// Deletes what nobody holding the subtree's keys can open (§8.1).
    ///
    /// The author holds the key of `node`, and every honest client wraps a child's key under its
    /// parent's key and seals its name and content with it, so everything below `node` decrypts
    /// for the author. A node that does not was written by a broken or malicious client of
    /// someone with `write` there; left in place it would make every rekey of the subtree, and
    /// so revocation and offboarding, fail. Removing it takes nothing from anyone with legitimate
    /// access (it was never readable with the real keys) and is no more than its writer could do
    /// with `rm`; it stays in git history.
    ///
    /// - a node whose key or name does not open is removed with its subtree (nothing below it is
    ///   readable either);
    /// - a node that opens but whose content does not is removed if it has no children; one with
    ///   children is kept, and [`Tx::rekey`] seals it again as a folder.
    fn purge_unreadable(&mut self, node: Id) -> Result<()> {
        let acc = Access::build(&self.state, self.me, self.id);
        if !acc.nodes.contains_key(&node) {
            return Ok(());
        }
        let mut doomed: Vec<(Id, &'static str)> = Vec::new();
        for n in self.state.subtree(node) {
            if n == node {
                continue;
            }
            let parent = self.state.nodes[&n].parent;
            let parent_readable = parent.is_some_and(|p| acc.nodes.contains_key(&p));
            if !acc.nodes.contains_key(&n) {
                // Only the topmost unreadable node; deleting it removes everything below.
                if parent_readable {
                    doomed.push((n, "its key or name cannot be decrypted"));
                }
            } else if acc.content(&self.state, n).is_err() && self.state.children(n).is_empty() {
                doomed.push((n, "its content cannot be decrypted"));
            }
        }
        for (n, why) in doomed {
            let parent = self.state.nodes[&n].parent.expect("not the root");
            let at = acc.path(parent).unwrap_or("?").to_string();
            self.push(Op::DeleteNode { id: n })?;
            self.warnings.push(format!(
                "removed node {} in {at}: {why} with the folder's key (written by a broken or malicious client; still in git history)",
                n.hex()
            ));
        }
        Ok(())
    }

    /// Re-wraps all grants in a subtree after its paths changed.
    fn rewrapped_grants(
        &mut self,
        sub: &[Id],
        proofs: &BTreeMap<Id, keyring::PathProof>,
    ) -> Result<Vec<Grant>> {
        let grants: Vec<Grant> = self.state.grants_on(sub).into_iter().cloned().collect();
        let mut out = Vec::new();
        for g in grants {
            let Some(proof) = proofs.get(&g.node).cloned() else {
                continue;
            };
            let nk = self.key(g.node)?;
            out.push(keyring::make_grant(
                &self.state,
                g.id,
                g.node,
                g.to,
                g.right,
                &nk,
                &proof,
            )?);
        }
        Ok(out)
    }

    pub fn mv(&mut self, src: &str, dst: &str) -> Result<()> {
        let id = self.resolve(src)?;
        if id == self.state.root {
            return Err(Error::usage("the root folder cannot be moved"));
        }
        let dst = normalize_path(dst)?;
        let dst = match self.access().resolve(&dst) {
            Some(d) if self.is_folder(d)? => {
                keyring::join(&dst, &self.access().nodes[&id].name.clone())
            }
            Some(_) => {
                return Err(Error::new(
                    Code::AlreadyExists,
                    format!("already exists: {dst}"),
                ));
            }
            None => dst,
        };
        if self.access().exists(&dst) {
            return Err(Error::new(
                Code::AlreadyExists,
                format!("already exists: {dst}"),
            ));
        }
        let (parent, name) = split_parent(&dst)?;
        validate_name(&name)?;
        let pid = self.resolve(&parent)?;
        if !self.is_folder(pid)? {
            return Err(Error::usage(format!("{parent} is not a folder")));
        }
        let old_path = self.path_of(id);
        let old = self.proof(id)?;
        let nk = self.key(id)?;
        // The node's proven path at its destination; the subtree keeps its salts below it.
        let moved = self.proof(pid)?.child(&name, keyring::name_salt(&nk));
        let sub = self.state.subtree(id);
        // New proofs for the nodes that carry grants: the moved node's new location followed by
        // the unchanged levels below it. Other nodes need none, so a node in the subtree this
        // author cannot read does not block the move.
        let granted: BTreeSet<Id> = self.state.grants_on(&sub).iter().map(|g| g.node).collect();
        let mut proofs = BTreeMap::new();
        for n in granted {
            let Some(p) = self.access().proof(n) else {
                // A grant on a node this author cannot read (e.g. one whose name commitment
                // does not match) cannot be re-issued; its holder will see it as unproven.
                let what = self.path_of(n);
                self.tasks.push(format!(
                    "re-issue the grants on {what} (node {}) after the move – this author cannot read it",
                    n.hex()
                ));
                continue;
            };
            let depth = old.salts.len();
            let comps = keyring::components(&p.path);
            if p.salts.len() < depth || comps.len() != p.salts.len() {
                return Err(Error::access_denied(&p.path));
            }
            let mut np = moved.clone();
            for (c, salt) in comps[depth..].iter().zip(&p.salts[depth..]) {
                np = np.child(c, *salt);
            }
            proofs.insert(n, np);
        }
        let grants = self.rewrapped_grants(&sub, &proofs)?;
        let vault = self.vault();
        let sealed_name = keyring::seal_name(vault, id, &nk, &name);
        if Some(pid) == self.state.nodes[&id].parent {
            self.push(Op::RenameNode {
                id,
                name: sealed_name.sealed,
                name_commit: sealed_name.commit,
                grants,
            })
        } else {
            let pk = self.key(pid)?;
            let wrapped_key = keyring::seal_node_key(vault, id, &pk, &nk);
            self.push(Op::MoveNode {
                id,
                parent: pid,
                wrapped_key,
                name: sealed_name.sealed,
                name_commit: sealed_name.commit,
                grants,
            })?;
            if self.state.rekey_pending.contains_key(&id) || self.state.stale_keys.contains_key(&id)
            {
                self.warnings.push(format!(
                    "{old_path} moved: whoever could read the old location but not the new one still holds its key; it waits for `nepomuk rekey --pending`"
                ));
            }
            Ok(())
        }
    }

    // ------------------------------------------------------------ Rekey

    /// Whether the author may rekey the node (admin on the parent, or master for the root).
    pub fn can_rekey(&mut self, node: Id) -> bool {
        match self.state.nodes.get(&node).and_then(|n| n.parent) {
            None => self.state.is_master(self.me),
            Some(p) => {
                self.state.has_right(self.me, p, Right::Admin) && self.access().key(p).is_some()
            }
        }
    }

    /// New node keys for the whole subtree, re-encrypted content, re-issued grants (§8.1).
    pub fn rekey(&mut self, node: Id) -> Result<()> {
        self.purge_unreadable(node)?;
        let sub = self.state.subtree(node);
        let vault = self.vault();
        let acc = Access::build(&self.state, self.me, self.id);
        let mut new_keys: BTreeMap<Id, Key32> = BTreeMap::new();
        let mut nodes = Vec::new();
        for n in &sub {
            let v = acc
                .nodes
                .get(n)
                .ok_or_else(|| Error::access_denied(acc.path(node).unwrap_or("?")))?;
            let content = match acc.content(&self.state, *n) {
                Ok(c) => c,
                // Left by `purge_unreadable` only when it has children: keep them reachable.
                Err(_) if *n != node && !self.state.children(*n).is_empty() => {
                    self.warnings.push(format!(
                        "{}: its content could not be decrypted; sealed again as an empty folder",
                        v.path
                    ));
                    NodeContent {
                        content: Content::Folder,
                        meta: Meta {
                            created: now(),
                            updated: now(),
                            not_after: None,
                            description: None,
                        },
                    }
                }
                Err(e) => return Err(e),
            };
            let nk = crypto::random_key();
            let parent = self.state.nodes[n].parent;
            let wrapped_key = match parent {
                None => None,
                Some(p) => {
                    let pk = new_keys
                        .get(&p)
                        .or_else(|| acc.key(p))
                        .ok_or_else(|| Error::access_denied(&v.path))?;
                    Some(keyring::seal_node_key(vault, *n, pk, &nk))
                }
            };
            let name = keyring::seal_name(vault, *n, &nk, &v.name);
            nodes.push(RekeyedNode {
                id: *n,
                wrapped_key,
                name: name.sealed,
                name_commit: name.commit,
                content: keyring::seal_content(vault, *n, &nk, &content),
            });
            new_keys.insert(*n, nk);
        }
        // New node keys mean new name salts for the whole subtree; the levels above keep theirs.
        let top = acc
            .proof(node)
            .ok_or_else(|| Error::access_denied(acc.path(node).unwrap_or("?")))?;
        let above = top.salts.len().saturating_sub(1);
        // Grants of disabled users are dropped: the new keys are not wrapped for them.
        let old: Vec<Grant> = self
            .state
            .grants_on(&sub)
            .into_iter()
            .filter(|g| match g.to {
                Principal::User(u) => self.state.active(u),
                Principal::Group(_) => true,
            })
            .cloned()
            .collect();
        let mut grants = Vec::new();
        for g in old {
            let p = acc
                .proof(g.node)
                .ok_or_else(|| Error::access_denied(&g.node.hex()))?;
            let mut salts = p.salts[..above].to_vec();
            if node != self.state.root {
                let mut chain: Vec<Id> = self
                    .state
                    .ancestors(g.node)
                    .into_iter()
                    .take_while(|x| *x != node)
                    .collect();
                chain.push(node);
                chain.reverse();
                salts.extend(chain.iter().map(|x| keyring::name_salt(&new_keys[x])));
            } else {
                let mut chain = self.state.ancestors(g.node);
                chain.pop(); // the root has no path component
                chain.reverse();
                salts.extend(chain.iter().map(|x| keyring::name_salt(&new_keys[x])));
            }
            grants.push(keyring::make_grant(
                &self.state,
                g.id,
                g.node,
                g.to,
                g.right,
                &new_keys[&g.node],
                &keyring::PathProof {
                    path: p.path,
                    salts,
                },
            )?);
        }
        self.push(Op::Rekey {
            node,
            nodes,
            grants,
        })
    }

    /// Rekeys each node (outermost first) or records a task when the author cannot.
    pub fn rekey_all(&mut self, nodes: BTreeSet<Id>) -> Result<()> {
        let mut todo: Vec<Id> = nodes
            .into_iter()
            .filter(|n| self.state.nodes.contains_key(n))
            .collect();
        todo.sort_by_key(|n| self.state.ancestors(*n).len());
        let mut done: Vec<Id> = Vec::new();
        for n in todo {
            if done.iter().any(|d| self.state.subtree(*d).contains(&n)) {
                continue;
            }
            if self.can_rekey(n) {
                // A rekey that cannot be built must not take the rest of the commit (the
                // revocation, the disabled user) down with it: undo it and leave a task.
                let (state, ops) = (self.state.clone(), self.ops.len());
                let warnings = self.warnings.len();
                match self.rekey(n) {
                    Ok(()) => done.push(n),
                    Err(e) if e.code == Code::AccessDenied => {
                        self.state = state;
                        self.ops.truncate(ops);
                        self.warnings.truncate(warnings);
                        self.access = None;
                        let p = self.path_of(n);
                        self.warnings.push(format!(
                            "{p} was not rekeyed ({}); whoever could read it still can",
                            e.message
                        ));
                        self.tasks.push(format!("rekey {p} (node {})", n.hex()));
                    }
                    Err(e) => return Err(e),
                }
            } else {
                let p = self.path_of(n);
                self.tasks.push(format!(
                    "rekey {p} (node {}) – requires admin on its parent",
                    n.hex()
                ));
                self.warnings.push(format!(
                    "{p} is not rekeyed: whoever lost access can still decrypt new content there until an admin of its parent folder runs `nepomuk rekey --pending` (the vault keeps the request)"
                ));
            }
        }
        Ok(())
    }

    /// Rekeys the nodes waiting for it (§8.1) that the author may rekey; returns their paths.
    pub fn rekey_pending(&mut self) -> Result<Vec<String>> {
        // A node read only by a stale group waits for the group's new key, not for a rekey.
        let waiting = |s: &State| -> BTreeSet<Id> {
            s.rekey_pending
                .keys()
                .chain(
                    s.stale_keys
                        .iter()
                        .filter(|(_, why)| why.iter().any(|r| !s.stale_groups.contains(r)))
                        .map(|(n, _)| n),
                )
                .copied()
                .collect()
        };
        let pending = waiting(&self.state);
        if pending.is_empty() {
            return Err(Error::not_found("pending rekeys"));
        }
        let before = pending.len();
        let paths: BTreeMap<Id, String> = pending.iter().map(|n| (*n, self.path_of(*n))).collect();
        self.rekey_all(pending)?;
        let left = waiting(&self.state);
        let done: Vec<String> = paths
            .into_iter()
            .filter(|(n, _)| !left.contains(n))
            .map(|(_, p)| p)
            .collect();
        if left.len() == before {
            return Err(Error::access_denied("pending rekeys").with(
                "reason",
                "none of the pending rekeys can be done by you: they need admin on the parent folder",
            ));
        }
        // The tasks are kept in the vault; repeating them as warnings adds nothing.
        self.warnings.retain(|w| !w.contains("rekey --pending"));
        Ok(done)
    }

    /// Marks all secrets in the subtrees for rotation; returns their paths.
    pub fn mark_rotation(&mut self, roots: &BTreeSet<Id>) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        for r in roots {
            if !self.state.nodes.contains_key(r) {
                continue;
            }
            for n in self.state.subtree(*r) {
                if !seen.insert(n) {
                    continue;
                }
                let acc = Access::build(&self.state, self.me, self.id);
                let is_secret = match acc.content(&self.state, n) {
                    Ok(c) => !matches!(c.content, Content::Folder),
                    Err(_) => true,
                };
                if !is_secret {
                    continue;
                }
                let p = self.path_of(n);
                out.push(p.clone());
                if self.state.rotation.contains(&n) {
                    continue;
                }
                if self.state.has_right(self.me, n, Right::Write) {
                    self.push(Op::MarkRotation { node: n })?;
                } else {
                    self.tasks.push(format!("mark {p} for rotation"));
                }
            }
        }
        Ok(out)
    }

    // ------------------------------------------------------------ Rights

    pub fn grant(&mut self, to: Principal, right: Right, path: &str) -> Result<()> {
        let node = self.resolve(path)?;
        let proof = self.proof(node)?;
        if let Some(existing) = self
            .state
            .grants
            .values()
            .find(|g| g.node == node && g.to == to)
            .cloned()
        {
            if existing.right == right {
                return Err(Error::new(Code::AlreadyExists, "the grant already exists"));
            }
            // Changing the right: replace the grant.
            self.push(Op::Revoke { grant: existing.id })?;
        }
        let nk = self.key(node)?;
        let g = keyring::make_grant(&self.state, Id::random(), node, to, right, &nk, &proof)?;
        self.push(Op::Grant { grant: g })
    }

    /// Revokes a grant and, unless `no_rekey`, rekeys the subtree; returns secrets to rotate.
    pub fn revoke(&mut self, who: Principal, path: &str, no_rekey: bool) -> Result<Vec<String>> {
        let node = self.resolve(path)?;
        let g = self
            .state
            .grants
            .values()
            .find(|g| g.node == node && g.to == who)
            .cloned()
            .ok_or_else(|| {
                Error::not_found(&format!("grant for {} on {path}", self.principal_name(who)))
            })?;
        self.push(Op::Revoke { grant: g.id })?;
        // Rekey first: it removes nodes nobody can read, which are then not listed for rotation.
        if no_rekey {
            self.warnings.push(
                "revoked without rekey: the revoked party can still decrypt future content".into(),
            );
        } else {
            self.rekey_all(BTreeSet::from([node]))?;
        }
        let rotate = self.mark_rotation(&BTreeSet::from([node]))?;
        if let Principal::User(u) = who
            && let Some(r) = self.state.effective_right(u, node)
        {
            self.warnings.push(format!(
                "{} still has `{}` on {path} through another grant",
                self.principal_name(who),
                r.as_str()
            ));
        }
        Ok(rotate)
    }

    pub fn sysgrant(&mut self, user: Id, right: SysRight, delegate: bool) -> Result<()> {
        self.push(Op::GrantSystemRight {
            user,
            right,
            delegate,
        })
    }

    pub fn sysrevoke(&mut self, user: Id, right: SysRight) -> Result<()> {
        self.push(Op::RevokeSystemRight { user, right })
    }

    pub fn clear_rotation(&mut self, path: &str) -> Result<()> {
        let node = self.resolve(path)?;
        if !self.state.rotation.contains(&node) {
            return Err(Error::not_found(&format!("{path} is not pending rotation")));
        }
        self.push(Op::ClearRotation { node })
    }

    // ------------------------------------------------------------ Users

    pub fn user_add(&mut self, req: &Request) -> Result<Id> {
        req.verify()?;
        crate::identity::validate_name(&req.name)?;
        let id = Id::random();
        self.push(Op::AddUser {
            user: User {
                id,
                name: req.name.clone(),
                kind: req.kind,
                kem: req.kem.clone(),
                sig: req.sig.clone(),
                credential: req.credential.clone(),
                proof: req.proof.clone(),
                disabled: false,
            },
        })?;
        Ok(id)
    }

    pub fn user_disable(&mut self, user: Id) -> Result<()> {
        self.push(Op::DisableUser { user })
    }

    /// Offboarding (§8.2) in one commit. Returns the secrets to rotate at the source.
    pub fn offboard(&mut self, user: Id) -> Result<Vec<String>> {
        if self.state.is_master(user) {
            return Err(Error::usage(
                "the master cannot be offboarded; transfer the master role first",
            ));
        }
        let mut affected: BTreeSet<Id> = BTreeSet::new();
        // Group memberships: new group keys.
        for g in self.state.user_groups(user) {
            affected.extend(
                self.state
                    .grants
                    .values()
                    .filter(|x| x.to == Principal::Group(g))
                    .map(|x| x.node),
            );
            let gname = self.state.groups[&g].name.clone();
            if self
                .state
                .sys_right(self.me, SysRight::GroupAdmin(g))
                .is_some()
                && self.access().group_kem(g).is_some()
            {
                self.group_remove_inner(g, user, false)?;
            } else {
                self.tasks.push(format!(
                    "remove {} from group {gname}",
                    self.state.users[&user].name
                ));
            }
        }
        // Direct grants.
        let direct: Vec<Grant> = self
            .state
            .grants
            .values()
            .filter(|g| g.to == Principal::User(user))
            .cloned()
            .collect();
        for g in direct {
            affected.insert(g.node);
            if self.state.has_right(self.me, g.node, Right::Admin) {
                self.push(Op::Revoke { grant: g.id })?;
            } else {
                let p = self.path_of(g.node);
                self.tasks.push(format!(
                    "revoke the grant of {} on {p}",
                    self.state.users[&user].name
                ));
            }
        }
        self.push(Op::DisableUser { user })?;
        // Rekey first: it removes nodes nobody can read, which are then not listed for rotation.
        self.rekey_all(affected.clone())?;
        let rotate = self.mark_rotation(&affected)?;
        Ok(rotate)
    }

    /// Replaces a user's identity (§4.4) and re-issues what the author is able to.
    pub fn user_replace(&mut self, user: Id, req: &Request) -> Result<()> {
        req.verify()?;
        let old_name = self
            .state
            .users
            .get(&user)
            .ok_or_else(|| Error::not_found("user"))?
            .name
            .clone();
        if !req.name.eq_ignore_ascii_case(&old_name) {
            return Err(Error::usage(format!(
                "the request is for {}, not {old_name}",
                req.name
            )));
        }
        let old_grants: Vec<Grant> = self
            .state
            .grants
            .values()
            .filter(|g| g.to == Principal::User(user))
            .cloned()
            .collect();
        // A disabled user comes back with nothing: their old grants are not re-issued.
        let was_disabled = !self.state.active(user);
        let old_grants: Vec<Grant> = if was_disabled { Vec::new() } else { old_grants };
        let old_groups = if was_disabled {
            Vec::new()
        } else {
            self.state.user_groups(user)
        };
        let old_group_admin: Vec<(Id, bool)> = self
            .state
            .sysrights
            .get(&user)
            .map(|m| {
                m.iter()
                    .filter_map(|(r, d)| {
                        if let SysRight::GroupAdmin(g) = r {
                            Some((*g, *d))
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let old_sysrights: Vec<(SysRight, bool)> = self
            .state
            .sysrights
            .get(&user)
            .map(|m| {
                m.iter()
                    .filter(|(r, _)| !matches!(r, SysRight::GroupAdmin(_)))
                    .map(|(r, d)| (*r, *d))
                    .collect()
            })
            .unwrap_or_default();
        let old_sysrights = if was_disabled {
            Vec::new()
        } else {
            old_sysrights
        };
        // The old keys may be in the wrong hands (that is often why they are replaced) and they
        // know every key they could read, from the history. Everything they could read gets new
        // keys: group keys first (while the user is still a member), the nodes at the end.
        let all_groups = self.state.user_groups(user);
        let mut readable: BTreeSet<Id> = self
            .state
            .grants
            .values()
            .filter(|g| match g.to {
                Principal::User(u) => u == user,
                Principal::Group(gr) => all_groups.contains(&gr),
            })
            .map(|g| g.node)
            .collect();
        let mut unrotated: BTreeSet<Id> = BTreeSet::new();
        for g in &all_groups {
            let can = self
                .state
                .sys_right(self.me, SysRight::GroupAdmin(*g))
                .is_some()
                && self.access().group_kem(*g).is_some();
            // Rotating needs the keys of everything the group can read; without them, leave it
            // as a task rather than failing the replacement.
            let (state, ops) = (self.state.clone(), self.ops.len());
            let rotated = can
                && match self.group_remove_inner(*g, user, false) {
                    Ok(()) => true,
                    Err(e) if e.code == Code::AccessDenied => {
                        self.state = state;
                        self.ops.truncate(ops);
                        self.access = None;
                        false
                    }
                    Err(e) => return Err(e),
                };
            if !rotated {
                // The vault keeps the group marked (and what it reads) until it gets a new key.
                let group = &self.state.groups[g];
                let others: Vec<String> = group
                    .members
                    .keys()
                    .filter(|m| **m != user)
                    .filter_map(|m| self.state.users.get(m).map(|u| u.name.clone()))
                    .collect();
                unrotated.insert(*g);
                self.tasks.push(match others.first() {
                    Some(_) => format!(
                        "give group {0} a new key – the replaced keys of {old_name} hold the current one: a group admin who is a member runs `nepomuk group add {0} {old_name}`, `nepomuk group remove {0} {old_name}` and `nepomuk group add {0} {old_name}`",
                        group.name
                    ),
                    None => format!(
                        "group {} has no other members and the replaced keys of {old_name} hold its key: revoke its grants",
                        group.name
                    ),
                });
            }
        }
        // What the user lost earlier without a rekey is known to the replaced keys too.
        readable.extend(
            self.state
                .rekey_pending
                .iter()
                .filter(|(_, who)| who.contains(&Principal::User(user)))
                .map(|(n, _)| *n),
        );
        readable.retain(|n| self.state.nodes.contains_key(n));
        self.push(Op::ReplaceIdentity {
            user,
            kind: req.kind,
            kem: req.kem.clone(),
            sig: req.sig.clone(),
            credential: req.credential.clone(),
            proof: req.proof.clone(),
        })?;
        // System rights are removed with the old keys; re-grant what the author may delegate.
        for (right, delegate) in old_sysrights {
            if self.state.sys_right(self.me, right) == Some(true) {
                self.push(Op::GrantSystemRight {
                    user,
                    right,
                    delegate,
                })?;
            } else {
                self.tasks.push(format!(
                    "grant the system right `{}` to {old_name} again",
                    crate::app::sysright_name(&self.state, right)
                ));
            }
        }
        for g in old_groups {
            if self
                .state
                .sys_right(self.me, SysRight::GroupAdmin(g))
                .is_some()
                && self.access().group_kem(g).is_some()
            {
                self.group_add_inner(g, user)?;
                if let Some((_, d)) = old_group_admin.iter().find(|(x, _)| *x == g) {
                    self.push(Op::GrantSystemRight {
                        user,
                        right: SysRight::GroupAdmin(g),
                        delegate: *d,
                    })?;
                }
            } else if !unrotated.contains(&g) {
                self.tasks.push(format!(
                    "add {old_name} back to group {}",
                    self.state.groups[&g].name
                ));
            }
        }
        for g in old_grants {
            let can = self
                .state
                .effective_right(self.me, g.node)
                .is_some_and(|r| {
                    r >= g.right
                        && r >= if g.right <= Right::Write {
                            Right::Share
                        } else {
                            Right::Admin
                        }
                });
            let path = self.path_of(g.node);
            if can && self.access().key(g.node).is_some() {
                let nk = self.key(g.node)?;
                let proof = self.proof(g.node)?;
                let ng = keyring::make_grant(
                    &self.state,
                    Id::random(),
                    g.node,
                    g.to,
                    g.right,
                    &nk,
                    &proof,
                )?;
                self.push(Op::Grant { grant: ng })?;
            } else {
                self.tasks.push(format!(
                    "grant {} `{}` on {path} again",
                    old_name,
                    g.right.as_str()
                ));
            }
        }
        self.rekey_all(readable)?;
        self.warnings.push(format!(
            "if the replaced keys of {old_name} may have been stolen, change the secrets they could read at their source"
        ));
        Ok(())
    }

    pub fn update_own_credential(&mut self, cred: crypto::PasswordSealed) -> Result<()> {
        self.push(Op::UpdateOwnCredential { credential: cred })
    }

    /// Replaces the author's own keys (§4.4), re-wrapping their grants and group memberships for
    /// the new public keys. Grants the author cannot read (unproven paths) are dropped.
    pub fn rotate_own_keys(
        &mut self,
        kem: crypto::KemPublic,
        sig: crypto::SigPublic,
        credential: Option<crypto::PasswordSealed>,
        proof: Vec<u8>,
    ) -> Result<()> {
        let me = self.me;
        let vault = self.vault();
        let mut tmp = self.state.clone();
        tmp.users.get_mut(&me).unwrap().kem = kem.clone();
        let mine: Vec<Grant> = self
            .state
            .grants
            .values()
            .filter(|g| g.to == Principal::User(me))
            .cloned()
            .collect();
        let mut grants = Vec::new();
        for g in mine {
            let (Some(nk), Some(proof)) = (
                self.access().key(g.node).cloned(),
                self.access().proof(g.node),
            ) else {
                self.warnings.push(format!(
                    "your grant on node {} was dropped: it cannot be read with your keys",
                    g.node.hex()
                ));
                continue;
            };
            grants.push(keyring::make_grant(
                &tmp, g.id, g.node, g.to, g.right, &nk, &proof,
            )?);
        }
        let mut memberships = BTreeMap::new();
        let groups: Vec<Id> = self
            .state
            .groups
            .values()
            .filter(|g| g.members.contains_key(&me))
            .map(|g| g.id)
            .collect();
        for gid in groups {
            let seed = match self.access().groups.get(&gid) {
                Some((seed, _)) => LockedSeed::from_slice(seed.as_ref())?,
                None => {
                    let name = self.state.groups[&gid].name.clone();
                    self.warnings.push(format!(
                        "you left group {name}: its key cannot be read with your keys"
                    ));
                    continue;
                }
            };
            memberships.insert(
                gid,
                crypto::wrap(&kem, seed.as_ref(), &keyring::aad_member(vault, gid, me))?,
            );
        }
        self.push(Op::RotateOwnKeys {
            kem,
            sig,
            credential,
            proof,
            grants,
            memberships,
        })?;
        if self
            .state
            .grants
            .values()
            .any(|g| g.to == Principal::User(me))
            || self
                .state
                .groups
                .values()
                .any(|g| g.members.contains_key(&me))
        {
            self.warnings.push(
                "your old keys can no longer sign or receive anything new, but whoever has them (or the old password and the git history) can still read what you could read until it is rekeyed; if they leaked, ask an admin to rekey your folders".into(),
            );
        }
        Ok(())
    }

    /// Transfers the master role (§8.3). Unless `keep_access`, the former master gives up its
    /// grants on the root in the same commit; either way the new master should rekey the root,
    /// since the former master held every node key.
    pub fn transfer_master(&mut self, user: Id, keep_access: bool) -> Result<()> {
        let root = self.state.root;
        if !self
            .state
            .grants
            .values()
            .any(|g| g.node == root && g.to == Principal::User(user) && g.right == Right::Admin)
        {
            let nk = self.key(root)?;
            let g = keyring::make_grant(
                &self.state,
                Id::random(),
                root,
                Principal::User(user),
                Right::Admin,
                &nk,
                &keyring::PathProof::root(),
            )?;
            // Replace a weaker grant on the root, if any.
            if let Some(old) = self
                .state
                .grants
                .values()
                .find(|g| g.node == root && g.to == Principal::User(user))
            {
                let id = old.id;
                self.push(Op::Revoke { grant: id })?;
            }
            self.push(Op::Grant { grant: g })?;
        }
        self.push(Op::TransferMaster { user })?;
        let new = self.state.users[&user].name.clone();
        if keep_access || user == self.me {
            self.warnings.push(format!(
                "you keep admin on / as a regular user; {new} can revoke it (`nepomuk revoke user:{} /`)",
                self.state.users[&self.me].name
            ));
            return Ok(());
        }
        let own: Vec<Id> = self
            .state
            .grants
            .values()
            .filter(|g| g.node == root && g.to == Principal::User(self.me))
            .map(|g| g.id)
            .collect();
        for g in own {
            self.push(Op::Revoke { grant: g })?;
        }
        self.warnings.push(format!(
            "you no longer have access to /, but you held every key until now: {new} should run `nepomuk rekey /`"
        ));
        self.tasks.push(format!("{new}: run `nepomuk rekey /`"));
        Ok(())
    }

    // ------------------------------------------------------------ Groups

    pub fn group_create(&mut self, name: &str) -> Result<Id> {
        crate::identity::validate_name(name)?;
        let id = Id::random();
        let seed = LockedSeed::random();
        let kem = KemSecret::from_seed(seed.as_ref(), "group");
        let wrapped = crypto::wrap(
            &self.state.users[&self.me].kem,
            seed.as_ref(),
            &keyring::aad_member(self.vault(), id, self.me),
        )?;
        let group = Group {
            id,
            name: name.to_string(),
            kem: kem.public().clone(),
            members: BTreeMap::from([(self.me, wrapped)]),
        };
        self.push(Op::CreateGroup { group })?;
        Ok(id)
    }

    fn group_add_inner(&mut self, group: Id, user: Id) -> Result<()> {
        let vault = self.vault();
        let seed = {
            let acc = self.access();
            let (seed, _) = acc.groups.get(&group).ok_or_else(|| {
                Error::new(
                    Code::AccessDenied,
                    "you must be a member of the group to add members",
                )
            })?;
            LockedSeed::from_slice(seed.as_ref())?
        };
        let kem = &self
            .state
            .users
            .get(&user)
            .ok_or_else(|| Error::not_found("user"))?
            .kem;
        let wrapped = crypto::wrap(kem, seed.as_ref(), &keyring::aad_member(vault, group, user))?;
        self.push(Op::AddMember {
            group,
            user,
            wrapped,
        })
    }

    pub fn group_add(&mut self, group: Id, user: Id) -> Result<()> {
        self.group_add_inner(group, user)
    }

    /// New group key, re-wrapped group grants and a rekey of the group's nodes (§5.3).
    fn group_remove_inner(&mut self, group: Id, user: Id, rekey: bool) -> Result<()> {
        let vault = self.vault();
        let seed = LockedSeed::random();
        let kem = KemSecret::from_seed(seed.as_ref(), "group");
        let g = self
            .state
            .groups
            .get(&group)
            .ok_or_else(|| Error::not_found("group"))?
            .clone();
        if self.access().group_kem(group).is_none() {
            return Err(Error::new(
                Code::AccessDenied,
                "you must be a member of the group to remove members",
            ));
        }
        // Disabled members leave the group too: the new key is not wrapped for them.
        let mut members = BTreeMap::new();
        for m in g
            .members
            .keys()
            .filter(|m| **m != user && self.state.active(**m))
        {
            let w = crypto::wrap(
                &self.state.users[m].kem,
                seed.as_ref(),
                &keyring::aad_member(vault, group, *m),
            )?;
            members.insert(*m, w);
        }
        let old: Vec<Grant> = self
            .state
            .grants
            .values()
            .filter(|x| x.to == Principal::Group(group))
            .cloned()
            .collect();
        let mut tmp = self.state.clone();
        tmp.groups.get_mut(&group).unwrap().kem = kem.public().clone();
        let mut grants = Vec::new();
        let mut nodes = BTreeSet::new();
        for x in old {
            let nk = self.key(x.node)?;
            let proof = self.proof(x.node)?;
            grants.push(keyring::make_grant(
                &tmp, x.id, x.node, x.to, x.right, &nk, &proof,
            )?);
            nodes.insert(x.node);
        }
        self.push(Op::RemoveMember {
            group,
            user,
            kem: kem.public().clone(),
            members,
            grants,
        })?;
        if rekey {
            self.rekey_all(nodes)?;
        }
        Ok(())
    }

    pub fn group_remove(&mut self, group: Id, user: Id) -> Result<()> {
        self.group_remove_inner(group, user, true)
    }
}

pub fn principal_name(state: &State, p: Principal) -> String {
    match p {
        Principal::User(u) => format!(
            "user:{}",
            state.users.get(&u).map(|u| u.name.as_str()).unwrap_or("?")
        ),
        Principal::Group(g) => format!(
            "group:{}",
            state.groups.get(&g).map(|g| g.name.as_str()).unwrap_or("?")
        ),
    }
}
