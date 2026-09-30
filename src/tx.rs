//! Building signed commits (§8): every high-level action becomes one or more operations that
//! are checked against the working state exactly as every other client will check them.

use std::collections::{BTreeMap, BTreeSet};

use crate::crypto::{self, KemSecret, Key32};
use crate::error::{Code, Error, Result};
use crate::format::{CheckpointBody, CommitBody, Envelope, RawEntry, VaultFile, to_cbor};
use crate::identity::{Request, Unlocked};
use crate::keyring::{self, Access};
use crate::memory::LockedSeed;
use crate::model::*;
use crate::verify::{Verified, apply_op, verify_file};

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

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '#'])
        || name.chars().any(char::is_control)
    {
        return Err(Error::usage(format!("invalid name: {name:?}")));
    }
    if name.len() > 255 {
        return Err(Error::usage("name too long"));
    }
    Ok(())
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
        proof: master.proof(IdentityKind::Local),
        disabled: false,
    };
    let content = NodeContent {
        content: Content::Folder,
        meta: Meta {
            created: now(),
            updated: now(),
            not_after: None,
        },
    };
    let node = Node {
        id: root,
        parent: None,
        wrapped_key: None,
        name: keyring::seal_name(vault_id, root, &nk, ""),
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
        "/",
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
    pub id: &'a Unlocked,
    pub ops: Vec<Op>,
    access: Option<Access>,
    pub warnings: Vec<String>,
    /// Work the author could not do (missing keys or rights), for other admins.
    pub tasks: Vec<String>,
}

/// Finds the vault user matching an unlocked identity.
pub fn find_me(state: &State, id: &Unlocked) -> Result<Id> {
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
    pub fn new(base: &'a Verified, id: &'a Unlocked) -> Result<Tx<'a>> {
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
        let sig = self.id.sig.sign("commit", &body);
        let mut file = self.base.file.clone();
        file.entries
            .push(RawEntry::from_envelope(Envelope { body, sig }));
        let master_fp = crate::verify::user_fp(&self.state.users[&self.state.master]);
        let verified = verify_file(file.clone(), &master_fp)?;
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
    ) -> Result<Id> {
        validate_name(name)?;
        let parent_path = self.path_of(parent);
        if !self.is_folder(parent)? {
            return Err(Error::usage(format!("{parent_path} is not a folder")));
        }
        let target = keyring::join(&parent_path, name);
        if self.access().resolve(&target).is_some() {
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
            },
        };
        let node = Node {
            id,
            parent: Some(parent),
            wrapped_key: Some(keyring::seal_node_key(vault, id, &pk, &nk)),
            name: keyring::seal_name(vault, id, &nk, name),
            content: keyring::seal_content(vault, id, &nk, &c),
        };
        self.push(Op::CreateNode { node })?;
        Ok(id)
    }

    pub fn mkdir(&mut self, path: &str, parents: bool) -> Result<Id> {
        let path = normalize_path(path)?;
        if let Some(id) = self.access().resolve(&path) {
            if parents && self.is_folder(id)? {
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
        self.create_node(pid, &name, Content::Folder, None)
    }

    /// Creates or replaces a secret.
    pub fn put(&mut self, path: &str, content: Content, not_after: Option<i64>) -> Result<Id> {
        let path = normalize_path(path)?;
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
        self.create_node(pid, &name, content, not_after)
    }

    pub fn rm(&mut self, path: &str) -> Result<()> {
        let id = self.resolve(path)?;
        if id == self.state.root {
            return Err(Error::usage("the root folder cannot be removed"));
        }
        self.push(Op::DeleteNode { id })
    }

    /// Re-wraps all grants in a subtree after its paths changed.
    fn rewrapped_grants(&mut self, sub: &[Id], paths: &BTreeMap<Id, String>) -> Result<Vec<Grant>> {
        let grants: Vec<Grant> = self.state.grants_on(sub).into_iter().cloned().collect();
        let mut out = Vec::new();
        for g in grants {
            let nk = self.key(g.node)?;
            let path = paths
                .get(&g.node)
                .cloned()
                .unwrap_or_else(|| self.path_of(g.node));
            out.push(keyring::make_grant(
                &self.state,
                g.id,
                g.node,
                g.to,
                g.right,
                &nk,
                &path,
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
        let (parent, name) = split_parent(&dst)?;
        validate_name(&name)?;
        let pid = self.resolve(&parent)?;
        if !self.is_folder(pid)? {
            return Err(Error::usage(format!("{parent} is not a folder")));
        }
        let old_path = self.path_of(id);
        let sub = self.state.subtree(id);
        let mut paths = BTreeMap::new();
        for n in &sub {
            let p = self.path_of(*n);
            paths.insert(*n, format!("{}{}", dst, &p[old_path.len()..]));
        }
        let grants = self.rewrapped_grants(&sub, &paths)?;
        let nk = self.key(id)?;
        let vault = self.vault();
        let sealed_name = keyring::seal_name(vault, id, &nk, &name);
        if Some(pid) == self.state.nodes[&id].parent {
            self.push(Op::RenameNode {
                id,
                name: sealed_name,
                grants,
            })
        } else {
            let pk = self.key(pid)?;
            let wrapped_key = keyring::seal_node_key(vault, id, &pk, &nk);
            self.push(Op::MoveNode {
                id,
                parent: pid,
                wrapped_key,
                name: sealed_name,
                grants,
            })?;
            self.warnings.push(format!(
                "{old_path} moved: whoever could read the old location still holds its key; consider `nepomuk rekey {dst}`"
            ));
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
            let content = acc.content(&self.state, *n)?;
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
            nodes.push(RekeyedNode {
                id: *n,
                wrapped_key,
                name: keyring::seal_name(vault, *n, &nk, &v.name),
                content: keyring::seal_content(vault, *n, &nk, &content),
            });
            new_keys.insert(*n, nk);
        }
        let old: Vec<Grant> = self.state.grants_on(&sub).into_iter().cloned().collect();
        let mut grants = Vec::new();
        for g in old {
            let path = acc.path(g.node).unwrap_or("?").to_string();
            grants.push(keyring::make_grant(
                &self.state,
                g.id,
                g.node,
                g.to,
                g.right,
                &new_keys[&g.node],
                &path,
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
                self.rekey(n)?;
                done.push(n);
            } else {
                let p = self.path_of(n);
                self.tasks.push(format!(
                    "rekey {p} (node {}) – requires admin on its parent",
                    n.hex()
                ));
            }
        }
        Ok(())
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
        let path = self.path_of(node);
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
        let g = keyring::make_grant(&self.state, Id::random(), node, to, right, &nk, &path)?;
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
        let rotate = self.mark_rotation(&BTreeSet::from([node]))?;
        if no_rekey {
            self.warnings.push(
                "revoked without rekey: the revoked party can still decrypt future content".into(),
            );
        } else {
            self.rekey_all(BTreeSet::from([node]))?;
        }
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
        let rotate = self.mark_rotation(&affected)?;
        self.rekey_all(affected)?;
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
        let old_groups = self.state.user_groups(user);
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
        self.push(Op::ReplaceIdentity {
            user,
            kind: req.kind,
            kem: req.kem.clone(),
            sig: req.sig.clone(),
            credential: req.credential.clone(),
            proof: req.proof.clone(),
        })?;
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
            } else {
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
                let ng = keyring::make_grant(
                    &self.state,
                    Id::random(),
                    g.node,
                    g.to,
                    g.right,
                    &nk,
                    &path,
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
        Ok(())
    }

    pub fn update_own_credential(&mut self, cred: crypto::PasswordSealed) -> Result<()> {
        self.push(Op::UpdateOwnCredential { credential: cred })
    }

    pub fn transfer_master(&mut self, user: Id) -> Result<()> {
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
                "/",
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
        self.push(Op::TransferMaster { user })
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
        let mut members = BTreeMap::new();
        for m in g.members.keys().filter(|m| **m != user) {
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
            let path = self.path_of(x.node);
            grants.push(keyring::make_grant(
                &tmp, x.id, x.node, x.to, x.right, &nk, &path,
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
