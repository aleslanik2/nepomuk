//! Replaying and verifying the log (§5.4, §7, §8): every client checks every signature and
//! that each operation's author held the required right at that moment.

use std::collections::BTreeSet;

use crate::crypto;
use crate::error::{Code, Error, Result};
use crate::format::{CheckpointBody, CommitBody, VaultFile, from_cbor};
use crate::model::*;

// ---------------------------------------------------------------- State queries

impl State {
    pub fn is_master(&self, user: Id) -> bool {
        self.master == user
    }

    pub fn user_by_name(&self, name: &str) -> Option<&User> {
        self.users
            .values()
            .find(|u| u.name.eq_ignore_ascii_case(name))
    }

    pub fn group_by_name(&self, name: &str) -> Option<&Group> {
        self.groups.values().find(|g| g.name == name)
    }

    pub fn user_groups(&self, user: Id) -> Vec<Id> {
        self.groups
            .values()
            .filter(|g| g.members.contains_key(&user))
            .map(|g| g.id)
            .collect()
    }

    pub fn active(&self, user: Id) -> bool {
        self.users.get(&user).is_some_and(|u| !u.disabled)
    }

    /// Node and all its ancestors, starting with the node itself.
    pub fn ancestors(&self, node: Id) -> Vec<Id> {
        let mut out = Vec::new();
        let mut cur = Some(node);
        while let Some(id) = cur {
            if out.contains(&id) {
                break;
            }
            out.push(id);
            cur = self.nodes.get(&id).and_then(|n| n.parent);
        }
        out
    }

    pub fn children(&self, node: Id) -> Vec<Id> {
        self.nodes
            .values()
            .filter(|n| n.parent == Some(node))
            .map(|n| n.id)
            .collect()
    }

    /// The node and all its descendants in pre-order.
    pub fn subtree(&self, node: Id) -> Vec<Id> {
        let mut out = Vec::new();
        let mut stack = vec![node];
        while let Some(id) = stack.pop() {
            out.push(id);
            let mut kids = self.children(id);
            kids.reverse();
            stack.extend(kids);
        }
        out
    }

    pub fn grants_on(&self, nodes: &[Id]) -> Vec<&Grant> {
        let set: BTreeSet<Id> = nodes.iter().copied().collect();
        self.grants
            .values()
            .filter(|g| set.contains(&g.node))
            .collect()
    }

    /// Effective tree right (§5.1): the maximum over grants on the node and its ancestors,
    /// direct or via groups. The master implicitly holds `admin` everywhere.
    pub fn effective_right(&self, user: Id, node: Id) -> Option<Right> {
        if !self.active(user) {
            return None;
        }
        if self.is_master(user) {
            return Some(Right::Admin);
        }
        let groups = self.user_groups(user);
        let path = self.ancestors(node);
        self.grants
            .values()
            .filter(|g| path.contains(&g.node))
            .filter(|g| match g.to {
                Principal::User(u) => u == user,
                Principal::Group(gr) => groups.contains(&gr),
            })
            .map(|g| g.right)
            .max()
    }

    pub fn has_right(&self, user: Id, node: Id, need: Right) -> bool {
        self.effective_right(user, node).is_some_and(|r| r >= need)
    }

    /// Returns `Some(delegate)` when the user holds the system right.
    pub fn sys_right(&self, user: Id, right: SysRight) -> Option<bool> {
        if !self.active(user) {
            return None;
        }
        if self.is_master(user) {
            return Some(true);
        }
        self.sysrights
            .get(&user)
            .and_then(|m| m.get(&right))
            .copied()
    }

    fn remove_grants_where(&mut self, f: impl Fn(&Grant) -> bool) {
        self.grants.retain(|_, g| !f(g));
    }
}

// ---------------------------------------------------------------- Verification

#[derive(Clone, Debug)]
pub struct CommitInfo {
    pub seq: u64,
    pub author: Id,
    pub time: i64,
    pub ops: Vec<String>,
    /// Nodes whose name, location or content the commit changed or removed.
    pub touched: Vec<Id>,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Verified {
    pub file: VaultFile,
    pub state: State,
    pub seq: u64,
    /// Logical head: the hash of the last commit (or the commit folded by a checkpoint).
    pub head: [u8; 32],
    pub checkpoint_seq: u64,
    pub checkpoint_time: i64,
    pub commits: Vec<CommitInfo>,
    /// Fingerprint of the current master.
    pub master_fp: String,
}

pub fn user_fp(u: &User) -> String {
    crypto::fingerprint(&u.kem, &u.sig)
}

/// What a proof of possession signs: the whole request, including the password credential, so
/// that whoever relays a request cannot swap the credential.
pub fn proof_data(
    name: &str,
    kind: IdentityKind,
    kem: &crypto::KemPublic,
    sig: &crypto::SigPublic,
    credential: Option<&crypto::PasswordSealed>,
) -> Vec<u8> {
    crate::format::to_cbor(&(name, kind, kem, sig, credential))
}

fn verify_proof(
    name: &str,
    kind: IdentityKind,
    kem: &crypto::KemPublic,
    sig: &crypto::SigPublic,
    credential: Option<&crypto::PasswordSealed>,
    proof: &[u8],
) -> bool {
    crypto::verify(
        sig,
        "request",
        &proof_data(name, kind, kem, sig, credential),
        proof,
    )
}

/// Checks a new identity's keys and credential (AddUser, ReplaceIdentity).
fn check_identity(
    name: &str,
    kind: IdentityKind,
    kem: &crypto::KemPublic,
    sig: &crypto::SigPublic,
    credential: Option<&crypto::PasswordSealed>,
    proof: &[u8],
) -> Result<()> {
    crypto::check_kem_public(kem).map_err(|e| deny(e.message))?;
    require(
        verify_proof(name, kind, kem, sig, credential, proof),
        "invalid proof of possession",
    )?;
    match (kind, credential) {
        (IdentityKind::Password, Some(c)) => c.check().map_err(|e| deny(e.message)),
        (IdentityKind::Password, None) => Err(deny("missing credential")),
        (IdentityKind::Local, None) => Ok(()),
        (IdentityKind::Local, Some(_)) => Err(deny("a local identity has no credential")),
    }
}

/// Fingerprint of the master that signed the checkpoint (entry 0) of a file, unverified.
pub fn checkpoint_master_fp(file: &VaultFile) -> Option<String> {
    let cp: CheckpointBody = from_cbor(&file.entries[0].envelope.body).ok()?;
    cp.state.users.get(&cp.state.master).map(user_fp)
}

fn sig_err(m: impl Into<String>) -> Error {
    Error::new(Code::SignatureInvalid, m)
}

/// Verifies a whole vault file against the pinned master fingerprint.
pub fn verify_file(file: VaultFile, pinned_fp: &str) -> Result<Verified> {
    verify_file_with(file, pinned_fp, &[])
}

/// Verifies a whole vault file. The checkpoint must be signed by the pinned master or by one of
/// `former` (masters pinned earlier on this machine, before a `TransferMaster` that has not
/// been compacted yet); the master after replaying the log must be the pinned one.
///
/// The root of trust is the signer of the checkpoint: a file signed by anyone else is rejected
/// whatever its log claims, including a `TransferMaster` to the pinned key (§5, §7.1). A caller
/// passing `former` must also check that the file continues the history it saw before, since
/// a former master can sign a checkpoint of any content.
pub fn verify_file_with(file: VaultFile, pinned_fp: &str, former: &[String]) -> Result<Verified> {
    let cp_entry = &file.entries[0];
    let cp: CheckpointBody = from_cbor(&cp_entry.envelope.body)?;
    if cp.vault_id != file.vault_id || cp.state.vault_id != file.vault_id {
        return Err(Error::format("checkpoint belongs to another vault"));
    }
    let master = cp
        .state
        .users
        .get(&cp.state.master)
        .ok_or_else(|| Error::format("checkpoint without master"))?;
    let signer = user_fp(master);
    if signer != pinned_fp && !former.contains(&signer) {
        return Err(Error::new(
            Code::UntrustedRoot,
            "the vault's checkpoint is not signed by the pinned master",
        )
        .with("pinned", pinned_fp)
        .with("found", signer));
    }
    let mut masters = vec![signer];
    if !crypto::verify(
        &master.sig,
        "checkpoint",
        &cp_entry.envelope.body,
        &cp_entry.envelope.sig,
    ) {
        return Err(sig_err("checkpoint signature is invalid"));
    }
    if !cp.state.nodes.contains_key(&cp.state.root) {
        return Err(Error::format("checkpoint without root folder"));
    }

    let mut state = cp.state;
    let mut seq = cp.seq;
    let mut prev_hash = cp_entry.hash();
    let mut head = cp.folded_head.unwrap_or(prev_hash);
    let mut commits = Vec::new();

    for entry in &file.entries[1..] {
        let body: CommitBody = from_cbor(&entry.envelope.body)?;
        if body.vault_id != file.vault_id {
            return Err(Error::format("commit belongs to another vault"));
        }
        if body.seq != seq + 1 || body.prev_hash != prev_hash {
            return Err(
                sig_err(format!("broken hash chain at #{}", body.seq)).with("seq", body.seq)
            );
        }
        let author = state
            .users
            .get(&body.author)
            .ok_or_else(|| Error::unauthorized(format!("#{}: unknown author", body.seq)))?;
        if author.disabled {
            return Err(Error::unauthorized(format!(
                "#{}: author {} is disabled",
                body.seq, author.name
            ))
            .with("seq", body.seq));
        }
        if !crypto::verify(
            &author.sig,
            "commit",
            &entry.envelope.body,
            &entry.envelope.sig,
        ) {
            return Err(sig_err(format!("#{}: invalid signature", body.seq)).with("seq", body.seq));
        }
        let mut next = state.clone();
        for op in &body.ops {
            apply_op(&mut next, body.author, op).map_err(|e| {
                Error::new(
                    Code::UnauthorizedOperation,
                    format!("#{}: {} rejected: {}", body.seq, op.name(), e.message),
                )
                .with("seq", body.seq)
            })?;
            if let Op::TransferMaster { user } = op {
                masters.push(user_fp(&next.users[user]));
            }
        }
        state = next;
        seq = body.seq;
        prev_hash = entry.hash();
        head = prev_hash;
        commits.push(CommitInfo {
            seq,
            author: body.author,
            time: body.time,
            ops: body.ops.iter().map(|o| o.name().to_string()).collect(),
            touched: body.ops.iter().filter_map(touched_node).collect(),
            hash: prev_hash,
        });
    }

    let current = masters.last().unwrap().clone();
    if pinned_fp != current {
        if masters.iter().any(|m| m == pinned_fp) {
            return Err(Error::new(
                Code::UntrustedRoot,
                format!("the master was transferred to {current}; confirm it with `nepomuk trust {current}`"),
            )
            .with("new_fingerprint", current));
        }
        return Err(Error::new(
            Code::UntrustedRoot,
            "the vault's master does not match the pinned fingerprint",
        )
        .with("pinned", pinned_fp)
        .with("found", current));
    }

    Ok(Verified {
        file,
        state,
        seq,
        head,
        checkpoint_seq: cp.seq,
        checkpoint_time: cp.time,
        commits,
        master_fp: current,
    })
}

fn touched_node(op: &Op) -> Option<Id> {
    match op {
        Op::UpdateNode { id, .. }
        | Op::RenameNode { id, .. }
        | Op::MoveNode { id, .. }
        | Op::DeleteNode { id } => Some(*id),
        Op::CreateNode { node } => Some(node.id),
        _ => None,
    }
}

// ---------------------------------------------------------------- Authorization of operations

fn deny(m: impl Into<String>) -> Error {
    Error::unauthorized(m)
}

fn require(cond: bool, m: &str) -> Result<()> {
    if cond { Ok(()) } else { Err(deny(m)) }
}

fn node_exists(s: &State, id: Id) -> Result<&Node> {
    s.nodes.get(&id).ok_or_else(|| deny("unknown node"))
}

fn parent_of(s: &State, id: Id) -> Result<Id> {
    node_exists(s, id)?
        .parent
        .ok_or_else(|| deny("the root folder has no parent"))
}

/// Replaced grants must be existing grants with unchanged metadata; only the ciphertext changes.
fn check_rewrapped(s: &State, grants: &[Grant], scope: &[Id]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for g in grants {
        let old = s
            .grants
            .get(&g.id)
            .ok_or_else(|| deny("re-wrapped grant does not exist"))?;
        require(old.same_meta(g), "re-wrapped grant changes its metadata")?;
        require(
            scope.contains(&g.node),
            "re-wrapped grant is outside the subtree",
        )?;
        require(seen.insert(g.id), "duplicate grant")?;
    }
    Ok(())
}

fn check_principal(s: &State, p: Principal) -> Result<()> {
    match p {
        Principal::User(u) => require(s.active(u), "recipient is unknown or disabled"),
        Principal::Group(g) => require(s.groups.contains_key(&g), "unknown group"),
    }
}

pub fn apply_op(s: &mut State, author: Id, op: &Op) -> Result<()> {
    match op {
        Op::AddUser { user } => {
            require(
                s.sys_right(author, SysRight::Users).is_some(),
                "requires `users`",
            )?;
            require(!s.users.contains_key(&user.id), "user id already exists")?;
            require(
                s.user_by_name(&user.name).is_none(),
                "user name already exists",
            )?;
            require(!user.disabled, "new user must be enabled")?;
            check_identity(
                &user.name,
                user.kind,
                &user.kem,
                &user.sig,
                user.credential.as_ref(),
                &user.proof,
            )?;
            require(
                !s.users
                    .values()
                    .any(|u| u.kem == user.kem || u.sig == user.sig),
                "these keys already belong to a user",
            )?;
            s.users.insert(user.id, user.clone());
        }
        Op::DisableUser { user } => {
            require(
                s.sys_right(author, SysRight::Users).is_some(),
                "requires `users`",
            )?;
            require(!s.is_master(*user), "the master cannot be disabled")?;
            let u = s.users.get_mut(user).ok_or_else(|| deny("unknown user"))?;
            u.disabled = true;
        }
        Op::ReplaceIdentity {
            user,
            kind,
            kem,
            sig,
            credential,
            proof,
        } => {
            require(
                s.sys_right(author, SysRight::Users).is_some(),
                "requires `users`",
            )?;
            require(!s.is_master(*user), "use master transfer for the master")?;
            let u = s.users.get(user).ok_or_else(|| deny("unknown user"))?;
            check_identity(&u.name, *kind, kem, sig, credential.as_ref(), proof)?;
            require(
                !s.users
                    .values()
                    .any(|o| o.id != *user && (o.kem == *kem || o.sig == *sig)),
                "these keys already belong to a user",
            )?;
            // Everything wrapped for the old keys becomes useless and is removed. System
            // rights are removed too: whoever approves the new keys must not inherit rights
            // they could not grant themselves; they are granted again explicitly. With nothing
            // left, re-enabling a disabled user (a returning employee) grants nothing.
            let uid = *user;
            s.remove_grants_where(|g| g.to == Principal::User(uid));
            for g in s.groups.values_mut() {
                g.members.remove(&uid);
            }
            s.sysrights.remove(&uid);
            let u = s.users.get_mut(user).unwrap();
            u.kind = *kind;
            u.kem = kem.clone();
            u.sig = sig.clone();
            u.credential = credential.clone();
            u.proof = proof.clone();
            u.disabled = false;
        }
        Op::UpdateOwnCredential { credential } => {
            let u = s
                .users
                .get_mut(&author)
                .ok_or_else(|| deny("unknown user"))?;
            require(
                u.kind == IdentityKind::Password,
                "only password identities store a credential",
            )?;
            credential.check().map_err(|e| deny(e.message))?;
            u.credential = Some(credential.clone());
        }
        Op::RotateOwnKeys {
            kem,
            sig,
            credential,
            proof,
            grants,
            memberships,
        } => {
            // The master's keys are what every client pins; they change by `TransferMaster`.
            require(!s.is_master(author), "the master cannot rotate its keys")?;
            let u = s.users.get(&author).ok_or_else(|| deny("unknown user"))?;
            check_identity(&u.name, u.kind, kem, sig, credential.as_ref(), proof)?;
            require(
                !s.users.values().any(|o| o.kem == *kem || o.sig == *sig),
                "these keys already belong to a user",
            )?;
            let me = Principal::User(author);
            let mut seen = BTreeSet::new();
            for g in grants {
                let old = s
                    .grants
                    .get(&g.id)
                    .ok_or_else(|| deny("re-wrapped grant does not exist"))?;
                require(old.to == me, "only one's own grants can be re-wrapped")?;
                require(old.same_meta(g), "re-wrapped grant changes its metadata")?;
                require(seen.insert(g.id), "duplicate grant")?;
            }
            for gid in memberships.keys() {
                require(
                    s.groups
                        .get(gid)
                        .is_some_and(|g| g.members.contains_key(&author)),
                    "not a member of the group",
                )?;
            }
            // Everything wrapped for the old keys is replaced or dropped.
            s.remove_grants_where(|g| g.to == me && !seen.contains(&g.id));
            for g in grants {
                s.grants.insert(g.id, g.clone());
            }
            for (gid, group) in s.groups.iter_mut() {
                if !group.members.contains_key(&author) {
                    continue;
                }
                match memberships.get(gid) {
                    Some(w) => {
                        group.members.insert(author, w.clone());
                    }
                    None => {
                        group.members.remove(&author);
                    }
                }
            }
            let u = s.users.get_mut(&author).unwrap();
            u.kem = kem.clone();
            u.sig = sig.clone();
            u.credential = credential.clone();
            u.proof = proof.clone();
        }
        Op::CreateGroup { group } => {
            require(
                s.sys_right(author, SysRight::Groups).is_some(),
                "requires `groups`",
            )?;
            require(!s.groups.contains_key(&group.id), "group id already exists")?;
            require(
                s.group_by_name(&group.name).is_none(),
                "group name already exists",
            )?;
            require(
                group.members.len() == 1 && group.members.contains_key(&author),
                "a new group contains exactly its creator",
            )?;
            s.groups.insert(group.id, group.clone());
            s.sysrights
                .entry(author)
                .or_default()
                .insert(SysRight::GroupAdmin(group.id), true);
        }
        Op::AddMember {
            group,
            user,
            wrapped,
        } => {
            let g = s.groups.get(group).ok_or_else(|| deny("unknown group"))?;
            require(
                s.sys_right(author, SysRight::GroupAdmin(*group)).is_some(),
                "requires `group-admin` of the group",
            )?;
            require(
                s.is_master(author) || g.members.contains_key(&author),
                "only a member of the group can add members",
            )?;
            require(s.active(*user), "unknown or disabled user")?;
            require(!g.members.contains_key(user), "already a member")?;
            s.groups
                .get_mut(group)
                .unwrap()
                .members
                .insert(*user, wrapped.clone());
        }
        Op::RemoveMember {
            group,
            user,
            kem,
            members,
            grants,
        } => {
            let g = s.groups.get(group).ok_or_else(|| deny("unknown group"))?;
            require(
                s.sys_right(author, SysRight::GroupAdmin(*group)).is_some(),
                "requires `group-admin` of the group",
            )?;
            require(g.members.contains_key(user), "not a member")?;
            let expected: BTreeSet<Id> = g.members.keys().filter(|m| *m != user).copied().collect();
            let got: BTreeSet<Id> = members.keys().copied().collect();
            require(
                expected == got,
                "the new group key must be wrapped for all remaining members",
            )?;
            let gid = *group;
            let group_grants: BTreeSet<Id> = s
                .grants
                .values()
                .filter(|x| x.to == Principal::Group(gid))
                .map(|x| x.id)
                .collect();
            let got: BTreeSet<Id> = grants.iter().map(|x| x.id).collect();
            require(
                group_grants == got,
                "all grants of the group must be re-wrapped",
            )?;
            let all: Vec<Id> = s.nodes.keys().copied().collect();
            check_rewrapped(s, grants, &all)?;
            let g = s.groups.get_mut(group).unwrap();
            g.kem = kem.clone();
            g.members = members.clone();
            for x in grants {
                s.grants.insert(x.id, x.clone());
            }
            if let Some(m) = s.sysrights.get_mut(user) {
                m.remove(&SysRight::GroupAdmin(gid));
            }
        }
        Op::CreateNode { node } => {
            let parent = node
                .parent
                .ok_or_else(|| deny("a new node needs a parent"))?;
            node_exists(s, parent)?;
            require(!s.nodes.contains_key(&node.id), "node id already exists")?;
            require(node.wrapped_key.is_some(), "missing wrapped key")?;
            require(
                s.has_right(author, parent, Right::Write),
                "requires `write` on the parent",
            )?;
            s.nodes.insert(node.id, node.clone());
        }
        Op::UpdateNode { id, content } => {
            node_exists(s, *id)?;
            require(
                s.has_right(author, *id, Right::Write),
                "requires `write` on the node",
            )?;
            s.nodes.get_mut(id).unwrap().content = content.clone();
        }
        Op::RenameNode {
            id,
            name,
            name_commit,
            grants,
        } => {
            let parent = parent_of(s, *id)?;
            require(
                s.has_right(author, parent, Right::Write),
                "requires `write` on the parent",
            )?;
            check_rewrapped(s, grants, &s.subtree(*id))?;
            let n = s.nodes.get_mut(id).unwrap();
            n.name = name.clone();
            n.name_commit = *name_commit;
            for g in grants {
                s.grants.insert(g.id, g.clone());
            }
        }
        Op::MoveNode {
            id,
            parent,
            wrapped_key,
            name,
            name_commit,
            grants,
        } => {
            let old_parent = parent_of(s, *id)?;
            node_exists(s, *parent)?;
            require(
                !s.subtree(*id).contains(parent),
                "cannot move a folder into itself",
            )?;
            require(
                s.has_right(author, old_parent, Right::Write),
                "requires `write` on the old parent",
            )?;
            require(
                s.has_right(author, *parent, Right::Write),
                "requires `write` on the new parent",
            )?;
            check_rewrapped(s, grants, &s.subtree(*id))?;
            let n = s.nodes.get_mut(id).unwrap();
            n.parent = Some(*parent);
            n.wrapped_key = Some(wrapped_key.clone());
            n.name = name.clone();
            n.name_commit = *name_commit;
            for g in grants {
                s.grants.insert(g.id, g.clone());
            }
        }
        Op::DeleteNode { id } => {
            let parent = parent_of(s, *id)?;
            require(
                s.has_right(author, parent, Right::Write),
                "requires `write` on the parent",
            )?;
            let sub: BTreeSet<Id> = s.subtree(*id).into_iter().collect();
            s.nodes.retain(|k, _| !sub.contains(k));
            s.remove_grants_where(|g| sub.contains(&g.node));
            s.rotation.retain(|k| !sub.contains(k));
        }
        Op::Grant { grant } => {
            node_exists(s, grant.node)?;
            check_principal(s, grant.to)?;
            require(!s.grants.contains_key(&grant.id), "grant id already exists")?;
            require(
                !s.grants
                    .values()
                    .any(|g| g.node == grant.node && g.to == grant.to),
                "the recipient already holds a grant on this node",
            )?;
            let own = s.effective_right(author, grant.node);
            let needed = if grant.right <= Right::Write {
                Right::Share
            } else {
                Right::Admin
            };
            require(
                own.is_some_and(|r| r >= needed),
                &format!("requires `{}` on the node", needed.as_str()),
            )?;
            require(
                own.is_some_and(|r| r >= grant.right),
                "cannot grant more than one holds",
            )?;
            s.grants.insert(grant.id, grant.clone());
        }
        Op::Revoke { grant } => {
            let g = s.grants.get(grant).ok_or_else(|| deny("unknown grant"))?;
            require(
                s.has_right(author, g.node, Right::Admin),
                "requires `admin` on the node",
            )?;
            require(
                !(g.node == s.root && g.to == Principal::User(s.master)),
                "the master's grant on the root cannot be revoked",
            )?;
            s.grants.remove(grant);
        }
        Op::Rekey {
            node,
            nodes,
            grants,
        } => {
            node_exists(s, *node)?;
            if *node == s.root {
                require(s.is_master(author), "only the master can rekey the root")?;
            } else {
                let parent = parent_of(s, *node)?;
                require(
                    s.has_right(author, parent, Right::Admin),
                    "requires `admin` on the parent",
                )?;
            }
            let sub = s.subtree(*node);
            let expected: BTreeSet<Id> = sub.iter().copied().collect();
            let got: BTreeSet<Id> = nodes.iter().map(|n| n.id).collect();
            require(
                expected == got && got.len() == nodes.len(),
                "rekey must cover the whole subtree",
            )?;
            let expected: BTreeSet<Id> = s.grants_on(&sub).iter().map(|g| g.id).collect();
            let got: BTreeSet<Id> = grants.iter().map(|g| g.id).collect();
            require(
                expected == got,
                "rekey must re-issue all grants in the subtree",
            )?;
            check_rewrapped(s, grants, &sub)?;
            for rn in nodes {
                let n = s.nodes.get_mut(&rn.id).unwrap();
                require(
                    rn.wrapped_key.is_some() == n.parent.is_some(),
                    "wrapped key mismatch",
                )?;
                n.wrapped_key = rn.wrapped_key.clone();
                n.name = rn.name.clone();
                n.name_commit = rn.name_commit;
                n.content = rn.content.clone();
            }
            for g in grants {
                s.grants.insert(g.id, g.clone());
            }
            if *node == s.root {
                s.former_master = None;
            }
        }
        Op::GrantSystemRight {
            user,
            right,
            delegate,
        } => {
            require(s.active(*user), "unknown or disabled user")?;
            require(
                s.is_master(author) || s.sys_right(author, *right) == Some(true),
                "requires the same right with `+delegate`",
            )?;
            if let SysRight::GroupAdmin(g) = right {
                let g = s.groups.get(g).ok_or_else(|| deny("unknown group"))?;
                require(
                    g.members.contains_key(user),
                    "`group-admin` can only be granted to a member",
                )?;
            }
            s.sysrights
                .entry(*user)
                .or_default()
                .insert(*right, *delegate);
        }
        Op::RevokeSystemRight { user, right } => {
            require(
                s.is_master(author) || s.sys_right(author, *right) == Some(true),
                "requires the same right with `+delegate`",
            )?;
            let m = s
                .sysrights
                .get_mut(user)
                .ok_or_else(|| deny("the user holds no such right"))?;
            require(m.remove(right).is_some(), "the user holds no such right")?;
        }
        Op::MarkRotation { node } => {
            node_exists(s, *node)?;
            require(
                s.has_right(author, *node, Right::Write),
                "requires `write` on the node",
            )?;
            s.rotation.insert(*node);
        }
        Op::ClearRotation { node } => {
            node_exists(s, *node)?;
            require(
                s.has_right(author, *node, Right::Write),
                "requires `write` on the node",
            )?;
            s.rotation.remove(node);
        }
        Op::TransferMaster { user } => {
            require(
                s.is_master(author),
                "only the master can transfer the master role",
            )?;
            require(s.active(*user), "unknown or disabled user")?;
            if *user != author {
                s.master = *user;
                s.former_master = Some(author);
            }
        }
    }
    Ok(())
}
