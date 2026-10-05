//! The key hierarchy (§6) as seen by one identity: identity → (group key) → grant → node key →
//! `wrap_key` → child key → … → `blob_key`.

use std::collections::BTreeMap;

use crate::crypto::{self, KemSecret, Key32, Sealed};
use crate::error::{Error, Result};
use crate::format::{from_cbor, to_cbor};
use crate::identity::Keys;
use crate::memory::LockedSeed;
use crate::model::*;

// ---------------------------------------------------------------- Keys and AADs

pub fn blob_key(nk: &[u8; 32]) -> Key32 {
    crypto::derive_key(nk, "blob")
}

pub fn wrap_key(nk: &[u8; 32]) -> Key32 {
    crypto::derive_key(nk, "wrap")
}

fn aad(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

pub fn aad_node_key(vault: Id, node: Id) -> Vec<u8> {
    aad(&[&vault.0, &node.0, b"node-key"])
}

pub fn aad_name(vault: Id, node: Id) -> Vec<u8> {
    aad(&[&vault.0, &node.0, b"name"])
}

pub fn aad_content(vault: Id, node: Id) -> Vec<u8> {
    aad(&[&vault.0, &node.0, b"content"])
}

pub fn aad_grant(vault: Id, node: Id, to: Principal) -> Vec<u8> {
    let kind: &[u8] = match to {
        Principal::User(_) => b"user",
        Principal::Group(_) => b"group",
    };
    aad(&[&vault.0, &node.0, kind, &to.id().0, b"grant"])
}

pub fn aad_member(vault: Id, group: Id, user: Id) -> Vec<u8> {
    aad(&[&vault.0, &group.0, &user.0, b"group-member"])
}

/// Salt of a node's name commitment, derived from its node key: known to everyone who can read
/// the node and handed to holders of grants below it (inside their encrypted grant payload).
pub fn name_salt(nk: &[u8; 32]) -> [u8; 32] {
    *crypto::derive_key(nk, "name-salt")
}

pub fn name_commit(vault: Id, node: Id, salt: &[u8; 32], name: &str) -> [u8; 32] {
    crypto::sha3(&[
        b"nepomuk/name",
        &crypto::framed(&[&vault.0, &node.0, salt, name.as_bytes()]),
    ])
}

/// An encrypted name and its public commitment.
pub struct SealedName {
    pub sealed: Sealed,
    pub commit: [u8; 32],
}

pub fn seal_name(vault: Id, node: Id, nk: &[u8; 32], name: &str) -> SealedName {
    SealedName {
        sealed: crypto::seal_padded(&blob_key(nk), name.as_bytes(), &aad_name(vault, node)),
        commit: name_commit(vault, node, &name_salt(nk), name),
    }
}

/// A path together with the name salts that prove it against the public commitments.
#[derive(Clone, Debug)]
pub struct PathProof {
    pub path: String,
    /// One salt per path component, outermost first.
    pub salts: Vec<[u8; 32]>,
}

impl PathProof {
    pub fn root() -> PathProof {
        PathProof {
            path: "/".into(),
            salts: Vec::new(),
        }
    }

    pub fn child(&self, name: &str, salt: [u8; 32]) -> PathProof {
        let mut salts = self.salts.clone();
        salts.push(salt);
        PathProof {
            path: join(&self.path, name),
            salts,
        }
    }
}

/// The path components of a normalized path (`/` has none).
pub fn components(path: &str) -> Vec<&str> {
    path.split('/').filter(|c| !c.is_empty()).collect()
}

/// Checks a path claimed for `node` against the tree (§6): it must have one component per level
/// below the root, and each component must match the public name commitment of the node at that
/// level. Nobody can claim a location for a node other than the one it has in the tree, because
/// the commitments of the real ancestors are set only by those who may write there.
pub fn check_path(state: &State, node: Id, path: &str, salts: &[[u8; 32]]) -> bool {
    let mut chain = state.ancestors(node);
    chain.reverse();
    if chain.first() != Some(&state.root)
        || state
            .nodes
            .get(&state.root)
            .is_none_or(|r| r.parent.is_some())
    {
        return false;
    }
    let comps = components(path);
    // Only the canonical spelling: "/" or "/a/b" with valid names, so that a proven path is
    // exactly what `resolve` and path arithmetic expect.
    let canonical = if comps.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", comps.join("/"))
    };
    if path != canonical || comps.iter().any(|c| crate::tx::validate_name(c).is_err()) {
        return false;
    }
    if comps.len() + 1 != chain.len() || salts.len() != comps.len() {
        return false;
    }
    chain[1..]
        .iter()
        .zip(comps.iter().zip(salts))
        .all(|(id, (name, salt))| {
            state
                .nodes
                .get(id)
                .is_some_and(|n| n.name_commit == name_commit(state.vault_id, *id, salt, name))
        })
}

pub fn seal_content(vault: Id, node: Id, nk: &[u8; 32], c: &NodeContent) -> Sealed {
    let bytes = zeroize::Zeroizing::new(to_cbor(c));
    crypto::seal_padded(&blob_key(nk), &bytes, &aad_content(vault, node))
}

pub fn seal_node_key(vault: Id, node: Id, parent_nk: &[u8; 32], nk: &[u8; 32]) -> Sealed {
    crypto::seal(&wrap_key(parent_nk), nk, &aad_node_key(vault, node))
}

fn to_key32(v: &[u8]) -> Result<Key32> {
    let a: [u8; 32] = v.try_into().map_err(|_| Error::decrypt())?;
    Ok(zeroize::Zeroizing::new(a))
}

// ---------------------------------------------------------------- Access view

pub struct Visible {
    pub key: Key32,
    pub path: String,
    pub name: String,
    /// Salts of the path components (see [`PathProof`]).
    pub salts: Vec<[u8; 32]>,
}

pub struct Access {
    pub vault: Id,
    pub me: Id,
    /// Group seeds and key pairs for groups the identity is a member of.
    pub groups: BTreeMap<Id, (LockedSeed, KemSecret)>,
    pub nodes: BTreeMap<Id, Visible>,
    /// Grants readable by this identity: grant id → (node, right).
    pub my_grants: BTreeMap<Id, (Id, Right)>,
    /// Grants addressed to this identity whose path does not match the tree; they are ignored.
    pub unproven: Vec<Id>,
}

pub fn join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

impl Access {
    pub fn build(state: &State, me: Id, id: &dyn Keys) -> Access {
        let vault = state.vault_id;
        let mut acc = Access {
            vault,
            me,
            groups: BTreeMap::new(),
            nodes: BTreeMap::new(),
            my_grants: BTreeMap::new(),
            unproven: Vec::new(),
        };
        if !state.active(me) {
            return acc;
        }
        for g in state.groups.values() {
            if let Some(w) = g.members.get(&me)
                && let Ok(seed) = id.unwrap(w, &aad_member(vault, g.id, me))
                && let Ok(seed) = LockedSeed::from_slice(&seed)
            {
                let kem = KemSecret::from_seed(seed.as_ref(), "group");
                if kem.public() == &g.kem {
                    acc.groups.insert(g.id, (seed, kem));
                }
            }
        }
        let mut roots: Vec<(Id, Key32, PathProof)> = Vec::new();
        for gr in state.grants.values() {
            let aad = aad_grant(vault, gr.node, gr.to);
            let bytes = match gr.to {
                Principal::User(u) if u == me => id.unwrap(&gr.wrapped, &aad),
                Principal::Group(g) => match acc.groups.get(&g) {
                    Some((_, k)) => crypto::unwrap(k, &gr.wrapped, &aad),
                    None => continue,
                },
                _ => continue,
            };
            let Ok(bytes) = bytes else {
                continue;
            };
            let Ok(payload) = from_cbor::<GrantPayload>(&bytes) else {
                continue;
            };
            let Ok(nk) = to_key32(&payload.node_key) else {
                continue;
            };
            let Some(n) = state.nodes.get(&gr.node) else {
                continue;
            };
            let salts: Option<Vec<[u8; 32]>> = payload
                .salts
                .iter()
                .map(|s| s.as_slice().try_into().ok())
                .collect();
            // The path is chosen by whoever issued the grant: accept it only when it matches
            // the node's real location in the tree and the node's own name.
            let proven = salts.filter(|salts| {
                check_path(state, gr.node, &payload.path, salts)
                    && (gr.node == state.root || salts.last() == Some(&name_salt(&nk)))
                    && open_name(vault, n, &nk).is_ok_and(|name| {
                        gr.node == state.root
                            || components(&payload.path).last() == Some(&name.as_str())
                    })
            });
            let Some(salts) = proven else {
                acc.unproven.push(gr.id);
                continue;
            };
            acc.my_grants.insert(gr.id, (gr.node, gr.right));
            roots.push((
                gr.node,
                nk,
                PathProof {
                    path: payload.path.clone(),
                    salts,
                },
            ));
        }
        // Shallowest grants first so that paths come from the highest reachable grant.
        roots.sort_by_key(|(n, _, _)| state.ancestors(*n).len());
        for (node, nk, proof) in roots {
            if acc.nodes.contains_key(&node) {
                continue;
            }
            let Some(n) = state.nodes.get(&node) else {
                continue;
            };
            let Ok(name) = open_name(vault, n, &nk) else {
                continue;
            };
            acc.descend(state, node, nk, proof, name);
        }
        acc
    }

    fn descend(&mut self, state: &State, node: Id, nk: Key32, proof: PathProof, name: String) {
        let mut stack = vec![(node, nk, proof, name)];
        while let Some((id, key, proof, name)) = stack.pop() {
            if self.nodes.contains_key(&id) {
                continue;
            }
            let wk = wrap_key(&key);
            for child in state.children(id) {
                let c = &state.nodes[&child];
                let Some(w) = &c.wrapped_key else { continue };
                let Ok(ck) = crypto::open(&wk, w, &aad_node_key(self.vault, child)) else {
                    continue;
                };
                let Ok(ck) = to_key32(&ck) else { continue };
                let Ok(cname) = open_name(self.vault, c, &ck) else {
                    continue;
                };
                // Names are checked only by honest writers: one with `/`, control or bidi
                // characters would forge paths or terminal output for every reader.
                if crate::tx::validate_name(&cname).is_err() {
                    continue;
                }
                let salt = name_salt(&ck);
                if c.name_commit != name_commit(self.vault, child, &salt, &cname) {
                    continue;
                }
                stack.push((child, ck, proof.child(&cname, salt), cname));
            }
            self.nodes.insert(
                id,
                Visible {
                    key,
                    path: proof.path,
                    name,
                    salts: proof.salts,
                },
            );
        }
    }

    /// The node at `path`; none when nothing or more than one visible node has that path.
    pub fn resolve(&self, path: &str) -> Option<Id> {
        let mut found = self.nodes.iter().filter(|(_, v)| v.path == path);
        match (found.next(), found.next()) {
            (Some((id, _)), None) => Some(*id),
            _ => None,
        }
    }

    /// Whether at least one visible node has `path`.
    pub fn exists(&self, path: &str) -> bool {
        self.nodes.values().any(|v| v.path == path)
    }

    /// Whether more than one visible node has `path` (two siblings with the same name).
    pub fn ambiguous(&self, path: &str) -> bool {
        self.nodes.values().filter(|v| v.path == path).count() > 1
    }

    /// The proven path of a visible node.
    pub fn proof(&self, node: Id) -> Option<PathProof> {
        self.nodes.get(&node).map(|v| PathProof {
            path: v.path.clone(),
            salts: v.salts.clone(),
        })
    }

    pub fn key(&self, node: Id) -> Option<&Key32> {
        self.nodes.get(&node).map(|v| &v.key)
    }

    pub fn path(&self, node: Id) -> Option<&str> {
        self.nodes.get(&node).map(|v| v.path.as_str())
    }

    pub fn content(&self, state: &State, node: Id) -> Result<NodeContent> {
        let v = self
            .nodes
            .get(&node)
            .ok_or_else(|| Error::access_denied(&node.hex()))?;
        let n = state
            .nodes
            .get(&node)
            .ok_or_else(|| Error::not_found(&v.path))?;
        let bytes = crypto::open_padded(
            &blob_key(&v.key),
            &n.content,
            &aad_content(self.vault, node),
        )?;
        from_cbor(&bytes)
    }

    pub fn group_kem(&self, group: Id) -> Option<&KemSecret> {
        self.groups.get(&group).map(|(_, k)| k)
    }
}

fn open_name(vault: Id, n: &Node, nk: &[u8; 32]) -> Result<String> {
    let b = crypto::open_padded(&blob_key(nk), &n.name, &aad_name(vault, n.id))?;
    String::from_utf8(b.to_vec()).map_err(|_| Error::decrypt())
}

/// Wraps a grant payload for a recipient.
pub fn make_grant(
    state: &State,
    id: Id,
    node: Id,
    to: Principal,
    right: Right,
    nk: &[u8; 32],
    proof: &PathProof,
) -> Result<Grant> {
    let kem = match to {
        Principal::User(u) => {
            &state
                .users
                .get(&u)
                .ok_or_else(|| Error::not_found("user"))?
                .kem
        }
        Principal::Group(g) => {
            &state
                .groups
                .get(&g)
                .ok_or_else(|| Error::not_found("group"))?
                .kem
        }
    };
    let payload = zeroize::Zeroizing::new(to_cbor(&GrantPayload {
        node_key: nk.to_vec(),
        path: proof.path.clone(),
        salts: proof
            .salts
            .iter()
            .map(|s| serde_bytes::ByteBuf::from(s.to_vec()))
            .collect(),
        right,
    }));
    let wrapped = crypto::wrap(kem, &payload, &aad_grant(state.vault_id, node, to))?;
    Ok(Grant {
        id,
        node,
        to,
        right,
        wrapped,
    })
}
