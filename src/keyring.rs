//! The key hierarchy (§6) as seen by one identity: identity → (group key) → grant → node key →
//! `wrap_key` → child key → … → `blob_key`.

use std::collections::BTreeMap;

use crate::crypto::{self, KemSecret, Key32, Sealed};
use crate::error::{Error, Result};
use crate::format::{from_cbor, to_cbor};
use crate::identity::Unlocked;
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

pub fn seal_name(vault: Id, node: Id, nk: &[u8; 32], name: &str) -> Sealed {
    crypto::seal_padded(&blob_key(nk), name.as_bytes(), &aad_name(vault, node))
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
}

pub struct Access {
    pub vault: Id,
    pub me: Id,
    /// Group seeds and key pairs for groups the identity is a member of.
    pub groups: BTreeMap<Id, (LockedSeed, KemSecret)>,
    pub nodes: BTreeMap<Id, Visible>,
    /// Grants readable by this identity: grant id → (node, right).
    pub my_grants: BTreeMap<Id, (Id, Right)>,
}

pub fn join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

impl Access {
    pub fn build(state: &State, me: Id, id: &Unlocked) -> Access {
        let vault = state.vault_id;
        let mut acc = Access {
            vault,
            me,
            groups: BTreeMap::new(),
            nodes: BTreeMap::new(),
            my_grants: BTreeMap::new(),
        };
        if !state.active(me) {
            return acc;
        }
        for g in state.groups.values() {
            if let Some(w) = g.members.get(&me)
                && let Ok(seed) = crypto::unwrap(&id.kem, w, &aad_member(vault, g.id, me))
                && let Ok(seed) = LockedSeed::from_slice(&seed)
            {
                let kem = KemSecret::from_seed(seed.as_ref(), "group");
                if kem.public() == &g.kem {
                    acc.groups.insert(g.id, (seed, kem));
                }
            }
        }
        let mut roots: Vec<(Id, Key32, String)> = Vec::new();
        for gr in state.grants.values() {
            let kem = match gr.to {
                Principal::User(u) if u == me => &id.kem,
                Principal::Group(g) => match acc.groups.get(&g) {
                    Some((_, k)) => k,
                    None => continue,
                },
                _ => continue,
            };
            let Ok(bytes) = crypto::unwrap(kem, &gr.wrapped, &aad_grant(vault, gr.node, gr.to))
            else {
                continue;
            };
            let Ok(payload) = from_cbor::<GrantPayload>(&bytes) else {
                continue;
            };
            let Ok(nk) = to_key32(&payload.node_key) else {
                continue;
            };
            acc.my_grants.insert(gr.id, (gr.node, gr.right));
            roots.push((gr.node, nk, payload.path.clone()));
        }
        // Shallowest grants first so that paths come from the highest reachable grant.
        roots.sort_by_key(|(n, _, _)| state.ancestors(*n).len());
        for (node, nk, path) in roots {
            if acc.nodes.contains_key(&node) {
                continue;
            }
            let Some(n) = state.nodes.get(&node) else {
                continue;
            };
            let Ok(name) = open_name(vault, n, &nk) else {
                continue;
            };
            acc.descend(state, node, nk, path, name);
        }
        acc
    }

    fn descend(&mut self, state: &State, node: Id, nk: Key32, path: String, name: String) {
        let mut stack = vec![(node, nk, path, name)];
        while let Some((id, key, path, name)) = stack.pop() {
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
                let cpath = join(&path, &cname);
                stack.push((child, ck, cpath, cname));
            }
            self.nodes.insert(id, Visible { key, path, name });
        }
    }

    pub fn resolve(&self, path: &str) -> Option<Id> {
        self.nodes
            .iter()
            .find(|(_, v)| v.path == path)
            .map(|(id, _)| *id)
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
    path: &str,
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
        path: path.to_string(),
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
