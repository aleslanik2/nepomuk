//! Read-only commands. They decrypt only the path to what is requested (§6).

use std::collections::BTreeMap;

use base64::Engine;
use serde_json::{Value, json};

use crate::app::{Ctx, Opened, sysright_name};
use crate::error::{Error, Result};
use crate::keyring::Access;
use crate::model::*;
use crate::tx::{self, find_me, principal_name};

pub const EXPIRY_WARNING_DAYS: i64 = 30;

pub fn access_for(ctx: &Ctx, o: &Opened) -> Result<(Id, Access)> {
    let id = ctx.unlock(&o.v.state)?;
    let me = find_me(&o.v.state, &*id)?;
    Ok((me, Access::build(&o.v.state, me, &*id)))
}

fn iso(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default()
}

fn entry(state: &State, acc: &Access, id: Id) -> Value {
    let v = &acc.nodes[&id];
    let c = acc.content(state, id).ok();
    let mut e = json!({
        "path": v.path,
        "name": v.name,
        "type": c.as_ref().map(|c| c.content.type_name()).unwrap_or("?"),
        "rotation_pending": state.rotation.contains(&id),
    });
    if let Some(c) = &c {
        e["updated"] = json!(iso(c.meta.updated));
        match &c.content {
            Content::Record { template, fields } => {
                e["template"] = json!(template);
                e["fields"] = json!(fields.keys().collect::<Vec<_>>());
                let types: serde_json::Map<String, Value> = fields
                    .iter()
                    .map(|(k, f)| {
                        let t = match f {
                            Field::Text { .. } => json!({ "type": "text" }),
                            Field::Binary { mime, data } => {
                                json!({ "type": "binary", "mime": mime, "size": data.len() })
                            }
                        };
                        (k.clone(), t)
                    })
                    .collect();
                e["field_types"] = Value::Object(types);
            }
            Content::Binary { mime, data } => {
                e["mime"] = json!(mime);
                e["size"] = json!(data.len());
            }
            _ => {}
        }
        if let Some(na) = c.meta.not_after {
            e["expires"] = json!(iso(na));
            e["expiring_soon"] = json!(na - tx::now() < EXPIRY_WARNING_DAYS * 86400);
        }
    }
    e
}

pub fn ls(ctx: &Ctx, o: &Opened, path: Option<&str>, recursive: bool) -> Result<Value> {
    let (_, acc) = access_for(ctx, o)?;
    let state = &o.v.state;
    let sort = |mut v: Vec<Id>| {
        v.sort_by(|a, b| acc.nodes[a].path.cmp(&acc.nodes[b].path));
        v
    };
    let roots: Vec<Id> = match path {
        Some(p) => {
            let p = tx::normalize_path(&ctx.path(p))?;
            match acc.resolve(&p) {
                Some(id) => vec![id],
                None if state.nodes.is_empty() => return Err(Error::not_found(&p)),
                None => {
                    // Parent folders of a grant are not readable; show grants below the path.
                    let prefix = if p == "/" {
                        "/".to_string()
                    } else {
                        format!("{p}/")
                    };
                    let below: Vec<Id> = acc
                        .nodes
                        .iter()
                        .filter(|(id, v)| {
                            v.path.starts_with(&prefix)
                                && !acc
                                    .nodes
                                    .contains_key(&state.nodes[id].parent.unwrap_or(**id))
                        })
                        .map(|(id, _)| *id)
                        .collect();
                    if below.is_empty() {
                        return Err(Error::not_found(&p));
                    }
                    return Ok(
                        json!({ "path": p, "entries": sort(below).into_iter().map(|i| entry(state, &acc, i)).collect::<Vec<_>>() }),
                    );
                }
            }
        }
        None => {
            let visible_roots: Vec<Id> = acc
                .nodes
                .keys()
                .filter(|id| {
                    state.nodes[id]
                        .parent
                        .is_none_or(|p| !acc.nodes.contains_key(&p))
                })
                .copied()
                .collect();
            if visible_roots.is_empty() {
                return Ok(json!({ "path": "/", "entries": [] }));
            }
            visible_roots
        }
    };
    let mut entries = Vec::new();
    let single_root_folder = roots.len() == 1
        && acc
            .content(state, roots[0])
            .map(|c| matches!(c.content, Content::Folder))
            .unwrap_or(false);
    let list_path = if single_root_folder {
        acc.nodes[&roots[0]].path.clone()
    } else {
        "/".to_string()
    };
    let mut stack: Vec<Id> = if single_root_folder {
        sort(
            state
                .children(roots[0])
                .into_iter()
                .filter(|c| acc.nodes.contains_key(c))
                .collect(),
        )
    } else {
        sort(roots)
    };
    stack.reverse();
    while let Some(id) = stack.pop() {
        entries.push(entry(state, &acc, id));
        if recursive {
            let mut kids = sort(
                state
                    .children(id)
                    .into_iter()
                    .filter(|c| acc.nodes.contains_key(c))
                    .collect(),
            );
            kids.reverse();
            stack.extend(kids);
        }
    }
    Ok(json!({ "path": list_path, "entries": entries }))
}

pub fn missing(acc: &Access, path: &str) -> Error {
    tx::missing(acc, path)
}

/// Splits `path#field`.
pub fn split_field(p: &str) -> (&str, Option<&str>) {
    match p.split_once('#') {
        Some((a, b)) => (a, Some(b)),
        None => (p, None),
    }
}

/// Raw bytes of a secret or a record field.
pub fn get_bytes(ctx: &Ctx, o: &Opened, spec: &str) -> Result<(String, Vec<u8>, bool)> {
    let (path, field) = split_field(spec);
    let path = tx::normalize_path(&ctx.path(path))?;
    let (_, acc) = access_for(ctx, o)?;
    let id = acc.resolve(&path).ok_or_else(|| missing(&acc, &path))?;
    let c = acc.content(&o.v.state, id)?;
    Ok(match (&c.content, field) {
        (Content::Text { value }, None) => (path, value.as_bytes().to_vec(), false),
        (Content::Binary { data, .. }, None) => (path, data.clone(), true),
        (Content::Record { fields, .. }, Some(f)) => match fields.get(f) {
            Some(Field::Text { value }) => {
                (format!("{path}#{f}"), value.as_bytes().to_vec(), false)
            }
            Some(Field::Binary { data, .. }) => (format!("{path}#{f}"), data.clone(), true),
            None => return Err(Error::not_found(&format!("{path}#{f}"))),
        },
        (Content::Record { .. }, None) => {
            return Err(Error::usage(format!(
                "{path} is a record; use {path}#<field>"
            )));
        }
        (Content::Folder, _) => return Err(Error::usage(format!("{path} is a folder"))),
        (_, Some(f)) => {
            return Err(Error::usage(format!(
                "{path} is not a record (no field {f})"
            )));
        }
    })
}

/// `node.get` / `get --json`: the secret with metadata; binary data base64-encoded.
pub fn get_json(ctx: &Ctx, o: &Opened, spec: &str) -> Result<Value> {
    let (path, field) = split_field(spec);
    if field.is_some() {
        let (p, bytes, binary) = get_bytes(ctx, o, spec)?;
        return Ok(value_json(&p, &bytes, binary));
    }
    let path = tx::normalize_path(&ctx.path(path))?;
    let (_, acc) = access_for(ctx, o)?;
    let id = acc.resolve(&path).ok_or_else(|| missing(&acc, &path))?;
    let c = acc.content(&o.v.state, id)?;
    let b64 = |d: &[u8]| base64::engine::general_purpose::STANDARD.encode(d);
    let mut out = entry(&o.v.state, &acc, id);
    match &c.content {
        Content::Text { value } => out["value"] = json!(value),
        Content::Binary { mime, data } => {
            out["mime"] = json!(mime);
            out["base64"] = json!(b64(data));
        }
        Content::Record { fields, .. } => {
            let mut m = serde_json::Map::new();
            for (k, f) in fields {
                m.insert(
                    k.clone(),
                    match f {
                        Field::Text { value } => json!({ "type": "text", "value": value }),
                        Field::Binary { mime, data } => {
                            json!({ "type": "binary", "mime": mime, "base64": b64(data) })
                        }
                    },
                );
            }
            out["fields"] = Value::Object(m);
        }
        Content::Folder => return Err(Error::usage(format!("{path} is a folder"))),
    }
    Ok(out)
}

fn value_json(path: &str, bytes: &[u8], binary: bool) -> Value {
    if binary {
        json!({ "path": path, "type": "binary", "base64": base64::engine::general_purpose::STANDARD.encode(bytes) })
    } else {
        json!({ "path": path, "type": "text", "value": String::from_utf8_lossy(bytes) })
    }
}

/// Who can access a path (§13 "who has access to this folder").
pub fn access(ctx: &Ctx, o: &Opened, path: &str) -> Result<Value> {
    let path = tx::normalize_path(&ctx.path(path))?;
    let (_, acc) = access_for(ctx, o)?;
    let s = &o.v.state;
    let id = acc.resolve(&path).ok_or_else(|| missing(&acc, &path))?;
    let chain = s.ancestors(id);
    let grants: Vec<Value> = s
        .grants
        .values()
        .filter(|g| chain.contains(&g.node))
        .map(|g| {
            json!({
                "principal": principal_name(s, g.to),
                "right": g.right.as_str(),
                "on": acc.path(g.node).unwrap_or("(a parent folder)"),
                "inherited": g.node != id,
            })
        })
        .collect();
    let mut effective: Vec<Value> = s
        .users
        .values()
        .filter_map(|u| s.effective_right(u.id, id).map(|r| (u, r)))
        .map(|(u, r)| json!({ "user": u.name, "right": r.as_str(), "master": s.is_master(u.id) }))
        .collect();
    effective.sort_by(|a, b| a["user"].as_str().cmp(&b["user"].as_str()));
    Ok(json!({ "path": path, "grants": grants, "effective": effective }))
}

/// What a user can access (§13), limited to what the viewer can see.
pub fn user_access(ctx: &Ctx, o: &Opened, name: &str) -> Result<Value> {
    let (_, acc) = access_for(ctx, o)?;
    let s = &o.v.state;
    let u = s
        .user_by_name(name)
        .ok_or_else(|| Error::not_found(&format!("user {name}")))?;
    let mut entries: Vec<Value> = acc
        .nodes
        .iter()
        .filter_map(|(id, v)| {
            let own = s.effective_right(u.id, *id)?;
            // Report only where the right starts, not every descendant.
            let parent = s.nodes[id].parent;
            let inherited = parent.is_some_and(|p| {
                s.effective_right(u.id, p) == Some(own) && acc.nodes.contains_key(&p)
            });
            (!inherited).then(|| json!({ "path": v.path, "right": own.as_str() }))
        })
        .collect();
    entries.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    Ok(
        json!({ "user": u.name, "master": s.is_master(u.id), "disabled": u.disabled, "access": entries }),
    )
}

pub fn whoami(ctx: &Ctx, o: &Opened) -> Result<Value> {
    let (me, acc) = access_for(ctx, o)?;
    let s = &o.v.state;
    let u = &s.users[&me];
    let sys: Vec<Value> = s
        .sysrights
        .get(&me)
        .map(|m| {
            m.iter()
                .map(|(r, d)| json!({ "right": sysright_name(s, *r), "delegate": d }))
                .collect()
        })
        .unwrap_or_default();
    let grants: Vec<Value> = acc
        .my_grants
        .values()
        .map(|(n, r)| json!({ "path": acc.path(*n).unwrap_or("?"), "right": r.as_str() }))
        .collect();
    Ok(json!({
        "name": u.name,
        "kind": u.kind,
        "fingerprint": crate::verify::user_fp(u),
        "user_id": me.hex(),
        "master": s.is_master(me),
        "groups": s.user_groups(me).iter().map(|g| s.groups[g].name.clone()).collect::<Vec<_>>(),
        "system_rights": sys,
        "grants": grants,
    }))
}

pub fn info(o: &Opened) -> Value {
    let s = &o.v.state;
    json!({
        "vault": o.loc.path.display().to_string(),
        "vault_id": s.vault_id.hex(),
        "format_version": crate::format::FORMAT_VERSION,
        "suite": crate::crypto::SUITE,
        "seq": o.v.seq,
        "checkpoint_seq": o.v.checkpoint_seq,
        "master": s.users[&s.master].name,
        "master_fingerprint": o.v.master_fp,
        "users": s.users.values().filter(|u| !u.disabled).count(),
        "disabled_users": s.users.values().filter(|u| u.disabled).count(),
        "groups": s.groups.len(),
        "nodes": s.nodes.len(),
        "grants": s.grants.len(),
        "pending_rotation": s.rotation.len(),
        "size": o.loaded.bytes.len(),
        "git": o.loc.is_git(),
    })
}

pub fn log(ctx: &Ctx, o: &Opened, limit: Option<usize>) -> Result<Value> {
    let s = &o.v.state;
    // Names of touched nodes are shown only where the reader has access.
    let acc = ctx
        .unlock(s)
        .ok()
        .and_then(|id| find_me(s, &*id).ok().map(|me| Access::build(s, me, &*id)));
    let mut commits: Vec<Value> =
        o.v.commits
            .iter()
            .rev()
            .map(|c| {
                let paths: Vec<&str> = c
                    .touched
                    .iter()
                    .filter_map(|n| acc.as_ref().and_then(|a| a.path(*n)))
                    .collect();
                json!({
                    "seq": c.seq,
                    "time": iso(c.time),
                    "author": s.users.get(&c.author).map(|u| u.name.as_str()).unwrap_or("?"),
                    "operations": c.ops,
                    "paths": paths,
                    "hash": hex::encode(c.hash),
                })
            })
            .collect();
    if let Some(l) = limit {
        commits.truncate(l);
    }
    Ok(json!({ "seq": o.v.seq, "checkpoint_seq": o.v.checkpoint_seq, "commits": commits }))
}

pub fn users(o: &Opened) -> Value {
    let s = &o.v.state;
    let list: Vec<Value> = s
        .users
        .values()
        .map(|u| {
            let sys: Vec<String> = s
                .sysrights
                .get(&u.id)
                .map(|m| m.iter().map(|(r, d)| format!("{}{}", sysright_name(s, *r), if *d { "+delegate" } else { "" })).collect())
                .unwrap_or_default();
            json!({
                "name": u.name,
                "kind": u.kind,
                "fingerprint": crate::verify::user_fp(u),
                "disabled": u.disabled,
                "master": s.is_master(u.id),
                "groups": s.user_groups(u.id).iter().map(|g| s.groups[g].name.clone()).collect::<Vec<_>>(),
                "system_rights": sys,
            })
        })
        .collect();
    json!({ "users": list })
}

pub fn groups(o: &Opened) -> Value {
    let s = &o.v.state;
    let list: Vec<Value> = s
        .groups
        .values()
        .map(|g| {
            let admins: Vec<&str> = s
                .sysrights
                .iter()
                .filter(|(_, m)| m.contains_key(&SysRight::GroupAdmin(g.id)))
                .filter_map(|(u, _)| s.users.get(u).map(|u| u.name.as_str()))
                .collect();
            json!({
                "name": g.name,
                "members": g.members.keys().filter_map(|u| s.users.get(u).map(|u| u.name.clone())).collect::<Vec<_>>(),
                "admins": admins,
                "grants": s.grants.values().filter(|x| x.to == Principal::Group(g.id)).count(),
            })
        })
        .collect();
    json!({ "groups": list })
}

pub fn rotation_list(ctx: &Ctx, o: &Opened) -> Result<Value> {
    let s = &o.v.state;
    let acc = access_for(ctx, o).ok().map(|(_, a)| a);
    let list: Vec<Value> = s
        .rotation
        .iter()
        .map(|n| {
            json!({
                "node": n.hex(),
                "path": acc.as_ref().and_then(|a| a.path(*n)).unwrap_or("(no access)"),
            })
        })
        .collect();
    Ok(json!({ "pending_rotation": list }))
}

pub fn expiring(ctx: &Ctx, o: &Opened) -> Result<Vec<String>> {
    let (_, acc) = access_for(ctx, o)?;
    let mut out = Vec::new();
    for id in acc.nodes.keys() {
        if let Ok(c) = acc.content(&o.v.state, *id)
            && let Some(na) = c.meta.not_after
            && na - tx::now() < EXPIRY_WARNING_DAYS * 86400
        {
            out.push(format!("{} expires {}", acc.nodes[id].path, iso(na)));
        }
    }
    Ok(out)
}

pub type Secrets = Vec<(String, zeroize::Zeroizing<Vec<u8>>)>;

/// Values of an exec profile (§11.3): environment variables and files.
pub fn profile_values(
    ctx: &Ctx,
    o: &Opened,
    profile: &crate::config::Profile,
) -> Result<(Secrets, Secrets)> {
    let mut env = Vec::new();
    let mut files = Vec::new();
    let mut cache: BTreeMap<String, zeroize::Zeroizing<Vec<u8>>> = BTreeMap::new();
    let mut fetch = |spec: &str| -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if let Some(v) = cache.get(spec) {
            return Ok(v.clone());
        }
        let (_, bytes, _) = get_bytes(ctx, o, spec)?;
        let v = zeroize::Zeroizing::new(bytes);
        cache.insert(spec.to_string(), v.clone());
        Ok(v)
    };
    for (var, spec) in &profile.env {
        env.push((var.clone(), fetch(spec)?));
    }
    for (var, spec) in &profile.file {
        files.push((var.clone(), fetch(spec)?));
    }
    Ok((env, files))
}
