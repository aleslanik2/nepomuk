//! `nepomuk serve --stdio` (§12.2): JSON-RPC 2.0 over stdin/stdout, one message per line.
//! Holds the unlocked identity for the session and forgets it after inactivity or on `lock`.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::app::{self, Ctx, Intent, Resolve};
use crate::error::{Code, Error, Result};
use crate::model::{Content, Field, Right};
use crate::queries;

const DEFAULT_TIMEOUT: u64 = 600;

fn send(v: &Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

fn notify(method: &str, params: Value) {
    send(&json!({ "jsonrpc": "2.0", "method": method, "params": params }));
}

fn p_str(p: &Value, k: &str) -> Result<String> {
    p.get(k)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| Error::usage(format!("missing parameter `{k}`")))
}

fn p_opt(p: &Value, k: &str) -> Option<String> {
    p.get(k).and_then(|v| v.as_str()).map(str::to_string)
}

fn p_bool(p: &Value, k: &str) -> bool {
    p.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn b64(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| Error::usage("invalid base64"))
}

fn intent(ctx: &Ctx, i: Intent) -> Result<Value> {
    app::execute(ctx, &i, None, Resolve::Ask)
}

fn content_from(p: &Value) -> Result<(Content, Option<i64>)> {
    content_from_json(p, true)
}

/// Content in the shape of `node.get` / `get --json`. With `validate`, a record must pass its
/// template's validation; without it, the validation only supplies the expiry when it can.
pub fn content_from_json(p: &Value, validate: bool) -> Result<(Content, Option<i64>)> {
    let t = p_opt(p, "type").unwrap_or_else(|| "text".into());
    Ok(match t.as_str() {
        "text" => (
            Content::Text {
                value: p_str(p, "value")?,
            },
            None,
        ),
        "binary" => (
            Content::Binary {
                mime: p_opt(p, "mime").unwrap_or_else(|| "application/octet-stream".into()),
                data: b64(&p_str(p, "base64")?)?,
            },
            None,
        ),
        "record" => {
            let template = p_opt(p, "template").unwrap_or_else(|| "generic".into());
            let mut fields = BTreeMap::new();
            let obj = p
                .get("fields")
                .and_then(|f| f.as_object())
                .ok_or_else(|| Error::usage("missing `fields`"))?;
            for (k, v) in obj {
                crate::tx::validate_name(k)?;
                let f = match v.get("type").and_then(|t| t.as_str()).unwrap_or("text") {
                    "binary" => Field::Binary {
                        mime: p_opt(v, "mime").unwrap_or_else(|| "application/octet-stream".into()),
                        data: b64(&p_str(v, "base64")?)?,
                    },
                    _ => Field::Text {
                        value: p_str(v, "value")?,
                    },
                };
                fields.insert(k.clone(), f);
            }
            let not_after = match crate::templates::validate(&template, &fields) {
                Ok(val) => val.not_after,
                Err(e) if validate => return Err(e),
                Err(_) => None,
            };
            (Content::Record { template, fields }, not_after)
        }
        other => return Err(Error::usage(format!("unknown type {other}"))),
    })
}

fn tp(ctx: &Ctx, p: &Value, k: &str) -> Result<String> {
    Ok(ctx.path(&p_str(p, k)?))
}

fn right(p: &Value) -> Result<Right> {
    let r = p_str(p, "right")?;
    Right::parse(&r).ok_or_else(|| Error::usage(format!("unknown right {r}")))
}

fn dispatch(ctx: &mut Ctx, method: &str, p: &Value) -> Result<Value> {
    match method {
        "version" => Ok(crate::cli::version_json()),
        "session.unlock" => {
            *ctx.unlocked.borrow_mut() = None;
            if let Some(e) = p_opt(p, "email") {
                ctx.opts.email = Some(e);
                ctx.opts.identity = None;
            }
            if let Some(i) = p_opt(p, "identity") {
                ctx.opts.identity = Some(i.into());
                ctx.opts.email = None;
            }
            let use_touchid = p_bool(p, "touchid");
            *ctx.purpose.borrow_mut() = Some(" in the nepomuk app".into());
            if !use_touchid {
                *ctx.password_override.borrow_mut() = Some(Zeroizing::new(p_str(p, "password")?));
            }
            // The app keeps its own session: a Touch ID unlock here must not also leave the
            // identity in the agent, where locking the app would not reach it.
            ctx.opts.touchid = use_touchid;
            ctx.opts.remember_touchid = p_bool(p, "remember_touchid");
            let result = app::open_vault(ctx, true).and_then(|o| {
                let id = ctx.unlock(&o.v.state)?;
                Ok(json!({ "name": id.name(), "fingerprint": id.fingerprint(), "touchid": crate::touchid::enabled_for(o.v.file.vault_id).is_some() }))
            });
            ctx.opts.touchid = false;
            ctx.opts.session = true;
            ctx.opts.remember_touchid = false;
            ctx.password_override.borrow_mut().take();
            result
        }
        "update.status" => {
            crate::upgrade::refresh_if_stale(&ctx.user);
            Ok(crate::upgrade::status())
        }
        "touchid.status" => {
            let loc = ctx.location()?;
            let loaded = loc.load(false)?;
            let vault = crate::format::peek_vault_id(&loaded.bytes)?;
            Ok(
                json!({ "available": crate::touchid::available(), "enabled": crate::touchid::enabled_for(vault) }),
            )
        }
        "touchid.disable" => {
            let loaded = ctx.location()?.load(false)?;
            let vault = crate::format::peek_vault_id(&loaded.bytes)?;
            Ok(json!({ "disabled": crate::touchid::disable(vault) }))
        }
        "session.lock" => {
            *ctx.unlocked.borrow_mut() = None;
            // Locking the app locks nepomuk: identities cached by the Touch ID agent for the
            // command line go too (`nepomuk lock`).
            let agent = crate::agent::forget(None);
            Ok(json!({ "locked": true, "agent_cleared": agent }))
        }
        "vault.status" => app::status(ctx),
        "vault.info" => Ok(queries::info(&app::open_vault(ctx, true)?)),
        "vault.verify" => {
            let o = app::open_vault(ctx, true)?;
            Ok(json!({ "ok": true, "seq": o.v.seq, "master_fingerprint": o.v.master_fp }))
        }
        "vault.log" => {
            let o = app::open_vault(ctx, true)?;
            queries::log(
                ctx,
                &o,
                p.get("limit").and_then(|l| l.as_u64()).map(|l| l as usize),
            )
        }
        "vault.trust" => app::trust(ctx, &p_str(p, "fingerprint")?, p_bool(p, "replace")),
        "whoami" => queries::whoami(ctx, &app::open_vault(ctx, true)?),
        "node.list" => {
            let o = app::open_vault(ctx, true)?;
            queries::ls(ctx, &o, p_opt(p, "path").as_deref(), p_bool(p, "recursive"))
        }
        "node.get" => {
            let o = app::open_vault(ctx, true)?;
            queries::get_json(ctx, &o, &tp(ctx, p, "path")?)
        }
        "node.put" => {
            let (content, not_after) = content_from(p)?;
            intent(
                ctx,
                Intent::Put {
                    path: tp(ctx, p, "path")?,
                    content,
                    not_after,
                    description: p_opt(p, "description"),
                },
            )
        }
        "node.mkdir" => intent(
            ctx,
            Intent::Mkdir {
                path: tp(ctx, p, "path")?,
                parents: p_bool(p, "parents"),
                description: p_opt(p, "description"),
            },
        ),
        "node.describe" => intent(
            ctx,
            Intent::Describe {
                path: tp(ctx, p, "path")?,
                description: p_opt(p, "description"),
            },
        ),
        "node.rm" => intent(
            ctx,
            Intent::Rm {
                path: tp(ctx, p, "path")?,
            },
        ),
        "node.mv" => intent(
            ctx,
            Intent::Mv {
                src: tp(ctx, p, "src")?,
                dst: tp(ctx, p, "dst")?,
            },
        ),
        "node.rekey" => intent(
            ctx,
            Intent::Rekey {
                path: tp(ctx, p, "path")?,
            },
        ),
        "access.list" => queries::access(ctx, &app::open_vault(ctx, true)?, &p_str(p, "path")?),
        "grant.add" => intent(
            ctx,
            Intent::Grant {
                who: p_str(p, "who")?,
                right: right(p)?,
                path: tp(ctx, p, "path")?,
            },
        ),
        "grant.revoke" => intent(
            ctx,
            Intent::Revoke {
                who: p_str(p, "who")?,
                path: tp(ctx, p, "path")?,
                no_rekey: p_bool(p, "no_rekey"),
            },
        ),
        "sysright.grant" => intent(
            ctx,
            Intent::SysGrant {
                user: p_str(p, "user")?,
                right: p_str(p, "right")?,
                delegate: p_bool(p, "delegate"),
            },
        ),
        "sysright.revoke" => intent(
            ctx,
            Intent::SysRevoke {
                user: p_str(p, "user")?,
                right: p_str(p, "right")?,
            },
        ),
        "user.list" => Ok(queries::users(&app::open_vault(ctx, true)?)),
        "user.add" => intent(
            ctx,
            Intent::UserAdd {
                request: p_str(p, "request")?,
            },
        ),
        "user.disable" => intent(
            ctx,
            Intent::UserDisable {
                name: p_str(p, "name")?,
            },
        ),
        "user.offboard" => intent(
            ctx,
            Intent::UserOffboard {
                name: p_str(p, "name")?,
            },
        ),
        "user.replace" => intent(
            ctx,
            Intent::UserReplace {
                name: p_str(p, "name")?,
                request: p_str(p, "request")?,
            },
        ),
        "group.list" => Ok(queries::groups(&app::open_vault(ctx, true)?)),
        "group.create" => intent(
            ctx,
            Intent::GroupCreate {
                name: p_str(p, "name")?,
            },
        ),
        "group.add" => intent(
            ctx,
            Intent::GroupAdd {
                group: p_str(p, "group")?,
                user: p_str(p, "user")?,
            },
        ),
        "group.remove" => intent(
            ctx,
            Intent::GroupRemove {
                group: p_str(p, "group")?,
                user: p_str(p, "user")?,
            },
        ),
        "rotation.list" => queries::rotation_list(ctx, &app::open_vault(ctx, true)?),
        "rotation.done" => intent(
            ctx,
            Intent::RotationDone {
                path: tp(ctx, p, "path")?,
            },
        ),
        "sync.run" => {
            notify("sync.progress", json!({ "stage": "fetch" }));
            let r = match p_opt(p, "resolve").as_deref() {
                Some("ours") => Resolve::Ours,
                Some("theirs") => Resolve::Theirs,
                _ => Resolve::Ask,
            };
            let out = app::sync(ctx, r)?;
            notify("sync.progress", json!({ "stage": "done" }));
            Ok(out)
        }
        "identity.request" => {
            // Password enrollment request (§4.3); keys and password stay on this machine.
            let email = p_str(p, "email")?;
            let password = Zeroizing::new(p_str(p, "password")?);
            let out = std::path::PathBuf::from(p_str(p, "out")?);
            crate::identity::validate_name(&email)?;
            crate::password::check(&password, &[&email])?;
            let id =
                crate::identity::Unlocked::generate(&email, crate::model::IdentityKind::Password);
            let cred = crate::identity::password_credential(&id, &password)?;
            let req = crate::identity::Request::new(&id, Some(cred));
            std::fs::write(&out, req.to_text())?;
            Ok(
                json!({ "name": email, "request": out.display().to_string(), "fingerprint": req.fingerprint() }),
            )
        }
        "identity.new" => {
            let name = p_str(p, "name")?;
            let pass = Zeroizing::new(p_str(p, "passphrase")?);
            let out = std::path::PathBuf::from(p_str(p, "out")?);
            crate::identity::validate_name(&name)?;
            crate::password::check(&pass, &[&name])?;
            if out.exists() {
                return Err(Error::new(
                    Code::AlreadyExists,
                    format!("{} already exists", out.display()),
                ));
            }
            let id = crate::identity::Unlocked::generate(&name, crate::model::IdentityKind::Local);
            let f = crate::identity::IdentityFile::create(&id, &pass)?;
            crate::config::write_private(&out, f.to_text().as_bytes())?;
            let req = crate::identity::Request::new(&id, None);
            let req_path = out.with_extension("request");
            std::fs::write(&req_path, req.to_text())?;
            Ok(
                json!({ "name": name, "identity": out.display().to_string(), "request": req_path.display().to_string(), "fingerprint": id.fingerprint() }),
            )
        }
        "request.inspect" => {
            let req =
                crate::identity::Request::parse(&std::fs::read_to_string(p_str(p, "path")?)?)?;
            req.verify()?;
            Ok(
                json!({ "name": req.name, "kind": req.kind, "fingerprint": req.fingerprint(), "request": req.to_text() }),
            )
        }
        "identity.local" => {
            // Identity files in the default folder (~/.config/nepomuk); no passphrase needed.
            let dir = crate::config::config_dir();
            let default = ctx
                .user
                .identity
                .clone()
                .unwrap_or_else(crate::config::default_identity_path);
            let mut files: Vec<Value> = std::fs::read_dir(&dir)
                .map(|rd| {
                    rd.flatten()
                        .map(|e| e.path())
                        .filter(|p| p.extension().is_some_and(|x| x == "npk"))
                        .filter_map(|p| {
                            let f = crate::identity::IdentityFile::parse(&std::fs::read_to_string(&p).ok()?).ok()?;
                            Some(json!({ "path": p.display().to_string(), "name": f.name, "fingerprint": f.fingerprint() }))
                        })
                        .collect()
                })
                .unwrap_or_default();
            if default.is_file()
                && !files
                    .iter()
                    .any(|f| f["path"] == default.display().to_string())
                && let Ok(f) =
                    crate::identity::IdentityFile::parse(&std::fs::read_to_string(&default)?)
            {
                files.push(json!({ "path": default.display().to_string(), "name": f.name, "fingerprint": f.fingerprint() }));
            }
            files.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
            // The CLI's default identity, or the only identity in the folder (e.g. master.npk after init).
            let default_path = if default.is_file() {
                Some(default.display().to_string())
            } else if files.len() == 1 {
                files[0]["path"].as_str().map(str::to_string)
            } else {
                None
            };
            Ok(json!({ "dir": dir.display().to_string(), "default": default_path, "files": files }))
        }
        "templates.list" => Ok(
            json!({ "templates": crate::templates::TEMPLATES.iter().map(|t| json!({
            "name": t.name,
            "fields": t.fields.iter().map(|(n, b)| json!({ "name": n, "binary": b })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>() }),
        ),
        "user.access" => {
            queries::user_access(ctx, &app::open_vault(ctx, true)?, &p_str(p, "name")?)
        }
        "exec.profiles" => Ok(
            json!({ "profiles": ctx.project.as_ref().map(|c| c.exec.iter().map(|(n, pr)| json!({
            "name": n, "env": pr.env.keys().collect::<Vec<_>>(), "files": pr.file.keys().collect::<Vec<_>>(),
        })).collect::<Vec<_>>()).unwrap_or_default() }),
        ),
        "passgen" => {
            let words = p.get("words").and_then(|w| w.as_u64()).unwrap_or(6) as usize;
            Ok(json!({ "passphrase": crate::password::passgen(words.max(4)).as_str() }))
        }
        "password.check" => {
            let pw = p_str(p, "password")?;
            let ctxw: Vec<String> = p
                .get("context")
                .and_then(|c| c.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let refs: Vec<&str> = ctxw.iter().map(String::as_str).collect();
            crate::password::check(&pw, &refs)?;
            Ok(json!({ "ok": true, "warning": crate::password::warning(&pw) }))
        }
        "exec.run" => {
            let profile_name = p_str(p, "profile")?;
            let command: Vec<String> = p
                .get("command")
                .and_then(|c| c.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .ok_or_else(|| Error::usage("missing `command`"))?;
            let project = ctx
                .project
                .as_ref()
                .ok_or_else(|| Error::usage("no .nepomuk.toml found"))?;
            let profile = project
                .exec
                .get(&profile_name)
                .ok_or_else(|| Error::not_found(&format!("exec profile {profile_name}")))?;
            let profile = crate::config::Profile {
                env: profile
                    .env
                    .iter()
                    .map(|(k, v)| (k.clone(), ctx.path(v)))
                    .collect(),
                file: profile
                    .file
                    .iter()
                    .map(|(k, v)| (k.clone(), ctx.path(v)))
                    .collect(),
            };
            let o = app::open_vault(ctx, true)?;
            let (env, files) = queries::profile_values(ctx, &o, &profile)?;
            let (code, stdout, stderr) = crate::exec::run_captured(
                crate::exec::ExecSpec {
                    env,
                    files,
                    mask: true,
                },
                &command,
            )?;
            Ok(json!({ "exit_code": code, "stdout": stdout, "stderr": stderr }))
        }
        _ => Err(
            Error::new(Code::Usage, format!("method not found: {method}")).with("rpc_code", -32601),
        ),
    }
}

pub fn run(mut ctx: Ctx) -> i32 {
    ctx.opts.json = true;
    ctx.opts.session = true;
    let timeout = Duration::from_secs(ctx.user.session_timeout.unwrap_or(DEFAULT_TIMEOUT));
    let (tx, rx) = mpsc::channel::<Option<String>>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) => {
                    if tx.send(Some(l)).is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tx.send(None);
    });
    let mut last = Instant::now();
    loop {
        let wait = if ctx.unlocked.borrow().is_some() {
            timeout.saturating_sub(last.elapsed())
        } else {
            Duration::from_secs(3600)
        };
        let msg = match rx.recv_timeout(wait) {
            Ok(Some(m)) => m,
            Ok(None) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if ctx.unlocked.borrow_mut().take().is_some() {
                    notify("session.expired", json!({ "reason": "inactivity" }));
                }
                continue;
            }
        };
        if ctx.unlocked.borrow().is_some() && last.elapsed() >= timeout {
            ctx.unlocked.borrow_mut().take();
            notify("session.expired", json!({ "reason": "inactivity" }));
        }
        if msg.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&msg) {
            Ok(v) => v,
            Err(_) => {
                send(
                    &json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "parse error" } }),
                );
                continue;
            }
        };
        // Background requests of the GUI (`"passive": true`, e.g. its status poll) are not
        // activity: otherwise the inactivity lock would never fire while the app is open.
        if req["params"]["passive"] != true {
            last = Instant::now();
        }
        let id = req.get("id").cloned();
        let Some(method) = req
            .get("method")
            .and_then(|m| m.as_str())
            .map(str::to_string)
        else {
            send(
                &json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32600, "message": "invalid request" } }),
            );
            continue;
        };
        let params = req.get("params").cloned().unwrap_or(json!({}));
        ctx.warnings.borrow_mut().clear();
        let result = dispatch(&mut ctx, &method, &params);
        let Some(id) = id else { continue }; // notification from the GUI: no response
        let warnings: Vec<String> = ctx.warnings.borrow_mut().drain(..).collect();
        match result {
            Ok(mut v) => {
                if !warnings.is_empty()
                    && let Value::Object(m) = &mut v
                {
                    m.insert("warnings".into(), json!(warnings));
                }
                send(&json!({ "jsonrpc": "2.0", "id": id, "result": v }));
            }
            Err(e) => {
                let code = e
                    .details
                    .get("rpc_code")
                    .and_then(|c| c.as_i64())
                    .unwrap_or(-32000);
                let mut details = e.details.clone();
                details.remove("rpc_code");
                send(&json!({ "jsonrpc": "2.0", "id": id, "error": {
                    "code": code, "message": e.message,
                    "data": { "api": crate::cli::API_VERSION, "code": e.code.as_str(), "details": details } } }));
            }
        }
    }
    *ctx.unlocked.borrow_mut() = None;
    0
}
