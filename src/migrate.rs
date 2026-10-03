//! `nepomuk migrate`: copies the folders and secrets of a vault in an older file format into the
//! current vault, by driving the older nepomuk binary that can still read it.
//!
//! The older binary runs as `serve --stdio`, so its identity is unlocked once and the secrets
//! travel over a pipe: they are never written to disk. Users, groups and grants are not copied
//! (they are bound to the old vault's keys); they are listed so they can be set up again.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::app::{self, Ctx, ImportEntry, Intent, Resolve};
use crate::error::{Code, Error, Result};
use crate::model::Content;

pub struct Source {
    /// The older nepomuk binary, e.g. `nepomuk-0.2.7`.
    pub cli: PathBuf,
    /// The older vault file.
    pub vault: PathBuf,
    /// Identity file for the older vault (default: that binary's default identity).
    pub identity: Option<PathBuf>,
    /// Email of a password identity in the older vault.
    pub email: Option<String>,
}

struct OldCli {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next: u64,
}

impl OldCli {
    fn start(src: &Source) -> Result<OldCli> {
        let vault = std::fs::canonicalize(&src.vault).map_err(|e| {
            Error::not_found(&src.vault.display().to_string()).with("reason", e.to_string())
        })?;
        // Run it away from any project: an older release pins a `root_fp` from a .nepomuk.toml it
        // finds in or above its working directory, so start it in nepomuk's own config folder.
        let dir = crate::config::config_dir();
        std::fs::create_dir_all(&dir)?;
        let mut cmd = Command::new(&src.cli);
        cmd.arg("--vault").arg(&vault);
        if let Some(i) = &src.identity {
            cmd.arg("--identity").arg(std::fs::canonicalize(i)?);
        }
        cmd.args(["serve", "--stdio"])
            .current_dir(dir)
            // Settings meant for the new vault must not leak into the old one.
            .env_remove("NEPOMUK_ROOT_FP")
            .env_remove("NEPOMUK_VAULT")
            .env_remove("NEPOMUK_PASSWORD")
            .env_remove("NEPOMUK_PASSPHRASE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().map_err(|e| {
            Error::not_found(&src.cli.display().to_string())
                .with("reason", format!("cannot start the older nepomuk: {e}"))
        })?;
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Ok(OldCli {
            child,
            stdin,
            stdout,
            next: 1,
        })
    }

    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next;
        self.next += 1;
        let msg = Zeroizing::new(
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string(),
        );
        self.stdin.write_all(msg.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;
        loop {
            let mut line = Zeroizing::new(String::new());
            if self.stdout.read_line(&mut line)? == 0 {
                return Err(Error::general(
                    "the older nepomuk exited unexpectedly (see its messages above)",
                ));
            }
            let Ok(v) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if v.get("id").and_then(Value::as_u64) != Some(id) {
                continue; // a notification
            }
            if let Some(e) = v.get("error") {
                let msg = e.get("message").and_then(Value::as_str).unwrap_or("error");
                let code = e
                    .get("data")
                    .and_then(|d| d.get("code"))
                    .and_then(Value::as_str)
                    .unwrap_or("ERROR");
                return Err(Error::general(format!(
                    "older nepomuk: {method}: {msg} ({code})"
                )));
            }
            return Ok(v.get("result").cloned().unwrap_or(Value::Null));
        }
    }
}

impl Drop for OldCli {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reads everything the old identity can see and writes it into the current vault.
pub fn run(ctx: &Ctx, src: &Source, dry_run: bool) -> Result<Value> {
    if ctx.opts.offline {
        // Offline writes are queued on disk, which would store the copied secrets there.
        return Err(Error::usage("migrate cannot run with --offline"));
    }
    let mut old = OldCli::start(src)?;
    let version = old.call("version", json!({}))?;
    let password = ctx.secret(
        "Password or passphrase of the identity in the older vault",
        &["NEPOMUK_MIGRATE_PASSWORD"],
    )?;
    let mut unlock = json!({ "password": password.as_str() });
    if let Some(e) = &src.email {
        unlock["email"] = json!(e);
    }
    if let Some(i) = &src.identity {
        unlock["identity"] = json!(std::fs::canonicalize(i)?.display().to_string());
    }
    drop(password);
    old.call("session.unlock", unlock)?;
    let whoami = old.call("whoami", json!({})).unwrap_or(Value::Null);

    let list = old.call("node.list", json!({ "recursive": true }))?;
    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    for e in list
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let path = e
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::general("older nepomuk: entry without a path"))?
            .to_string();
        match e.get("type").and_then(Value::as_str) {
            Some("folder") => entries.push(ImportEntry {
                path,
                content: Content::Folder,
                not_after: None,
            }),
            Some("text" | "binary" | "record") => {
                let got = old.call("node.get", json!({ "path": path }))?;
                let (content, not_after) = crate::serve::content_from_json(&got, false)?;
                entries.push(ImportEntry {
                    path,
                    content,
                    not_after,
                });
            }
            _ => skipped.push(path),
        }
    }
    drop(old);

    let folders = entries
        .iter()
        .filter(|e| matches!(e.content, Content::Folder))
        .count();
    let secrets = entries.len() - folders;
    let paths: Vec<String> = entries.iter().map(|e| e.path.clone()).collect();
    let mut out = json!({
        "source_version": version.get("cli").cloned().unwrap_or(Value::Null),
        "folders": folders,
        "secrets": secrets,
        "paths": paths,
        "not_migrated": "users, groups, grants and system rights – set them up again in the new vault",
    });
    if let Some(g) = whoami.get("grants") {
        out["old_grants"] = g.clone();
    }
    if !skipped.is_empty() {
        out["skipped"] = json!(skipped);
    }
    if dry_run {
        out["dry_run"] = json!(true);
        return Ok(out);
    }
    if entries.is_empty() {
        return Err(Error::new(
            Code::NotFound,
            "the older vault shows nothing to this identity",
        ));
    }
    let result = app::execute(ctx, &Intent::Import { entries }, None, Resolve::Ask)?;
    if let Some(seq) = result.get("seq") {
        out["seq"] = seq.clone();
    }
    Ok(out)
}
