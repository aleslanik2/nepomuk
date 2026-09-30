mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::Stdio;

use common::*;
use serde_json::{Value, json};

/// A vault repository with a bare remote; the vault lives in clone `a`.
fn git_env(tag: &str) -> Env {
    let mut e = Env::bare(tag);
    let root = e.dir.path().to_path_buf();
    git(&root, &["init", "-q", "--bare", "-b", "main", "remote.git"]);
    git(&root, &["clone", "-q", "remote.git", "a"]);
    e.vault = root.join("a/vault.nepomuk");
    e.cmd(&["init"], &[("NEPOMUK_PASSPHRASE", MASTER_PASS)], None)
        .ok();
    e
}

fn with_vault(e: &Env, vault: &Path, args: &[&str]) -> Res {
    let id = e.master_identity();
    let mut a = vec![
        "--vault",
        vault.to_str().unwrap(),
        "--identity",
        id.to_str().unwrap(),
    ];
    a.extend_from_slice(args);
    e.cmd(&a, &[("NEPOMUK_PASSPHRASE", MASTER_PASS)], None)
}

#[test]
fn git_push_and_concurrent_writers() {
    let e = git_env("git");
    let root = e.dir.path();
    assert!(git(&root.join("remote.git"), &["log", "--oneline", "main"]).contains("nepomuk: init"));
    e.m(&["mkdir", "/a"]).ok();
    git(root, &["clone", "-q", "remote.git", "b"]);
    let b = root.join("b/vault.nepomuk");
    let checkout = std::fs::read(&b).unwrap();
    with_vault(&e, &b, &["mkdir", "/b"]).ok();
    e.m(&["mkdir", "/c"]).ok();
    let log = git(&root.join("remote.git"), &["log", "--format=%s", "main"]);
    assert_eq!(
        log.lines().collect::<Vec<_>>(),
        vec![
            "nepomuk: #3 by master (1 operation)",
            "nepomuk: #2 by master (1 operation)",
            "nepomuk: #1 by master (1 operation)",
            "nepomuk: init",
        ]
    );
    // The checkout itself is never modified.
    assert_eq!(std::fs::read(&b).unwrap(), checkout);
    let ls = with_vault(&e, &b, &["ls"]).data();
    assert_eq!(ls["entries"].as_array().unwrap().len(), 3);
    // .gitattributes drivers are committed by init.
    let attrs = git(&root.join("remote.git"), &["show", "main:.gitattributes"]);
    assert!(attrs.contains("vault.nepomuk binary diff=nepomuk merge=nepomuk"));
}

#[test]
fn rejected_push_is_retried() {
    let e = git_env("retry");
    let hook = e.path("remote.git/hooks/pre-receive");
    // Reject the first push after installing the hook, as if someone else had pushed first.
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\nif [ ! -f {0} ]; then touch {0}; echo 'rejected' >&2; exit 1; fi\nexit 0\n",
            e.path("once").display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    e.m(&["mkdir", "/x"]).ok();
    assert!(e.path("once").exists());
    assert_eq!(e.m(&["ls"]).data()["entries"][0]["path"], "/x");
}

#[test]
fn ci_rejects_vault_older_than_submodule_pin() {
    let e = git_env("pin");
    let root = e.dir.path();
    e.m(&["mkdir", "/one"]).ok();
    let c1 = git(&root.join("remote.git"), &["rev-parse", "main"]);
    e.m(&["mkdir", "/two"]).ok();
    // The application pins the submodule at the newest commit.
    git(root, &["init", "-q", "-b", "main", "app"]);
    git(
        &root.join("app"),
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            "../remote.git",
            "secrets",
        ],
    );
    std::fs::write(
        root.join("app/.nepomuk.toml"),
        "vault = \"secrets/vault.nepomuk\"\n",
    )
    .unwrap();
    // An attacker with push access rolls the vault repository back.
    git(
        &root.join("a"),
        &[
            "push",
            "-q",
            "-f",
            "origin",
            &format!("{c1}:refs/heads/main"),
        ],
    );
    let fp = e.m(&["info"]);
    assert_eq!(
        fp.err_code(),
        "ROLLBACK_DETECTED",
        "a client with memory notices"
    );
    let master_fp = {
        let mem = std::fs::read_dir(e.path("state/vaults"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let j: Value = serde_json::from_slice(&std::fs::read(mem).unwrap()).unwrap();
        j["pin"].as_str().unwrap().to_string()
    };
    // A fresh CI runner without memory relies on the submodule pin.
    let id = e.master_identity();
    let mut c = e.command(
        &["--identity", id.to_str().unwrap(), "info"],
        &[
            ("NEPOMUK_PASSPHRASE", MASTER_PASS),
            ("NEPOMUK_ROOT_FP", &master_fp),
            ("CI", "true"),
        ],
    );
    c.current_dir(root.join("app"))
        .env_remove("NEPOMUK_VAULT")
        .env("NEPOMUK_STATE_DIR", e.path("state-ci"));
    let out = c.output().unwrap();
    let j: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(j["error"]["code"], "STALE_BELOW_PIN", "{j}");
}

#[test]
fn offline_changes_and_sync() {
    let e = git_env("offline");
    let root = e.dir.path();
    e.m(&["mkdir", "/s"]).ok();
    e.m_in(&["put", "/s/token"], b"v1").ok();
    // Offline: the change is queued, encrypted, and reported as pending.
    let r = e.m_in(&["--offline", "put", "/s/new"], b"queued");
    assert_eq!(r.data()["pending"], true);
    assert_eq!(e.m(&["status"]).data()["state"], "ahead");
    let pending = std::fs::read_dir(e.path("state/pending"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(!String::from_utf8_lossy(&std::fs::read(pending).unwrap()).contains("queued"));
    // Another client writes in the meantime.
    git(root, &["clone", "-q", "remote.git", "b"]);
    with_vault(&e, &root.join("b/vault.nepomuk"), &["mkdir", "/other"]).ok();
    let d = e.m(&["sync"]).data();
    assert_eq!(d["state"], "up-to-date");
    assert_eq!(e.m(&["get", "/s/new"]).data()["value"], "queued");
    assert_eq!(e.m(&["status"]).data()["state"], "up-to-date");

    // Conflict: the same secret changed by both sides.
    e.m_in(&["--offline", "put", "/s/token"], b"mine").ok();
    // Written by a different identity (Jane) so that the change is someone else's.
    e.add_password_user("jane@example.com");
    e.m(&["grant", "user:jane@example.com", "write", "/s"]).ok();
    e.u_in("jane@example.com", &["put", "/s/token"], b"theirs")
        .ok();
    let r = e.m(&["sync"]);
    assert_eq!(r.code, 6);
    assert_eq!(r.json()["data"]["state"], "conflict");
    assert_eq!(e.m(&["get", "/s/token"]).data()["value"], "theirs");
    e.m(&["sync", "--resolve", "ours"]).ok();
    assert_eq!(e.m(&["get", "/s/token"]).data()["value"], "mine");
}

#[test]
fn exec_injects_masks_and_cleans_up() {
    let e = Env::new("exec");
    e.m(&["mkdir", "-p", "/projects/eshop-android/signing"])
        .ok();
    std::fs::write(e.path("release.jks"), b"KEYSTORE-BYTES").unwrap();
    // keytool may be missing or reject the fake keystore; use a generic record.
    e.m_in(
        &[
            "put",
            "/projects/eshop-android/signing/release",
            "--field",
            "keystore=@release.jks",
            "--field",
            "key_alias=eshop-upload",
            "--field-prompt",
            "key_password",
        ],
        b"super-secret-key-pw\n",
    )
    .ok();
    std::fs::write(
        e.path(".nepomuk.toml"),
        format!(
            "vault = \"{}\"\nprefix = \"/projects/eshop-android\"\n\n[exec.android-release]\nfile.ANDROID_KEYSTORE = \"signing/release#keystore\"\nenv.ANDROID_KEY_ALIAS = \"signing/release#key_alias\"\nenv.ANDROID_KEY_PASSWORD = \"signing/release#key_password\"\n",
            e.vault.display()
        ),
    )
    .unwrap();
    let id = e.master_identity();
    let script = "echo \"pw=$ANDROID_KEY_PASSWORD alias=$ANDROID_KEY_ALIAS\"; cat \"$ANDROID_KEYSTORE\"; echo; echo \"$ANDROID_KEYSTORE\"; echo \"id=${NEPOMUK_PASSPHRASE:-none}\"; exit 3";
    let r = e.cmd(
        &[
            "--identity",
            id.to_str().unwrap(),
            "exec",
            "android-release",
            "--mask",
            "--",
            "sh",
            "-c",
            script,
        ],
        &[("NEPOMUK_PASSPHRASE", MASTER_PASS)],
        None,
    );
    assert_eq!(r.code, 3, "{}\n{}", r.stdout, r.stderr);
    assert!(r.stdout.contains("pw=*** alias=***"), "{}", r.stdout);
    assert!(!r.stdout.contains("super-secret-key-pw"));
    assert!(
        r.stdout.contains("***"),
        "keystore content masked: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("id=none"),
        "nepomuk's own credentials do not reach the child"
    );
    let file_path = r
        .stdout
        .lines()
        .find(|l| l.starts_with('/'))
        .unwrap()
        .to_string();
    if !file_path.starts_with("/proc/") {
        assert!(
            !Path::new(&file_path).exists(),
            "secret file removed after the run"
        );
    }
    // Missing access: the command is not started.
    let ci = e.add_local_user("ci-eshop-android");
    let r = e.cmd(
        &[
            "--identity",
            ci.to_str().unwrap(),
            "exec",
            "android-release",
            "--",
            "sh",
            "-c",
            "touch started",
        ],
        &[("NEPOMUK_PASSPHRASE", &password_for("ci-eshop-android"))],
        None,
    );
    assert_eq!(r.err_code(), "ACCESS_DENIED");
    assert!(!e.path("started").exists());
    e.m(&[
        "grant",
        "user:ci-eshop-android",
        "read",
        "/projects/eshop-android/signing",
    ])
    .ok();
    let r = e.cmd(
        &[
            "--identity",
            ci.to_str().unwrap(),
            "exec",
            "android-release",
            "--",
            "sh",
            "-c",
            "test -n \"$ANDROID_KEY_PASSWORD\" && touch started",
        ],
        &[
            ("NEPOMUK_PASSPHRASE", &password_for("ci-eshop-android")),
            ("GITHUB_ACTIONS", "true"),
        ],
        None,
    );
    assert_eq!(r.code, 0, "{}{}", r.stdout, r.stderr);
    assert!(r.stdout.contains("::add-mask::super-secret-key-pw"));
    assert!(e.path("started").exists());
}

#[test]
fn serve_stdio_session() {
    let e = Env::new("serve");
    e.m(&["mkdir", "/infra"]).ok();
    e.m_in(&["put", "/infra/pw"], b"from-serve").ok();
    let mut c = e.command(&["serve", "--stdio"], &[]);
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut call = |id: u64, method: &str, params: Value| -> Value {
        writeln!(
            stdin,
            "{}",
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
        )
        .unwrap();
        loop {
            let l = lines.next().unwrap().unwrap();
            let v: Value = serde_json::from_str(&l).unwrap();
            if v.get("id") == Some(&json!(id)) {
                return v;
            }
        }
    };
    let r = call(1, "version", json!({}));
    assert_eq!(r["result"]["api"], 1);
    let r = call(2, "node.list", json!({}));
    assert_eq!(r["error"]["data"]["code"], "PASSWORD_REQUIRED");
    let id = e.master_identity();
    let r = call(
        3,
        "session.unlock",
        json!({ "identity": id.to_str().unwrap(), "password": MASTER_PASS }),
    );
    assert_eq!(r["result"]["name"], "master", "{r}");
    let r = call(4, "node.list", json!({ "recursive": true }));
    assert_eq!(r["result"]["entries"].as_array().unwrap().len(), 2);
    assert!(
        r["result"]["entries"][1].get("value").is_none(),
        "node.list returns metadata only"
    );
    let r = call(5, "node.get", json!({ "path": "/infra/pw" }));
    assert_eq!(r["result"]["value"], "from-serve");
    let r = call(
        6,
        "node.put",
        json!({ "path": "/infra/new", "type": "text", "value": "v" }),
    );
    assert!(r["result"]["seq"].is_number(), "{r}");
    let r = call(7, "session.lock", json!({}));
    assert_eq!(r["result"]["locked"], true);
    let r = call(8, "node.get", json!({ "path": "/infra/pw" }));
    assert_eq!(r["error"]["data"]["code"], "PASSWORD_REQUIRED");
    let r = call(9, "no.such", json!({}));
    assert_eq!(r["error"]["code"], -32601);
    drop(stdin);
    assert!(child.wait().unwrap().success());
}
