mod common;

use common::*;

#[test]
fn store_and_read_secrets() {
    let e = Env::new("basic");
    e.m(&["mkdir", "-p", "/infra/db"]).ok();
    e.m_in(&["put", "/infra/db/prod-password"], b"S3cret\n")
        .ok();
    let d = e.m(&["get", "/infra/db/prod-password"]).data();
    assert_eq!(d["value"], "S3cret");

    std::fs::write(e.path("release.jks"), [0u8, 1, 2, 3, 255]).unwrap();
    e.m(&["put", "/infra/db/blob", "@release.jks"]).ok();
    let out = e.path("out.bin");
    e.m(&["get", "/infra/db/blob", "--out", out.to_str().unwrap()])
        .ok();
    assert_eq!(std::fs::read(&out).unwrap(), vec![0u8, 1, 2, 3, 255]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    e.m_in(
        &[
            "put",
            "/infra/db/rec",
            "--field",
            "user=admin",
            "--field-prompt",
            "password",
        ],
        b"pw-from-stdin\n",
    )
    .ok();
    assert_eq!(
        e.m(&["get", "/infra/db/rec#password"]).data()["value"],
        "pw-from-stdin"
    );
    assert_eq!(e.m(&["get", "/infra/db/rec#user"]).data()["value"], "admin");

    let ls = e.m(&["ls", "-r"]).data();
    let paths: Vec<&str> = ls["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        vec![
            "/infra",
            "/infra/db",
            "/infra/db/blob",
            "/infra/db/prod-password",
            "/infra/db/rec"
        ]
    );

    assert_eq!(e.m(&["get", "/infra/db/missing"]).err_code(), "NOT_FOUND");
    assert_eq!(e.m(&["mkdir", "/infra"]).err_code(), "ALREADY_EXISTS");

    // Update keeps the node, rename and remove work.
    e.m_in(&["put", "/infra/db/prod-password"], b"S3cret-2")
        .ok();
    assert_eq!(
        e.m(&["get", "/infra/db/prod-password"]).data()["value"],
        "S3cret-2"
    );
    e.m(&["mv", "/infra/db/prod-password", "/infra/db/main-password"])
        .ok();
    assert_eq!(
        e.m(&["get", "/infra/db/main-password"]).data()["value"],
        "S3cret-2"
    );
    e.m(&["rm", "/infra/db"]).ok();
    assert_eq!(
        e.m(&["get", "/infra/db/main-password"]).err_code(),
        "NOT_FOUND"
    );
    e.m(&["verify", "--full"]).ok();
}

#[test]
fn secrets_are_never_arguments() {
    let e = Env::new("args");
    assert_eq!(e.m(&["put", "/x", "plaintext"]).err_code(), "USAGE");
}

#[test]
fn file_hides_names_and_values() {
    let e = Env::new("hidden");
    e.m(&["mkdir", "/very-secret-folder-name"]).ok();
    e.m_in(
        &["put", "/very-secret-folder-name/token"],
        b"visible-token-value",
    )
    .ok();
    let bytes = std::fs::read(&e.vault).unwrap();
    let hay = String::from_utf8_lossy(&bytes);
    assert!(!hay.contains("very-secret-folder-name"));
    assert!(!hay.contains("visible-token-value"));
    assert!(!hay.contains("token"));
}

#[test]
fn permissions_are_enforced() {
    let e = Env::new("perm");
    e.add_password_user("jane@example.com");
    e.add_password_user("bob@example.com");
    e.m(&["mkdir", "-p", "/projects/a"]).ok();
    e.m(&["mkdir", "-p", "/projects/b"]).ok();
    e.m_in(&["put", "/projects/a/key"], b"a-key").ok();
    e.m_in(&["put", "/projects/b/key"], b"b-key").ok();

    // No grant: nothing visible.
    assert_eq!(
        e.u("jane@example.com", &["get", "/projects/a/key"])
            .err_code(),
        "ACCESS_DENIED"
    );
    assert_eq!(
        e.u("jane@example.com", &["ls"]).data()["entries"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    e.m(&["grant", "user:jane@example.com", "share", "/projects/a"])
        .ok();
    assert_eq!(
        e.u("jane@example.com", &["get", "/projects/a/key"]).data()["value"],
        "a-key"
    );
    assert_eq!(
        e.u("jane@example.com", &["get", "/projects/b/key"])
            .err_code(),
        "ACCESS_DENIED"
    );
    // Jane sees her grant but not the names of parent folders.
    let ls = e.u("jane@example.com", &["ls"]).data();
    assert_eq!(ls["entries"][0]["path"], "/projects/a/key");

    // share: can write, can grant read/write, cannot grant admin.
    e.u_in("jane@example.com", &["put", "/projects/a/key2"], b"x")
        .ok();
    e.u(
        "jane@example.com",
        &["grant", "user:bob@example.com", "read", "/projects/a"],
    )
    .ok();
    assert_eq!(
        e.u(
            "jane@example.com",
            &["grant", "user:bob@example.com", "admin", "/projects/a"]
        )
        .err_code(),
        "ACCESS_DENIED"
    );
    assert_eq!(
        e.u(
            "jane@example.com",
            &["grant", "user:bob@example.com", "read", "/projects/b"]
        )
        .err_code(),
        "ACCESS_DENIED"
    );

    // read: cannot write, cannot grant.
    assert_eq!(
        e.u("bob@example.com", &["get", "/projects/a/key"]).data()["value"],
        "a-key"
    );
    assert_eq!(
        e.u_in("bob@example.com", &["put", "/projects/a/key"], b"evil")
            .err_code(),
        "ACCESS_DENIED"
    );
    assert_eq!(
        e.u("bob@example.com", &["rm", "/projects/a/key"])
            .err_code(),
        "ACCESS_DENIED"
    );
    assert_eq!(
        e.u(
            "jane@example.com",
            &["revoke", "user:bob@example.com", "/projects/a"]
        )
        .err_code(),
        "ACCESS_DENIED"
    );

    // System rights: users.
    assert_eq!(
        e.u("jane@example.com", &["user", "disable", "bob@example.com"])
            .err_code(),
        "ACCESS_DENIED"
    );
    e.m(&["sysgrant", "jane@example.com", "users"]).ok();
    assert_eq!(
        e.u(
            "jane@example.com",
            &["sysgrant", "bob@example.com", "users"]
        )
        .err_code(),
        "ACCESS_DENIED"
    );
    e.u("jane@example.com", &["user", "disable", "bob@example.com"])
        .ok();
    assert_eq!(
        e.u("bob@example.com", &["get", "/projects/a/key"])
            .err_code(),
        "IDENTITY_DISABLED"
    );

    let acc = e.m(&["access", "/projects/a/key"]).data();
    let users: Vec<&str> = acc["effective"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["user"].as_str().unwrap())
        .collect();
    assert_eq!(users, vec!["jane@example.com", "master"]);
}

#[test]
fn wrong_password_and_weak_password() {
    let e = Env::new("pw");
    e.add_password_user("jane@example.com");
    let r = e.cmd(
        &["--email", "jane@example.com", "ls"],
        &[("NEPOMUK_PASSWORD", "not-the-right-password")],
        None,
    );
    assert_eq!(r.err_code(), "BAD_CREDENTIALS");
    assert_eq!(r.code, 3);
    let r = e.cmd(
        &[
            "identity",
            "request",
            "--email",
            "x@example.com",
            "--out",
            "x.req",
        ],
        &[("NEPOMUK_PASSWORD", "short")],
        None,
    );
    assert_eq!(r.err_code(), "WEAK_PASSWORD");
    let r = e.cmd(
        &[
            "identity",
            "request",
            "--email",
            "x@example.com",
            "--out",
            "x.req",
        ],
        &[("NEPOMUK_PASSWORD", "x@example.com12345")],
        None,
    );
    assert_eq!(r.err_code(), "WEAK_PASSWORD");
    // Without any password source and in --json mode it never prompts.
    let r = e.cmd(&["--email", "jane@example.com", "ls"], &[], None);
    assert_eq!(r.err_code(), "PASSWORD_REQUIRED");
    assert_eq!(r.code, 7);
}

#[test]
fn password_change() {
    let e = Env::new("passwd");
    e.add_password_user("jane@example.com");
    let old = password_for("jane@example.com");
    let new = "a-completely-new-long-password";
    let input = format!("{old}\n{new}\n");
    e.cmd(
        &[
            "--email",
            "jane@example.com",
            "--password-stdin",
            "identity",
            "passwd",
        ],
        &[],
        Some(input.as_bytes()),
    )
    .ok();
    let r = e.cmd(
        &["--email", "jane@example.com", "whoami"],
        &[("NEPOMUK_PASSWORD", new)],
        None,
    );
    assert_eq!(r.data()["name"], "jane@example.com");
    assert_eq!(
        e.u("jane@example.com", &["whoami"]).err_code(),
        "BAD_CREDENTIALS"
    );
}

#[test]
fn groups_and_membership_removal() {
    let e = Env::new("groups");
    e.add_password_user("alice@example.com");
    e.add_password_user("carol@example.com");
    e.m(&["mkdir", "-p", "/projects/eshop/signing"]).ok();
    e.m_in(&["put", "/projects/eshop/signing/token"], b"t0k3n")
        .ok();
    e.m(&["group", "create", "android-release"]).ok();
    e.m(&["group", "add", "android-release", "alice@example.com"])
        .ok();
    e.m(&["group", "add", "android-release", "carol@example.com"])
        .ok();
    e.m(&[
        "grant",
        "group:android-release",
        "read",
        "/projects/eshop/signing",
    ])
    .ok();
    assert_eq!(
        e.u(
            "alice@example.com",
            &["get", "/projects/eshop/signing/token"]
        )
        .data()["value"],
        "t0k3n"
    );
    assert_eq!(
        e.u(
            "carol@example.com",
            &["get", "/projects/eshop/signing/token"]
        )
        .data()["value"],
        "t0k3n"
    );

    e.m(&["group", "remove", "android-release", "alice@example.com"])
        .ok();
    assert_eq!(
        e.u(
            "alice@example.com",
            &["get", "/projects/eshop/signing/token"]
        )
        .err_code(),
        "ACCESS_DENIED"
    );
    // The remaining member still reads (new group key wrapped for her, grants re-issued after rekey).
    assert_eq!(
        e.u(
            "carol@example.com",
            &["get", "/projects/eshop/signing/token"]
        )
        .data()["value"],
        "t0k3n"
    );

    // group-admin can only be granted to a member.
    assert_eq!(
        e.m(&[
            "sysgrant",
            "alice@example.com",
            "group-admin:android-release"
        ])
        .err_code(),
        "ACCESS_DENIED"
    );
    e.m(&[
        "sysgrant",
        "carol@example.com",
        "group-admin:android-release",
    ])
    .ok();
    e.u(
        "carol@example.com",
        &["group", "add", "android-release", "alice@example.com"],
    )
    .ok();
    assert_eq!(
        e.u(
            "alice@example.com",
            &["get", "/projects/eshop/signing/token"]
        )
        .data()["value"],
        "t0k3n"
    );
    let g = e.m(&["group", "list"]).data();
    assert_eq!(g["groups"][0]["members"].as_array().unwrap().len(), 3);
}

#[test]
fn revoke_rekeys_and_marks_rotation() {
    let e = Env::new("revoke");
    e.add_password_user("bob@example.com");
    e.m(&["mkdir", "-p", "/infra/db"]).ok();
    e.m_in(&["put", "/infra/db/pw"], b"old-pw").ok();
    e.m(&["grant", "user:bob@example.com", "read", "/infra/db"])
        .ok();
    assert_eq!(
        e.u("bob@example.com", &["get", "/infra/db/pw"]).data()["value"],
        "old-pw"
    );

    let before = e.m(&["log"]).data()["seq"].as_u64().unwrap();
    let d = e.m(&["revoke", "user:bob@example.com", "/infra/db"]).data();
    assert_eq!(d["rotate"], serde_json::json!(["/infra/db/pw"]));
    let log = e.m(&["log", "-n", "1"]).data();
    let ops = log["commits"][0]["operations"].as_array().unwrap();
    assert!(
        ops.iter().any(|o| o == "Revoke") && ops.iter().any(|o| o == "Rekey"),
        "{ops:?}"
    );
    assert_eq!(
        log["seq"].as_u64().unwrap(),
        before + 1,
        "revoke and rekey are one commit"
    );

    assert_eq!(
        e.u("bob@example.com", &["get", "/infra/db/pw"]).err_code(),
        "ACCESS_DENIED"
    );
    let rot = e.m(&["rotation", "list"]).data();
    assert_eq!(rot["pending_rotation"][0]["path"], "/infra/db/pw");
    e.m_in(&["put", "/infra/db/pw"], b"new-pw").ok();
    e.m(&["rotation", "done", "/infra/db/pw"]).ok();
    assert_eq!(
        e.m(&["rotation", "list"]).data()["pending_rotation"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(e.m(&["get", "/infra/db/pw"]).data()["value"], "new-pw");
}

#[test]
fn offboarding() {
    let e = Env::new("offboard");
    e.add_password_user("alice@example.com");
    e.add_password_user("carol@example.com");
    e.m(&["mkdir", "-p", "/projects/x/signing"]).ok();
    e.m(&["mkdir", "-p", "/teams/core"]).ok();
    e.m_in(&["put", "/projects/x/signing/key"], b"k").ok();
    e.m_in(&["put", "/teams/core/wifi"], b"w").ok();
    e.m(&["group", "create", "core"]).ok();
    e.m(&["group", "add", "core", "alice@example.com"]).ok();
    e.m(&["group", "add", "core", "carol@example.com"]).ok();
    e.m(&["grant", "group:core", "read", "/teams/core"]).ok();
    e.m(&[
        "grant",
        "user:alice@example.com",
        "write",
        "/projects/x/signing",
    ])
    .ok();

    let d = e.m(&["user", "offboard", "alice@example.com"]).data();
    let mut rotate: Vec<String> = d["rotate"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    rotate.sort();
    assert_eq!(rotate, vec!["/projects/x/signing/key", "/teams/core/wifi"]);
    assert!(d.get("tasks").is_none(), "master can do everything: {d}");

    assert_eq!(
        e.u("alice@example.com", &["ls"]).err_code(),
        "IDENTITY_DISABLED"
    );
    assert_eq!(
        e.u("carol@example.com", &["get", "/teams/core/wifi"])
            .data()["value"],
        "w"
    );
    let users = e.m(&["user", "list"]).data();
    let alice = users["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["name"] == "alice@example.com")
        .unwrap()
        .clone();
    assert_eq!(alice["disabled"], true);
    assert_eq!(alice["groups"].as_array().unwrap().len(), 0);
    e.m(&["verify"]).ok();
}

#[test]
fn delegated_offboarding_returns_tasks() {
    let e = Env::new("offboard-tasks");
    e.add_password_user("it@example.com");
    e.add_password_user("alice@example.com");
    e.m(&["mkdir", "-p", "/infra"]).ok();
    e.m(&["grant", "user:alice@example.com", "read", "/infra"])
        .ok();
    e.m(&["sysgrant", "it@example.com", "users"]).ok();
    let d = e
        .u("it@example.com", &["user", "offboard", "alice@example.com"])
        .data();
    let tasks = d["tasks"].as_array().unwrap();
    assert!(
        tasks.iter().any(|t| t.as_str().unwrap().contains("revoke")),
        "{tasks:?}"
    );
    assert!(
        tasks.iter().any(|t| t.as_str().unwrap().contains("rekey")),
        "{tasks:?}"
    );
    assert_eq!(
        e.u("alice@example.com", &["ls"]).err_code(),
        "IDENTITY_DISABLED"
    );
}

#[test]
fn replace_identity() {
    let e = Env::new("replace");
    e.add_password_user("jane@example.com");
    e.m(&["mkdir", "/docs"]).ok();
    e.m_in(&["put", "/docs/a"], b"A").ok();
    e.m(&["grant", "user:jane@example.com", "read", "/docs"])
        .ok();
    // Jane forgot her password: a new request under the same email.
    let newpw = "another-very-long-password-x";
    e.cmd(
        &[
            "identity",
            "request",
            "--email",
            "jane@example.com",
            "--out",
            "jane2.request",
        ],
        &[("NEPOMUK_PASSWORD", newpw)],
        None,
    )
    .ok();
    e.m(&["user", "replace", "jane@example.com", "jane2.request"])
        .ok();
    assert_eq!(
        e.u("jane@example.com", &["ls"]).err_code(),
        "BAD_CREDENTIALS"
    );
    let r = e.cmd(
        &["--email", "jane@example.com", "get", "/docs/a"],
        &[("NEPOMUK_PASSWORD", newpw)],
        None,
    );
    assert_eq!(r.data()["value"], "A");
}

#[test]
fn trust_and_root_of_trust() {
    let e = Env::new("trust");
    let info = e.m(&["info"]).data();
    let fp = info["master_fingerprint"].as_str().unwrap().to_string();

    // A client without a pin refuses to open the vault.
    let fresh = |args: &[&str], env: &[(&str, &str)]| {
        let mut c = e.command(args, env);
        c.env("NEPOMUK_STATE_DIR", e.path("state2"));
        let out = c.output().unwrap();
        Res {
            code: out.status.code().unwrap(),
            stdout: String::from_utf8_lossy(&out.stdout).into(),
            stderr: String::from_utf8_lossy(&out.stderr).into(),
        }
    };
    let id = e.master_identity();
    let id = id.to_str().unwrap();
    let r = fresh(
        &["--identity", id, "info"],
        &[("NEPOMUK_PASSPHRASE", MASTER_PASS)],
    );
    assert_eq!(r.err_code(), "UNTRUSTED_ROOT");
    assert_eq!(r.code, 4);
    // A wrong fingerprint is rejected.
    let other = Env::new("trust-other");
    let other_fp = other.m(&["info"]).data()["master_fingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        fresh(&["trust", &other_fp], &[]).err_code(),
        "UNTRUSTED_ROOT"
    );
    let r = fresh(
        &["--identity", id, "info"],
        &[
            ("NEPOMUK_PASSPHRASE", MASTER_PASS),
            ("NEPOMUK_ROOT_FP", &other_fp),
        ],
    );
    assert_eq!(r.err_code(), "UNTRUSTED_ROOT");
    // CI: pinned through the environment.
    let r = fresh(
        &["--identity", id, "info"],
        &[
            ("NEPOMUK_PASSPHRASE", MASTER_PASS),
            ("NEPOMUK_ROOT_FP", &fp),
        ],
    );
    r.data();
    fresh(&["trust", &fp], &[]).data();
    fresh(
        &["--identity", id, "info"],
        &[("NEPOMUK_PASSPHRASE", MASTER_PASS)],
    )
    .data();

    // A vault file swapped for another vault with a different master is rejected.
    std::fs::copy(&other.vault, &e.vault).unwrap();
    let r = e.m(&["info"]);
    assert_eq!(r.err_code(), "UNTRUSTED_ROOT");
}

#[test]
fn tampering_rollback_and_fork() {
    let e = Env::new("tamper");
    e.m(&["mkdir", "/a"]).ok();
    let v1 = std::fs::read(&e.vault).unwrap();
    let mem_path = std::fs::read_dir(e.path("state/vaults"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let m1 = std::fs::read(&mem_path).unwrap();
    e.m(&["mkdir", "/b"]).ok();
    let v2 = std::fs::read(&e.vault).unwrap();
    let m2 = std::fs::read(&mem_path).unwrap();

    // Flip one byte inside the last commit.
    let mut bad = v2.clone();
    let n = bad.len();
    bad[n - 200] ^= 0x01;
    std::fs::write(&e.vault, &bad).unwrap();
    let r = e.m(&["info"]);
    assert_eq!(r.code, 4, "{}", r.stdout);
    assert!(["SIGNATURE_INVALID", "UNSUPPORTED_FORMAT"].contains(&r.err_code().as_str()));

    // An older version: rollback.
    std::fs::write(&e.vault, &v1).unwrap();
    assert_eq!(e.m(&["info"]).err_code(), "ROLLBACK_DETECTED");

    // A different #2 built on #1 while the client remembers the original #2: fork.
    std::fs::write(&mem_path, &m1).unwrap();
    e.m(&["mkdir", "/c"]).ok();
    std::fs::write(&mem_path, &m2).unwrap();
    assert_eq!(e.m(&["info"]).err_code(), "FORK_DETECTED");
}

#[test]
fn master_transfer() {
    let e = Env::new("transfer");
    let old_fp = e.m(&["info"]).data()["master_fingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    let new_master = e.add_local_user("new-master");
    let d = e.m(&["master", "transfer", "new-master"]).data();
    let new_fp = d["new_fingerprint"].as_str().unwrap().to_string();
    // The author's client follows the transfer it signed.
    let info = e.l(&new_master, "new-master", &["whoami"]).data();
    assert_eq!(info["master"], true);
    assert_eq!(e.m(&["whoami"]).data()["master"], false);
    // Other clients (e.g. CI pinned to the old master) must confirm the new fingerprint.
    let mut c = e.command(&["info"], &[("NEPOMUK_ROOT_FP", &old_fp)]);
    c.env("NEPOMUK_STATE_DIR", e.path("state-ci"))
        .env(
            "NEPOMUK_IDENTITY",
            std::fs::read_to_string(&new_master).unwrap(),
        )
        .env("NEPOMUK_PASSPHRASE", password_for("new-master"));
    let out = c.output().unwrap();
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(j["error"]["code"], "UNTRUSTED_ROOT");
    assert_eq!(j["error"]["details"]["new_fingerprint"], new_fp.as_str());
}

#[test]
fn compact_keeps_state() {
    let e = Env::new("compact");
    for i in 0..5 {
        e.m(&["mkdir", &format!("/f{i}")]).ok();
    }
    e.m_in(&["put", "/f0/s"], b"v").ok();
    let d = e.m(&["compact"]).data();
    assert!(d["size_after"].as_u64() < d["size_before"].as_u64());
    assert_eq!(e.m(&["get", "/f0/s"]).data()["value"], "v");
    let info = e.m(&["info"]).data();
    assert_eq!(info["seq"], info["checkpoint_seq"]);
    e.m(&["mkdir", "/after"]).ok();
    // A non-master cannot compact.
    let ci = e.add_local_user("ci-x");
    assert_eq!(
        e.l(&ci, "ci-x", &["compact"]).err_code(),
        "UNAUTHORIZED_OPERATION"
    );
}

#[test]
fn templates_validate() {
    let e = Env::new("tpl");
    e.m(&["mkdir", "/s"]).ok();
    let r = e.m_in(
        &[
            "put",
            "/s/r",
            "--template",
            "android-signing",
            "--field",
            "key_alias=x",
        ],
        b"",
    );
    assert_eq!(r.err_code(), "TEMPLATE_VALIDATION");
    let r = e.m(&["put", "/s/r", "--template", "nope", "--field", "a=b"]);
    assert_eq!(r.err_code(), "USAGE");
}

#[test]
fn version_json() {
    let e = Env::bare("version");
    let d = e.cmd(&["version"], &[], None).data();
    assert_eq!(d["api"], 1);
    assert_eq!(d["suites"][0], "NPQ-1");
}

#[test]
fn passgen() {
    let e = Env::bare("passgen");
    let d = e.cmd(&["passgen"], &[], None).data();
    assert!(d["passphrase"].as_str().unwrap().split('-').count() >= 6);
    assert!(d["bits"].as_f64().unwrap() >= 77.0);
}

#[test]
fn android_signing_template_with_keytool() {
    if std::process::Command::new("keytool")
        .arg("-help")
        .output()
        .is_err()
    {
        eprintln!("keytool not available, skipping");
        return;
    }
    let e = Env::new("keytool");
    let ks = e.path("release.jks");
    let st = std::process::Command::new("keytool")
        .args([
            "-genkeypair",
            "-keystore",
            ks.to_str().unwrap(),
            "-storetype",
            "PKCS12",
            "-storepass",
            "store-pass-123",
            "-keypass",
            "store-pass-123",
            "-alias",
            "eshop-upload",
            "-keyalg",
            "EC",
            "-groupname",
            "secp256r1",
            "-validity",
            "20",
            "-dname",
            "CN=Test",
        ])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );
    e.m(&["mkdir", "-p", "/projects/eshop-android/signing"])
        .ok();
    let path = "/projects/eshop-android/signing/release";
    let base = [
        "put",
        path,
        "--template",
        "android-signing",
        "--field",
        "keystore=@release.jks",
        "--field",
        "key_alias=eshop-upload",
        "--field-prompt",
        "store_password",
        "--field-prompt",
        "key_password",
    ];
    assert_eq!(
        e.m_in(&base, b"wrong-store-pass\nstore-pass-123\n")
            .err_code(),
        "TEMPLATE_VALIDATION"
    );
    e.m_in(&base, b"store-pass-123\nstore-pass-123\n").ok();
    let ls = e.m(&["ls", "/projects/eshop-android/signing"]).data();
    let entry = &ls["entries"][0];
    assert_eq!(entry["template"], "android-signing");
    assert_eq!(
        entry["expiring_soon"], true,
        "valid for 20 days only: {entry}"
    );
}

#[test]
fn git_textconv_shows_public_metadata_only() {
    let e = Env::new("textconv");
    e.m(&["mkdir", "/secret-name"]).ok();
    let r = e
        .cmd(&["git-textconv", e.vault.to_str().unwrap()], &[], None)
        .ok();
    assert!(r.stdout.contains("#1"));
    assert!(r.stdout.contains("CreateNode"));
    assert!(r.stdout.contains("valid up to #1"));
    assert!(!r.stdout.contains("secret-name"));
    let r = e.cmd(&["git-merge", "a", "b", "c"], &[], None);
    assert_eq!(r.code, 1);
}

#[test]
fn doctor_reports_identity_and_vault() {
    let e = Env::new("doctor");
    let id = e.master_identity();
    let d = e
        .cmd(&["--identity", id.to_str().unwrap(), "doctor"], &[], None)
        .data();
    let checks = d["checks"].as_array().unwrap();
    let find = |area: &str, text: &str| {
        checks
            .iter()
            .any(|c| c["area"] == area && c["message"].as_str().unwrap().contains(text))
    };
    assert!(find("identity", "--identity"), "{d}");
    assert!(
        find("identity", "the master identity is on this computer"),
        "{d}"
    );
    assert!(find("vault", "verifies"), "{d}");
    assert!(find("vault", "the vault's master"), "{d}");
    assert_eq!(d["problems"], 0);

    // A broken configuration is a problem, with exit code 1.
    std::fs::write(
        e.path("cfg/config.toml"),
        "identity = \"/nonexistent/id.npk\"\n",
    )
    .unwrap();
    let r = e.cmd(&["doctor"], &[], None);
    assert_eq!(r.code, 1);
    let j = r.json();
    assert!(
        j["data"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["level"] == "problem"
                && c["message"].as_str().unwrap().contains("does not exist")),
        "{j}"
    );
}

/// PKCS12 keystores may protect the key with a password different from the store password
/// (keytool cannot check that; the template must not reject it).
#[test]
fn android_signing_pkcs12_with_a_separate_key_password() {
    let java = std::process::Command::new("java").arg("-version").output();
    if java.is_err()
        || std::process::Command::new("keytool")
            .arg("-help")
            .output()
            .is_err()
    {
        eprintln!("java/keytool not available, skipping");
        return;
    }
    let e = Env::new("p12keypass");
    let jks = e.path("tmp.jks");
    let st = std::process::Command::new("keytool")
        .args([
            "-genkeypair",
            "-storetype",
            "JKS",
            "-keystore",
            jks.to_str().unwrap(),
            "-storepass",
            "jks-store-pass",
            "-keypass",
            "jks-key-pass",
            "-alias",
            "upload",
            "-keyalg",
            "EC",
            "-groupname",
            "secp256r1",
            "-validity",
            "400",
            "-dname",
            "CN=Test",
        ])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );
    std::fs::write(e.path("ToPkcs12.java"), r#"
import java.io.*; import java.security.*; import java.security.cert.Certificate;
public class ToPkcs12 { public static void main(String[] a) throws Exception {
  KeyStore jks = KeyStore.getInstance("JKS");
  try (InputStream in = new FileInputStream(a[0])) { jks.load(in, "jks-store-pass".toCharArray()); }
  Key k = jks.getKey("upload", "jks-key-pass".toCharArray());
  Certificate[] chain = jks.getCertificateChain("upload");
  KeyStore p12 = KeyStore.getInstance("PKCS12"); p12.load(null, null);
  p12.setKeyEntry("upload", k, "key-pass-BBB".toCharArray(), chain);
  try (OutputStream out = new FileOutputStream(a[1])) { p12.store(out, "store-pass-AAA".toCharArray()); }
}}
"#).unwrap();
    let st = std::process::Command::new("java")
        .current_dir(e.dir.path())
        .args(["ToPkcs12.java", "tmp.jks", "release.p12"])
        .output()
        .unwrap();
    if !st.status.success() {
        eprintln!(
            "cannot run single-file Java programs (no JDK), skipping: {}",
            String::from_utf8_lossy(&st.stderr)
        );
        return;
    }
    e.m(&["mkdir", "/s"]).ok();
    let put = |name: &str, input: &[u8]| {
        e.m_in(
            &[
                "put",
                &format!("/s/{name}"),
                "--template",
                "android-signing",
                "--field",
                "keystore=@release.p12",
                "--field",
                "key_alias=upload",
                "--field-prompt",
                "store_password",
                "--field-prompt",
                "key_password",
            ],
            input,
        )
    };
    put("ok", b"store-pass-AAA\nkey-pass-BBB\n").ok();
    assert_eq!(
        put("wrong-key", b"store-pass-AAA\nkey-pass-XXX\n").err_code(),
        "TEMPLATE_VALIDATION"
    );
    assert_eq!(
        put("wrong-store", b"store-pass-XXX\nkey-pass-BBB\n").err_code(),
        "TEMPLATE_VALIDATION"
    );
    assert_eq!(
        e.m(&["get", "/s/ok#key_password"]).data()["value"],
        "key-pass-BBB"
    );
}
