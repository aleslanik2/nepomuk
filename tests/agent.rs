//! The Touch ID agent: a fingerprint at most once per `agent_timeout`.
//! A fake `nepomuk-touchid` stands in for the Secure Enclave and counts the prompts.
#![cfg(target_os = "macos")]

mod common;

use common::*;

const FAKE_HELPER: &str = r#"#!/usr/bin/python3
import base64, json, sys
log = sys.argv[0] + ".log"
cmd = sys.argv[1]
if cmd == "available":
    sys.exit(0)
data = sys.stdin.buffer.read()
with open(log, "a") as f:
    f.write(cmd + "\n")
if cmd == "open":
    with open(sys.argv[0] + ".reason", "a") as f:
        f.write(sys.argv[2] + "\n")
if cmd == "seal":
    sys.stdout.write(json.dumps({"version": 1, "fake": base64.b64encode(data).decode()}))
elif cmd == "open":
    sys.stdout.buffer.write(base64.b64decode(json.loads(data)["fake"]))
"#;

fn prompts(helper: &std::path::Path) -> usize {
    std::fs::read_to_string(helper.with_extension("log"))
        .unwrap_or_default()
        .lines()
        .filter(|l| *l == "open")
        .count()
}

#[test]
fn touch_id_once_per_timeout() {
    let e = Env::new("agent");
    let helper = e.path("nepomuk-touchid");
    std::fs::write(&helper, FAKE_HELPER).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::write(e.path("cfg/config.toml"), "agent_timeout = 3\n").unwrap();
    let tmp = std::env::temp_dir();
    let base: Vec<(&str, &str)> = vec![
        ("NEPOMUK_TOUCHID_HELPER", helper.to_str().unwrap()),
        ("TMPDIR", tmp.to_str().unwrap()),
    ];
    let id = e.master_identity();
    let id = id.to_str().unwrap();

    let mut enable_env = base.clone();
    enable_env.push(("NEPOMUK_PASSPHRASE", MASTER_PASS));
    e.cmd(
        &["--identity", id, "identity", "touchid", "enable"],
        &enable_env,
        None,
    )
    .ok();
    let touch = || e.cmd(&["--touchid", "whoami"], &base, None);

    assert_eq!(touch().data()["master"], true);
    assert_eq!(prompts(&helper), 1);
    // The prompt says who, for what and for how long – never paths of identities.
    let reason = std::fs::read_to_string(helper.with_extension("reason")).unwrap();
    assert_eq!(
        reason.trim(),
        "use master for vault.nepomuk for 3 seconds: nepomuk whoami"
    );
    // Within the timeout: no new prompt.
    assert_eq!(touch().data()["master"], true);
    e.m(&["ls"]).ok();
    assert_eq!(touch().data()["master"], true);
    assert_eq!(prompts(&helper), 1, "the agent serves the identity");
    let status = e.cmd(&["agent"], &base, None).data();
    assert_eq!(status["vaults"].as_array().unwrap().len(), 1);

    // `nepomuk lock` forgets it.
    e.cmd(&["lock"], &base, None).ok();
    touch().ok();
    assert_eq!(prompts(&helper), 2);

    // The timeout expires.
    std::thread::sleep(std::time::Duration::from_secs(4));
    touch().ok();
    assert_eq!(prompts(&helper), 3);

    // Disabling Touch ID forgets the cached identity too.
    e.cmd(&["identity", "touchid", "disable"], &base, None).ok();
    assert_eq!(
        e.cmd(&["--touchid", "whoami"], &base, None).err_code(),
        "PASSWORD_REQUIRED"
    );
    e.cmd(&["lock"], &base, None);
}

#[test]
fn agent_can_be_turned_off() {
    let e = Env::new("agent-off");
    let helper = e.path("nepomuk-touchid");
    std::fs::write(&helper, FAKE_HELPER).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::write(e.path("cfg/config.toml"), "agent_timeout = 0\n").unwrap();
    let tmp = std::env::temp_dir();
    let base = [
        ("NEPOMUK_TOUCHID_HELPER", helper.to_str().unwrap()),
        ("TMPDIR", tmp.to_str().unwrap()),
    ];
    let id = e.master_identity();
    e.cmd(
        &[
            "--identity",
            id.to_str().unwrap(),
            "identity",
            "touchid",
            "enable",
        ],
        &[base[0], base[1], ("NEPOMUK_PASSPHRASE", MASTER_PASS)],
        None,
    )
    .ok();
    e.cmd(&["--touchid", "whoami"], &base, None).ok();
    e.cmd(&["--touchid", "whoami"], &base, None).ok();
    assert_eq!(
        prompts(&helper),
        2,
        "with agent_timeout = 0 every command asks"
    );
}

#[test]
fn touch_id_prompt_names_the_project() {
    let e = Env::new("agent-project");
    let helper = e.path("nepomuk-touchid");
    std::fs::write(&helper, FAKE_HELPER).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::write(e.path("cfg/config.toml"), "agent_timeout = 0\n").unwrap();
    std::fs::write(
        e.path(".nepomuk.toml"),
        format!(
            "name = \"eshop-android\"\nvault = \"{}\"\n\n[exec.release]\nenv.X = \"/nothing\"\n",
            e.vault.display()
        ),
    )
    .unwrap();
    let tmp = std::env::temp_dir();
    let base = [
        ("NEPOMUK_TOUCHID_HELPER", helper.to_str().unwrap()),
        ("TMPDIR", tmp.to_str().unwrap()),
    ];
    let id = e.master_identity();
    e.cmd(
        &[
            "--identity",
            id.to_str().unwrap(),
            "identity",
            "touchid",
            "enable",
        ],
        &[base[0], base[1], ("NEPOMUK_PASSPHRASE", MASTER_PASS)],
        None,
    )
    .ok();
    // exec fails (no such secret), but only after the prompt.
    let _ = e.cmd(
        &[
            "--touchid",
            "exec",
            "release",
            "--",
            "echo",
            "SECRET-LOOKING-ARG",
        ],
        &base,
        None,
    );
    let reason = std::fs::read_to_string(helper.with_extension("reason")).unwrap();
    assert_eq!(
        reason.trim(),
        "use master for eshop-android (vault.nepomuk): nepomuk exec release"
    );
}

/// Audit finding 7: a Touch ID unlock in the app does not feed the agent, and locking the app
/// clears identities the agent holds for the command line.
#[test]
fn app_lock_clears_the_agent() {
    use std::io::{BufRead, BufReader, Write};
    let e = Env::new("agent-app");
    let helper = e.path("nepomuk-touchid");
    std::fs::write(&helper, FAKE_HELPER).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::write(e.path("cfg/config.toml"), "agent_timeout = 60\n").unwrap();
    let tmp = std::env::temp_dir();
    let base: Vec<(&str, &str)> = vec![
        ("NEPOMUK_TOUCHID_HELPER", helper.to_str().unwrap()),
        ("TMPDIR", tmp.to_str().unwrap()),
    ];
    let id = e.master_identity();
    let mut enable_env = base.clone();
    enable_env.push(("NEPOMUK_PASSPHRASE", MASTER_PASS));
    e.cmd(
        &[
            "--identity",
            id.to_str().unwrap(),
            "identity",
            "touchid",
            "enable",
        ],
        &enable_env,
        None,
    )
    .ok();
    e.cmd(&["lock"], &base, None);
    let cached = || {
        e.cmd(&["agent"], &base, None).json()["data"]["vaults"]
            .as_array()
            .map_or(0, |v| v.len())
    };

    let mut c = e.command(&["serve", "--stdio"], &base);
    c.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut app = c.spawn().unwrap();
    let mut stdin = app.stdin.take().unwrap();
    let mut stdout = BufReader::new(app.stdout.take().unwrap());
    let mut call = |id: u32, method: &str, params: serde_json::Value| {
        let req =
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(stdin, "{req}").unwrap();
        loop {
            let mut line = String::new();
            stdout.read_line(&mut line).unwrap();
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            if v["id"] == id {
                return v;
            }
        }
    };
    let r = call(1, "session.unlock", serde_json::json!({ "touchid": true }));
    assert_eq!(r["result"]["name"], "master", "{r}");
    assert_eq!(
        cached(),
        0,
        "the app's Touch ID unlock must not feed the agent"
    );

    // The command line caches the identity; locking the app clears it.
    e.cmd(&["--touchid", "whoami"], &base, None).ok();
    assert_eq!(cached(), 1);
    let r = call(2, "session.lock", serde_json::json!({}));
    assert_eq!(r["result"]["agent_cleared"], true, "{r}");
    assert_eq!(cached(), 0);
    drop(stdin);
    let _ = app.wait();
}
