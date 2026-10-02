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
