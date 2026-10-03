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

fn setup(e: &Env, timeout: u64) -> std::path::PathBuf {
    let helper = e.path("nepomuk-touchid");
    std::fs::write(&helper, FAKE_HELPER).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::write(
        e.path("cfg/config.toml"),
        format!("agent_timeout = {timeout}\n"),
    )
    .unwrap();
    helper
}

fn reasons(helper: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(helper.with_extension("reason"))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn touch_id_once_per_timeout_in_one_terminal() {
    let e = Env::new("agent");
    let helper = setup(&e, 3);
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

    // Programs without a terminal are not remembered: each one asks.
    let touch = || e.cmd(&["--touchid", "whoami"], &base, None);
    assert_eq!(touch().data()["master"], true);
    assert_eq!(touch().data()["master"], true);
    assert_eq!(prompts(&helper), 2);
    // The prompt says who and for what – never paths of identities – and, without a terminal,
    // promises no caching.
    assert_eq!(
        reasons(&helper).last().unwrap(),
        "use master for vault.nepomuk: nepomuk whoami"
    );

    // One terminal: asked once for reading; a change asks again; reading stays cached.
    let whoami: &[&str] = &["--touchid", "whoami"];
    let r = e.in_terminal(&[
        (whoami, &base),
        (whoami, &base),
        (&["--touchid", "ls"], &base),
        (&["--touchid", "mkdir", "/fresh"], &base),
        (whoami, &base),
        (&["agent"], &base),
    ]);
    assert_eq!(r[0].data()["master"], true);
    assert_eq!(r[1].data()["master"], true);
    r[2].data();
    r[3].data();
    assert_eq!(r[4].data()["master"], true);
    assert_eq!(
        prompts(&helper),
        4,
        "one prompt to read, one for the change"
    );
    assert_eq!(
        reasons(&helper)[2],
        "use master for vault.nepomuk for 3 seconds in this terminal: nepomuk whoami"
    );
    assert_eq!(r[5].data()["vaults"].as_array().unwrap().len(), 1);

    // Another terminal does not get it.
    e.in_terminal(&[(whoami, &base)])[0].data();
    assert_eq!(prompts(&helper), 5);

    // `nepomuk lock` forgets it, from anywhere.
    e.cmd(&["lock"], &base, None).ok();
    let r = e.in_terminal(&[(whoami, &base), (whoami, &base)]);
    r[1].data();
    assert_eq!(prompts(&helper), 6);

    // The timeout expires.
    std::thread::sleep(std::time::Duration::from_secs(4));
    e.in_terminal(&[(whoami, &base)])[0].data();
    assert_eq!(prompts(&helper), 7);

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
