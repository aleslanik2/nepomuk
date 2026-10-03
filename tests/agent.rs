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

/// A failed check is reported as a GitHub Actions annotation as well as a panic.
macro_rules! check {
    ($cond:expr, $($fmt:tt)+) => {
        if !$cond {
            let msg = format!($($fmt)+).replace('\n', " | ");
            panic!("\n::error title=agent test::{msg}\n");
        }
    };
}

fn enable_touchid(e: &Env, base: &[(&str, &str)]) {
    let id = e.master_identity();
    let mut env = base.to_vec();
    env.push(("NEPOMUK_PASSPHRASE", MASTER_PASS));
    e.cmd(
        &[
            "--identity",
            id.to_str().unwrap(),
            "identity",
            "touchid",
            "enable",
        ],
        &env,
        None,
    )
    .ok();
}

#[test]
fn touch_id_cached_per_terminal_for_reading() {
    let e = Env::new("agent");
    // Long enough that slow CI machines do not hit the timeout within one step.
    let helper = setup(&e, 120);
    let tmp = std::env::temp_dir();
    let base: Vec<(&str, &str)> = vec![
        ("NEPOMUK_TOUCHID_HELPER", helper.to_str().unwrap()),
        ("TMPDIR", tmp.to_str().unwrap()),
    ];
    enable_touchid(&e, &base);

    // Programs without a terminal are not remembered: each one asks.
    let touch = || e.cmd(&["--touchid", "whoami"], &base, None);
    touch().data();
    touch().data();
    check!(
        prompts(&helper) == 2,
        "detached: {} prompts, expected 2",
        prompts(&helper)
    );
    let last = reasons(&helper).last().cloned().unwrap_or_default();
    check!(
        last == "use master for vault.nepomuk: nepomuk whoami",
        "detached prompt reason: {last}"
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
    let outputs: Vec<String> = r.iter().map(|x| x.stdout.trim().to_string()).collect();
    for (i, x) in r.iter().enumerate().take(5) {
        check!(x.code == 0, "terminal step {i} failed: {outputs:?}");
    }
    check!(
        prompts(&helper) == 4,
        "one terminal: {} prompts, expected 4 | reasons {:?} | outputs {outputs:?}",
        prompts(&helper),
        reasons(&helper)
    );
    let r2 = reasons(&helper).get(2).cloned().unwrap_or_default();
    check!(
        r2 == "use master for vault.nepomuk for 2 minutes in this terminal: nepomuk whoami",
        "terminal prompt reason: {r2}"
    );
    let vaults = r[5].data()["vaults"]
        .as_array()
        .map(|v| v.len())
        .unwrap_or(0);
    check!(vaults == 1, "agent status in the terminal: {}", outputs[5]);

    // Another terminal does not get it.
    let r = e.in_terminal(&[(whoami, &base)]);
    check!(r[0].code == 0, "other terminal: {}", r[0].stdout);
    check!(
        prompts(&helper) == 5,
        "other terminal: {} prompts, expected 5",
        prompts(&helper)
    );

    // `nepomuk lock` forgets it, from anywhere.
    e.cmd(&["lock"], &base, None).ok();
    let r = e.in_terminal(&[(whoami, &base), (whoami, &base)]);
    check!(r[1].code == 0, "after lock: {}", r[1].stdout);
    check!(
        prompts(&helper) == 6,
        "after lock: {} prompts, expected 6",
        prompts(&helper)
    );

    // Disabling Touch ID forgets the cached identity too.
    e.cmd(&["identity", "touchid", "disable"], &base, None).ok();
    let code = e.cmd(&["--touchid", "whoami"], &base, None).err_code();
    check!(code == "PASSWORD_REQUIRED", "after disable: {code}");
    e.cmd(&["lock"], &base, None);
}

#[test]
fn touch_id_cache_expires() {
    let e = Env::new("agent-expiry");
    let helper = setup(&e, 2);
    let tmp = std::env::temp_dir();
    let base: Vec<(&str, &str)> = vec![
        ("NEPOMUK_TOUCHID_HELPER", helper.to_str().unwrap()),
        ("TMPDIR", tmp.to_str().unwrap()),
    ];
    enable_touchid(&e, &base);
    let whoami: &[&str] = &["--touchid", "whoami"];
    // In one terminal: asked, then asked again once the timeout has passed.
    let r = e.in_terminal(&[(whoami, &base), (&["@sleep", "3"], &[]), (whoami, &base)]);
    check!(r[2].code == 0, "after the timeout: {}", r[2].stdout);
    check!(
        prompts(&helper) == 2,
        "after the timeout: {} prompts, expected 2",
        prompts(&helper)
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
