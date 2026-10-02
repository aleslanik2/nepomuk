//! `nepomuk doctor`: checks the installation and the configuration without unlocking anything.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use crate::app::Ctx;
use crate::config;
use crate::identity::IdentityFile;
use crate::upgrade;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

pub struct Check {
    pub area: &'static str,
    pub level: Level,
    pub message: String,
    pub hint: Option<String>,
}

fn ok(area: &'static str, m: impl Into<String>) -> Check {
    Check {
        area,
        level: Level::Ok,
        message: m.into(),
        hint: None,
    }
}

fn warn(area: &'static str, m: impl Into<String>, hint: impl Into<String>) -> Check {
    Check {
        area,
        level: Level::Warn,
        message: m.into(),
        hint: Some(hint.into()),
    }
}

fn fail(area: &'static str, m: impl Into<String>, hint: impl Into<String>) -> Check {
    Check {
        area,
        level: Level::Fail,
        message: m.into(),
        hint: Some(hint.into()),
    }
}

fn tilde(p: &Path) -> String {
    match dirs::home_dir() {
        Some(h) if p.starts_with(&h) => format!("~/{}", p.strip_prefix(&h).unwrap().display()),
        _ => p.display().to_string(),
    }
}

fn have(cmd: &str, arg: &str) -> bool {
    Command::new(cmd)
        .arg(arg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Version of an installed macOS app bundle (CFBundleShortVersionString).
fn app_version(app: &Path) -> Option<String> {
    let plist = std::fs::read_to_string(app.join("Contents/Info.plist")).ok()?;
    let after = plist
        .split("<key>CFBundleShortVersionString</key>")
        .nth(1)?;
    let start = after.find("<string>")? + "<string>".len();
    let end = after[start..].find("</string>")? + start;
    Some(after[start..end].trim().to_string())
}

/// Compares with the latest release on GitHub.
fn latest_check(current: &str, out: &mut Vec<Check>) {
    match upgrade::latest_tag() {
        Some(latest) if upgrade::is_newer(&latest, current) => out.push(warn(
            "version",
            format!("nepomuk {current} is installed; {latest} is available"),
            "run `nepomuk upgrade`",
        )),
        Some(latest) => out.push(ok(
            "version",
            format!("nepomuk {current} is the latest release ({latest})"),
        )),
        None => {
            let hint = if std::env::var_os("GH_TOKEN").is_none()
                && std::env::var_os("GITHUB_TOKEN").is_none()
            {
                "the repository is private: set GH_TOKEN (e.g. `export GH_TOKEN=$(gh auth token)`) or check the network"
            } else {
                "check the network and that `gh` is logged in"
            };
            out.push(warn(
                "version",
                format!("nepomuk {current}; the latest release could not be looked up"),
                hint,
            ));
        }
    }
}

fn version_checks(out: &mut Vec<Check>) {
    let current = upgrade::current();
    if std::env::var_os("NEPOMUK_NO_UPDATE_CHECK").is_some() {
        out.push(warn(
            "version",
            format!("nepomuk {current}; the latest release was not looked up"),
            "NEPOMUK_NO_UPDATE_CHECK is set",
        ));
    } else {
        latest_check(current, out);
    }
    if let Ok(exe) = std::env::current_exe().and_then(|e| e.canonicalize())
        && cfg!(target_os = "macos")
        && !exe.to_string_lossy().contains(".app/Contents/MacOS")
    {
        let helper = exe.with_file_name("nepomuk-touchid");
        if helper.is_file() {
            out.push(ok(
                "version",
                "the Touch ID helper is installed next to the CLI",
            ));
        } else {
            out.push(warn(
                "version",
                "the Touch ID helper (nepomuk-touchid) is missing next to the CLI",
                format!("reinstall with `nepomuk upgrade --tag v{current}` or install.sh"),
            ));
        }
    }
    if cfg!(target_os = "macos") {
        let home = dirs::home_dir().unwrap_or_default();
        for app in [
            PathBuf::from("/Applications/nepomuk.app"),
            home.join("Applications/nepomuk.app"),
        ] {
            if let Some(v) = app_version(&app) {
                if v == current {
                    out.push(ok(
                        "version",
                        format!("the desktop app in {} is {v}", tilde(app.parent().unwrap())),
                    ));
                } else {
                    out.push(warn(
                        "version",
                        format!(
                            "the desktop app in {} is {v}, the CLI is {current}",
                            tilde(app.parent().unwrap())
                        ),
                        "run `nepomuk upgrade --gui`",
                    ));
                }
            }
        }
    }
    if !upgrade::enabled(&config::UserConfig::load().unwrap_or_default()) {
        out.push(warn(
            "version",
            "update notices are turned off",
            "remove `update_check = false` from config.toml to be told about new releases",
        ));
    }
}

fn path_checks(out: &mut Vec<Check>) {
    let Ok(exe) = std::env::current_exe().and_then(|e| e.canonicalize()) else {
        return;
    };
    let dir = exe.parent().unwrap().to_path_buf();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let dirs_in_path: Vec<PathBuf> = std::env::split_paths(&path).collect();
    let name = if cfg!(windows) {
        "nepomuk.exe"
    } else {
        "nepomuk"
    };
    let first = dirs_in_path
        .iter()
        .map(|d| d.join(name))
        .find(|p| p.is_file());
    match first {
        Some(p) if p.canonicalize().ok().as_deref() == Some(exe.as_path()) => out.push(ok(
            "path",
            format!("`nepomuk` in PATH is this installation ({})", tilde(&exe)),
        )),
        Some(p) => out.push(warn(
            "path",
            format!(
                "`nepomuk` in PATH is {}, not this one ({})",
                tilde(&p),
                tilde(&exe)
            ),
            "remove the older installation or reorder PATH",
        )),
        None => out.push(warn(
            "path",
            format!("{} is not in PATH", tilde(&dir)),
            format!(
                "add `export PATH=\"{}:$PATH\"` to your shell profile",
                dir.display()
            ),
        )),
    }
}

/// Identity configuration; returns the fingerprints of identity files found, for the vault check.
fn identity_checks(ctx: &Ctx, out: &mut Vec<Check>) -> Vec<(String, String)> {
    let mut fps = Vec::new();
    let cfg_dir = config::config_dir();
    let cfg_file = cfg_dir.join("config.toml");
    match std::fs::read_to_string(&cfg_file) {
        Ok(s) => match toml::from_str::<config::UserConfig>(&s) {
            Ok(_) => out.push(ok("identity", format!("{} is valid", tilde(&cfg_file)))),
            Err(e) => out.push(fail(
                "identity",
                format!("{} cannot be read: {e}", tilde(&cfg_file)),
                "fix the TOML syntax",
            )),
        },
        Err(_) => out.push(ok(
            "identity",
            format!("no {} (defaults are used)", tilde(&cfg_file)),
        )),
    }

    fn check_file(label: &str, p: &Path, out: &mut Vec<Check>, fps: &mut Vec<(String, String)>) {
        match std::fs::read_to_string(p) {
            Ok(t) => match IdentityFile::parse(&t) {
                Ok(f) => {
                    out.push(ok(
                        "identity",
                        format!("{label}: {} ({}, {})", tilde(p), f.name, f.fingerprint()),
                    ));
                    fps.push((f.name.clone(), f.fingerprint()));
                }
                Err(_) => out.push(fail(
                    "identity",
                    format!("{label}: {} is not a nepomuk identity file", tilde(p)),
                    "point it to an .npk file",
                )),
            },
            Err(_) => out.push(fail(
                "identity",
                format!("{label}: {} does not exist", tilde(p)),
                "fix `identity` in config.toml or create one with `nepomuk identity new`",
            )),
        }
    }

    let mut configured = false;
    if let Some(p) = &ctx.opts.identity {
        check_file("--identity", p, out, &mut fps);
        configured = true;
    }
    if let Ok(v) = std::env::var("NEPOMUK_IDENTITY") {
        configured = true;
        match IdentityFile::parse(&v) {
            Ok(f) => {
                out.push(ok(
                    "identity",
                    format!("NEPOMUK_IDENTITY: {} ({})", f.name, f.fingerprint()),
                ));
                fps.push((f.name.clone(), f.fingerprint()));
            }
            Err(_) => out.push(fail(
                "identity",
                "NEPOMUK_IDENTITY does not hold an identity file",
                "set it to the file's content (or base64 of it)",
            )),
        }
    }
    if let Some(p) = &ctx.user.identity {
        check_file("identity in config.toml", p, out, &mut fps);
        configured = true;
    }
    if let Some(e) = ctx
        .opts
        .email
        .clone()
        .or_else(|| std::env::var("NEPOMUK_EMAIL").ok())
        .or_else(|| ctx.user.email.clone())
    {
        out.push(ok("identity", format!("password identity: {e}")));
        fps.push((e, String::new()));
        configured = true;
    }
    let default = config::default_identity_path();
    if default.is_file() {
        check_file("default identity", &default, out, &mut fps);
        configured = true;
    }
    let master = cfg_dir.join("master.npk");
    if master.is_file() {
        if let Ok(f) = std::fs::read_to_string(&master)
            .map_err(|_| ())
            .and_then(|t| IdentityFile::parse(&t).map_err(|_| ()))
        {
            fps.push((f.name.clone(), f.fingerprint()));
        }
        out.push(warn(
            "identity",
            format!("the master identity is on this computer ({})", tilde(&master)),
            "keep the master offline; use it only for administration and work with an ordinary user",
        ));
    }
    if !configured {
        out.push(warn(
            "identity",
            "no identity is configured",
            format!(
                "add `identity = \"{}\"` or `email = \"you@example.com\"` to {}, or pass --identity / --email",
                if master.is_file() { master.display().to_string() } else { default.display().to_string() },
                tilde(&cfg_file)
            ),
        ));
    }
    fps
}

fn vault_checks(ctx: &Ctx, fps: &[(String, String)], out: &mut Vec<Check>) {
    let loc = match ctx.location() {
        Ok(l) => l,
        Err(_) => {
            out.push(warn(
                "vault",
                "no vault is configured",
                "set `export NEPOMUK_VAULT=~/path/vault.nepomuk` in your shell profile, use a project with .nepomuk.toml, or pass --vault",
            ));
            return;
        }
    };
    let source = if ctx.opts.vault.is_some() {
        "--vault"
    } else if std::env::var_os("NEPOMUK_VAULT").is_some() {
        "NEPOMUK_VAULT"
    } else {
        ".nepomuk.toml"
    };
    if !loc.path.is_file() && !loc.is_git() {
        out.push(fail(
            "vault",
            format!("{} ({source}) does not exist", tilde(&loc.path)),
            "fix the path",
        ));
        return;
    }
    match crate::app::open_vault(ctx, true) {
        Ok(o) => {
            out.push(ok(
                "vault",
                format!(
                    "{} ({source}) verifies: #{}, master {}",
                    tilde(&loc.path),
                    o.v.seq,
                    o.v.master_fp
                ),
            ));
            if !loc.is_git() {
                out.push(ok(
                    "vault",
                    "the vault is a plain file (no git remote): changes are written directly",
                ));
            }
            let s = &o.v.state;
            let mine: Vec<String> = fps
                .iter()
                .filter_map(|(name, fp)| {
                    s.users.values().find(|u| {
                        if fp.is_empty() {
                            u.name.eq_ignore_ascii_case(name)
                        } else {
                            crate::verify::user_fp(u) == *fp
                        }
                    })
                })
                .map(|u| {
                    if s.is_master(u.id) {
                        format!("{}, the vault's master", u.name)
                    } else if u.disabled {
                        format!("{} (disabled)", u.name)
                    } else {
                        u.name.clone()
                    }
                })
                .collect();
            if mine.is_empty() {
                out.push(warn(
                    "vault",
                    "none of the configured identities is a user of this vault",
                    "send an access request (`nepomuk identity request`) to an administrator",
                ));
            } else {
                out.push(ok(
                    "vault",
                    format!("you are {} in this vault", mine.join(", ")),
                ));
            }
            let vault = o.v.file.vault_id;
            if let Some(who) = crate::touchid::enabled_for(vault) {
                let who = match who {
                    crate::touchid::Who::Email { email } => email,
                    crate::touchid::Who::File { path } => tilde(&path),
                };
                out.push(ok(
                    "touchid",
                    format!("Touch ID unlocks {who} for this vault"),
                ));
                if crate::agent::status().is_some() {
                    out.push(ok(
                        "touchid",
                        "the agent is running (`nepomuk lock` forgets the unlocked identity)",
                    ));
                }
            } else if crate::touchid::available() {
                out.push(ok("touchid", "Touch ID is available but not set up for this vault (`nepomuk identity touchid enable`)"));
            }
        }
        Err(e) => {
            let hint = match e.code {
                crate::error::Code::UntrustedRoot => {
                    "verify the master fingerprint with your administrator and run `nepomuk trust <fingerprint>`"
                }
                crate::error::Code::RollbackDetected | crate::error::Code::ForkDetected => {
                    "someone may be tampering with the vault; contact your administrator"
                }
                crate::error::Code::Offline => "check the network or the git remote",
                _ => "see the message",
            };
            out.push(fail(
                "vault",
                format!(
                    "{} ({source}): {} [{}]",
                    tilde(&loc.path),
                    e.message,
                    e.code.as_str()
                ),
                hint,
            ));
        }
    }
}

fn tool_checks(out: &mut Vec<Check>) {
    if have("git", "--version") {
        out.push(ok("tools", "git is available"));
    } else {
        out.push(warn(
            "tools",
            "git is not available",
            "install git to use vaults in git repositories",
        ));
    }
    if have("ssh-keygen", "-?") {
        out.push(ok(
            "tools",
            "ssh-keygen is available (release verification)",
        ));
    } else {
        out.push(warn(
            "tools",
            "ssh-keygen is not available",
            "install OpenSSH; `nepomuk upgrade` needs it to verify releases",
        ));
    }
}

pub fn run(ctx: &Ctx) -> Vec<Check> {
    let mut out = Vec::new();
    version_checks(&mut out);
    path_checks(&mut out);
    let fps = identity_checks(ctx, &mut out);
    vault_checks(ctx, &fps, &mut out);
    tool_checks(&mut out);
    out
}

pub fn to_json(checks: &[Check]) -> Value {
    let level = |l: Level| match l {
        Level::Ok => "ok",
        Level::Warn => "warning",
        Level::Fail => "problem",
    };
    json!({
        "problems": checks.iter().filter(|c| c.level == Level::Fail).count(),
        "warnings": checks.iter().filter(|c| c.level == Level::Warn).count(),
        "checks": checks.iter().map(|c| json!({
            "area": c.area, "level": level(c.level), "message": c.message, "hint": c.hint,
        })).collect::<Vec<_>>(),
    })
}

pub fn to_text(checks: &[Check]) -> String {
    let mut s = String::new();
    let mut area = "";
    for c in checks {
        if c.area != area {
            area = c.area;
            s.push_str(&format!("\n{area}\n"));
        }
        let mark = match c.level {
            Level::Ok => "  ✓",
            Level::Warn => "  !",
            Level::Fail => "  ✗",
        };
        s.push_str(&format!("{mark} {}\n", c.message));
        if let Some(h) = &c.hint {
            s.push_str(&format!("      → {h}\n"));
        }
    }
    let problems = checks.iter().filter(|c| c.level == Level::Fail).count();
    let warnings = checks.iter().filter(|c| c.level == Level::Warn).count();
    s.push_str(&format!("\n{problems} problem(s), {warnings} warning(s)\n"));
    s.trim_start().to_string()
}
