//! Update notices and `nepomuk upgrade`.
//!
//! The latest release is looked up at most once a day in a detached background process, so no
//! command waits for the network. `nepomuk upgrade` downloads the release's installer, verifies
//! it against the signed SHA256SUMS with the release key below (the same key the installers
//! embed) and runs it for the location of the running binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config;
use crate::error::{Code, Error, Result};

pub const REPO: &str = "aleslanik2/nepomuk";
const NAMESPACE: &str = "nepomuk-release";

/// Keys allowed to sign releases; keep in sync with install.sh and install.ps1
/// (`scripts/release-signers.sh check` compares all three).
pub const RELEASE_SIGNERS: &str = "\
release@nepomuk ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClyxfJb2+KHFDtD0JbFya1aAdTl7zrawzY7NA7cH2Uo
";

const CHECK_EVERY: i64 = 24 * 3600;
const NOTIFY_EVERY: i64 = 24 * 3600;

pub fn current() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// "v1.2.3" or "1.2.3" → (1, 2, 3)
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().trim_start_matches('v').split(['.', '-', '+']);
    Some((
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    ))
}

pub fn is_newer(latest: &str, current: &str) -> bool {
    matches!((parse_version(latest), parse_version(current)), (Some(l), Some(c)) if l > c)
}

// ---------------------------------------------------------------- Cache

#[derive(Default, Serialize, Deserialize)]
struct Cache {
    checked_at: Option<i64>,
    latest: Option<String>,
    notified_at: Option<i64>,
}

fn cache_path() -> PathBuf {
    config::state_dir().join("update.json")
}

fn load() -> Cache {
    std::fs::read(cache_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save(c: &Cache) {
    let _ = config::write_private(&cache_path(), &serde_json::to_vec_pretty(c).unwrap());
}

pub fn enabled(user: &config::UserConfig) -> bool {
    user.update_check.unwrap_or(true)
        && std::env::var_os("NEPOMUK_NO_UPDATE_CHECK").is_none()
        && !config::is_ci()
}

/// What is known without touching the network.
pub fn status() -> Value {
    let c = load();
    let latest = c.latest.clone();
    json!({
        "current": current(),
        "latest": latest,
        "newer": latest.as_deref().is_some_and(|l| is_newer(l, current())),
        "checked_at": c.checked_at,
    })
}

/// Starts a background lookup when the cached answer is older than a day.
pub fn refresh_if_stale(user: &config::UserConfig) {
    if enabled(user)
        && load()
            .checked_at
            .is_none_or(|t| crate::tx::now() - t > CHECK_EVERY)
    {
        spawn_refresh();
    }
}

/// Called after a command: refreshes the cache in the background when it is stale and returns
/// a notice (at most once a day) when a newer release is known.
pub fn notice(user: &config::UserConfig) -> Option<String> {
    if !enabled(user) {
        return None;
    }
    let now = crate::tx::now();
    let mut c = load();
    if c.checked_at.is_none_or(|t| now - t > CHECK_EVERY) {
        spawn_refresh();
    }
    let latest = c.latest.clone()?;
    if !is_newer(&latest, current()) || c.notified_at.is_some_and(|t| now - t < NOTIFY_EVERY) {
        return None;
    }
    c.notified_at = Some(now);
    save(&c);
    Some(format!(
        "nepomuk {latest} is available (you have {}); run `nepomuk upgrade`",
        current()
    ))
}

fn spawn_refresh() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut cmd = Command::new(exe);
    cmd.args(["upgrade", "--refresh"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let _ = cmd.spawn();
}

/// `nepomuk upgrade --refresh` (background): looks up the latest release.
pub fn refresh() -> Result<Option<String>> {
    let mut c = load();
    c.checked_at = Some(crate::tx::now());
    let latest = latest_tag();
    if let Some(l) = &latest {
        c.latest = Some(l.clone());
    }
    save(&c);
    Ok(latest)
}

// ---------------------------------------------------------------- Network (curl or gh)

fn token() -> Option<String> {
    std::env::var("GH_TOKEN")
        .ok()
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
        .filter(|t| !t.is_empty())
}

fn have(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// The tag of the latest release: through `gh` when a token is set (private repository),
/// otherwise from the public /releases/latest redirect.
pub fn latest_tag() -> Option<String> {
    if token().is_some() && have("gh") {
        let out = Command::new("gh")
            .args([
                "release", "view", "-R", REPO, "--json", "tagName", "-q", ".tagName",
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        let t = String::from_utf8_lossy(&out.stdout).trim().to_string();
        return (out.status.success() && parse_version(&t).is_some()).then_some(t);
    }
    let out = Command::new("curl")
        .args([
            "-fsSLI",
            "-o",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
            "-w",
            "%{url_effective}",
            "--max-time",
            "15",
        ])
        .arg(format!("https://github.com/{REPO}/releases/latest"))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let url = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let tag = url.rsplit('/').next()?.to_string();
    (out.status.success() && parse_version(&tag).is_some()).then_some(tag)
}

/// A mirror (or a local directory for tests): `<base>/<tag>/<file>`.
fn base_url() -> Option<String> {
    std::env::var("NEPOMUK_UPGRADE_BASE_URL")
        .ok()
        .filter(|b| !b.is_empty())
}

fn signers() -> Result<String> {
    match std::env::var_os("NEPOMUK_UPGRADE_SIGNERS") {
        Some(f) => Ok(std::fs::read_to_string(f)?),
        None => Ok(RELEASE_SIGNERS.to_string()),
    }
}

fn download(tag: &str, name: &str, dir: &Path) -> Result<PathBuf> {
    let dest = dir.join(name);
    let ok = if let Some(base) = base_url() {
        Command::new("curl")
            .args(["--proto", "=https,file", "-fsSL", "-o"])
            .arg(&dest)
            .arg(format!("{}/{tag}/{name}", base.trim_end_matches('/')))
            .stdin(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    } else if token().is_some() && have("gh") {
        Command::new("gh")
            .args(["release", "download", tag, "-R", REPO, "-p", name, "-D"])
            .arg(dir)
            .args(["--clobber"])
            .stdin(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    } else {
        Command::new("curl")
            .args([
                "--proto",
                "=https",
                "--tlsv1.2",
                "-fsSL",
                "--retry",
                "3",
                "-o",
            ])
            .arg(&dest)
            .arg(format!(
                "https://github.com/{REPO}/releases/download/{tag}/{name}"
            ))
            .stdin(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    if !ok || !dest.is_file() {
        return Err(Error::new(
            Code::Offline,
            format!("cannot download {name} of {tag}"),
        ));
    }
    Ok(dest)
}

/// Verifies SHA256SUMS against the release key and returns the hash listed for `name`.
fn verified_hash(dir: &Path, sums: &Path, sig: &Path, name: &str) -> Result<String> {
    let keys = signers()?;
    let signers = dir.join("allowed_signers");
    std::fs::write(&signers, &keys)?;
    let principal = keys
        .split_whitespace()
        .next()
        .ok_or_else(|| Error::general("no release key"))?
        .to_string();
    let ok = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&signers)
        .args(["-I", &principal, "-n", NAMESPACE, "-s"])
        .arg(sig)
        .stdin(std::fs::File::open(sums)?)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| Error::general("ssh-keygen (OpenSSH) is required to verify the release"))?;
    if !ok.success() {
        return Err(Error::new(
            Code::SignatureInvalid,
            "SHA256SUMS of the release is not signed by the release key",
        ));
    }
    let text = std::fs::read_to_string(sums)?;
    text.lines()
        .filter_map(|l| l.split_once(char::is_whitespace))
        .find(|(_, f)| f.trim().trim_start_matches('*') == name)
        .map(|(h, _)| h.to_lowercase())
        .ok_or_else(|| {
            Error::new(
                Code::SignatureInvalid,
                format!("{name} of this release is not covered by its signed SHA256SUMS (releases before v0.2.4); install it with install.sh instead"),
            )
        })
}

fn sha256_file(p: &Path) -> Result<String> {
    use sha2::Digest;
    Ok(hex::encode(sha2::Sha256::digest(std::fs::read(p)?)))
}

// ---------------------------------------------------------------- Upgrade

/// Where the desktop app is installed, if it is.
fn installed_app(exe_dir: &Path) -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        let home = dirs::home_dir()?;
        [
            PathBuf::from("/Applications/nepomuk.app"),
            home.join("Applications/nepomuk.app"),
        ]
        .into_iter()
        .find(|p| p.is_dir())
    } else if cfg!(windows) {
        // The Windows app is not next to the CLI; `nepomuk upgrade --gui` updates it.
        None
    } else {
        Some(exe_dir.join("nepomuk-gui")).filter(|p| p.is_file())
    }
}

pub struct Plan {
    pub tag: String,
    pub newer: bool,
}

pub fn plan(force_tag: Option<&str>) -> Result<Plan> {
    let tag = match force_tag {
        Some(t) => t.to_string(),
        None => latest_tag().ok_or_else(|| {
            Error::new(Code::Offline, "cannot find the latest release (offline, or a private repository without GH_TOKEN)")
        })?,
    };
    let newer = is_newer(&tag, current());
    let mut c = load();
    c.checked_at = Some(crate::tx::now());
    c.latest = Some(tag.clone());
    save(&c);
    Ok(Plan { tag, newer })
}

/// Downloads, verifies and runs the release's installer. `gui`: Some(true) forces the app,
/// Some(false) skips it, None updates it when it is installed.
pub fn run(tag: &str, gui: Option<bool>) -> Result<i32> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let exe_dir = exe
        .parent()
        .ok_or_else(|| Error::general("cannot locate the installed binary"))?
        .to_path_buf();
    if exe_dir.join("Contents").exists() || exe.to_string_lossy().contains(".app/Contents/MacOS") {
        return Err(Error::usage(
            "this nepomuk is part of the desktop app; upgrade the command line installation instead",
        ));
    }
    let work = std::env::temp_dir().join(format!("nepomuk-upgrade-{}", std::process::id()));
    std::fs::create_dir_all(&work)?;
    let result = (|| {
        let installer = if cfg!(windows) {
            "install.ps1"
        } else {
            "install.sh"
        };
        let sums = download(tag, "SHA256SUMS", &work)?;
        let sig = download(tag, "SHA256SUMS.sig", &work)?;
        let script = download(tag, installer, &work)?;
        let expected = verified_hash(&work, &sums, &sig, installer)?;
        if sha256_file(&script)? != expected {
            return Err(Error::new(
                Code::SignatureInvalid,
                format!("{installer} does not match the signed SHA256SUMS"),
            ));
        }
        let app = installed_app(&exe_dir);
        let with_gui = gui.unwrap_or(app.is_some());
        let status = if cfg!(windows) {
            let mut c = Command::new("powershell");
            c.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
                .arg(&script);
            c.args(["-Version", tag, "-Dir"])
                .arg(&exe_dir)
                .arg("-NoPath");
            if with_gui {
                c.arg("-Gui");
            }
            c.status()?
        } else {
            let mut c = Command::new("sh");
            c.arg(&script)
                .args(["--version", tag, "--dir"])
                .arg(&exe_dir);
            if let Some(base) = base_url() {
                c.arg("--base-url")
                    .arg(format!("{}/{tag}", base.trim_end_matches('/')));
            }
            if let Some(f) = std::env::var_os("NEPOMUK_UPGRADE_SIGNERS") {
                c.arg("--signers").arg(f);
            }
            if with_gui {
                c.arg("--gui");
                if let Some(app) = app.as_ref().and_then(|a| a.parent()) {
                    c.arg("--app-dir").arg(app);
                }
            }
            c.status()?
        };
        Ok(status.code().unwrap_or(1))
    })();
    let _ = std::fs::remove_dir_all(&work);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v0.2.10"), Some((0, 2, 10)));
        assert!(is_newer("v0.2.10", "0.2.9"));
        assert!(is_newer("v1.0.0", "0.9.9"));
        assert!(!is_newer("v0.2.3", "0.2.3"));
        assert!(!is_newer("v0.2.2", "0.2.3"));
        assert!(!is_newer("latest", "0.2.3"));
    }
}
