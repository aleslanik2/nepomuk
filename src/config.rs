//! Configuration (§10.2): project `.nepomuk.toml`, user `config.toml` and local state
//! (root pins, highest seen `seq`, pending offline changes).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Code, Error, Result};
use crate::model::Id;

// ---------------------------------------------------------------- Directories

fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

/// `~/.config/nepomuk` (Windows `%APPDATA%\nepomuk`).
pub fn config_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("NEPOMUK_CONFIG_DIR") {
        return PathBuf::from(d);
    }
    if cfg!(windows) {
        return dirs::config_dir().unwrap_or_else(home).join("nepomuk");
    }
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(x) if !x.is_empty() => PathBuf::from(x).join("nepomuk"),
        _ => home().join(".config").join("nepomuk"),
    }
}

/// `~/.local/state/nepomuk` (Windows `%LOCALAPPDATA%`, macOS `~/Library/Application Support`).
pub fn state_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("NEPOMUK_STATE_DIR") {
        return PathBuf::from(d);
    }
    if cfg!(windows) || cfg!(target_os = "macos") {
        return dirs::data_local_dir().unwrap_or_else(home).join("nepomuk");
    }
    match std::env::var_os("XDG_STATE_HOME") {
        Some(x) if !x.is_empty() => PathBuf::from(x).join("nepomuk"),
        _ => home().join(".local").join("state").join("nepomuk"),
    }
}

pub fn default_identity_path() -> PathBuf {
    config_dir().join("identity.npk")
}

/// Writes a file readable only by the current user, atomically.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ---------------------------------------------------------------- User config

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UserConfig {
    /// Path to a local identity file.
    pub identity: Option<PathBuf>,
    /// Default email of a password identity.
    pub email: Option<String>,
    /// `serve --stdio` inactivity limit in seconds.
    pub session_timeout: Option<u64>,
    /// How long the agent keeps an identity unlocked with Touch ID, in seconds (0 = never).
    pub agent_timeout: Option<u64>,
    /// Look up new releases once a day (default true; off in CI).
    pub update_check: Option<bool>,
}

impl UserConfig {
    pub fn load() -> Result<UserConfig> {
        let p = config_dir().join("config.toml");
        match std::fs::read_to_string(&p) {
            Ok(s) => toml::from_str(&s).map_err(|e| Error::usage(format!("{}: {e}", p.display()))),
            Err(_) => Ok(UserConfig::default()),
        }
    }
}

// ---------------------------------------------------------------- Project config

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub file: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProjectConfig {
    /// Shown in the Touch ID prompt (default: the project folder's name).
    pub name: Option<String>,
    pub vault: Option<PathBuf>,
    pub remote_ref: Option<String>,
    pub prefix: Option<String>,
    pub root_fp: Option<String>,
    #[serde(default)]
    pub exec: BTreeMap<String, Profile>,
    /// Directory containing the `.nepomuk.toml`.
    #[serde(skip)]
    pub dir: PathBuf,
}

impl ProjectConfig {
    /// Finds `.nepomuk.toml` in the current directory or its ancestors.
    pub fn discover() -> Result<Option<ProjectConfig>> {
        let mut dir = std::env::current_dir()?;
        loop {
            let p = dir.join(".nepomuk.toml");
            if p.is_file() {
                let s = std::fs::read_to_string(&p)?;
                let mut c: ProjectConfig = toml::from_str(&s)
                    .map_err(|e| Error::usage(format!("{}: {e}", p.display())))?;
                c.dir = dir;
                return Ok(Some(c));
            }
            if !dir.pop() {
                return Ok(None);
            }
        }
    }

    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| {
                self.dir
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "this project".into())
            })
    }

    pub fn vault_path(&self) -> Option<PathBuf> {
        self.vault.as_ref().map(|v| self.dir.join(v))
    }

    /// Resolves a path relative to `prefix` (paths starting with `/` are absolute).
    pub fn resolve(&self, path: &str) -> String {
        resolve_path(self.prefix.as_deref(), path)
    }
}

pub fn resolve_path(prefix: Option<&str>, path: &str) -> String {
    if path.starts_with('/') {
        return path.to_string();
    }
    match prefix {
        Some(p) => format!("{}/{}", p.trim_end_matches('/'), path),
        None => format!("/{path}"),
    }
}

// ---------------------------------------------------------------- Local state

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VaultMemory {
    /// Pinned master fingerprint.
    pub pin: Option<String>,
    /// Highest seen `seq` and its head hash (rollback / fork detection, §7.2).
    pub seq: Option<u64>,
    pub head: Option<String>,
    /// Last time the remote was fetched successfully (unix seconds).
    pub fetched_at: Option<i64>,
}

fn memory_path(vault: Id) -> PathBuf {
    state_dir()
        .join("vaults")
        .join(format!("{}.json", vault.hex()))
}

impl VaultMemory {
    pub fn load(vault: Id) -> VaultMemory {
        std::fs::read(memory_path(vault))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, vault: Id) -> Result<()> {
        write_private(
            &memory_path(vault),
            &serde_json::to_vec_pretty(self).unwrap(),
        )
    }
}

pub fn pending_path(vault: Id) -> PathBuf {
    state_dir()
        .join("pending")
        .join(format!("{}.npk", vault.hex()))
}

pub fn is_ci() -> bool {
    [
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "BUILDKITE",
        "JENKINS_URL",
        "TF_BUILD",
    ]
    .iter()
    .any(|v| std::env::var(v).is_ok_and(|x| !x.is_empty() && x != "false" && x != "0"))
}

pub fn untrusted(msg: &str) -> Error {
    Error::new(Code::UntrustedRoot, msg)
}
