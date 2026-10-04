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
    /// Masters pinned earlier, replaced after a master transfer; until the new master compacts
    /// the vault, its checkpoint is still signed by one of them.
    #[serde(default)]
    pub former: Vec<String>,
    /// Highest seen `seq` and its head hash (rollback / fork detection, §7.2).
    pub seq: Option<u64>,
    pub head: Option<String>,
    /// Hash of the checkpoint entry of the version seen last (it covers the signed body and the
    /// signature, so nobody can produce another checkpoint with the same hash).
    #[serde(default)]
    pub checkpoint: Option<String>,
    /// Last time the remote was fetched successfully (unix seconds).
    pub fetched_at: Option<i64>,
}

fn memory_path(vault: Id) -> PathBuf {
    state_dir()
        .join("vaults")
        .join(format!("{}.json", vault.hex()))
}

impl VaultMemory {
    /// Loads the memory of a vault; a missing file is an empty memory, but an unreadable or
    /// corrupt one is an error, so that rollback protection and the pin never fail open.
    pub fn load(vault: Id) -> Result<VaultMemory> {
        let path = memory_path(vault);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(VaultMemory::default());
            }
            Err(e) => {
                return Err(Error::general(format!(
                    "cannot read the local state {}: {e}",
                    path.display()
                )));
            }
        };
        serde_json::from_slice(&bytes).map_err(|e| {
            Error::general(format!(
                "the local state {} is corrupt ({e}); it holds the pinned master and rollback protection, so check it before removing it",
                path.display()
            ))
        })
    }

    /// Pins a new master fingerprint, remembering the previous one.
    pub fn repin(&mut self, fp: &str) -> Option<String> {
        let previous = self.pin.replace(fp.to_string());
        if let Some(p) = &previous
            && p != fp
            && !self.former.contains(p)
        {
            self.former.push(p.clone());
        }
        previous
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

/// Which vault was opened from which file on this machine. Pins are kept per `vault_id`, so a
/// file swapped for another vault (a new id, a new master) would otherwise look exactly like a
/// vault opened for the first time (§7.1).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Locations {
    /// Canonical vault path → vault id (hex).
    #[serde(default)]
    pub vaults: BTreeMap<String, String>,
    /// Project folder (of its `.nepomuk.toml`) → the vault it used last and where. A project
    /// that names another file or branch could otherwise divert to a vault of the repository
    /// owner's choosing, or to a copy nobody else reads.
    #[serde(default)]
    pub projects: BTreeMap<String, ProjectSeen>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProjectSeen {
    pub vault: String,
    pub location: String,
}

fn project_key(dir: &Path) -> String {
    dir.canonicalize()
        .unwrap_or_else(|_| dir.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn locations_path() -> PathBuf {
    state_dir().join("locations.json")
}

/// The key of a vault location: its canonical absolute path.
pub fn location_key(path: &Path) -> String {
    let canon = match (path.parent(), path.file_name()) {
        (Some(dir), Some(name)) => dir
            .canonicalize()
            .map(|d| d.join(name))
            .unwrap_or_else(|_| path.to_path_buf()),
        _ => path.to_path_buf(),
    };
    canon.to_string_lossy().into_owned()
}

impl Locations {
    /// Fails closed like [`VaultMemory::load`].
    pub fn load() -> Result<Locations> {
        let path = locations_path();
        match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| {
                Error::general(format!(
                    "the local state {} is corrupt ({e}); check it before removing it",
                    path.display()
                ))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Locations::default()),
            Err(e) => Err(Error::general(format!(
                "cannot read the local state {}: {e}",
                path.display()
            ))),
        }
    }

    /// The vault seen at `path`, or used by `project`, before – if it is a different one than
    /// `vault`.
    pub fn previous(&self, path: &Path, project: Option<&Path>, vault: Id) -> Option<Id> {
        let at_path = self
            .vaults
            .get(&location_key(path))
            .and_then(|h| Id::parse(h));
        let in_project = project
            .and_then(|d| self.projects.get(&project_key(d)))
            .and_then(|p| Id::parse(&p.vault));
        at_path
            .filter(|id| *id != vault)
            .or(in_project.filter(|id| *id != vault))
    }

    /// Where `project` used this same `vault` before, if that was somewhere else.
    pub fn moved(&self, project: Option<&Path>, location: &str, vault: Id) -> Option<String> {
        let seen = self.projects.get(&project_key(project?))?;
        (Id::parse(&seen.vault) == Some(vault) && seen.location != location)
            .then(|| seen.location.clone())
    }

    /// Remembers `vault` at `path`; writes only when something changed.
    pub fn record(path: &Path, project: Option<&Path>, location: &str, vault: Id) -> Result<()> {
        let mut l = Locations::load()?;
        let key = location_key(path);
        let seen = ProjectSeen {
            vault: vault.hex(),
            location: location.to_string(),
        };
        let project = project.map(project_key);
        let same_project = project.as_ref().is_none_or(|p| {
            l.projects
                .get(p)
                .is_some_and(|s| s.vault == seen.vault && s.location == seen.location)
        });
        if l.vaults.get(&key) == Some(&vault.hex()) && same_project {
            return Ok(());
        }
        l.vaults.insert(key, vault.hex());
        if let Some(p) = project {
            l.projects.insert(p, seen);
        }
        write_private(&locations_path(), &serde_json::to_vec_pretty(&l).unwrap())
    }
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
