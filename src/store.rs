//! Reading and writing the vault file (§9): through the system `git` when the file lives in a
//! repository with a remote, otherwise directly on disk.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{Code, Error, Result};

#[derive(Clone, Debug)]
pub struct GitCtx {
    /// Repository top level.
    pub top: PathBuf,
    /// Path of the vault file inside the repository.
    pub rel: String,
    pub remote: String,
    pub branch: String,
    /// Whether the remote is configured.
    pub has_remote: bool,
}

impl GitCtx {
    pub fn remote_ref(&self) -> String {
        format!("{}/{}", self.remote, self.branch)
    }
}

#[derive(Clone, Debug)]
pub struct Location {
    pub path: PathBuf,
    pub git: Option<GitCtx>,
}

#[derive(Debug)]
pub struct Loaded {
    pub bytes: Vec<u8>,
    /// The fetch failed; the data comes from the last fetched version.
    pub offline: bool,
    /// The remote commit the data was read from (git mode).
    pub base_commit: Option<String>,
}

pub enum SaveError {
    /// The push was rejected because the remote moved on.
    Rejected,
    Other(Error),
}

impl From<Error> for SaveError {
    fn from(e: Error) -> Self {
        SaveError::Other(e)
    }
}

/// Every git invocation goes through here. The vault path comes from `.nepomuk.toml`, i.e. from
/// whoever controls the project repository, so git must never pick up a repository (and its
/// `config`) that arrived as files in a clone:
/// - `safe.bareRepository=explicit` stops git from discovering a bare repository committed into
///   the project (git ≥ 2.38; older versions ignore it, [`Location::detect`] checks again);
/// - `core.fsmonitor` and the `ext::` transport would run commands from that config;
/// - hooks (`pre-push`, …) run nothing nepomuk needs, and a repository unpacked from an archive
///   may bring its own `.git/hooks`.
fn git(dir: &Path) -> Command {
    let mut c = Command::new("git");
    c.args([
        "-c",
        "safe.bareRepository=explicit",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "core.hooksPath=/dev/null",
    ]);
    c.arg("-C").arg(dir);
    c.env("GIT_TERMINAL_PROMPT", "0");
    c
}

/// A work tree whose top level has no `.git` is not one a user created with `git init` or
/// `git clone`: it comes from a bare repository carried inside another repository (with
/// `core.worktree` pointing at its parent). Its config is attacker-controlled; never run git
/// commands that read it.
fn check_top(top: &Path) -> Result<()> {
    if top.join(".git").exists() {
        return Ok(());
    }
    Err(Error::git(format!(
        "refusing to use the git repository at {}: it has no .git (an embedded repository from a clone?)",
        top.display()
    )))
}

fn run(mut c: Command) -> Result<String> {
    let out = c
        .stdin(Stdio::null())
        .output()
        .map_err(|e| Error::git(format!("cannot run git: {e}")))?;
    if !out.status.success() {
        return Err(Error::git(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

fn run_bytes(mut c: Command) -> Result<Vec<u8>> {
    let out = c
        .stdin(Stdio::null())
        .output()
        .map_err(|e| Error::git(format!("cannot run git: {e}")))?;
    if !out.status.success() {
        return Err(Error::git(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(out.stdout)
}

fn run_stdin(mut c: Command, input: &[u8]) -> Result<String> {
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::git(format!("cannot run git: {e}")))?;
    child.stdin.take().unwrap().write_all(input)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(Error::git(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

impl Location {
    /// Detects whether `path` is inside a git work tree and which remote ref to use.
    pub fn detect(path: &Path, remote_ref: Option<&str>) -> Result<Location> {
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let dir = path.parent().unwrap_or(Path::new("/")).to_path_buf();
        if !dir.is_dir() {
            return Err(Error::not_found(&dir.display().to_string()));
        }
        let mut c = git(&dir);
        c.args(["rev-parse", "--show-toplevel"]);
        let top = match run(c) {
            Ok(t) if !t.is_empty() => PathBuf::from(t),
            Err(e) if e.message.contains("safe.bareRepository") => {
                return Err(Error::git(format!(
                    "refusing to use the bare git repository around {}: {}",
                    dir.display(),
                    e.message
                )));
            }
            _ => return Ok(Location { path, git: None }),
        };
        let top = top.canonicalize().unwrap_or(top);
        check_top(&top)?;
        let canon_dir = dir.canonicalize().unwrap_or(dir);
        let rel_dir = canon_dir
            .strip_prefix(&top)
            .unwrap_or(Path::new(""))
            .to_path_buf();
        let file_name = path
            .file_name()
            .ok_or_else(|| Error::usage("invalid vault path"))?;
        let rel = rel_dir.join(file_name).to_string_lossy().replace('\\', "/");
        let (remote, branch) = match remote_ref {
            Some(r) => r
                .split_once('/')
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .unwrap_or(("origin".into(), r.into())),
            None => ("origin".into(), "main".into()),
        };
        let mut c = git(&top);
        c.args(["remote", "get-url", &remote]);
        let has_remote = run(c).is_ok();
        Ok(Location {
            path,
            git: Some(GitCtx {
                top,
                rel,
                remote,
                branch,
                has_remote,
            }),
        })
    }

    fn remote(&self) -> Option<&GitCtx> {
        self.git.as_ref().filter(|g| g.has_remote)
    }

    /// Fetches the remote (if any). Returns false when offline.
    pub fn fetch(&self) -> bool {
        let Some(g) = self.remote() else { return true };
        let mut c = git(&g.top);
        c.args([
            "fetch",
            "--quiet",
            &g.remote,
            &format!("+refs/heads/{0}:refs/remotes/{1}/{0}", g.branch, g.remote),
        ]);
        match run(c) {
            Ok(_) => true,
            // Reachable, but the branch does not exist yet (empty repository).
            Err(e) => e.message.contains("couldn't find remote ref"),
        }
    }

    fn remote_head(&self, g: &GitCtx) -> Option<String> {
        let mut c = git(&g.top);
        c.args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("refs/remotes/{}^{{commit}}", g.remote_ref()),
        ]);
        run(c).ok().filter(|s| !s.is_empty())
    }

    /// Reads the current version: `git show origin/main:<file>` in git mode (§9.1).
    pub fn load(&self, fetch: bool) -> Result<Loaded> {
        if let Some(g) = self.remote() {
            let offline = fetch && !self.fetch();
            if let Some(head) = self.remote_head(g) {
                let mut c = git(&g.top);
                c.args(["show", &format!("{head}:{}", g.rel)]);
                match run_bytes(c) {
                    Ok(bytes) => {
                        return Ok(Loaded {
                            bytes,
                            offline,
                            base_commit: Some(head),
                        });
                    }
                    Err(_) => {
                        return Err(Error::not_found(&format!("{}:{}", g.remote_ref(), g.rel)));
                    }
                }
            }
            if offline {
                return Err(Error::new(
                    Code::Offline,
                    "cannot reach the vault repository",
                ));
            }
        }
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Loaded {
                bytes,
                offline: false,
                base_commit: None,
            }),
            Err(_) => Err(Error::not_found(&self.path.display().to_string())),
        }
    }

    /// Reads the version at the checked-out commit (the submodule pin, §9.5).
    pub fn load_pinned(&self) -> Option<Vec<u8>> {
        let g = self.git.as_ref()?;
        let mut c = git(&g.top);
        c.args(["show", &format!("HEAD:{}", g.rel)]);
        run_bytes(c).ok()
    }

    /// Writes a new version (§9.2). In git mode: a commit on top of the remote head via
    /// plumbing, without touching the checkout, followed by a push.
    pub fn save(
        &self,
        loaded: &Loaded,
        bytes: &[u8],
        message: &str,
    ) -> std::result::Result<(), SaveError> {
        self.save_with(loaded, bytes, &[], message)
    }

    fn save_with(
        &self,
        loaded: &Loaded,
        bytes: &[u8],
        extra: &[(&str, &[u8])],
        message: &str,
    ) -> std::result::Result<(), SaveError> {
        let Some(g) = self.remote() else {
            // Local mode: refuse to overwrite a file that changed since it was read.
            if let Ok(cur) = std::fs::read(&self.path)
                && cur != loaded.bytes
            {
                return Err(SaveError::Rejected);
            }
            write_atomic(&self.path, bytes)?;
            return Ok(());
        };
        if loaded.offline {
            return Err(SaveError::Other(Error::new(
                Code::Offline,
                "cannot write while offline (use --offline)",
            )));
        }
        let mut c = git(&g.top);
        c.args(["hash-object", "-w", "--stdin", "--no-filters"]);
        let blob = run_stdin(c, bytes)?;
        let index = std::env::temp_dir().join(format!(
            "nepomuk-index-{}-{}",
            std::process::id(),
            crate::model::Id::random().short()
        ));
        let result = (|| -> Result<String> {
            if let Some(base) = &loaded.base_commit {
                let mut c = git(&g.top);
                c.env("GIT_INDEX_FILE", &index).args(["read-tree", base]);
                run(c)?;
            }
            let mut c = git(&g.top);
            c.env("GIT_INDEX_FILE", &index).args([
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("100644,{blob},{}", g.rel),
            ]);
            run(c)?;
            for (rel, data) in extra {
                let mut c = git(&g.top);
                c.args(["hash-object", "-w", "--stdin", "--no-filters"]);
                let b = run_stdin(c, data)?;
                let mut c = git(&g.top);
                c.env("GIT_INDEX_FILE", &index).args([
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    &format!("100644,{b},{rel}"),
                ]);
                run(c)?;
            }
            let mut c = git(&g.top);
            c.env("GIT_INDEX_FILE", &index).arg("write-tree");
            let tree = run(c)?;
            let mut c = git(&g.top);
            c.args(["commit-tree", &tree, "-m", message]);
            if let Some(base) = &loaded.base_commit {
                c.args(["-p", base]);
            }
            run(c)
        })();
        let _ = std::fs::remove_file(&index);
        let commit = result?;
        let mut c = git(&g.top);
        c.args([
            "push",
            "--quiet",
            "--porcelain",
            &g.remote,
            &format!("{commit}:refs/heads/{}", g.branch),
        ]);
        let out = c
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::git(format!("cannot run git: {e}")))?;
        if !out.status.success() {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if text.contains("rejected")
                || text.contains("fetch first")
                || text.contains("non-fast-forward")
            {
                return Err(SaveError::Rejected);
            }
            if text.contains("Could not read from remote") || text.contains("unable to access") {
                return Err(SaveError::Other(Error::new(
                    Code::Offline,
                    text.trim().to_string(),
                )));
            }
            return Err(SaveError::Other(Error::git(text.trim().to_string())));
        }
        let mut c = git(&g.top);
        c.args([
            "update-ref",
            &format!("refs/remotes/{}", g.remote_ref()),
            &commit,
        ]);
        let _ = run(c);
        Ok(())
    }

    /// Writes a brand-new vault (`init`). With a remote, the file and `.gitattributes` are
    /// committed and pushed directly; otherwise they are written to the work tree.
    /// Returns true when pushed.
    pub fn create(&self, bytes: &[u8]) -> Result<bool> {
        if self.path.exists() {
            return Err(Error::new(
                Code::AlreadyExists,
                format!("{} already exists", self.path.display()),
            ));
        }
        let attrs = format!(
            "{} binary diff=nepomuk merge=nepomuk\n",
            self.path.file_name().unwrap().to_string_lossy()
        );
        if let Some(g) = self.remote() {
            if !self.fetch() {
                return Err(Error::new(
                    Code::Offline,
                    "cannot reach the vault repository",
                ));
            }
            if let Some(head) = self.remote_head(g) {
                let mut c = git(&g.top);
                c.args(["cat-file", "-e", &format!("{head}:{}", g.rel)]);
                if run(c).is_ok() {
                    return Err(Error::new(
                        Code::AlreadyExists,
                        format!("{} already exists on {}", g.rel, g.remote_ref()),
                    ));
                }
            }
            let loaded = Loaded {
                bytes: Vec::new(),
                offline: false,
                base_commit: self.remote_head(g),
            };
            let attrs_rel = match g.rel.rfind('/') {
                Some(i) => format!("{}/.gitattributes", &g.rel[..i]),
                None => ".gitattributes".to_string(),
            };
            return match self.save_with(
                &loaded,
                bytes,
                &[(&attrs_rel, attrs.as_bytes())],
                "nepomuk: init",
            ) {
                Ok(()) => Ok(true),
                Err(SaveError::Rejected) => Err(Error::new(
                    Code::SyncContention,
                    "the remote changed during init",
                )),
                Err(SaveError::Other(e)) => Err(e),
            };
        }
        write_atomic(&self.path, bytes)?;
        if self.git.is_some() {
            let ga = self.path.with_file_name(".gitattributes");
            if !ga.exists() {
                std::fs::write(ga, attrs)?;
            }
        }
        Ok(false)
    }

    pub fn is_git(&self) -> bool {
        self.remote().is_some()
    }
}

/// Git commit message that reveals nothing (§9.2).
pub fn commit_message(seq: u64, author: &str, ops: usize) -> String {
    format!(
        "nepomuk: #{seq} by {author} ({ops} operation{})",
        if ops == 1 { "" } else { "s" }
    )
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
