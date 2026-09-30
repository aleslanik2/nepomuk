//! Application layer shared by the CLI and `serve --stdio`: opening and verifying the vault,
//! unlocking identities and executing write intents with automatic push and sync (§9).

use std::cell::RefCell;
use std::io::{BufRead, BufReader, IsTerminal};
use std::path::PathBuf;
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::config::{self, ProjectConfig, UserConfig, VaultMemory};
use crate::crypto;
use crate::error::{Code, Error, Result};
use crate::format::{CheckpointBody, VaultFile, from_cbor, to_cbor};
use crate::identity::{self, IdentityFile, Request, Unlocked};
use crate::model::*;
use crate::store::{self, Loaded, Location, SaveError};
use crate::tx::{self, Tx};
use crate::verify::{Verified, verify_file};

const MAX_PUSH_ATTEMPTS: usize = 5;

// ---------------------------------------------------------------- Context

#[derive(Clone, Default)]
pub struct Options {
    pub vault: Option<PathBuf>,
    pub json: bool,
    pub identity: Option<PathBuf>,
    pub email: Option<String>,
    pub password_fd: Option<i32>,
    pub password_stdin: bool,
    pub ci: bool,
    pub offline: bool,
    /// `serve --stdio`: identities are unlocked only through `session.unlock`.
    pub session: bool,
    /// Unlock with Touch ID (macOS, when set up for the vault).
    pub touchid: bool,
    /// After a successful unlock, seal the password for Touch ID on this Mac.
    pub remember_touchid: bool,
}

pub struct Ctx {
    pub opts: Options,
    pub project: Option<ProjectConfig>,
    pub user: UserConfig,
    /// Unlocked identity cached for the session (`serve --stdio`) or the current command.
    pub unlocked: RefCell<Option<Rc<Unlocked>>>,
    /// Password handed over by the GUI (`session.unlock`).
    pub password_override: RefCell<Option<Zeroizing<String>>>,
    secret_reader: RefCell<Option<Box<dyn BufRead>>>,
    pub warnings: RefCell<Vec<String>>,
}

impl Ctx {
    pub fn new(opts: Options) -> Result<Ctx> {
        Ok(Ctx {
            opts,
            project: ProjectConfig::discover()?,
            user: UserConfig::load()?,
            unlocked: RefCell::new(None),
            password_override: RefCell::new(None),
            secret_reader: RefCell::new(None),
            warnings: RefCell::new(Vec::new()),
        })
    }

    pub fn warn(&self, w: impl Into<String>) {
        self.warnings.borrow_mut().push(w.into());
    }

    pub fn ci(&self) -> bool {
        self.opts.ci || config::is_ci()
    }

    pub fn interactive(&self) -> bool {
        !self.opts.json && std::io::stdin().is_terminal()
    }

    /// Resolves a user-supplied tree path against the project prefix.
    pub fn path(&self, p: &str) -> String {
        let prefix = self.project.as_ref().and_then(|c| c.prefix.as_deref());
        config::resolve_path(prefix, p)
    }

    pub fn location(&self) -> Result<Location> {
        let path = self
            .opts
            .vault
            .clone()
            .or_else(|| std::env::var_os("NEPOMUK_VAULT").map(PathBuf::from))
            .or_else(|| self.project.as_ref().and_then(|p| p.vault_path()))
            .ok_or_else(|| {
                Error::usage("no vault: use --vault, NEPOMUK_VAULT or a .nepomuk.toml")
            })?;
        let remote_ref = self.project.as_ref().and_then(|p| p.remote_ref.clone());
        Location::detect(&path, remote_ref.as_deref())
    }

    // ------------------------------------------------------------ Secret input (§10.1)

    fn reader_line(&self) -> Result<Option<Zeroizing<String>>> {
        let mut r = self.secret_reader.borrow_mut();
        if r.is_none() {
            if let Some(fd) = self.opts.password_fd {
                *r = Some(Box::new(BufReader::new(fd_file(fd)?)));
            } else if self.opts.password_stdin {
                *r = Some(Box::new(BufReader::new(std::io::stdin())));
            } else {
                return Ok(None);
            }
        }
        let mut line = Zeroizing::new(String::new());
        r.as_mut().unwrap().read_line(&mut line)?;
        let trimmed = Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_string());
        Ok(Some(trimmed))
    }

    /// Reads a password or passphrase: GUI session, `--password-fd`, `--password-stdin`,
    /// environment variables (CI) or a hidden TTY prompt.
    pub fn secret(&self, prompt: &str, env: &[&str]) -> Result<Zeroizing<String>> {
        if let Some(p) = self.password_override.borrow_mut().take() {
            return Ok(p);
        }
        if let Some(l) = self.reader_line()? {
            return Ok(l);
        }
        for v in env {
            if let Ok(x) = std::env::var(v) {
                return Ok(Zeroizing::new(x));
            }
        }
        if !self.opts.json && tty_available() {
            return rpassword::prompt_password(format!("{prompt}: "))
                .map(Zeroizing::new)
                .map_err(|e| Error::general(format!("cannot read password: {e}")));
        }
        Err(Error::new(Code::PasswordRequired, format!("{prompt} required")).with("prompt", prompt))
    }

    /// A new password, confirmed twice on a TTY.
    pub fn new_secret(&self, prompt: &str, env: &[&str]) -> Result<Zeroizing<String>> {
        let tty = self.password_override.borrow().is_none()
            && self.opts.password_fd.is_none()
            && !self.opts.password_stdin
            && !env.iter().any(|v| std::env::var(v).is_ok())
            && !self.opts.json
            && tty_available();
        let p = self.secret(prompt, env)?;
        if tty {
            let again = self.secret("Repeat", &[])?;
            if *again != *p {
                return Err(Error::usage("the passwords do not match"));
            }
        }
        Ok(p)
    }

    /// A value for `--field-prompt`: hidden prompt on a TTY, otherwise one line of stdin.
    pub fn field_value(&self, name: &str) -> Result<Zeroizing<String>> {
        if !self.opts.json && std::io::stdin().is_terminal() && tty_available() {
            return rpassword::prompt_password(format!("{name}: "))
                .map(Zeroizing::new)
                .map_err(|e| Error::general(format!("cannot read {name}: {e}")));
        }
        let mut line = Zeroizing::new(String::new());
        std::io::stdin().lock().read_line(&mut line)?;
        if line.is_empty() {
            return Err(Error::new(
                Code::PasswordRequired,
                format!("value of field {name} required"),
            ));
        }
        Ok(Zeroizing::new(
            line.trim_end_matches(['\n', '\r']).to_string(),
        ))
    }

    // ------------------------------------------------------------ Identity

    fn identity_file(&self) -> Result<Option<IdentityFile>> {
        if let Some(p) = &self.opts.identity {
            let t = std::fs::read_to_string(p)
                .map_err(|_| Error::not_found(&p.display().to_string()))?;
            return Ok(Some(IdentityFile::parse(&t)?));
        }
        if self.opts.email.is_some() {
            return Ok(None);
        }
        if let Ok(v) = std::env::var("NEPOMUK_IDENTITY") {
            return Ok(Some(IdentityFile::parse(&v)?));
        }
        if let Some(p) = &self.user.identity {
            let t = std::fs::read_to_string(p)
                .map_err(|_| Error::not_found(&p.display().to_string()))?;
            return Ok(Some(IdentityFile::parse(&t)?));
        }
        if self.user.email.is_some() || std::env::var("NEPOMUK_EMAIL").is_ok() {
            return Ok(None);
        }
        let p = config::default_identity_path();
        if p.is_file() {
            return Ok(Some(IdentityFile::parse(&std::fs::read_to_string(p)?)?));
        }
        Ok(None)
    }

    fn identity_file_path(&self) -> Option<PathBuf> {
        let p = self
            .opts
            .identity
            .clone()
            .or_else(|| self.user.identity.clone())
            .unwrap_or_else(config::default_identity_path);
        let p = if p.is_absolute() {
            p
        } else {
            std::env::current_dir().ok()?.join(p)
        };
        p.is_file().then_some(p)
    }

    fn unlock_touchid(&self, state: &State) -> Result<Unlocked> {
        let (who, pass) = crate::touchid::unlock(state.vault_id, "unlock the nepomuk vault")?;
        match who {
            crate::touchid::Who::Email { email } => {
                let user = state.user_by_name(&email).ok_or_else(|| {
                    Error::new(Code::BadCredentials, format!("unknown user {email}"))
                })?;
                if user.disabled {
                    return Err(Error::new(
                        Code::IdentityDisabled,
                        "this identity has been disabled",
                    ));
                }
                identity::unlock_password_user(user, &pass).map_err(|e| stale_touchid(state, e))
            }
            crate::touchid::Who::File { path } => {
                let text = std::fs::read_to_string(&path)
                    .map_err(|_| Error::not_found(&path.display().to_string()))?;
                IdentityFile::parse(&text)?
                    .unlock(&pass)
                    .map_err(|e| stale_touchid(state, e))
            }
        }
    }

    fn email(&self) -> Option<String> {
        self.opts
            .email
            .clone()
            .or_else(|| std::env::var("NEPOMUK_EMAIL").ok())
            .or_else(|| self.user.email.clone())
    }

    /// Unlocks the identity for this command (once per session).
    pub fn unlock(&self, state: &State) -> Result<Rc<Unlocked>> {
        if let Some(u) = self.unlocked.borrow().as_ref() {
            return Ok(u.clone());
        }
        if self.opts.session && self.password_override.borrow().is_none() {
            return Err(Error::new(
                Code::PasswordRequired,
                "the session is locked; call session.unlock",
            ));
        }
        if self.opts.touchid {
            let rc = Rc::new(self.unlock_touchid(state)?);
            *self.unlocked.borrow_mut() = Some(rc.clone());
            return Ok(rc);
        }
        let id = if let Some(f) = self.identity_file()? {
            let pass = self.secret(
                &format!("Passphrase for {}", f.name),
                &["NEPOMUK_PASSPHRASE"],
            )?;
            let id = f.unlock(&pass)?;
            if self.opts.remember_touchid {
                let path = self.identity_file_path().ok_or_else(|| {
                    Error::usage("Touch ID needs the identity as a file (--identity)")
                })?;
                crate::touchid::enable(state.vault_id, crate::touchid::Who::File { path }, &pass)?;
            }
            id
        } else if let Some(email) = self.email() {
            let user = state
                .user_by_name(&email)
                .ok_or_else(|| Error::new(Code::BadCredentials, format!("unknown user {email}")))?;
            if user.disabled {
                return Err(Error::new(
                    Code::IdentityDisabled,
                    "this identity has been disabled",
                ));
            }
            let pass = self.secret(&format!("Password for {email}"), &["NEPOMUK_PASSWORD"])?;
            let id = identity::unlock_password_user(user, &pass)?;
            if self.opts.remember_touchid {
                crate::touchid::enable(
                    state.vault_id,
                    crate::touchid::Who::Email {
                        email: user.name.clone(),
                    },
                    &pass,
                )?;
            }
            if user
                .credential
                .as_ref()
                .is_some_and(|c| c.kdf.weaker_than(&crypto::KdfParams::default_params()))
            {
                self.warn("your password uses outdated Argon2id parameters; run `nepomuk identity passwd` to strengthen them");
            }
            id
        } else {
            return Err(Error::usage(
                "no identity: use --identity <file>, --email <email> or create one with `nepomuk identity new`",
            ));
        };
        let rc = Rc::new(id);
        *self.unlocked.borrow_mut() = Some(rc.clone());
        Ok(rc)
    }

    /// Unlocks without a vault (local identity files only).
    pub fn unlock_file(&self) -> Result<Rc<Unlocked>> {
        let f = self
            .identity_file()?
            .ok_or_else(|| Error::usage("this command needs a local identity file (--identity)"))?;
        let pass = self.secret(
            &format!("Passphrase for {}", f.name),
            &["NEPOMUK_PASSPHRASE"],
        )?;
        Ok(Rc::new(f.unlock(&pass)?))
    }
}

/// The sealed password no longer works (it was changed): forget it.
fn stale_touchid(state: &State, e: Error) -> Error {
    if e.code == Code::BadCredentials {
        crate::touchid::disable(state.vault_id);
        return Error::new(
            Code::BadCredentials,
            "the password saved for Touch ID no longer works; unlock with your password to set it up again",
        );
    }
    e
}

fn tty_available() -> bool {
    #[cfg(unix)]
    {
        std::fs::File::open("/dev/tty").is_ok()
    }
    #[cfg(not(unix))]
    {
        std::io::stdin().is_terminal()
    }
}

#[cfg(unix)]
fn fd_file(fd: i32) -> Result<std::fs::File> {
    use std::os::unix::io::FromRawFd;
    if fd < 0 {
        return Err(Error::usage("invalid --password-fd"));
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(not(unix))]
fn fd_file(_fd: i32) -> Result<std::fs::File> {
    Err(Error::usage(
        "--password-fd is not supported on this platform",
    ))
}

// ---------------------------------------------------------------- Opening the vault

pub struct Opened {
    pub loc: Location,
    pub loaded: Loaded,
    pub v: Verified,
}

/// Determines the pinned master fingerprint (§7.1).
fn pin_for(
    ctx: &Ctx,
    vault: crate::model::Id,
    mem: &mut VaultMemory,
    file: &VaultFile,
) -> Result<String> {
    if let Ok(fp) = std::env::var("NEPOMUK_ROOT_FP")
        && !fp.is_empty()
    {
        return Ok(fp);
    }
    if let Some(p) = &mem.pin {
        return Ok(p.clone());
    }
    if let Some(fp) = ctx.project.as_ref().and_then(|p| p.root_fp.clone()) {
        mem.pin = Some(fp.clone());
        mem.save(vault)?;
        ctx.warn(format!(
            "pinned the master fingerprint {fp} from .nepomuk.toml"
        ));
        return Ok(fp);
    }
    let found = claimed_master_fp(file).unwrap_or_default();
    Err(Error::new(
        Code::UntrustedRoot,
        "no pinned master fingerprint for this vault; verify it out of band and run `nepomuk trust <fingerprint>`",
    )
    .with("vault_id", vault.hex())
    .with("claimed_fingerprint", found))
}

/// The master fingerprint the file claims (unverified; for display only).
pub fn claimed_master_fp(file: &VaultFile) -> Option<String> {
    let cp: CheckpointBody = from_cbor(&file.entries[0].envelope.body).ok()?;
    cp.state
        .users
        .get(&cp.state.master)
        .map(crate::verify::user_fp)
}

/// Rollback and fork detection against the local memory (§7.2).
fn check_memory(v: &Verified, mem: &VaultMemory) -> Result<()> {
    let (Some(seq), Some(head)) = (mem.seq, mem.head.as_deref()) else {
        return Ok(());
    };
    if v.seq < seq {
        return Err(Error::new(
            Code::RollbackDetected,
            format!("the vault is at #{} but #{seq} has been seen before", v.seq),
        )
        .with("seen_seq", seq)
        .with("found_seq", v.seq));
    }
    let seen_hash = if v.seq == seq {
        Some(v.head)
    } else {
        v.commits.iter().find(|c| c.seq == seq).map(|c| c.hash)
    };
    if let Some(h) = seen_hash
        && hex::encode(h) != head
    {
        return Err(Error::new(
            Code::ForkDetected,
            format!("#{seq} differs from the version seen before"),
        )
        .with("seq", seq));
    }
    Ok(())
}

/// In CI the version pinned by the submodule commit is the lower bound (§9.5).
fn check_submodule_pin(loc: &Location, v: &Verified) -> Result<()> {
    let Some(bytes) = loc.load_pinned() else {
        return Ok(());
    };
    let Ok(pinned) = VaultFile::parse(&bytes) else {
        return Ok(());
    };
    if pinned.vault_id != v.file.vault_id {
        return Err(Error::new(
            Code::StaleBelowPin,
            "the pinned vault is a different vault",
        ));
    }
    let (pseq, phead) = pinned.logical_head()?;
    if v.seq < pseq {
        return Err(Error::new(
            Code::StaleBelowPin,
            format!(
                "{} is at #{} but the submodule pins #{pseq}",
                loc.git.as_ref().map(|g| g.remote_ref()).unwrap_or_default(),
                v.seq
            ),
        ));
    }
    let on_chain = if v.seq == pseq {
        v.head == phead
    } else if pseq > v.checkpoint_seq {
        v.commits.iter().any(|c| c.seq == pseq && c.hash == phead)
    } else {
        true // compacted past the pin: comparing seq is enough
    };
    if !on_chain {
        return Err(Error::new(
            Code::ForkDetected,
            "the submodule pin is not an ancestor of the current vault",
        ));
    }
    Ok(())
}

pub fn open_vault(ctx: &Ctx, fetch: bool) -> Result<Opened> {
    let loc = ctx.location()?;
    let loaded = loc.load(fetch && !ctx.opts.offline)?;
    let file = VaultFile::parse(&loaded.bytes)?;
    let vault = file.vault_id;
    let mut mem = VaultMemory::load(vault);
    let pin = pin_for(ctx, vault, &mut mem, &file)?;
    let v = verify_file(file, &pin)?;
    check_memory(&v, &mem)?;
    if ctx.ci() {
        check_submodule_pin(&loc, &v)?;
    }
    if loaded.offline {
        let age = mem.fetched_at.map(|t| tx::now() - t);
        ctx.warn(match age {
            Some(a) => format!(
                "offline: using the last fetched version ({} old)",
                human_age(a)
            ),
            None => "offline: using the last fetched version".into(),
        });
    } else if loc.is_git() && fetch {
        mem.fetched_at = Some(tx::now());
    }
    remember(&mut mem, &v);
    mem.save(vault)?;
    Ok(Opened { loc, loaded, v })
}

fn remember(mem: &mut VaultMemory, v: &Verified) {
    if mem.seq.is_none_or(|s| v.seq >= s) {
        mem.seq = Some(v.seq);
        mem.head = Some(hex::encode(v.head));
    }
}

pub fn human_age(secs: i64) -> String {
    match secs {
        s if s < 120 => format!("{s} s"),
        s if s < 7200 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3600),
        s => format!("{} days", s / 86400),
    }
}

// ---------------------------------------------------------------- Write intents

/// A write expressed as intent ("store X", "give Bob read") so that it can be replayed on top of
/// a newer vault after a rejected push or during `sync` (§9.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "intent", rename_all = "kebab-case")]
pub enum Intent {
    Mkdir {
        path: String,
        parents: bool,
    },
    Put {
        path: String,
        content: Content,
        not_after: Option<i64>,
    },
    Rm {
        path: String,
    },
    Mv {
        src: String,
        dst: String,
    },
    Rekey {
        path: String,
    },
    Grant {
        who: String,
        right: Right,
        path: String,
    },
    Revoke {
        who: String,
        path: String,
        no_rekey: bool,
    },
    UserAdd {
        request: String,
    },
    UserDisable {
        name: String,
    },
    UserOffboard {
        name: String,
    },
    UserReplace {
        name: String,
        request: String,
    },
    GroupCreate {
        name: String,
    },
    GroupAdd {
        group: String,
        user: String,
    },
    GroupRemove {
        group: String,
        user: String,
    },
    SysGrant {
        user: String,
        right: String,
        delegate: bool,
    },
    SysRevoke {
        user: String,
        right: String,
    },
    RotationDone {
        path: String,
    },
    Passwd {
        credential: crypto::PasswordSealed,
    },
    MasterTransfer {
        user: String,
    },
}

impl Drop for Intent {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Intent::Put { content, .. } = self {
            match content {
                Content::Text { value } => value.zeroize(),
                Content::Binary { data, .. } => data.zeroize(),
                Content::Record { fields, .. } => {
                    for f in fields.values_mut() {
                        match f {
                            Field::Text { value } => value.zeroize(),
                            Field::Binary { data, .. } => data.zeroize(),
                        }
                    }
                }
                Content::Folder => {}
            }
        }
    }
}

pub fn parse_sysright(state: &State, s: &str) -> Result<SysRight> {
    Ok(match s {
        "users" => SysRight::Users,
        "groups" => SysRight::Groups,
        "audit" => SysRight::Audit,
        _ => {
            let g = s.strip_prefix("group-admin:").ok_or_else(|| {
                Error::usage(format!(
                    "unknown system right {s:?} (users, groups, audit, group-admin:<group>)"
                ))
            })?;
            SysRight::GroupAdmin(
                state
                    .group_by_name(g)
                    .ok_or_else(|| Error::not_found(&format!("group {g}")))?
                    .id,
            )
        }
    })
}

pub fn sysright_name(state: &State, r: SysRight) -> String {
    match r {
        SysRight::Users => "users".into(),
        SysRight::Groups => "groups".into(),
        SysRight::Audit => "audit".into(),
        SysRight::GroupAdmin(g) => format!(
            "group-admin:{}",
            state.groups.get(&g).map(|g| g.name.as_str()).unwrap_or("?")
        ),
    }
}

impl Intent {
    /// The node this intent modifies, for conflict detection.
    fn target(&self, tx: &mut Tx) -> Option<crate::model::Id> {
        match self {
            Intent::Put { path, .. } | Intent::Rm { path } => tx.resolve(path).ok(),
            Intent::Mv { src, .. } => tx.resolve(src).ok(),
            _ => None,
        }
    }

    fn apply(&self, tx: &mut Tx) -> Result<Value> {
        Ok(match self {
            Intent::Mkdir { path, parents } => {
                tx.mkdir(path, *parents)?;
                json!({ "path": tx::normalize_path(path)? })
            }
            Intent::Put {
                path,
                content,
                not_after,
            } => {
                tx.put(path, content.clone(), *not_after)?;
                json!({ "path": tx::normalize_path(path)?, "type": content.type_name() })
            }
            Intent::Rm { path } => {
                tx.rm(path)?;
                json!({ "path": tx::normalize_path(path)? })
            }
            Intent::Mv { src, dst } => {
                tx.mv(src, dst)?;
                json!({ "from": src, "to": dst })
            }
            Intent::Rekey { path } => {
                let n = tx.resolve(path)?;
                if !tx.can_rekey(n) {
                    return Err(
                        Error::access_denied(path).with("reason", "requires admin on the parent")
                    );
                }
                tx.rekey(n)?;
                json!({ "path": path })
            }
            Intent::Grant { who, right, path } => {
                let p = tx.principal(who)?;
                tx.grant(p, *right, path)?;
                json!({ "who": tx.principal_name(p), "right": right.as_str(), "path": path })
            }
            Intent::Revoke {
                who,
                path,
                no_rekey,
            } => {
                let p = tx.principal(who)?;
                let rotate = tx.revoke(p, path, *no_rekey)?;
                json!({ "who": tx.principal_name(p), "path": path, "rotate": rotate })
            }
            Intent::UserAdd { request } => {
                let req = Request::parse(request)?;
                let id = tx.user_add(&req)?;
                json!({ "user": req.name, "id": id.hex(), "fingerprint": req.fingerprint() })
            }
            Intent::UserDisable { name } => {
                let u = tx.user_named(name)?;
                tx.user_disable(u)?;
                json!({ "user": name })
            }
            Intent::UserOffboard { name } => {
                let u = tx.user_named(name)?;
                let rotate = tx.offboard(u)?;
                json!({ "user": name, "rotate": rotate })
            }
            Intent::UserReplace { name, request } => {
                let u = tx.user_named(name)?;
                let req = Request::parse(request)?;
                tx.user_replace(u, &req)?;
                json!({ "user": name, "fingerprint": req.fingerprint() })
            }
            Intent::GroupCreate { name } => {
                let g = tx.group_create(name)?;
                json!({ "group": name, "id": g.hex() })
            }
            Intent::GroupAdd { group, user } => {
                let (g, u) = (tx.group_named(group)?, tx.user_named(user)?);
                tx.group_add(g, u)?;
                json!({ "group": group, "user": user })
            }
            Intent::GroupRemove { group, user } => {
                let (g, u) = (tx.group_named(group)?, tx.user_named(user)?);
                tx.group_remove(g, u)?;
                json!({ "group": group, "user": user })
            }
            Intent::SysGrant {
                user,
                right,
                delegate,
            } => {
                let u = tx.user_named(user)?;
                let r = parse_sysright(&tx.state, right)?;
                tx.sysgrant(u, r, *delegate)?;
                json!({ "user": user, "right": right, "delegate": delegate })
            }
            Intent::SysRevoke { user, right } => {
                let u = tx.user_named(user)?;
                let r = parse_sysright(&tx.state, right)?;
                tx.sysrevoke(u, r)?;
                json!({ "user": user, "right": right })
            }
            Intent::RotationDone { path } => {
                tx.clear_rotation(path)?;
                json!({ "path": path })
            }
            Intent::Passwd { credential } => {
                tx.update_own_credential(credential.clone())?;
                json!({ "updated": true })
            }
            Intent::MasterTransfer { user } => {
                let u = tx.user_named(user)?;
                tx.transfer_master(u)?;
                let fp = crate::verify::user_fp(&tx.state.users[&u]);
                json!({ "user": user, "new_fingerprint": fp })
            }
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolve {
    Ask,
    Ours,
    Theirs,
}

/// Applies an intent on top of the latest vault, signs it and pushes, retrying after a rejected
/// push (§9.2). `base_seq` is the version the user saw when expressing the intent.
pub fn execute(
    ctx: &Ctx,
    intent: &Intent,
    base_seq: Option<u64>,
    resolve: Resolve,
) -> Result<Value> {
    if ctx.opts.offline {
        return queue_offline(ctx, intent);
    }
    let mut base_seq = base_seq;
    for _ in 0..MAX_PUSH_ATTEMPTS {
        let opened = open_vault(ctx, true)?;
        let id = ctx.unlock(&opened.v.state)?;
        let base = *base_seq.get_or_insert(opened.v.seq);
        let mut tx = Tx::new(&opened.v, &id)?;
        if let Some(target) = intent.target(&mut tx) {
            let me = tx.me;
            let changed = opened
                .v
                .commits
                .iter()
                .any(|c| c.seq > base && c.author != me && c.touched.contains(&target));
            if changed && resolve != Resolve::Ours {
                if resolve == Resolve::Theirs {
                    return Ok(json!({ "skipped": true, "reason": "changed by someone else" }));
                }
                return Err(Error::new(
                    Code::Conflict,
                    "the same secret was changed by someone else in the meantime",
                )
                .with("path", tx.access().path(target).unwrap_or("?").to_string()));
            }
        }
        let mut out = intent.apply(&mut tx)?;
        let me_name = opened.v.state.users[&tx.me].name.clone();
        let (file, verified, warnings, tasks) = tx.commit()?;
        let ops = verified.commits.last().map(|c| c.ops.len()).unwrap_or(0);
        let msg = store::commit_message(verified.seq, &me_name, ops);
        match opened.loc.save(&opened.loaded, &file.serialize(), &msg) {
            Ok(()) => {
                let mut mem = VaultMemory::load(verified.file.vault_id);
                if verified.master_fp != opened.v.master_fp && mem.pin.is_some() {
                    // This client signed the transfer itself.
                    mem.pin = Some(verified.master_fp.clone());
                }
                remember(&mut mem, &verified);
                mem.save(verified.file.vault_id)?;
                for w in warnings {
                    ctx.warn(w);
                }
                if let Value::Object(m) = &mut out {
                    m.insert("seq".into(), json!(verified.seq));
                    if !tasks.is_empty() {
                        m.insert("tasks".into(), json!(tasks));
                    }
                }
                return Ok(out);
            }
            Err(SaveError::Rejected) => continue,
            Err(SaveError::Other(e)) => return Err(e),
        }
    }
    Err(Error::new(
        Code::SyncContention,
        format!("the push was rejected {MAX_PUSH_ATTEMPTS} times; try again later"),
    ))
}

// ---------------------------------------------------------------- Offline changes

#[derive(Serialize, Deserialize)]
struct PendingItem {
    intent: Intent,
    base_seq: u64,
    created: i64,
}

#[derive(Serialize, Deserialize)]
struct PendingFile {
    identity: String,
    items: crypto::Wrapped,
}

fn pending_aad(vault: crate::model::Id) -> Vec<u8> {
    [&vault.0[..], b"pending"].concat()
}

fn load_pending(ctx: &Ctx, vault: crate::model::Id, id: &Unlocked) -> Result<Vec<PendingItem>> {
    let p = config::pending_path(vault);
    let Ok(bytes) = std::fs::read(&p) else {
        return Ok(Vec::new());
    };
    let f: PendingFile = from_cbor(&bytes)?;
    if f.identity != id.fingerprint() {
        ctx.warn("pending offline changes belong to another identity and were left untouched");
        return Ok(Vec::new());
    }
    let plain = crypto::unwrap(&id.kem, &f.items, &pending_aad(vault))?;
    from_cbor(&plain)
}

fn save_pending(vault: crate::model::Id, id: &Unlocked, items: &[PendingItem]) -> Result<()> {
    let p = config::pending_path(vault);
    if items.is_empty() {
        let _ = std::fs::remove_file(p);
        return Ok(());
    }
    let plain = Zeroizing::new(to_cbor(&items));
    let items = crypto::wrap(id.kem.public(), &plain, &pending_aad(vault))?;
    config::write_private(
        &p,
        &to_cbor(&PendingFile {
            identity: id.fingerprint(),
            items,
        }),
    )
}

fn queue_offline(ctx: &Ctx, intent: &Intent) -> Result<Value> {
    let opened = open_vault(ctx, false)?;
    let id = ctx.unlock(&opened.v.state)?;
    // Check that the intent applies to the current state before queueing it.
    let mut tx = Tx::new(&opened.v, &id)?;
    let out = intent.apply(&mut tx)?;
    let vault = opened.v.file.vault_id;
    let mut items = load_pending(ctx, vault, &id)?;
    items.push(PendingItem {
        intent: intent.clone(),
        base_seq: opened.v.seq,
        created: tx::now(),
    });
    save_pending(vault, &id, &items)?;
    ctx.warn(format!(
        "offline: {} change(s) not pushed; run `nepomuk sync` when online",
        items.len()
    ));
    let mut out = out;
    if let Value::Object(m) = &mut out {
        m.insert("pending".into(), json!(true));
    }
    Ok(out)
}

/// `nepomuk sync` (§9.3): replays pending intents on top of the latest vault.
pub fn sync(ctx: &Ctx, resolve: Resolve) -> Result<Value> {
    let opened = open_vault(ctx, true)?;
    if opened.loaded.offline {
        return Err(Error::new(
            Code::Offline,
            "cannot reach the vault repository",
        ));
    }
    let vault = opened.v.file.vault_id;
    if !config::pending_path(vault).is_file() {
        return Ok(json!({ "state": "up-to-date", "seq": opened.v.seq, "replayed": [] }));
    }
    let id = ctx.unlock(&opened.v.state)?;
    let items = load_pending(ctx, vault, &id)?;
    let mut replayed = Vec::new();
    let mut conflicts = Vec::new();
    let mut dropped = Vec::new();
    let mut keep = Vec::new();
    for item in items {
        let label = describe(&item.intent);
        match execute(ctx, &item.intent, Some(item.base_seq), resolve) {
            Ok(v) => replayed.push(json!({ "change": label, "result": v })),
            Err(e) if e.code == Code::Conflict => {
                conflicts
                    .push(json!({ "change": label, "message": e.message, "details": e.details }));
                keep.push(item);
            }
            Err(e)
                if matches!(
                    e.code,
                    Code::NotFound
                        | Code::AccessDenied
                        | Code::AlreadyExists
                        | Code::UnauthorizedOperation
                ) =>
            {
                ctx.warn(format!("dropped `{label}`: {}", e.message));
                dropped.push(json!({ "change": label, "reason": e.message }));
            }
            Err(e) => {
                keep.push(item);
                save_pending(vault, &id, &keep)?;
                return Err(e);
            }
        }
    }
    save_pending(vault, &id, &keep)?;
    let state = if conflicts.is_empty() {
        "up-to-date"
    } else {
        "conflict"
    };
    if !conflicts.is_empty() {
        ctx.warn("conflicts: run `nepomuk sync --resolve ours` to overwrite or `--resolve theirs` to discard your changes");
    }
    Ok(json!({ "state": state, "replayed": replayed, "conflicts": conflicts, "dropped": dropped }))
}

pub fn describe(i: &Intent) -> String {
    match i {
        Intent::Mkdir { path, .. } => format!("mkdir {path}"),
        Intent::Put { path, .. } => format!("put {path}"),
        Intent::Rm { path } => format!("rm {path}"),
        Intent::Mv { src, dst } => format!("mv {src} {dst}"),
        Intent::Rekey { path } => format!("rekey {path}"),
        Intent::Grant { who, right, path } => format!("grant {who} {} {path}", right.as_str()),
        Intent::Revoke { who, path, .. } => format!("revoke {who} {path}"),
        Intent::UserAdd { .. } => "user add".into(),
        Intent::UserDisable { name } => format!("user disable {name}"),
        Intent::UserOffboard { name } => format!("user offboard {name}"),
        Intent::UserReplace { name, .. } => format!("user replace {name}"),
        Intent::GroupCreate { name } => format!("group create {name}"),
        Intent::GroupAdd { group, user } => format!("group add {group} {user}"),
        Intent::GroupRemove { group, user } => format!("group remove {group} {user}"),
        Intent::SysGrant { user, right, .. } => format!("sysgrant {user} {right}"),
        Intent::SysRevoke { user, right } => format!("sysrevoke {user} {right}"),
        Intent::RotationDone { path } => format!("rotation done {path}"),
        Intent::Passwd { .. } => "identity passwd".into(),
        Intent::MasterTransfer { user } => format!("master transfer {user}"),
    }
}

/// Status of the local view (§13: up to date / behind / ahead / conflict).
pub fn status(ctx: &Ctx) -> Result<Value> {
    let opened = open_vault(ctx, true)?;
    let vault = opened.v.file.vault_id;
    let pending = config::pending_path(vault).is_file();
    let checkout_seq = std::fs::read(&opened.loc.path)
        .ok()
        .and_then(|b| VaultFile::parse(&b).ok())
        .and_then(|f| f.logical_head().ok())
        .map(|(seq, _)| seq);
    let state = if opened.loaded.offline {
        "offline"
    } else if pending {
        "ahead"
    } else {
        "up-to-date"
    };
    let mem = VaultMemory::load(vault);
    let mut out = json!({
        "state": state,
        "seq": opened.v.seq,
        "pending_changes": pending,
        "git": opened.loc.is_git(),
        "last_fetch": mem.fetched_at,
    });
    if let (Some(n), true) = (checkout_seq, opened.loc.is_git()) {
        // The checked-out file (e.g. the submodule pointer) is informational only.
        out["checkout_seq"] = json!(n);
        out["checkout_behind"] = json!(n < opened.v.seq);
    }
    Ok(out)
}

// ---------------------------------------------------------------- Init / trust / compact

pub fn init(ctx: &Ctx, name: &str, out: Option<PathBuf>) -> Result<Value> {
    identity::validate_name(name)?;
    let loc = ctx.location()?;
    let out = out.unwrap_or_else(|| config::config_dir().join("master.npk"));
    if out.exists() {
        return Err(Error::new(
            Code::AlreadyExists,
            format!("{} already exists", out.display()),
        ));
    }
    let pass = ctx.new_secret("New master passphrase", &["NEPOMUK_PASSPHRASE"])?;
    crate::password::check(&pass, &[name])?;
    let master = Unlocked::generate(name, IdentityKind::Local);
    let file = tx::genesis(&master)?;
    let idf = IdentityFile::create(&master, &pass)?;
    config::write_private(&out, idf.to_text().as_bytes())?;
    let pushed = match loc.create(&file.serialize()) {
        Ok(p) => p,
        Err(e) => {
            let _ = std::fs::remove_file(&out);
            return Err(e);
        }
    };
    let fp = master.fingerprint();
    let mut mem = VaultMemory::load(file.vault_id);
    mem.pin = Some(fp.clone());
    mem.seq = Some(0);
    mem.head = Some(hex::encode(file.head_hash()));
    mem.save(file.vault_id)?;
    Ok(json!({
        "vault": loc.path.display().to_string(),
        "vault_id": file.vault_id.hex(),
        "master_fingerprint": fp,
        "master_identity": out.display().to_string(),
        "pushed": pushed,
    }))
}

pub fn trust(ctx: &Ctx, fp: &str) -> Result<Value> {
    if !fp.starts_with("npk1") || bech32::decode(fp).is_err() {
        return Err(Error::usage("invalid fingerprint (expected npk1…)"));
    }
    let loc = ctx.location()?;
    let loaded = loc.load(!ctx.opts.offline)?;
    let file = VaultFile::parse(&loaded.bytes)?;
    let vault = file.vault_id;
    // Verify before pinning: the fingerprint must be the vault's current master.
    let v = verify_file(file, fp)?;
    let mut mem = VaultMemory::load(vault);
    let previous = mem.pin.replace(fp.to_string());
    remember(&mut mem, &v);
    mem.save(vault)?;
    Ok(json!({ "vault_id": vault.hex(), "pinned": fp, "previous": previous, "seq": v.seq }))
}

pub fn compact(ctx: &Ctx) -> Result<Value> {
    for _ in 0..MAX_PUSH_ATTEMPTS {
        let opened = open_vault(ctx, true)?;
        let id = ctx.unlock(&opened.v.state)?;
        let file = tx::compact(&opened.v, &id)?;
        let before = opened.loaded.bytes.len();
        let bytes = file.serialize();
        let msg = format!("nepomuk: compact at #{}", opened.v.seq);
        match opened.loc.save(&opened.loaded, &bytes, &msg) {
            Ok(()) => {
                return Ok(
                    json!({ "seq": opened.v.seq, "size_before": before, "size_after": bytes.len() }),
                );
            }
            Err(SaveError::Rejected) => continue,
            Err(SaveError::Other(e)) => return Err(e),
        }
    }
    Err(Error::new(
        Code::SyncContention,
        "the push was rejected repeatedly",
    ))
}

pub fn read_file_arg(path: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| Error::not_found(path).with("reason", e.to_string()))
}
