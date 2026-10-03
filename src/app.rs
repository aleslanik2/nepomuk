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
use crate::format::{VaultFile, from_cbor, to_cbor};
use crate::identity::{self, IdentityFile, Keys, Request, Unlocked};
use crate::model::*;
use crate::store::{self, Loaded, Location, SaveError};
use crate::tx::{self, Tx};
use crate::verify::{Verified, verify_file_with};

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

/// An identity unlocked for this process: with its own keys, or served by the Touch ID agent
/// (which can only read).
#[derive(Clone)]
pub enum Session {
    Local(Rc<Unlocked>),
    Agent(Rc<crate::agent::AgentKeys>),
}

impl Session {
    pub fn keys(&self) -> Rc<dyn Keys> {
        match self {
            Session::Local(u) => u.clone(),
            Session::Agent(a) => a.clone(),
        }
    }
}

pub struct Ctx {
    pub opts: Options,
    pub project: Option<ProjectConfig>,
    pub user: UserConfig,
    /// Unlocked identity cached for the session (`serve --stdio`) or the current command.
    pub unlocked: RefCell<Option<Session>>,
    /// Password handed over by the GUI (`session.unlock`).
    pub password_override: RefCell<Option<Zeroizing<String>>>,
    secret_reader: RefCell<Option<Box<dyn BufRead>>>,
    pub warnings: RefCell<Vec<String>>,
    /// What the identity is unlocked for, shown in the Touch ID prompt.
    pub purpose: RefCell<Option<String>>,
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
            purpose: RefCell::new(None),
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

    /// The text of the Touch ID prompt ("nepomuk is trying to <reason>"): which identity, which
    /// vault, for how long and for what. Never contains secrets: they are never arguments.
    fn touchid_reason(&self, state: &State) -> String {
        let who = match crate::touchid::enabled_for(state.vault_id) {
            Some(crate::touchid::Who::Email { email }) => email,
            Some(crate::touchid::Who::File { path }) => std::fs::read_to_string(&path)
                .ok()
                .and_then(|t| IdentityFile::parse(&t).ok())
                .map(|f| f.name)
                .unwrap_or_else(|| "your identity".into()),
            None => "your identity".into(),
        };
        let vault = self
            .location()
            .ok()
            .and_then(|l| l.path.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "the vault".into());
        let ttl = self.agent_ttl();
        let lasting = if ttl > 0 && crate::agent::has_terminal() {
            match ttl {
                t if t % 60 == 0 => format!(
                    " for {} minute{} in this terminal",
                    t / 60,
                    if t == 60 { "" } else { "s" }
                ),
                t => format!(" for {t} seconds in this terminal"),
            }
        } else {
            String::new()
        };
        let purpose = match self.purpose.borrow().as_deref() {
            Some(p) => p.to_string(),
            None => String::new(),
        };
        let subject = match &self.project {
            Some(p) => format!("{} ({vault})", p.display_name()),
            None => vault,
        };
        let mut reason = format!("use {who} for {subject}{lasting}{purpose}");
        if reason.chars().count() > 200 {
            reason = reason.chars().take(199).collect::<String>() + "…";
        }
        reason
    }

    fn unlock_touchid(&self, state: &State) -> Result<Unlocked> {
        let reason = self.touchid_reason(state);
        let (who, pass) = crate::touchid::unlock(state.vault_id, &reason)?;
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

    /// Unlocks the identity for reading (once per command or GUI session). With Touch ID, an
    /// identity the agent still holds for this terminal is used without a new prompt.
    pub fn unlock(&self, state: &State) -> Result<Rc<dyn Keys>> {
        if let Some(s) = self.unlocked.borrow().as_ref() {
            return Ok(s.keys());
        }
        self.check_session()?;
        if self.opts.touchid
            && self.agent_ttl() > 0
            && crate::agent::has_terminal()
            && let Some(a) = crate::agent::keys(state.vault_id)
                .filter(|a| state.users.values().any(|u| a.matches(u) && !u.disabled))
        {
            let a = Rc::new(a);
            *self.unlocked.borrow_mut() = Some(Session::Agent(a.clone()));
            return Ok(a);
        }
        Ok(self.unlock_local(state)?)
    }

    /// Unlocks the identity with its own keys, as signing a change needs. An identity held by
    /// the Touch ID agent is not enough: every change asks for the fingerprint again.
    pub fn unlock_for_write(&self, state: &State) -> Result<Rc<Unlocked>> {
        if let Some(Session::Local(u)) = self.unlocked.borrow().as_ref() {
            return Ok(u.clone());
        }
        self.check_session()?;
        self.unlock_local(state)
    }

    fn check_session(&self) -> Result<()> {
        if self.opts.session && !self.opts.touchid && self.password_override.borrow().is_none() {
            return Err(Error::new(
                Code::PasswordRequired,
                "the session is locked; call session.unlock",
            ));
        }
        Ok(())
    }

    /// How long the agent keeps an identity (0 = not at all; never in a GUI session).
    fn agent_ttl(&self) -> u64 {
        if self.opts.session {
            return 0;
        }
        self.user
            .agent_timeout
            .unwrap_or(crate::agent::DEFAULT_TIMEOUT)
    }

    fn unlock_local(&self, state: &State) -> Result<Rc<Unlocked>> {
        if self.opts.touchid {
            let id = self.unlock_touchid(state)?;
            let ttl = self.agent_ttl();
            // Remembered only for a terminal session (see `agent`); other programs ask each time.
            if ttl > 0
                && crate::agent::has_terminal()
                && let Err(e) = crate::agent::put(state.vault_id, &id, ttl)
            {
                self.warn(format!(
                    "Touch ID will be asked again next time: {}",
                    e.message
                ));
            }
            let rc = Rc::new(id);
            *self.unlocked.borrow_mut() = Some(Session::Local(rc.clone()));
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
        *self.unlocked.borrow_mut() = Some(Session::Local(rc.clone()));
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
    loc: &Location,
    vault: crate::model::Id,
    mem: &VaultMemory,
    file: &VaultFile,
) -> Result<String> {
    let project_fp = ctx.project.as_ref().and_then(|p| p.root_fp.clone());
    if let Ok(fp) = std::env::var("NEPOMUK_ROOT_FP")
        && !fp.is_empty()
    {
        // The environment is meant for CI, which has no local pin. On a machine that has
        // one, a different value (e.g. from a project's .envrc) must not silently replace it.
        if let Some(p) = &mem.pin
            && *p != fp
        {
            return Err(Error::new(
                Code::UntrustedRoot,
                "NEPOMUK_ROOT_FP differs from the master fingerprint pinned on this machine",
            )
            .with("pinned", p.clone())
            .with("environment", fp));
        }
        return Ok(fp);
    }
    if let Some(p) = &mem.pin {
        if let Some(fp) = project_fp
            && fp != *p
        {
            ctx.warn(format!(
                ".nepomuk.toml names the master {fp}, but {p} is pinned on this machine; the pin is used"
            ));
        }
        return Ok(p.clone());
    }
    // A fingerprint from .nepomuk.toml is never pinned automatically: whoever controls the
    // project repository could ship a vault of their own together with a matching fingerprint.
    let found = claimed_master_fp(file).unwrap_or_default();
    let mut err = Error::new(
        Code::UntrustedRoot,
        "no pinned master fingerprint for this vault; verify it out of band and run `nepomuk trust <fingerprint>`",
    )
    .with("vault_id", vault.hex())
    .with("claimed_fingerprint", found);
    if let Some(fp) = project_fp {
        err = err.with("project_fingerprint", fp);
    }
    Err(with_replaced_vault(err, loc, vault)?)
}

/// A vault without a pin at a place where another, pinned vault was opened before is not a
/// first start: the file has been swapped. Say so, and require `trust --replace`.
fn with_replaced_vault(err: Error, loc: &Location, vault: crate::model::Id) -> Result<Error> {
    let Some(prev) = config::Locations::load()?.previous(&loc.path, vault) else {
        return Ok(err);
    };
    let Some(prev_pin) = VaultMemory::load(prev)?.pin else {
        return Ok(err);
    };
    let mut e = Error::new(
        Code::UntrustedRoot,
        format!(
            "{} held another vault before, pinned to {prev_pin}; this file is a different vault with a different master. If this was not announced to you, do not trust it",
            loc.path.display()
        ),
    );
    e.details = err.details;
    Ok(e.with("replaces_vault_id", prev.hex())
        .with("pinned", prev_pin)
        .with("needs_replace", true))
}

/// The master fingerprint the file claims (unverified; for display only).
pub fn claimed_master_fp(file: &VaultFile) -> Option<String> {
    crate::verify::checkpoint_master_fp(file)
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
    let pinned = VaultFile::parse(&bytes).map_err(|e| {
        Error::new(
            Code::StaleBelowPin,
            format!(
                "the vault pinned by the submodule cannot be read: {}",
                e.message
            ),
        )
    })?;
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
    let mut mem = VaultMemory::load(vault)?;
    let pin = pin_for(ctx, &loc, vault, &mem, &file)?;
    let v = verify_file_with(file, &pin, &mem.former).map_err(|e| {
        // Signed by a key that is not the pinned master and no transfer from it: a different
        // vault with the same id, not a first start.
        if e.code == Code::UntrustedRoot && e.details.get("found").is_some() {
            e.with("needs_replace", true)
        } else {
            e
        }
    })?;
    check_memory(&v, &mem)?;
    check_former_signer(&v, &mut mem, &pin)?;
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
    if !ctx.ci() {
        config::Locations::record(&loc.path, vault)?;
    }
    Ok(Opened { loc, loaded, v })
}

/// A checkpoint signed by a former master is accepted only as the continuation of the version
/// seen before the transfer – never as a fresh history, which a former master (who may have
/// left or been compromised) could otherwise forge. Once the pinned master has signed the
/// checkpoint (after `compact`), former masters are forgotten.
pub fn check_former_signer(v: &Verified, mem: &mut VaultMemory, pin: &str) -> Result<()> {
    let signer = crate::verify::checkpoint_master_fp(&v.file).unwrap_or_default();
    if signer == pin {
        mem.former.clear();
        return Ok(());
    }
    if contains_seen(v, mem) {
        return Ok(());
    }
    Err(Error::new(
        Code::UntrustedRoot,
        "the vault is signed by a former master and does not continue the version seen before; ask the current master to run `nepomuk compact`",
    )
    .with("signer", signer))
}

/// Whether the file continues the history seen on this machine: its checkpoint entry is the one
/// seen before, or the remembered head is one of its commits (a commit's hash chains back to the
/// exact checkpoint entry). A matching `folded_head` alone proves nothing, since whoever signs a
/// checkpoint can claim any folded head.
fn contains_seen(v: &Verified, mem: &VaultMemory) -> bool {
    if mem
        .checkpoint
        .as_deref()
        .is_some_and(|c| hex::encode(v.file.entries[0].hash()) == c)
    {
        return true;
    }
    let (Some(seq), Some(head)) = (mem.seq, mem.head.as_deref()) else {
        return false;
    };
    v.commits
        .iter()
        .any(|c| c.seq == seq && hex::encode(c.hash) == head)
}

fn remember(mem: &mut VaultMemory, v: &Verified) {
    if mem.seq.is_none_or(|s| v.seq >= s) {
        mem.seq = Some(v.seq);
        mem.head = Some(hex::encode(v.head));
        mem.checkpoint = Some(hex::encode(v.file.entries[0].hash()));
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

/// Public keys for `identity passwd` (§4.4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotatedKeys {
    pub kem: crypto::KemPublic,
    pub sig: crypto::SigPublic,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
    /// The new password over the current seed, used instead when the user is the master.
    pub master_credential: Option<crypto::PasswordSealed>,
}

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
    /// Removal by node id (for nodes whose name cannot be decrypted).
    RmNode {
        node: String,
    },
    Mv {
        src: String,
        dst: String,
    },
    Rekey {
        path: String,
    },
    /// Rekeys what the vault records as pending (§8.1) as far as the author may.
    RekeyPending,
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
        /// New keys (§4.4): the credential seals a new seed, so the old password (still in the
        /// git history) no longer unlocks the identity. Public parts only; no secret is stored
        /// in the intent.
        #[serde(default)]
        rotate: Option<RotatedKeys>,
    },
    MasterTransfer {
        user: String,
        /// The former master keeps its grant on the root (§8.3).
        #[serde(default)]
        keep_access: bool,
    },
    /// Folders and secrets copied from another vault (`nepomuk migrate`), in one commit.
    Import {
        entries: Vec<ImportEntry>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImportEntry {
    pub path: String,
    pub content: Content,
    pub not_after: Option<i64>,
}

fn zeroize_content(content: &mut Content) {
    use zeroize::Zeroize;
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

impl Drop for Intent {
    fn drop(&mut self) {
        match self {
            Intent::Put { content, .. } => zeroize_content(content),
            Intent::Import { entries } => {
                for e in entries {
                    zeroize_content(&mut e.content);
                }
            }
            _ => {}
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
            Intent::RmNode { node } => crate::model::Id::parse(node),
            _ => None,
        }
    }

    fn apply(&self, tx: &mut Tx) -> Result<Value> {
        Ok(match self {
            Intent::Import { entries } => {
                let (mut folders, mut secrets) = (0, 0);
                for e in entries {
                    if matches!(e.content, Content::Folder) {
                        if e.path != "/" {
                            tx.mkdir(&e.path, true)?;
                        }
                        folders += 1;
                    } else {
                        let (parent, _) = tx::split_parent(&e.path)?;
                        if parent != "/" {
                            tx.mkdir(&parent, true)?;
                        }
                        if tx.access().exists(&tx::normalize_path(&e.path)?) {
                            return Err(Error::new(
                                Code::AlreadyExists,
                                format!("already exists in this vault: {}", e.path),
                            )
                            .with("path", e.path.clone()));
                        }
                        tx.put(&e.path, e.content.clone(), e.not_after)?;
                        secrets += 1;
                    }
                }
                json!({ "folders": folders, "secrets": secrets })
            }
            Intent::Mkdir { path, parents } => {
                tx.mkdir(path, *parents)?;
                json!({ "path": tx::normalize_path(path)? })
            }
            Intent::RmNode { node } => {
                let id = crate::model::Id::parse(node)
                    .ok_or_else(|| Error::usage(format!("invalid node id: {node}")))?;
                tx.rm_node(id)?;
                json!({ "node": id.hex() })
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
            Intent::RekeyPending => {
                let done = tx.rekey_pending()?;
                json!({ "rekeyed": done })
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
            Intent::Passwd { credential, rotate } => match rotate {
                Some(k) if !tx.state.is_master(tx.me) => {
                    tx.rotate_own_keys(
                        k.kem.clone(),
                        k.sig.clone(),
                        Some(credential.clone()),
                        k.proof.clone(),
                    )?;
                    json!({ "updated": true, "rotated": true })
                }
                _ => {
                    // Only the credential of the master changes: its keys are pinned everywhere.
                    let cred = match rotate {
                        Some(k) => k.master_credential.clone().ok_or_else(|| {
                            Error::general("missing credential for the current keys")
                        })?,
                        None => credential.clone(),
                    };
                    tx.update_own_credential(cred)?;
                    tx.warnings.push(
                        "the master's keys are pinned everywhere and stay the same: whoever knows the old password and has the git history can still unlock it; if it leaked, transfer the master role to a new identity".into(),
                    );
                    json!({ "updated": true, "rotated": false })
                }
            },
            Intent::MasterTransfer { user, keep_access } => {
                let u = tx.user_named(user)?;
                tx.transfer_master(u, *keep_access)?;
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
        let id = ctx.unlock_for_write(&opened.v.state)?;
        let base = *base_seq.get_or_insert(opened.v.seq);
        let mut tx = Tx::new(&opened.v, &*id)?;
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
                let mut mem = VaultMemory::load(verified.file.vault_id)?;
                if verified.master_fp != opened.v.master_fp && mem.pin.is_some() {
                    // This client signed the transfer itself.
                    mem.repin(&verified.master_fp);
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

fn load_pending(ctx: &Ctx, vault: crate::model::Id, id: &dyn Keys) -> Result<Vec<PendingItem>> {
    let p = config::pending_path(vault);
    let Ok(bytes) = std::fs::read(&p) else {
        return Ok(Vec::new());
    };
    let f: PendingFile = from_cbor(&bytes)?;
    if f.identity != id.fingerprint() {
        ctx.warn("pending offline changes belong to another identity and were left untouched");
        return Ok(Vec::new());
    }
    let plain = id.unwrap(&f.items, &pending_aad(vault))?;
    from_cbor(&plain)
}

fn save_pending(vault: crate::model::Id, id: &dyn Keys, items: &[PendingItem]) -> Result<()> {
    let p = config::pending_path(vault);
    if items.is_empty() {
        let _ = std::fs::remove_file(p);
        return Ok(());
    }
    let plain = Zeroizing::new(to_cbor(&items));
    let items = crypto::wrap(id.kem_public(), &plain, &pending_aad(vault))?;
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
    let id = ctx.unlock_for_write(&opened.v.state)?;
    // Check that the intent applies to the current state before queueing it.
    let mut tx = Tx::new(&opened.v, &*id)?;
    let out = intent.apply(&mut tx)?;
    let vault = opened.v.file.vault_id;
    let mut items = load_pending(ctx, vault, &*id)?;
    items.push(PendingItem {
        intent: intent.clone(),
        base_seq: opened.v.seq,
        created: tx::now(),
    });
    save_pending(vault, &*id, &items)?;
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
    let id = ctx.unlock_for_write(&opened.v.state)?;
    let items = load_pending(ctx, vault, &*id)?;
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
                save_pending(vault, &*id, &keep)?;
                return Err(e);
            }
        }
    }
    save_pending(vault, &*id, &keep)?;
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
        Intent::RmNode { node } => format!("rm --node {node}"),
        Intent::Mv { src, dst } => format!("mv {src} {dst}"),
        Intent::Rekey { path } => format!("rekey {path}"),
        Intent::RekeyPending => "rekey --pending".into(),
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
        Intent::MasterTransfer { user, .. } => format!("master transfer {user}"),
        Intent::Import { entries } => format!("import of {} items", entries.len()),
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
    let mem = VaultMemory::load(vault)?;
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
    let mut mem = VaultMemory::load(file.vault_id)?;
    mem.pin = Some(fp.clone());
    mem.seq = Some(0);
    mem.head = Some(hex::encode(file.head_hash()));
    mem.checkpoint = Some(hex::encode(file.head_hash()));
    mem.save(file.vault_id)?;
    config::Locations::record(&loc.path, file.vault_id)?;
    Ok(json!({
        "vault": loc.path.display().to_string(),
        "vault_id": file.vault_id.hex(),
        "master_fingerprint": fp,
        "master_identity": out.display().to_string(),
        "pushed": pushed,
    }))
}

/// Pins the master fingerprint of the vault (§7.1).
///
/// Replacing a pin is what an attacker who swaps the vault file wants the user to do, so it
/// needs `replace` unless the file proves the change: its checkpoint is signed by the master
/// pinned here (or a former one) and its log transfers the master role to `fp`. The same holds
/// for a vault at a place where another pinned vault was opened before.
pub fn trust(ctx: &Ctx, fp: &str, replace: bool) -> Result<Value> {
    if !fp.starts_with("npk1") || bech32::decode(fp).is_err() {
        return Err(Error::usage("invalid fingerprint (expected npk1…)"));
    }
    let loc = ctx.location()?;
    let loaded = loc.load(!ctx.opts.offline)?;
    let file = VaultFile::parse(&loaded.bytes)?;
    let vault = file.vault_id;
    let mut mem = VaultMemory::load(vault)?;
    let signer = claimed_master_fp(&file).unwrap_or_default();
    let replacing = mem.pin.clone().filter(|p| p != fp);
    let proven = mem.pin.as_deref() == Some(signer.as_str()) || mem.former.contains(&signer);
    let replacing_vault = match config::Locations::load()?.previous(&loc.path, vault) {
        Some(prev) => VaultMemory::load(prev)?.pin.map(|p| (prev, p)),
        None => None,
    };
    let unproven_change = replacing.is_some() && !(proven && signer != fp);
    if !replace && (unproven_change || replacing_vault.is_some()) {
        let mut e = Error::new(
            Code::UntrustedRoot,
            "this would replace the master pinned on this computer; a vault swapped by an attacker looks exactly like this. Confirm the new fingerprint with your administrator, then run `nepomuk trust --replace <fingerprint>`",
        )
        .with("found", signer.clone())
        .with("needs_replace", true);
        if let Some(p) = &replacing {
            e = e.with("pinned", p.clone());
        }
        if let Some((prev, p)) = &replacing_vault {
            e = e
                .with("replaces_vault_id", prev.hex())
                .with("pinned", p.clone());
        }
        return Err(e);
    }
    if replace && unproven_change {
        // A deliberate new root of trust: nothing pinned before is trusted any more, and the
        // history seen under the old master says nothing about the new one.
        mem = VaultMemory {
            fetched_at: mem.fetched_at,
            ..Default::default()
        };
    }
    // Verify before pinning: the fingerprint must be the vault's current master, and the
    // checkpoint must be signed by it or by a master pinned here before.
    let mut trusted = mem.former.clone();
    trusted.extend(mem.pin.clone());
    let v = verify_file_with(file, fp, &trusted).map_err(|e| {
        if e.code == Code::UntrustedRoot && signer != fp && !trusted.contains(&signer) {
            e.with(
                "hint",
                "the vault was handed over to this master but not compacted since; ask the master to run `nepomuk compact`, or pin the former master first",
            )
        } else {
            e
        }
    })?;
    if signer != fp && !contains_seen(&v, &mem) {
        return Err(Error::new(
            Code::UntrustedRoot,
            "the vault is signed by a former master and does not continue the version seen before; ask the current master to run `nepomuk compact`",
        )
        .with("signer", signer));
    }
    // Keep the former master only while the vault still needs it (its checkpoint is signed by
    // it); re-pinning for any other reason must not leave the old key trusted.
    let previous = mem.pin.replace(fp.to_string());
    if signer == fp {
        mem.former.clear();
    } else if previous.as_deref() == Some(signer.as_str()) && !mem.former.contains(&signer) {
        mem.former.push(signer.clone());
    }
    remember(&mut mem, &v);
    mem.save(vault)?;
    config::Locations::record(&loc.path, vault)?;
    let previous = replacing.or(previous).or(replacing_vault.map(|(_, p)| p));
    Ok(json!({ "vault_id": vault.hex(), "pinned": fp, "previous": previous, "seq": v.seq }))
}

pub fn compact(ctx: &Ctx) -> Result<Value> {
    for _ in 0..MAX_PUSH_ATTEMPTS {
        let opened = open_vault(ctx, true)?;
        let id = ctx.unlock_for_write(&opened.v.state)?;
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
