//! Command line interface (§10). Every command supports `--json` and then never prompts.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::app::{self, Ctx, Intent, Options, Resolve};
use crate::config;
use crate::error::{Code, Error, Result};
use crate::identity::{self, IdentityFile, Request, Unlocked};
use crate::model::{Content, Field, IdentityKind, Right};
use crate::queries;

pub const API_VERSION: u32 = 1;

#[derive(Parser)]
#[command(
    name = "nepomuk",
    version,
    about = "Post-quantum secrets vault in a single file in git"
)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Args)]
pub struct Global {
    /// Vault file (default: NEPOMUK_VAULT or `vault` in .nepomuk.toml)
    #[arg(long, global = true)]
    pub vault: Option<PathBuf>,
    /// Machine-readable output; never prompts
    #[arg(long, global = true)]
    pub json: bool,
    /// Local identity file (default: NEPOMUK_IDENTITY or ~/.config/nepomuk/identity.npk)
    #[arg(long, global = true)]
    pub identity: Option<PathBuf>,
    /// Log in with the password identity of this email
    #[arg(long, global = true)]
    pub email: Option<String>,
    /// Read passwords from this file descriptor, one per line
    #[arg(long, global = true, value_name = "N")]
    pub password_fd: Option<i32>,
    /// Read passwords from stdin, one per line
    #[arg(long, global = true)]
    pub password_stdin: bool,
    /// CI mode: verify against the submodule pin (auto-detected)
    #[arg(long, global = true)]
    pub ci: bool,
    /// Queue writes locally instead of pushing (emergency option)
    #[arg(long, global = true)]
    pub offline: bool,
    /// Unlock with Touch ID (macOS; set up with `nepomuk identity touchid enable`)
    #[arg(long, global = true)]
    pub touchid: bool,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Create a new vault and its master identity
    Init {
        /// Name of the master identity
        #[arg(long, default_value = "master")]
        name: String,
        /// Where to write the master identity file (default ~/.config/nepomuk/master.npk)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Pin the master fingerprint of the vault
    Trust { fingerprint: String },
    /// Show vault information
    Info,
    /// Show sync status (up to date / behind / ahead / conflict)
    Status,
    /// Verify every signature and permission in the log
    Verify {
        /// Ignore any cache (the log is always fully verified)
        #[arg(long)]
        full: bool,
    },
    /// Show the log of changes
    Log {
        #[arg(long, short = 'n')]
        limit: Option<usize>,
    },
    /// Fold the log into a new checkpoint (master only)
    Compact,
    /// Replay pending offline changes on top of the latest vault
    Sync {
        /// How to resolve conflicts: ours (overwrite) or theirs (discard own change)
        #[arg(long, value_parser = ["ours", "theirs"])]
        resolve: Option<String>,
    },
    /// Manage your identity
    #[command(subcommand)]
    Identity(IdentityCmd),
    /// Generate a passphrase (6 words ≈ 77 bits)
    Passgen {
        #[arg(long, default_value_t = 6)]
        words: usize,
    },
    /// Manage users
    #[command(subcommand)]
    User(UserCmd),
    /// Manage groups
    #[command(subcommand)]
    Group(GroupCmd),
    /// List folders and secrets
    Ls {
        path: Option<String>,
        #[arg(short, long)]
        recursive: bool,
    },
    /// Create a folder
    Mkdir {
        path: String,
        /// Create parent folders as needed
        #[arg(short, long)]
        parents: bool,
    },
    /// Store a secret: value from a hidden prompt, stdin (-), a file (@path) or record fields
    Put(PutArgs),
    /// Read a secret (`path` or `path#field`)
    Get {
        path: String,
        /// Write to a file with 0600 permissions
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Rename or move a folder or secret
    Mv { src: String, dst: String },
    /// Remove a folder (recursively) or secret
    Rm { path: String },
    /// Replace the keys of a subtree (admin on the parent)
    Rekey { path: String },
    /// Secrets pending rotation at the source
    #[command(subcommand)]
    Rotation(RotationCmd),
    /// Grant a right: `grant user:<email>|group:<name> read|write|share|admin <path>`
    Grant {
        who: String,
        right: String,
        path: String,
    },
    /// Revoke a grant and rekey the subtree
    Revoke {
        who: String,
        path: String,
        /// Do not rekey (the revoked party can still decrypt future content)
        #[arg(long)]
        no_rekey: bool,
    },
    /// Who has access to a path
    Access { path: String },
    /// Your identity, rights and grants
    Whoami,
    /// Grant a system right: users, groups, audit, group-admin:<group>
    Sysgrant {
        user: String,
        right: String,
        #[arg(long)]
        delegate: bool,
    },
    /// Revoke a system right
    Sysrevoke { user: String, right: String },
    /// Run a command with the secrets of a profile from .nepomuk.toml
    Exec {
        profile: String,
        /// Mask secret values in the output (default in CI)
        #[arg(long)]
        mask: bool,
        #[arg(long, conflicts_with = "mask")]
        no_mask: bool,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// JSON-RPC 2.0 over stdin/stdout for the GUI
    Serve {
        #[arg(long, required = true)]
        stdio: bool,
    },
    /// Version of the CLI, JSON API, file format and crypto suites
    Version,
    /// Master management
    #[command(subcommand)]
    Master(MasterCmd),
    /// Check the installation, the identity configuration and the vault
    Doctor,
    /// Forget identities kept unlocked by the Touch ID agent
    Lock,
    /// Install the latest release (verified with the release key)
    Upgrade {
        /// Only report whether a newer release exists
        #[arg(long)]
        check: bool,
        /// A specific release instead of the latest, e.g. v0.2.3
        #[arg(long, value_name = "TAG")]
        tag: Option<String>,
        /// Also install or update the desktop app
        #[arg(long, conflicts_with = "no_gui")]
        gui: bool,
        /// Do not touch the desktop app
        #[arg(long)]
        no_gui: bool,
        #[arg(long, hide = true)]
        refresh: bool,
    },
    /// The Touch ID agent (started automatically)
    #[command(hide = true)]
    Agent {
        #[arg(long)]
        daemon: bool,
    },
    /// git textconv driver: public metadata of a vault file (`diff.nepomuk.textconv`)
    #[command(name = "git-textconv", hide = true)]
    GitTextconv { file: PathBuf },
    /// git merge driver: always refuses (`merge.nepomuk.driver`)
    #[command(name = "git-merge", hide = true)]
    GitMerge {
        #[arg(num_args = 0..)]
        files: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum IdentityCmd {
    /// Create a local identity file protected by a passphrase
    New {
        #[arg(long)]
        name: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Create an enrollment request for an administrator
    Request {
        /// Password identity for this email
        #[arg(long, conflicts_with_all = ["ssh_key", "local"])]
        email: Option<String>,
        /// Post-quantum SSH key (mldsa44-ed25519)
        #[arg(long)]
        ssh_key: Option<PathBuf>,
        /// Request for the local identity file (--identity or the default one)
        #[arg(long)]
        local: bool,
        #[arg(long)]
        out: PathBuf,
    },
    /// Change your password or passphrase
    Passwd,
    /// Show the fingerprint of a local identity file
    Show,
    /// Unlock with Touch ID on this Mac (the password is sealed by the Secure Enclave)
    #[command(subcommand)]
    Touchid(TouchidCmd),
}

#[derive(Subcommand)]
pub enum TouchidCmd {
    /// Ask for the password once and seal it for Touch ID
    Enable,
    /// Forget the sealed password for this vault
    Disable,
    Status,
}

#[derive(Subcommand)]
pub enum UserCmd {
    /// Approve an enrollment request
    Add {
        request: PathBuf,
    },
    List,
    Disable {
        name: String,
    },
    /// Disable a user everywhere, rekey and list secrets to rotate
    Offboard {
        name: String,
    },
    /// Replace a user's identity (lost password or key)
    Replace {
        name: String,
        request: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum GroupCmd {
    Create { name: String },
    Add { group: String, user: String },
    Remove { group: String, user: String },
    List,
}

#[derive(Subcommand)]
pub enum RotationCmd {
    List,
    /// Mark a secret as rotated
    Done {
        path: String,
    },
}

#[derive(Subcommand)]
pub enum MasterCmd {
    /// Transfer the master role to another user
    Transfer { user: String },
    /// Split the master seed into Shamir shares (not in this version)
    Backup {
        #[arg(long)]
        shares: Option<u8>,
        #[arg(long)]
        threshold: Option<u8>,
    },
    /// Restore the master seed from Shamir shares (not in this version)
    Restore,
}

#[derive(Args)]
pub struct PutArgs {
    pub path: String,
    /// `-` for stdin or `@file`
    pub source: Option<String>,
    /// Record template: android-signing, pkcs12-cert, generic
    #[arg(long)]
    pub template: Option<String>,
    /// Record field `name=value` or `name=@file`
    #[arg(long = "field", value_name = "NAME=VALUE")]
    pub fields: Vec<String>,
    /// Record field read from a hidden prompt (or a line of stdin)
    #[arg(long = "field-prompt", value_name = "NAME")]
    pub field_prompts: Vec<String>,
    /// MIME type of a binary secret
    #[arg(long)]
    pub mime: Option<String>,
}

// ---------------------------------------------------------------- Output

pub struct Out {
    pub data: Value,
    pub human: Option<String>,
    pub exit: i32,
}

impl Out {
    fn data(data: Value) -> Out {
        Out {
            data,
            human: None,
            exit: 0,
        }
    }
    fn human(data: Value, human: String) -> Out {
        Out {
            data,
            human: Some(human),
            exit: 0,
        }
    }
}

fn render_generic(v: &Value, indent: usize, out: &mut String) {
    let pad = " ".repeat(indent);
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                match x {
                    Value::Object(_) | Value::Array(_) if !is_empty(x) => {
                        out.push_str(&format!("{pad}{k}:\n"));
                        render_generic(x, indent + 2, out);
                    }
                    _ => out.push_str(&format!("{pad}{k}: {}\n", scalar(x))),
                }
            }
        }
        Value::Array(a) => {
            for x in a {
                match x {
                    Value::Object(_) => {
                        let mut inner = String::new();
                        render_generic(x, indent + 2, &mut inner);
                        out.push_str(&format!("{pad}-{}\n", &inner.trim_end()[indent + 1..]));
                    }
                    _ => out.push_str(&format!("{pad}- {}\n", scalar(x))),
                }
            }
        }
        _ => out.push_str(&format!("{pad}{}\n", scalar(v))),
    }
}

fn is_empty(v: &Value) -> bool {
    match v {
        Value::Object(m) => m.is_empty(),
        Value::Array(a) => a.is_empty(),
        _ => false,
    }
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".into(),
        Value::Array(a) if a.is_empty() => "(none)".into(),
        Value::Object(m) if m.is_empty() => "(none)".into(),
        x => x.to_string(),
    }
}

pub fn print_ok(ctx: &Ctx, out: &Out) {
    let warnings: Vec<String> = ctx.warnings.borrow().clone();
    if ctx.opts.json {
        let mut data = out.data.clone();
        if !warnings.is_empty()
            && let Value::Object(m) = &mut data
        {
            m.insert("warnings".into(), json!(warnings));
        }
        println!(
            "{}",
            json!({ "api": API_VERSION, "ok": true, "data": data })
        );
    } else {
        for w in &warnings {
            eprintln!("warning: {w}");
        }
        let text = match &out.human {
            Some(h) => h.clone(),
            None => {
                let mut s = String::new();
                render_generic(&out.data, 0, &mut s);
                s
            }
        };
        print!("{text}");
        if !text.is_empty() && !text.ends_with('\n') {
            println!();
        }
    }
}

pub fn error_json(e: &Error) -> Value {
    json!({ "api": API_VERSION, "ok": false,
            "error": { "code": e.code.as_str(), "message": e.message, "details": e.details } })
}

pub fn print_err(json_mode: bool, e: &Error) {
    if json_mode {
        println!("{}", error_json(e));
    } else {
        eprintln!("error: {} [{}]", e.message, e.code.as_str());
        for (k, v) in &e.details {
            eprintln!("  {k}: {}", scalar(v));
        }
    }
}

// ---------------------------------------------------------------- Dispatch

pub fn main() -> i32 {
    crate::memory::harden_process();
    let args: Vec<String> = std::env::args().collect();
    let json_mode = args.iter().any(|a| a == "--json");
    let cli = match Cli::try_parse_from(&args) {
        Ok(c) => c,
        Err(e) => {
            use clap::error::ErrorKind;
            if matches!(
                e.kind(),
                ErrorKind::DisplayHelp
                    | ErrorKind::DisplayVersion
                    | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ) || !json_mode
            {
                e.exit();
            }
            print_err(
                true,
                &Error::usage(
                    e.to_string()
                        .lines()
                        .next()
                        .unwrap_or("usage error")
                        .to_string(),
                ),
            );
            return 2;
        }
    };
    let g = cli.global;
    let opts = Options {
        vault: g.vault,
        json: g.json,
        identity: g.identity,
        email: g.email,
        password_fd: g.password_fd,
        password_stdin: g.password_stdin,
        ci: g.ci,
        offline: g.offline,
        session: false,
        touchid: g.touchid,
        remember_touchid: false,
    };
    let ctx = match Ctx::new(opts) {
        Ok(c) => c,
        Err(e) => {
            print_err(json_mode, &e);
            return e.code.exit_code();
        }
    };
    if let Cmd::Serve { .. } = cli.cmd {
        return crate::serve::run(ctx);
    }
    let quiet = matches!(
        cli.cmd,
        Cmd::Doctor
            | Cmd::Upgrade { .. }
            | Cmd::Agent { .. }
            | Cmd::GitTextconv { .. }
            | Cmd::GitMerge { .. }
            | Cmd::Exec { .. }
    );
    let result = run(&ctx, cli.cmd);
    if !quiet
        && !ctx.opts.json
        && let Some(n) = crate::upgrade::notice(&ctx.user)
    {
        eprintln!("note: {n}");
    }
    match result {
        Ok(out) => {
            if out.exit >= 0 && !(out.data.is_null() && out.human.is_none()) {
                print_ok(&ctx, &out);
            }
            out.exit.max(0)
        }
        Err(e) => {
            if !ctx.opts.json {
                for w in ctx.warnings.borrow().iter() {
                    eprintln!("warning: {w}");
                }
            }
            print_err(ctx.opts.json, &e);
            e.code.exit_code()
        }
    }
}

fn intent(ctx: &Ctx, i: Intent) -> Result<Out> {
    Ok(Out::data(app::execute(ctx, &i, None, Resolve::Ask)?))
}

fn parse_right(s: &str) -> Result<Right> {
    Right::parse(s)
        .ok_or_else(|| Error::usage(format!("unknown right {s:?} (read, write, share, admin)")))
}

fn read_text_file(p: &PathBuf) -> Result<String> {
    std::fs::read_to_string(p).map_err(|_| Error::not_found(&p.display().to_string()))
}

pub fn version_json() -> Value {
    json!({
        "cli": env!("CARGO_PKG_VERSION"),
        "api": API_VERSION,
        "formats": [crate::format::FORMAT_VERSION],
        "suites": [crate::crypto::SUITE],
    })
}

pub fn run(ctx: &Ctx, cmd: Cmd) -> Result<Out> {
    match cmd {
        Cmd::Init { name, out } => {
            let d = app::init(ctx, &name, out)?;
            let human = format!(
                "Vault created: {}\nMaster identity: {}\nMaster fingerprint: {}\n\nPin this fingerprint in CI (NEPOMUK_ROOT_FP) and on every client (`nepomuk trust`).\nKeep the master identity offline.{}\n",
                d["vault"].as_str().unwrap_or(""),
                d["master_identity"].as_str().unwrap_or(""),
                d["master_fingerprint"].as_str().unwrap_or(""),
                if d["pushed"] == json!(true) {
                    "\nThe vault was committed and pushed."
                } else {
                    ""
                }
            );
            Ok(Out::human(d, human))
        }
        Cmd::Trust { fingerprint } => Ok(Out::data(app::trust(ctx, &fingerprint)?)),
        Cmd::Info => {
            let o = app::open_vault(ctx, true)?;
            Ok(Out::data(queries::info(&o)))
        }
        Cmd::Status => Ok(Out::data(app::status(ctx)?)),
        Cmd::Verify { .. } => {
            let o = app::open_vault(ctx, true)?;
            let d = json!({ "ok": true, "seq": o.v.seq, "commits_verified": o.v.commits.len(), "master_fingerprint": o.v.master_fp });
            let h = format!(
                "OK: #{} – {} commits verified, master {}\n",
                o.v.seq,
                o.v.commits.len(),
                o.v.master_fp
            );
            Ok(Out::human(d, h))
        }
        Cmd::Log { limit } => {
            let o = app::open_vault(ctx, true)?;
            let d = queries::log(ctx, &o, limit)?;
            let mut h = String::new();
            for c in d["commits"].as_array().unwrap() {
                h.push_str(&format!(
                    "#{:<5} {}  {:<24} {}{}\n",
                    c["seq"],
                    c["time"].as_str().unwrap_or(""),
                    c["author"].as_str().unwrap_or(""),
                    c["operations"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_str().unwrap_or(""))
                        .collect::<Vec<_>>()
                        .join(", "),
                    match c["paths"].as_array() {
                        Some(p) if !p.is_empty() => format!(
                            "  ({})",
                            p.iter()
                                .map(|x| x.as_str().unwrap_or(""))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        _ => String::new(),
                    }
                ));
            }
            if h.is_empty() {
                h = format!("no commits since checkpoint #{}\n", d["checkpoint_seq"]);
            }
            Ok(Out::human(d, h))
        }
        Cmd::Compact => Ok(Out::data(app::compact(ctx)?)),
        Cmd::Sync { resolve } => {
            let r = match resolve.as_deref() {
                Some("ours") => Resolve::Ours,
                Some("theirs") => Resolve::Theirs,
                _ => Resolve::Ask,
            };
            let d = app::sync(ctx, r)?;
            let exit = if d["state"] == "conflict" {
                Code::Conflict.exit_code()
            } else {
                0
            };
            Ok(Out {
                data: d,
                human: None,
                exit,
            })
        }
        Cmd::Identity(c) => identity_cmd(ctx, c),
        Cmd::Passgen { words } => {
            if words < 4 {
                return Err(Error::usage("use at least 4 words"));
            }
            let p = crate::password::passgen(words);
            let bits = crate::password::passgen_bits(words);
            Ok(Out::human(
                json!({ "passphrase": p.as_str(), "bits": bits.floor() }),
                format!("{}\n", p.as_str()),
            ))
        }
        Cmd::User(c) => match c {
            UserCmd::Add { request } => {
                let text = read_text_file(&request)?;
                let req = Request::parse(&text)?;
                req.verify()?;
                if !ctx.opts.json {
                    eprintln!(
                        "Adding {} with fingerprint {} – verify it with the user.",
                        req.name,
                        req.fingerprint()
                    );
                }
                intent(ctx, Intent::UserAdd { request: text })
            }
            UserCmd::List => {
                let o = app::open_vault(ctx, true)?;
                let d = queries::users(&o);
                let mut h = String::new();
                for u in d["users"].as_array().unwrap() {
                    let mut flags = Vec::new();
                    if u["master"] == true {
                        flags.push("master".to_string());
                    }
                    if u["disabled"] == true {
                        flags.push("disabled".to_string());
                    }
                    for g in u["groups"].as_array().unwrap() {
                        flags.push(format!("group:{}", g.as_str().unwrap()));
                    }
                    for r in u["system_rights"].as_array().unwrap() {
                        flags.push(r.as_str().unwrap().to_string());
                    }
                    h.push_str(&format!(
                        "{:<32} {:<8} {}  {}\n",
                        u["name"].as_str().unwrap(),
                        u["kind"].as_str().unwrap(),
                        u["fingerprint"].as_str().unwrap(),
                        flags.join(" ")
                    ));
                }
                Ok(Out::human(d, h))
            }
            UserCmd::Disable { name } => intent(ctx, Intent::UserDisable { name }),
            UserCmd::Offboard { name } => {
                let d = app::execute(
                    ctx,
                    &Intent::UserOffboard { name: name.clone() },
                    None,
                    Resolve::Ask,
                )?;
                let mut h = format!("{name} was offboarded.\n");
                if let Some(r) = d["rotate"].as_array().filter(|r| !r.is_empty()) {
                    h.push_str("\nRotate these secrets at their source:\n");
                    for x in r {
                        h.push_str(&format!("  [ ] {}\n", x.as_str().unwrap_or("")));
                    }
                }
                if let Some(t) = d["tasks"].as_array() {
                    h.push_str("\nTasks for other administrators:\n");
                    for x in t {
                        h.push_str(&format!("  - {}\n", x.as_str().unwrap_or("")));
                    }
                }
                Ok(Out::human(d, h))
            }
            UserCmd::Replace { name, request } => {
                let text = read_text_file(&request)?;
                intent(
                    ctx,
                    Intent::UserReplace {
                        name,
                        request: text,
                    },
                )
            }
        },
        Cmd::Group(c) => match c {
            GroupCmd::Create { name } => intent(ctx, Intent::GroupCreate { name }),
            GroupCmd::Add { group, user } => intent(
                ctx,
                Intent::GroupAdd {
                    group,
                    user: strip_user(&user),
                },
            ),
            GroupCmd::Remove { group, user } => intent(
                ctx,
                Intent::GroupRemove {
                    group,
                    user: strip_user(&user),
                },
            ),
            GroupCmd::List => {
                let o = app::open_vault(ctx, true)?;
                Ok(Out::data(queries::groups(&o)))
            }
        },
        Cmd::Ls { path, recursive } => {
            let o = app::open_vault(ctx, true)?;
            let d = queries::ls(ctx, &o, path.as_deref(), recursive)?;
            let mut h = String::new();
            for e in d["entries"].as_array().unwrap() {
                let t = e["type"].as_str().unwrap_or("");
                let mut flags = Vec::new();
                if let Some(tpl) = e["template"].as_str() {
                    flags.push(tpl.to_string());
                }
                if e["rotation_pending"] == true {
                    flags.push("ROTATE".into());
                }
                if e["expiring_soon"] == true {
                    flags.push(format!("EXPIRES {}", e["expires"].as_str().unwrap_or("")));
                }
                let path = e["path"].as_str().unwrap_or("");
                let shown = if t == "folder" {
                    format!("{path}/")
                } else {
                    path.to_string()
                };
                h.push_str(&format!(
                    "{:<7} {shown}{}\n",
                    t,
                    if flags.is_empty() {
                        String::new()
                    } else {
                        format!("  [{}]", flags.join(", "))
                    }
                ));
            }
            Ok(Out::human(d, h))
        }
        Cmd::Mkdir { path, parents } => intent(
            ctx,
            Intent::Mkdir {
                path: ctx.path(&path),
                parents,
            },
        ),
        Cmd::Put(a) => put(ctx, a),
        Cmd::Get { path, out } => get(ctx, &path, out),
        Cmd::Mv { src, dst } => intent(
            ctx,
            Intent::Mv {
                src: ctx.path(&src),
                dst: ctx.path(&dst),
            },
        ),
        Cmd::Rm { path } => intent(
            ctx,
            Intent::Rm {
                path: ctx.path(&path),
            },
        ),
        Cmd::Rekey { path } => intent(
            ctx,
            Intent::Rekey {
                path: ctx.path(&path),
            },
        ),
        Cmd::Rotation(RotationCmd::List) => {
            let o = app::open_vault(ctx, true)?;
            Ok(Out::data(queries::rotation_list(ctx, &o)?))
        }
        Cmd::Rotation(RotationCmd::Done { path }) => intent(
            ctx,
            Intent::RotationDone {
                path: ctx.path(&path),
            },
        ),
        Cmd::Grant { who, right, path } => {
            let right = parse_right(&right)?;
            intent(
                ctx,
                Intent::Grant {
                    who,
                    right,
                    path: ctx.path(&path),
                },
            )
        }
        Cmd::Revoke {
            who,
            path,
            no_rekey,
        } => intent(
            ctx,
            Intent::Revoke {
                who,
                path: ctx.path(&path),
                no_rekey,
            },
        ),
        Cmd::Access { path } => {
            let o = app::open_vault(ctx, true)?;
            Ok(Out::data(queries::access(ctx, &o, &path)?))
        }
        Cmd::Whoami => {
            let o = app::open_vault(ctx, true)?;
            Ok(Out::data(queries::whoami(ctx, &o)?))
        }
        Cmd::Sysgrant {
            user,
            right,
            delegate,
        } => intent(
            ctx,
            Intent::SysGrant {
                user: strip_user(&user),
                right,
                delegate,
            },
        ),
        Cmd::Sysrevoke { user, right } => intent(
            ctx,
            Intent::SysRevoke {
                user: strip_user(&user),
                right,
            },
        ),
        Cmd::Exec {
            profile,
            mask,
            no_mask,
            command,
        } => exec(ctx, &profile, mask, no_mask, &command),
        Cmd::Serve { .. } => unreachable!(),
        Cmd::Version => {
            let v = version_json();
            let h = format!(
                "nepomuk {} (api {}, format {}, suite {})\n",
                v["cli"].as_str().unwrap(),
                API_VERSION,
                crate::format::FORMAT_VERSION,
                crate::crypto::SUITE
            );
            Ok(Out::human(v, h))
        }
        Cmd::Master(MasterCmd::Transfer { user }) => {
            let d = app::execute(
                ctx,
                &Intent::MasterTransfer {
                    user: strip_user(&user),
                },
                None,
                Resolve::Ask,
            )?;
            if let Some(fp) = d["new_fingerprint"].as_str() {
                ctx.warn(format!("every client and CI must now pin the new master: `nepomuk trust {fp}` / NEPOMUK_ROOT_FP"));
            }
            Ok(Out::data(d))
        }
        Cmd::Doctor => {
            let checks = crate::doctor::run(ctx);
            let problems = checks
                .iter()
                .filter(|c| c.level == crate::doctor::Level::Fail)
                .count();
            Ok(Out {
                data: crate::doctor::to_json(&checks),
                human: Some(crate::doctor::to_text(&checks)),
                exit: if problems > 0 { 1 } else { 0 },
            })
        }
        Cmd::Upgrade {
            check,
            tag,
            gui,
            no_gui,
            refresh,
        } => {
            if refresh {
                let _ = crate::upgrade::refresh();
                return Ok(Out {
                    data: Value::Null,
                    human: None,
                    exit: 0,
                });
            }
            let plan = crate::upgrade::plan(tag.as_deref())?;
            let current = crate::upgrade::current();
            if check {
                let h = if plan.newer {
                    format!(
                        "nepomuk {} is available (you have {current}); run `nepomuk upgrade`\n",
                        plan.tag
                    )
                } else {
                    format!("nepomuk {current} is up to date\n")
                };
                return Ok(Out::human(
                    json!({ "current": current, "latest": plan.tag, "newer": plan.newer }),
                    h,
                ));
            }
            if !plan.newer && tag.is_none() {
                return Ok(Out::human(
                    json!({ "current": current, "latest": plan.tag, "upgraded": false }),
                    format!("nepomuk {current} is up to date\n"),
                ));
            }
            let gui = if gui {
                Some(true)
            } else if no_gui {
                Some(false)
            } else {
                None
            };
            let code = crate::upgrade::run(&plan.tag, gui)?;
            if code != 0 {
                return Err(Error::general(format!(
                    "the installer of {} failed",
                    plan.tag
                )));
            }
            Ok(Out::human(
                json!({ "previous": current, "installed": plan.tag, "upgraded": true }),
                String::new(),
            ))
        }
        Cmd::Lock => Ok(Out::data(
            json!({ "locked": crate::agent::forget(None) || crate::agent::status().is_none() }),
        )),
        Cmd::Agent { daemon } => {
            if daemon {
                return Ok(Out {
                    data: Value::Null,
                    human: None,
                    exit: crate::agent::run_daemon(),
                });
            }
            Ok(Out::data(
                crate::agent::status().unwrap_or_else(|| json!({ "running": false })),
            ))
        }
        Cmd::GitTextconv { file } => {
            print!("{}", textconv(&std::fs::read(&file)?));
            Ok(Out {
                data: Value::Null,
                human: None,
                exit: 0,
            })
        }
        Cmd::GitMerge { .. } => {
            eprintln!("nepomuk: vault files cannot be merged by git; use `nepomuk sync`");
            Ok(Out {
                data: Value::Null,
                human: None,
                exit: 1,
            })
        }
        Cmd::Master(_) => Err(Error::general(
            "master backup/restore (Shamir shares, hardware token) is not implemented in this version",
        )),
    }
}

/// Public metadata only: seq, author, operation types, signature validity (§9.4).
fn textconv(bytes: &[u8]) -> String {
    use crate::format::{CheckpointBody, CommitBody, VaultFile, from_cbor};
    let file = match VaultFile::parse(bytes) {
        Ok(f) => f,
        Err(e) => return format!("(not a valid nepomuk vault: {})\n", e.message),
    };
    let mut out = format!("nepomuk vault {}\n", file.vault_id.hex());
    let Ok(cp) = from_cbor::<CheckpointBody>(&file.entries[0].envelope.body) else {
        return out + "(malformed checkpoint)\n";
    };
    let mut users: BTreeMap<crate::model::Id, String> = cp
        .state
        .users
        .values()
        .map(|u| (u.id, u.name.clone()))
        .collect();
    let claimed = app::claimed_master_fp(&file).unwrap_or_default();
    out.push_str(&format!(
        "checkpoint #{} master {} ({} users, {} nodes, {} grants)\n",
        cp.seq,
        claimed,
        cp.state.users.len(),
        cp.state.nodes.len(),
        cp.state.grants.len()
    ));
    for e in &file.entries[1..] {
        let Ok(c) = from_cbor::<CommitBody>(&e.envelope.body) else {
            out.push_str("(malformed commit)\n");
            continue;
        };
        for op in &c.ops {
            if let crate::model::Op::AddUser { user } = op {
                users.insert(user.id, user.name.clone());
            }
        }
        let time = chrono::DateTime::from_timestamp(c.time, 0)
            .map(|d| d.to_rfc3339())
            .unwrap_or_default();
        let ops: Vec<&str> = c.ops.iter().map(|o| o.name()).collect();
        out.push_str(&format!(
            "#{} {} {} {}\n",
            c.seq,
            time,
            users.get(&c.author).map(String::as_str).unwrap_or("?"),
            ops.join(", ")
        ));
    }
    // Signatures and permissions against the master the file claims (not a trust decision).
    match crate::verify::verify_file(file, &claimed) {
        Ok(v) => out.push_str(&format!(
            "signatures and permissions: valid up to #{}\n",
            v.seq
        )),
        Err(e) => out.push_str(&format!(
            "signatures and permissions: INVALID – {}\n",
            e.message
        )),
    }
    out
}

fn strip_user(u: &str) -> String {
    u.strip_prefix("user:").unwrap_or(u).to_string()
}

// ---------------------------------------------------------------- identity

fn identity_cmd(ctx: &Ctx, c: IdentityCmd) -> Result<Out> {
    match c {
        IdentityCmd::Touchid(t) => {
            let o = app::open_vault(ctx, true)?;
            let vault = o.v.file.vault_id;
            match t {
                TouchidCmd::Enable => {
                    if !crate::touchid::available() {
                        return Err(Error::usage("Touch ID is not available on this computer"));
                    }
                    let ctx2 = Ctx::new(Options {
                        remember_touchid: true,
                        touchid: false,
                        ..ctx.opts.clone()
                    })?;
                    let id = ctx2.unlock(&o.v.state)?;
                    Ok(Out::data(json!({ "enabled": true, "identity": id.name })))
                }
                TouchidCmd::Disable => {
                    crate::agent::forget(Some(vault));
                    Ok(Out::data(
                        json!({ "disabled": crate::touchid::disable(vault) }),
                    ))
                }
                TouchidCmd::Status => Ok(Out::data(json!({
                    "available": crate::touchid::available(),
                    "enabled": crate::touchid::enabled_for(vault).is_some(),
                    "identity": crate::touchid::enabled_for(vault),
                }))),
            }
        }
        IdentityCmd::New { name, out } => {
            identity::validate_name(&name)?;
            let out = out
                .or_else(|| ctx.opts.identity.clone())
                .unwrap_or_else(config::default_identity_path);
            if out.exists() {
                return Err(Error::new(
                    Code::AlreadyExists,
                    format!("{} already exists", out.display()),
                ));
            }
            let pass = ctx.new_secret(
                &format!("New passphrase for {name}"),
                &["NEPOMUK_PASSPHRASE"],
            )?;
            crate::password::check(&pass, &[&name])?;
            if let Some(w) = crate::password::warning(&pass) {
                ctx.warn(w);
            }
            let id = Unlocked::generate(&name, IdentityKind::Local);
            let f = IdentityFile::create(&id, &pass)?;
            config::write_private(&out, f.to_text().as_bytes())?;
            Ok(Out::data(
                json!({ "name": name, "identity": out.display().to_string(), "fingerprint": id.fingerprint() }),
            ))
        }
        IdentityCmd::Request {
            email,
            ssh_key,
            local,
            out,
        } => {
            if out.exists() {
                return Err(Error::new(
                    Code::AlreadyExists,
                    format!("{} already exists", out.display()),
                ));
            }
            let req = if let Some(k) = ssh_key {
                return Err(ssh_key_error(&k));
            } else if let Some(email) = email {
                identity::validate_name(&email)?;
                let pass =
                    ctx.new_secret(&format!("New password for {email}"), &["NEPOMUK_PASSWORD"])?;
                crate::password::check(&pass, &[&email])?;
                if let Some(w) = crate::password::warning(&pass) {
                    ctx.warn(w);
                }
                let id = Unlocked::generate(&email, IdentityKind::Password);
                let cred = identity::password_credential(&id, &pass)?;
                Request::new(&id, Some(cred))
            } else if local
                || ctx.opts.identity.is_some()
                || std::env::var("NEPOMUK_IDENTITY").is_ok()
                || config::default_identity_path().is_file()
            {
                let id = ctx.unlock_file()?;
                Request::new(&id, None)
            } else {
                return Err(Error::usage(
                    "use --email <email>, --local (identity file) or --ssh-key <key>",
                ));
            };
            std::fs::write(&out, req.to_text())?;
            let h = format!(
                "Request written to {}\nFingerprint: {}\nSend the file to an administrator and confirm the fingerprint with them.\n",
                out.display(),
                req.fingerprint()
            );
            Ok(Out::human(
                json!({ "name": req.name, "request": out.display().to_string(), "fingerprint": req.fingerprint() }),
                h,
            ))
        }
        IdentityCmd::Passwd => {
            let file_mode = ctx.opts.email.is_none()
                && (ctx.opts.identity.is_some()
                    || ctx.user.identity.is_some()
                    || config::default_identity_path().is_file())
                && ctx.user.email.is_none();
            if file_mode {
                let path = ctx
                    .opts
                    .identity
                    .clone()
                    .or_else(|| ctx.user.identity.clone())
                    .unwrap_or_else(config::default_identity_path);
                let id = ctx.unlock_file()?;
                let pass = ctx.new_secret("New passphrase", &[])?;
                crate::password::check(&pass, &[&id.name])?;
                let f = IdentityFile::create(&id, &pass)?;
                config::write_private(&path, f.to_text().as_bytes())?;
                return Ok(Out::data(
                    json!({ "identity": path.display().to_string(), "updated": true }),
                ));
            }
            let o = app::open_vault(ctx, true)?;
            let id = ctx.unlock(&o.v.state)?;
            if id.kind != IdentityKind::Password {
                return Err(Error::usage("not a password identity"));
            }
            let pass = ctx.new_secret("New password", &[])?;
            crate::password::check(&pass, &[&id.name])?;
            let cred = identity::password_credential(&id, &pass)?;
            intent(ctx, Intent::Passwd { credential: cred })
        }
        IdentityCmd::Show => {
            let path = ctx
                .opts
                .identity
                .clone()
                .or_else(|| ctx.user.identity.clone())
                .unwrap_or_else(config::default_identity_path);
            let f = match std::env::var("NEPOMUK_IDENTITY") {
                Ok(v) if ctx.opts.identity.is_none() => IdentityFile::parse(&v)?,
                _ => IdentityFile::parse(&read_text_file(&path)?)?,
            };
            Ok(Out::data(
                json!({ "name": f.name, "fingerprint": f.fingerprint() }),
            ))
        }
    }
}

fn ssh_key_error(path: &PathBuf) -> Error {
    let pubpath = if path.extension().is_some_and(|e| e == "pub") {
        path.clone()
    } else {
        path.with_extension("pub")
    };
    let text = std::fs::read_to_string(&pubpath)
        .or_else(|_| std::fs::read_to_string(path))
        .unwrap_or_default();
    let kind = text.split_whitespace().next().unwrap_or("unknown");
    if kind.contains("mldsa44") && kind.contains("ed25519") {
        Error::new(Code::UnsupportedSshKey, "PQ SSH identities are not supported in this version yet; use --email or a local identity")
            .with("key_type", kind)
    } else {
        Error::new(
            Code::UnsupportedSshKey,
            format!("only mldsa44-ed25519 SSH keys are accepted, not {kind}"),
        )
        .with("key_type", kind)
    }
}

// ---------------------------------------------------------------- put / get

fn guess_mime(path: &str) -> String {
    let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "jks" | "keystore" => "application/x-java-keystore",
        "p12" | "pfx" => "application/x-pkcs12",
        "pem" | "crt" | "key" => "application/x-pem-file",
        "json" => "application/json",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }
    .to_string()
}

fn read_stdin() -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(Vec::new());
    std::io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

fn put(ctx: &Ctx, a: PutArgs) -> Result<Out> {
    let path = ctx.path(&a.path);
    let is_record = a.template.is_some() || !a.fields.is_empty() || !a.field_prompts.is_empty();
    let (content, not_after) = if is_record {
        if a.source.is_some() {
            return Err(Error::usage("a record takes --field values, not a source"));
        }
        let template = a.template.clone().unwrap_or_else(|| "generic".into());
        crate::templates::get(&template)?;
        let mut fields: BTreeMap<String, Field> = BTreeMap::new();
        for f in &a.fields {
            let (k, v) = f
                .split_once('=')
                .ok_or_else(|| Error::usage(format!("--field expects name=value, got {f:?}")))?;
            crate::tx::validate_name(k)?;
            let field = match v.strip_prefix('@') {
                Some(file) => Field::Binary {
                    mime: guess_mime(file),
                    data: app::read_file_arg(file)?,
                },
                None => Field::Text {
                    value: v.to_string(),
                },
            };
            fields.insert(k.to_string(), field);
        }
        if !a.field_prompts.is_empty() && ctx.opts.password_stdin && !std::io::stdin().is_terminal()
        {
            return Err(Error::usage(
                "stdin carries the field values; pass the password with --password-fd or the environment",
            ));
        }
        for k in &a.field_prompts {
            crate::tx::validate_name(k)?;
            let v = ctx.field_value(k)?;
            fields.insert(
                k.clone(),
                Field::Text {
                    value: v.to_string(),
                },
            );
        }
        let val = crate::templates::validate(&template, &fields)?;
        for w in val.warnings {
            ctx.warn(w);
        }
        (Content::Record { template, fields }, val.not_after)
    } else {
        match a.source.as_deref() {
            Some(s) if s.starts_with('@') => {
                let file = &s[1..];
                (
                    Content::Binary {
                        mime: a.mime.clone().unwrap_or_else(|| guess_mime(file)),
                        data: app::read_file_arg(file)?,
                    },
                    None,
                )
            }
            Some("-") => stdin_content(ctx, &a)?,
            Some(other) => {
                return Err(Error::usage(format!(
                    "secret values are never passed as arguments; use a prompt, `-` for stdin or @file (got {other:?})"
                )));
            }
            None if std::io::stdin().is_terminal() && !ctx.opts.json => {
                let v = ctx.field_value("Value")?;
                (
                    Content::Text {
                        value: v.to_string(),
                    },
                    None,
                )
            }
            None => stdin_content(ctx, &a)?,
        }
    };
    intent(
        ctx,
        Intent::Put {
            path,
            content,
            not_after,
        },
    )
}

fn stdin_content(ctx: &Ctx, a: &PutArgs) -> Result<(Content, Option<i64>)> {
    if ctx.opts.password_stdin {
        return Err(Error::usage(
            "stdin carries the secret; pass the password with --password-fd or the environment",
        ));
    }
    let data = read_stdin()?;
    Ok(match (std::str::from_utf8(&data), &a.mime) {
        (Ok(s), None) => {
            let s = s
                .strip_suffix('\n')
                .map(|x| x.strip_suffix('\r').unwrap_or(x))
                .unwrap_or(s);
            (
                Content::Text {
                    value: s.to_string(),
                },
                None,
            )
        }
        (_, mime) => (
            Content::Binary {
                mime: mime
                    .clone()
                    .unwrap_or_else(|| "application/octet-stream".into()),
                data: data.to_vec(),
            },
            None,
        ),
    })
}

fn get(ctx: &Ctx, spec: &str, out: Option<PathBuf>) -> Result<Out> {
    let o = app::open_vault(ctx, true)?;
    for w in queries::expiring(ctx, &o).unwrap_or_default() {
        if w.starts_with(&ctx.path(queries::split_field(spec).0)) {
            ctx.warn(w);
        }
    }
    if let Some(out) = out {
        let (path, bytes, _) = queries::get_bytes(ctx, &o, spec)?;
        let bytes = Zeroizing::new(bytes);
        config::write_private(&out, &bytes)?;
        return Ok(Out::human(
            json!({ "path": path, "out": out.display().to_string(), "size": bytes.len() }),
            String::new(),
        ));
    }
    if ctx.opts.json {
        return Ok(Out::data(queries::get_json(ctx, &o, &ctx.path(spec))?));
    }
    let (_, bytes, binary) = queries::get_bytes(ctx, &o, spec)?;
    let bytes = Zeroizing::new(bytes);
    let mut stdout = std::io::stdout().lock();
    if binary && stdout.is_terminal() {
        return Err(Error::usage(
            "binary content; use --out <file> or redirect stdout",
        ));
    }
    stdout.write_all(&bytes)?;
    if !binary && stdout.is_terminal() {
        stdout.write_all(b"\n")?;
    }
    stdout.flush()?;
    for w in ctx.warnings.borrow().iter() {
        eprintln!("warning: {w}");
    }
    Ok(Out {
        data: Value::Null,
        human: None,
        exit: 0,
    })
}

// ---------------------------------------------------------------- exec

fn exec(ctx: &Ctx, name: &str, mask: bool, no_mask: bool, command: &[String]) -> Result<Out> {
    let project = ctx
        .project
        .as_ref()
        .ok_or_else(|| Error::usage("no .nepomuk.toml found"))?;
    let profile = project
        .exec
        .get(name)
        .ok_or_else(|| Error::not_found(&format!("exec profile {name}")))?
        .clone();
    let o = app::open_vault(ctx, true)?;
    let resolve = |m: &BTreeMap<String, String>| -> BTreeMap<String, String> {
        m.iter().map(|(k, v)| (k.clone(), ctx.path(v))).collect()
    };
    let profile = config::Profile {
        env: resolve(&profile.env),
        file: resolve(&profile.file),
    };
    let (env, files) = queries::profile_values(ctx, &o, &profile)?;
    drop(o);
    for w in ctx.warnings.borrow().iter() {
        eprintln!("warning: {w}");
    }
    let mask = !no_mask && (mask || ctx.ci());
    let code = crate::exec::run(crate::exec::ExecSpec { env, files, mask }, command)?;
    Ok(Out {
        data: Value::Null,
        human: None,
        exit: code,
    })
}
