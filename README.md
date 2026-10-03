# nepomuk

**A post-quantum secrets vault that lives in a single file in git – with permissions enforced by cryptography, not by code.**

> [!WARNING]
> **Use at your own risk.** nepomuk is an early, unaudited implementation. It may contain bugs that expose or destroy your secrets, and the file format may still change. It comes without any warranty (see the [license](LICENSE)). Keep an independent copy of everything you store in it, and do not use it for production secrets before the independent security audit required by the MVP.

> **Status: early implementation, not audited.** The CLI and the GUI implement the [specification](docs/SPECIFICATION.md); see [Implementation status](#implementation-status).

nepomuk stores passwords, certificates and binary files (keystores, `.p12`, `.pem`, …) in a folder tree inside one encrypted file that you commit to a git repository. Every user can read only what they hold a key for, and every change must be signed by someone who is allowed to make it. The design and source code are public by intent – knowing how nepomuk works does not help an attacker.

## Why nepomuk

A company's secrets – database passwords, API tokens, TLS certificates, the keystore that signs the Android app – tend to end up in `.env` files, chat messages, personal password managers and CI settings, with nobody sure who can see what. The usual fixes each give something up:

- **A secrets server** (HashiCorp Vault, cloud secret managers) enforces permissions well, but it is one more service to run, secure, back up and keep available – and its operators can, in the end, get at every secret in it.
- **Encrypted files in git** (SOPS, git-crypt, pass/gopass) need no server, but encryption only controls *reading*. Anyone who can push to the repository can replace a secret or add a recipient, and nothing tells the readers.

nepomuk keeps the "no server, just git" approach and closes that gap:

- **Writes are enforced too.** Every change is signed, and every client replays the whole history and rejects any change its author was not allowed to make. A colleague with push access but no rights on `signing/` cannot swap the release keystore – the vault would refuse to open.
- **Permissions like a file system.** Folders, inheritance, groups and delegated administration (`read`, `write`, `share`, `admin`), so a team lead can manage their project's secrets without anyone handing out keys by hand.
- **Built for CI.** `nepomuk exec` hands a build exactly the secrets its narrow identity may read, only for the duration of one command, so a pipeline can sign a release without any developer ever seeing the keys.
- **Made for a public history.** Git keeps every old version forever, so nepomuk uses hybrid post-quantum cryptography: a file copied today must stay unreadable when quantum computers arrive.
- **Leaving people behind.** Offboarding removes a person everywhere, rotates the keys and lists the secrets that must be changed at the source.

nepomuk is not the right tool if you want to know who *read* a secret (reads happen offline and cannot be audited), if you keep secrets only for yourself (a personal password manager is simpler), or if you already run a secrets server that does the job.

## Features

- **One file, one company vault** – kept in its own git repository and shared into projects as a submodule.
- **Folder-based permissions** – `read`, `write`, `share` and `admin` on folders or individual secrets, inherited down the tree, granted to users or groups.
- **Cryptographic enforcement** – reading requires holding a wrapped key; writing requires a valid signature. A custom client cannot bypass either.
- **Hybrid post-quantum crypto** – ML-KEM-1024 + X25519 for encryption, ML-DSA-65 + Ed25519 for signatures, XChaCha20-Poly1305 for data, Argon2id for passwords. Safe against "harvest now, decrypt later" on git history.
- **Two ways to log in** – email + password (following NIST SP 800-63B-4), or an identity file protected by a passphrase (for CI and the master). On macOS, Touch ID can unlock either.
- **Master + delegation** – one master identity, kept offline, that can do anything; everyone else only what they were granted, never more than the granter holds.
- **Tamper-evident history** – a signed, hash-chained log of changes with rollback and fork detection.
- **Git-native workflow** – automatic push after every change, conflict-aware `sync`, readable `git diff` of public metadata.
- **CI-first** – `nepomuk exec` injects secrets into a single build command and cleans up afterwards.
- **Offboarding** – one command removes a person everywhere, rotates keys and lists the secrets that must be changed at the source.
- **CLI + GUI** – a Rust CLI for Linux, Windows and macOS; a desktop app that simply drives the CLI.

## Examples

### Create a vault

```bash
# in a new, dedicated repository
nepomuk init --vault vault.nepomuk
# creates the master identity (~/.config/nepomuk/master.npk) and prints its
# fingerprint (npk1…) – pin it in CI and on every client
```

### Add a user

```bash
# the new user, on their own machine – keys and password never leave it
nepomuk identity request --email jane@example.com --out jane.request
# or, e.g. for CI, an identity file protected by a passphrase
nepomuk identity new --name ci-eshop-android --out ci.npk
nepomuk --identity ci.npk identity request --local --out ci.request

# an administrator with the `users` right
nepomuk user add jane.request
nepomuk group create android-release
nepomuk group add android-release jane@example.com
```

### Store and read secrets

```bash
nepomuk mkdir /infra/db --description "Production PostgreSQL"
nepomuk put /infra/db/prod-password            # value read from a hidden prompt
nepomuk put /infra/tls/wildcard.p12 --template pkcs12-cert \
  --field bundle=@wildcard.p12 --field-prompt password

nepomuk describe /infra/db/prod-password "Password of the app user, rotated yearly"

nepomuk ls -r /infra
nepomuk get /infra/db/prod-password
```

A description says what a folder or secret is for. It is not secret, but only those who can read the item see it; `ls` shows its first line, `describe <path> --clear` removes it.

### Grant and revoke access

```bash
nepomuk grant group:backend read /infra/db
nepomuk grant user:jane@example.com admin /projects/eshop-android

nepomuk access /infra/db                       # who can read this?
nepomuk revoke user:bob@example.com /infra/db  # also rekeys the subtree
nepomuk user offboard bob@example.com          # removes Bob everywhere, lists secrets to rotate
```

### Sign an Android release in CI

Store the keystore together with its alias and passwords as one record:

```bash
nepomuk put /projects/eshop-android/signing/release \
  --template android-signing \
  --field keystore=@release.jks \
  --field key_alias=eshop-upload \
  --field-prompt store_password --field-prompt key_password

nepomuk grant user:ci-eshop-android read /projects/eshop-android/signing
```

Map the fields to the build in the application's `.nepomuk.toml`:

```toml
name   = "eshop-android"                  # shown in the Touch ID prompt
vault  = "secrets/vault.nepomuk"          # submodule with the company vault
prefix = "/projects/eshop-android"

[exec.android-release]
file.ANDROID_KEYSTORE      = "signing/release#keystore"
env.ANDROID_STORE_PASSWORD = "signing/release#store_password"
env.ANDROID_KEY_ALIAS      = "signing/release#key_alias"
env.ANDROID_KEY_PASSWORD   = "signing/release#key_password"
```

Run the build – secrets exist only for the lifetime of the Gradle process and are masked in its output:

```bash
nepomuk exec android-release -- ./gradlew bundleRelease
```

In GitHub Actions:

```yaml
- name: Build and sign
  env:
    NEPOMUK_IDENTITY:   ${{ secrets.NEPOMUK_IDENTITY }}
    NEPOMUK_PASSPHRASE: ${{ secrets.NEPOMUK_PASSPHRASE }}
    NEPOMUK_ROOT_FP:    ${{ vars.NEPOMUK_ROOT_FP }}
  run: nepomuk exec android-release -- ./gradlew bundleRelease
```

### Stay in sync

```bash
nepomuk status        # up to date / changes not pushed / offline
nepomuk sync          # replays your pending changes on top of the latest vault
nepomuk verify --full # re-verify every signature and permission in the log
```

## How it works (in short)

Every folder and secret has its own random key. A parent's key unlocks its children's keys, so a grant on a folder covers the whole subtree. A grant is simply that key encrypted (hybrid ML-KEM + X25519) for a user or a group. Every change is a signed entry in an append-only log inside the file; each client replays the log and rejects any change whose author was not allowed to make it. The master's fingerprint is pinned outside the file, and clients remember the latest version they have seen to detect rollbacks.

See [docs/SPECIFICATION.md](docs/SPECIFICATION.md) for the full design: threat model, cryptography, file format, permission model, git integration, CLI and JSON API, and GUI.

## Installing

```bash
curl -fsSL https://github.com/aleslanik2/nepomuk/releases/latest/download/install.sh | sh -s -- --gui --system
```

This installs the latest release: the CLI into `/usr/local/bin` (using sudo) and the desktop app into Applications on macOS, as an AppImage with a menu entry on Linux, or through its installer on Windows. Without `--system` everything goes to your user account (the CLI into `~/.local/bin`); without `--gui` only the CLI is installed. Nothing is installed unless `SHA256SUMS` carries a valid release signature and every download matches it.

The script runs on Linux, macOS and Windows in Git Bash; for PowerShell use `install.ps1` from the same release (`-Gui`, `-System`). Other options: `--version <tag>` for a specific release, `--dir <path>` for another CLI location, `--sha256 <hash>` to pin the exact archive in CI, and `--from-source` to build with cargo (the app also needs Node.js). `nepomuk doctor` checks the installation: whether it is up to date, whether `nepomuk` in `PATH` is this installation, how the identity and the vault are configured, and whether you are a user of the vault. Later, `nepomuk upgrade` installs a newer release the same way (it updates the desktop app too, when installed); the CLI looks for new releases once a day and mentions them (`update_check = false` in `~/.config/nepomuk/config.toml` turns this off). While the repository is private, the download above does not work: set `GH_TOKEN`, get `install.sh` with `gh release download -R aleslanik2/nepomuk -p install.sh` and run `sh install.sh --gui --system`.

## Moving a vault from 0.2.x (obsolete)

`nepomuk migrate` is obsolete: it is kept only for moving vaults from 0.2.x and will be removed in a future release.

File format 2 (this version) fixes security flaws found in review and cannot read vaults created by 0.2.x. Keep the old binary (e.g. as `nepomuk-0.2.7`), create a new vault and copy the folders and secrets over; the old binary reads them and they travel through a pipe, never through a file:

```bash
nepomuk init --vault vault.nepomuk --out ~/.config/nepomuk/master-v2.npk
nepomuk --vault vault.nepomuk --identity ~/.config/nepomuk/master-v2.npk \
  migrate --from-cli ./nepomuk-0.2.7 --from-vault old/vault.nepomuk \
          --from-identity ~/.config/nepomuk/master.npk
```

Users, groups and grants are bound to the old vault's keys and are not copied; the output lists the old grants so they can be set up again. `--dry-run` shows what would be copied. Identity files (`*.npk`) stay valid, but fingerprints are computed differently, so pin the new master with `nepomuk trust` on every client.

## Building

```bash
cargo build --release          # target/release/nepomuk
cargo test                     # unit, CLI, security and git workflow tests
```

Git drivers for readable `git diff` and a refusing merge (`init` commits the matching `.gitattributes`):

```bash
git config diff.nepomuk.textconv "nepomuk git-textconv"
git config merge.nepomuk.driver "nepomuk git-merge %O %A %B"
```

## Releasing

1. Once: create the release signing key (`ssh-keygen -t ed25519 -C release@nepomuk -f nepomuk-release`) and put `release@nepomuk <public key>` into `RELEASE_SIGNERS` in `install.sh` and `$ReleaseSigners` in `install.ps1` (`scripts/release-signers.sh check` compares them).
2. Bump `version` in `Cargo.toml`, `gui/src-tauri/Cargo.toml` and `gui/src-tauri/tauri.conf.json`, then push a tag `v<version>`. [`.github/workflows/release.yml`](.github/workflows/release.yml) runs the tests and the UI harness, builds the CLI for six targets (static musl on Linux) and the desktop app for macOS, Windows and Linux, smoke-tests both installers, and creates the release with `SHA256SUMS` over every file.
3. Signing: with the secret `NEPOMUK_RELEASE_SIGNING_KEY` the workflow signs and publishes; without it the release stays a draft and `scripts/sign-release.sh v<version> <key>` signs it offline and publishes it.

## GUI

```bash
gui/scripts/prepare-sidecars.sh                 # builds the CLI (and the Touch ID helper) for bundling
cd gui/src-tauri && npx @tauri-apps/cli build     # or: cargo run for development
node gui/tests/harness.mjs target/debug/nepomuk  # drives the UI in headless Chrome against the real CLI
```

The web UI has no file system or network access; the Rust backend only forwards JSON-RPC to `nepomuk serve --stdio`, which holds the unlocked identity.

## Implementation status

Implemented:

- crypto suite `NPQ-1` (ML-KEM-1024 + X25519, ML-DSA-65 + Ed25519, XChaCha20-Poly1305, Argon2id, SHA3-256/HKDF), size padding, zeroized and `mlock`ed seeds, core dumps disabled
- file format: signed checkpoint + hash-chained signed commits, full replay with per-operation authorization, root-of-trust pinning, rollback/fork detection, submodule pin check in CI, `compact`
- identities: email + password (NIST SP 800-63B-4 rules, blocklist, passphrase generator) and local identity files (CI, master); enrollment requests with proof of possession; `identity passwd`, `user replace`
- tree rights `read`/`write`/`share`/`admin`, system rights `users`/`groups`/`audit`/`group-admin` with `+delegate`, groups with their own KEM keys, revoke with automatic rekey, offboarding with rotation list and tasks for other admins, `master transfer`
- secrets `text`, `binary`, `record` with templates `android-signing`, `pkcs12-cert` (validated with `keytool`), `generic`; expiry warnings
- git: reads `origin/main`, plumbing commit + push on every write, retry on a rejected push, `--offline` queue (encrypted to the own identity) and `sync` with conflict resolution
- `exec` profiles (memfd on Linux, private `0700`/`0600` files elsewhere, output masking, `::add-mask::`, signal forwarding, cleanup)
- `--json` for every command, `serve --stdio` (JSON-RPC 2.0 with session lock and inactivity timeout)
- GUI (Tauri, [`gui/`](gui)) driving the bundled CLI: pinning the master with a visual fingerprint, login and enrollment, secrets tree with sealed values and collapsible folders, template forms, access management, users, groups, offboarding checklist, rotation, audit log, sync and conflicts, `exec` profiles; clipboard excluded from history and cleared after 30 s, lock on inactivity and screen lock
- Touch ID on macOS (optional, per Mac): `nepomuk identity touchid enable` or the checkbox at login seals the password with a Secure Enclave key usable only after Touch ID with the currently enrolled fingers ([`macos/touchid`](macos/touchid)); `--touchid` or the button at login unlocks with it; in a terminal the CLI asks for the fingerprint at most once per 10 minutes for reading, and again for every change (an agent keeps the identity for that terminal session only – programs started from it, background jobs included, can use it; other windows and programs without a terminal cannot – until `agent_timeout` in `config.toml` expires, the screen locks or `nepomuk lock`; it never hands out the private keys, it only unwraps keys for the caller)

Not implemented yet: notarized / Authenticode-signed GUI installers, PQ SSH identities (`mldsa44-ed25519` keys are recognized and refused), master on a hardware token and Shamir backup (`master backup`/`restore`), Have I Been Pwned check, zxcvbn estimation (a simple heuristic warns instead), the verification cache, nested groups, Windows ACLs for `exec` files, and automatic strengthening of Argon2id parameters (a warning is shown instead).

## What nepomuk cannot do

- It cannot audit **reads** – decryption happens offline on the user's machine.
- It cannot take back what someone has already seen – after revoking access, rotate the secret at its source.
- It cannot protect the vault if the **master key** is compromised – keep it offline and backed up (a hardware token and Shamir backup are planned).

## Roadmap

1. Finish the MVP: master on a hardware token with Shamir backup, post-quantum SSH identities (`mldsa44-ed25519`), notarized and signed installers, an independent security audit.
2. Google Workspace directory check (alerts on departed employees, group mapping).
3. More templates (iOS signing, TLS), pull-request workflow for selected folders.

## License

[Apache License 2.0](LICENSE)
