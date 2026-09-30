# nepomuk

**A post-quantum secrets vault that lives in a single file in git – with permissions enforced by cryptography, not by code.**

> [!WARNING]
> **Use at your own risk.** nepomuk is an early, unaudited implementation. It may contain bugs that expose or destroy your secrets, and the file format may still change. It comes without any warranty (see the [license](LICENSE)). Keep an independent copy of everything you store in it, and do not use it for production secrets before the independent security audit required by the MVP.

> **Status: early implementation, not audited.** The CLI and the GUI implement the [specification](docs/SPECIFICATION.md); see [Implementation status](#implementation-status).

nepomuk stores passwords, certificates and binary files (keystores, `.p12`, `.pem`, …) in a folder tree inside one encrypted file that you commit to a git repository. Every user can read only what they hold a key for, and every change must be signed by someone who is allowed to make it. The design and source code are public by intent – knowing how nepomuk works does not help an attacker.

## Features

- **One file, one company vault** – kept in its own git repository and shared into projects as a submodule.
- **Folder-based permissions** – `read`, `write`, `share` and `admin` on folders or individual secrets, inherited down the tree, granted to users or groups.
- **Cryptographic enforcement** – reading requires holding a wrapped key; writing requires a valid signature. A custom client cannot bypass either.
- **Hybrid post-quantum crypto** – ML-KEM-1024 + X25519 for encryption, ML-DSA-65 + Ed25519 for signatures, XChaCha20-Poly1305 for data, Argon2id for passwords. Safe against "harvest now, decrypt later" on git history.
- **Two ways to log in** – email + password (following NIST SP 800-63B-4), or a post-quantum SSH key (`mldsa44-ed25519`, OpenSSH 10.4+). Classical SSH keys are rejected.
- **Master + delegation** – one master identity (offline, on a hardware token, Shamir-backed) that can do anything; everyone else only what they were granted, never more than the granter holds.
- **Tamper-evident history** – a signed, hash-chained log of changes with rollback and fork detection.
- **Git-native workflow** – automatic push after every change, conflict-aware `sync`, readable `git diff` of public metadata.
- **CI-first** – `nepomuk exec` injects secrets into a single build command and cleans up afterwards.
- **Offboarding** – one command removes a person everywhere, rotates keys and lists the secrets that must be changed at the source.
- **CLI + GUI** – a Rust CLI for Linux, Windows and macOS; a Tauri GUI that simply drives the CLI.

## Examples

### Create a vault

```bash
# in a new, dedicated repository
nepomuk init --vault vault.nepomuk
# prints the master fingerprint (npk1…) – pin it in CI and on every client
```

### Add a user

```bash
# the new user, on their own machine – keys and password never leave it
nepomuk identity request --email jane@example.com --out jane.request
# or with a post-quantum SSH key
nepomuk identity request --ssh-key ~/.ssh/id_mldsa44_ed25519 --out jane.request

# an administrator with the `users` right
nepomuk user add jane.request
nepomuk group add android-release jane@example.com
```

### Store and read secrets

```bash
nepomuk mkdir /infra/db
nepomuk put /infra/db/prod-password            # value read from a hidden prompt
nepomuk put /infra/tls/wildcard.p12 --template pkcs12-cert \
  --field bundle=@wildcard.p12 --field-prompt password

nepomuk ls -r /infra
nepomuk get /infra/db/prod-password
```

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
nepomuk status        # up to date / behind / ahead / conflict
nepomuk sync          # replays your pending changes on top of the latest vault
nepomuk verify --full # re-verify every signature and permission in the log
```

## How it works (in short)

Every folder and secret has its own random key. A parent's key unlocks its children's keys, so a grant on a folder covers the whole subtree. A grant is simply that key encrypted (hybrid ML-KEM + X25519) for a user or a group. Every change is a signed entry in an append-only log inside the file; each client replays the log and rejects any change whose author was not allowed to make it. The master's fingerprint is pinned outside the file, and clients remember the latest version they have seen to detect rollbacks.

See [docs/SPECIFICATION.md](docs/SPECIFICATION.md) for the full design: threat model, cryptography, file format, permission model, git integration, CLI and JSON API, and GUI.

## Installing

The latest release, command line and desktop app:

```bash
curl -fsSL https://github.com/aleslanik2/nepomuk/releases/latest/download/install.sh -o install.sh
sh install.sh          # the CLI, into ~/.local/bin
sh install.sh --gui    # the desktop app
```

The script works on Linux, macOS and Windows (in Git Bash); on Windows without Git Bash use `install.ps1` from the same release (`./install.ps1`, `./install.ps1 -Gui`). The desktop app goes to Applications on macOS, to an AppImage with a menu entry on Linux, and through a per-user installer on Windows. Nothing is installed unless `SHA256SUMS` carries a valid release signature and the download matches it.

Options: `--version <tag>` installs a specific release, `--dir <path>` changes where the CLI goes, `--sha256 <hash>` pins the exact archive (recommended in CI), and `--from-source` builds with cargo instead of downloading (`--source <dir>` for a local checkout; the GUI also needs Node.js). While the repository is private, set `GH_TOKEN` and the script downloads through the GitHub CLI.

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
2. Bump `version` in `Cargo.toml`, then push a tag `v<version>`. [`.github/workflows/release.yml`](.github/workflows/release.yml) tests, builds six targets (static musl on Linux), smoke-tests both installers, and creates the release with `SHA256SUMS`.
3. Signing: with the secret `NEPOMUK_RELEASE_SIGNING_KEY` the workflow signs and publishes; without it the release stays a draft and `scripts/sign-release.sh v<version> <key>` signs it offline and publishes it.

## GUI

```bash
gui/scripts/prepare-sidecars.sh                 # builds the CLI (and the Touch ID helper) for bundling
cd gui/src-tauri && cargo tauri build            # or: cargo run for development
node gui/tests/harness.mjs target/debug/nepomuk  # drives the UI in headless Chrome against the real CLI
```

The web UI has no file system or network access; the Rust backend only forwards JSON-RPC to `nepomuk serve --stdio`, which holds the unlocked identity.

## Implementation status

Implemented in the CLI:

- crypto suite `NPQ-1` (ML-KEM-1024 + X25519, ML-DSA-65 + Ed25519, XChaCha20-Poly1305, Argon2id, SHA3-256/HKDF), size padding, zeroized and `mlock`ed seeds, core dumps disabled
- file format: signed checkpoint + hash-chained signed commits, full replay with per-operation authorization, root-of-trust pinning, rollback/fork detection, submodule pin check in CI, `compact`
- identities: email + password (NIST SP 800-63B-4 rules, blocklist, passphrase generator) and local identity files (CI, master); enrollment requests with proof of possession; `identity passwd`, `user replace`
- tree rights `read`/`write`/`share`/`admin`, system rights `users`/`groups`/`audit`/`group-admin` with `+delegate`, groups with their own KEM keys, revoke with automatic rekey, offboarding with rotation list and tasks for other admins, `master transfer`
- secrets `text`, `binary`, `record` with templates `android-signing`, `pkcs12-cert` (validated with `keytool`), `generic`; expiry warnings
- git: reads `origin/main`, plumbing commit + push on every write, retry on a rejected push, `--offline` queue (encrypted to the own identity) and `sync` with conflict resolution
- `exec` profiles (memfd on Linux, private `0700`/`0600` files elsewhere, output masking, `::add-mask::`, signal forwarding, cleanup)
- `--json` for every command, `serve --stdio` (JSON-RPC 2.0 with session lock and inactivity timeout)
- GUI (Tauri, [`gui/`](gui)) driving the bundled CLI: pinning the master with a visual fingerprint, login and enrollment, secrets tree with sealed values, template forms, access management, users, groups, offboarding checklist, rotation, audit log, sync and conflicts, `exec` profiles; clipboard excluded from history and cleared after 30 s, lock on inactivity and screen lock
- Touch ID on macOS (optional, per Mac): `nepomuk identity touchid enable` or the checkbox at login seals the password with a Secure Enclave key usable only after Touch ID with the currently enrolled fingers ([`macos/touchid`](macos/touchid)); `--touchid` or the button at login unlocks with it

Not implemented yet: notarized / Authenticode-signed GUI installers, PQ SSH identities (`mldsa44-ed25519` keys are recognized and refused), master on a hardware token and Shamir backup (`master backup`/`restore`), Have I Been Pwned check, zxcvbn estimation (a simple heuristic warns instead), the verification cache, nested groups, Windows ACLs for `exec` files, and automatic strengthening of Argon2id parameters (a warning is shown instead).

## What nepomuk cannot do

- It cannot audit **reads** – decryption happens offline on the user's machine.
- It cannot take back what someone has already seen – after revoking access, rotate the secret at its source.
- It cannot protect the vault if the **master key** is compromised – keep it offline and backed up with Shamir shares.

## Roadmap

1. MVP: CLI, GUI, identities, permissions, groups, records and templates, `exec`, signed log, git integration, offboarding, hardware-token master.
2. Google Workspace directory check (alerts on departed employees, group mapping).
3. More templates (iOS signing, TLS), pull-request workflow for selected folders.

## License

[Apache License 2.0](LICENSE)
