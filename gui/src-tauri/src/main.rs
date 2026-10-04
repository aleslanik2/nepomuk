//! nepomuk GUI backend (§13): translates between the web UI and `nepomuk serve --stdio`.
//! It holds no keys and does no cryptography; the web layer gets no file system or network
//! access beyond the explicit commands below.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod clipboard;
mod lockwatch;
mod sidecar;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

use sidecar::{Sidecar, err};

const API_VERSION: u64 = 1;

struct AppState {
    sidecar: Mutex<Option<Arc<Sidecar>>>,
    /// Counts locks; an operation that spans a lock (a save dialog) checks it.
    locks: std::sync::atomic::AtomicU64,
    /// One lock at a time (the window and the screen-lock watcher may both lock).
    locking: Mutex<()>,
    /// What the sidecar was started for, to start a fresh one after a forced lock.
    target: Mutex<Option<(Option<PathBuf>, Option<PathBuf>)>>,
    clipboard: clipboard::SecretClipboard,
}

impl AppState {
    fn current(&self) -> Result<Arc<Sidecar>, Value> {
        self.sidecar
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| err("GUI_NOT_CONNECTED", "no vault is open"))
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Value> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| err("GUI_INTERNAL", e.to_string()))
}

/// Starts the CLI for a vault file or a project folder (with `.nepomuk.toml`) and checks
/// API compatibility (§12.3).
#[tauri::command]
async fn connect(
    app: AppHandle,
    state: State<'_, AppState>,
    vault: Option<String>,
    project: Option<String>,
) -> Result<Value, Value> {
    state.sidecar.lock().unwrap().take();
    let vault = vault.map(PathBuf::from);
    let project = project.map(PathBuf::from);
    let sc = Sidecar::spawn(app, vault.clone(), project.clone())?;
    let s2 = sc.clone();
    let version = blocking(move || s2.call("version", json!({}))).await??;
    if version.get("api").and_then(Value::as_u64) != Some(API_VERSION) {
        return Err(json!({
            "code": "GUI_INCOMPATIBLE_CLI",
            "message": format!("this GUI needs JSON API {API_VERSION}; the bundled CLI reports {}", version["api"]),
            "details": version,
        }));
    }
    *state.sidecar.lock().unwrap() = Some(sc);
    *state.target.lock().unwrap() = Some((vault.clone(), project.clone()));
    Ok(json!({
        "version": version,
        "vault": vault.map(|p| p.display().to_string()),
        "project": project.map(|p| p.display().to_string()),
    }))
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), Value> {
    state.sidecar.lock().unwrap().take();
    Ok(())
}

/// How long a lock may wait for the CLI before the CLI is ended instead.
const LOCK_WAIT: Duration = Duration::from_secs(2);

/// Locks the session. The CLI handles one request at a time, so a long operation (`exec`, a
/// slow git) would delay a plain `session.lock`: if it does not answer within `LOCK_WAIT`, the
/// process is ended – which forgets the identity – and a fresh, locked one is started.
fn lock_now(app: &AppHandle) -> Value {
    let state = app.state::<AppState>();
    let _one = state.locking.lock().unwrap();
    state
        .locks
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    state.clipboard.clear_secret();
    let Some(sc) = state.sidecar.lock().unwrap().clone() else {
        return json!({ "locked": true, "restarted": false });
    };
    if let Some(Ok(_)) = sc.call_within("session.lock", json!({}), Some(LOCK_WAIT)) {
        return json!({ "locked": true, "restarted": false });
    }
    sc.kill();
    state.sidecar.lock().unwrap().take();
    let target = state.target.lock().unwrap().clone();
    let fresh = target.and_then(|(v, p)| Sidecar::spawn(app.clone(), v, p).ok());
    let restarted = fresh.is_some();
    if let Some(fresh) = fresh {
        // The ended process could not forget identities cached by the Touch ID agent.
        let _ = fresh.call_within("session.lock", json!({}), Some(LOCK_WAIT));
        *state.sidecar.lock().unwrap() = Some(fresh);
    }
    json!({ "locked": true, "restarted": restarted })
}

#[tauri::command]
async fn lock_session(app: AppHandle) -> Result<Value, Value> {
    blocking(move || lock_now(&app)).await
}

/// Forwards one JSON-RPC call to the CLI.
#[tauri::command]
async fn rpc(
    state: State<'_, AppState>,
    method: String,
    params: Option<Value>,
) -> Result<Value, Value> {
    let sc = state.current()?;
    blocking(move || sc.call(&method, params.unwrap_or_else(|| json!({})))).await?
}

fn path_string(p: tauri_plugin_dialog::FilePath) -> Option<String> {
    p.into_path().ok().map(|p| p.display().to_string())
}

/// System dialogs for choosing a vault, a project folder, an identity or a request file.
#[tauri::command]
async fn pick(app: AppHandle, kind: String) -> Result<Option<String>, Value> {
    blocking(move || {
        let d = app.dialog().file();
        match kind.as_str() {
            "vault" => d
                .set_title("Open a vault")
                .add_filter("nepomuk vault", &["nepomuk"])
                .blocking_pick_file(),
            "project" => d
                .set_title("Open a project folder with .nepomuk.toml")
                .blocking_pick_folder(),
            "identity" => d
                .set_title("Choose an identity file")
                .add_filter("nepomuk identity", &["npk"])
                .blocking_pick_file(),
            "request" => d
                .set_title("Choose an access request")
                .add_filter("nepomuk request", &["request"])
                .blocking_pick_file(),
            _ => d.blocking_pick_file(),
        }
        .and_then(path_string)
    })
    .await
}

#[tauri::command]
async fn pick_save(app: AppHandle, default_name: String) -> Result<Option<String>, Value> {
    blocking(move || {
        app.dialog()
            .file()
            .set_file_name(&default_name)
            .blocking_save_file()
            .and_then(path_string)
    })
    .await
}

/// Reads a file chosen by the user (binary secrets and record fields).
#[tauri::command]
async fn pick_file_b64(app: AppHandle) -> Result<Option<Value>, Value> {
    blocking(move || {
        let path = app
            .dialog()
            .file()
            .set_title("Choose a file to store")
            .blocking_pick_file()
            .and_then(|p| p.into_path().ok())?;
        let data = Zeroizing::new(std::fs::read(&path).ok()?);
        Some(json!({
            "name": path.file_name().map(|n| n.to_string_lossy().to_string()),
            "size": data.len(),
            "base64": base64::engine::general_purpose::STANDARD.encode(&*data),
        }))
    })
    .await
}

fn secret_bytes(v: &Value) -> Result<Zeroizing<Vec<u8>>, Value> {
    if let Some(s) = v.get("value").and_then(Value::as_str) {
        return Ok(Zeroizing::new(s.as_bytes().to_vec()));
    }
    if let Some(b) = v.get("base64").and_then(Value::as_str) {
        return base64::engine::general_purpose::STANDARD
            .decode(b)
            .map(Zeroizing::new)
            .map_err(|_| err("GUI_INTERNAL", "invalid base64 from the CLI"));
    }
    Err(err("USAGE", "choose a single value or a record field"))
}

/// Copies a secret without handing it to the web layer.
#[tauri::command]
async fn copy_secret(
    app: AppHandle,
    state: State<'_, AppState>,
    spec: String,
    seconds: Option<u64>,
) -> Result<(), Value> {
    let sc = state.current()?;
    let locks = state.locks.load(std::sync::atomic::Ordering::SeqCst);
    let v = blocking(move || sc.call("node.get", json!({ "path": spec }))).await??;
    if v.get("value").is_none() {
        return Err(err(
            "USAGE",
            "only text values can be copied; save files instead",
        ));
    }
    let bytes = secret_bytes(&v)?;
    let text = Zeroizing::new(String::from_utf8_lossy(&bytes).to_string());
    // Under the lock guard: a lock either happened before (then nothing is copied) or comes
    // after and clears the clipboard. The guard may wait for a lock in progress: off the async
    // runtime.
    let clear_after = Duration::from_secs(seconds.unwrap_or(30).clamp(5, 600));
    blocking(move || {
        let state = app.state::<AppState>();
        let _one = state.locking.lock().unwrap();
        if state.locks.load(std::sync::atomic::Ordering::SeqCst) != locks {
            return Err(err("PASSWORD_REQUIRED", "the session was locked"));
        }
        state.clipboard.copy_secret(text, clear_after);
        Ok(())
    })
    .await?
}

#[tauri::command]
async fn copy_plain(state: State<'_, AppState>, text: String) -> Result<(), Value> {
    state.clipboard.copy_plain(text);
    Ok(())
}

/// Saves a secret only through the system dialog (§13), readable only by the user.
#[tauri::command]
async fn save_secret(
    app: AppHandle,
    state: State<'_, AppState>,
    spec: String,
    default_name: String,
) -> Result<Option<String>, Value> {
    state.current()?;
    let locks = state.locks.load(std::sync::atomic::Ordering::SeqCst);
    blocking(move || {
        // Ask where first; fetch the secret only afterwards, and not at all if the session was
        // locked while the (native, unclosable) save dialog was open.
        let Some(path) = app
            .dialog()
            .file()
            .set_file_name(&default_name)
            .blocking_save_file()
            .and_then(|p| p.into_path().ok())
        else {
            return Ok(None);
        };
        let state = app.state::<AppState>();
        if state.locks.load(std::sync::atomic::Ordering::SeqCst) != locks {
            return Err(err("PASSWORD_REQUIRED", "the session was locked"));
        }
        let v = state.current()?.call("node.get", json!({ "path": spec }))?;
        let bytes = secret_bytes(&v)?;
        let _one = state.locking.lock().unwrap();
        if state.locks.load(std::sync::atomic::Ordering::SeqCst) != locks {
            return Err(err("PASSWORD_REQUIRED", "the session was locked"));
        }
        write_private(&path, &bytes)
            .map_err(|e| err("GENERAL", format!("cannot write {}: {e}", path.display())))?;
        Ok(Some(path.display().to_string()))
    })
    .await?
}

/// Writes a secret so that only the user can read it, also when the file already exists: the
/// data goes to a new `0600` file next to the target, which then replaces it (a symlink at the
/// target is replaced, not followed). The permissions of an existing file are not inherited.
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("not a file name"))?;
    // `create_new` below refuses an existing file, so the name only has to be unlikely.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let tmp = dir.join(format!(
        ".{}.nepomuk-{}-{nanos}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn export_tightens_an_existing_file_and_replaces_symlinks() {
        let dir = std::env::temp_dir().join(format!("nepomuk-gui-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("secret.p12");
        std::fs::write(&target, b"old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        super::write_private(&target, b"new secret").unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&target).unwrap(), b"new secret");

        let victim = dir.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        super::write_private(&link, b"x").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert!(
            !std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(left.len(), 3, "{left:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Locks the session whenever the screen gets locked.
fn watch_screen_lock(app: AppHandle) {
    std::thread::spawn(move || {
        let mut was_locked = false;
        loop {
            std::thread::sleep(Duration::from_secs(3));
            let locked = lockwatch::screen_locked().unwrap_or(false);
            if locked && !was_locked {
                // The window hides its content first; the CLI is locked (or ended) after.
                let _ = app.emit("nepomuk:locked", json!({ "reason": "screen" }));
                lock_now(&app);
            }
            was_locked = locked;
        }
    });
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            sidecar: Mutex::new(None),
            locks: std::sync::atomic::AtomicU64::new(0),
            locking: Mutex::new(()),
            target: Mutex::new(None),
            clipboard: clipboard::SecretClipboard::start(),
        })
        .setup(|app| {
            watch_screen_lock(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            connect,
            disconnect,
            rpc,
            lock_session,
            pick,
            pick_save,
            pick_file_b64,
            copy_secret,
            copy_plain,
            save_secret
        ])
        .run(tauri::generate_context!())
        .expect("error while running the nepomuk GUI");
}
