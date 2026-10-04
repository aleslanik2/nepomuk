//! The bundled CLI in `serve --stdio` mode (§13). This process holds the unlocked identity;
//! the GUI backend only forwards JSON-RPC messages and has no cryptography.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use serde_json::{Value, json};
use tauri::{AppHandle, Emitter};

type Pending = Arc<Mutex<HashMap<u64, mpsc::Sender<Result<Value, Value>>>>>;

pub struct Sidecar {
    child: Mutex<Child>,
    stdin: Mutex<ChildStdin>,
    pending: Pending,
    next: AtomicU64,
}

/// An error in the shape of the CLI's JSON API (§12.1).
pub fn err(code: &str, message: impl Into<String>) -> Value {
    json!({ "code": code, "message": message.into(), "details": {} })
}

/// The CLI next to the GUI executable (Tauri bundles `externalBin` there), `NEPOMUK_CLI`
/// for development, or `nepomuk` from PATH.
pub fn locate_cli() -> PathBuf {
    if let Some(p) = std::env::var_os("NEPOMUK_CLI") {
        return PathBuf::from(p);
    }
    let exe_name = if cfg!(windows) {
        "nepomuk.exe"
    } else {
        "nepomuk"
    };
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let p = dir.join(exe_name);
        if p.is_file() {
            return p;
        }
    }
    PathBuf::from(exe_name)
}

impl Sidecar {
    pub fn spawn(
        app: AppHandle,
        vault: Option<PathBuf>,
        project: Option<PathBuf>,
    ) -> Result<Arc<Sidecar>, Value> {
        let cli = locate_cli();
        let mut cmd = Command::new(&cli);
        cmd.arg("serve").arg("--stdio");
        if let Some(v) = &vault {
            cmd.arg("--vault").arg(v);
        }
        if let Some(dir) = project
            .as_deref()
            .or_else(|| vault.as_deref().and_then(Path::parent))
        {
            cmd.current_dir(dir);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                err(
                    "GUI_CLI_MISSING",
                    format!("cannot start {}: {e}", cli.display()),
                )
            })?;
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let reader_pending = pending.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                match msg.get("id").and_then(Value::as_u64) {
                    Some(id) => {
                        if let Some(tx) = reader_pending.lock().unwrap().remove(&id) {
                            let result = match msg.get("error") {
                                Some(e) => Err(rpc_error(e)),
                                None => Ok(msg.get("result").cloned().unwrap_or(Value::Null)),
                            };
                            let _ = tx.send(result);
                        }
                    }
                    None => {
                        let _ = app.emit("nepomuk:notification", &msg);
                    }
                }
            }
            // The CLI exited: fail everything still waiting.
            for (_, tx) in reader_pending.lock().unwrap().drain() {
                let _ = tx.send(Err(err("GUI_CLI_EXITED", "the nepomuk process exited")));
            }
            let _ = app.emit("nepomuk:exited", ());
        });
        Ok(Arc::new(Sidecar {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            pending,
            next: AtomicU64::new(1),
        }))
    }

    /// Sends a request and waits for its response (blocking).
    pub fn call(&self, method: &str, params: Value) -> Result<Value, Value> {
        self.call_within(method, params, None)
            .unwrap_or_else(|| Err(err("GUI_CLI_EXITED", "the nepomuk process exited")))
    }

    /// Like `call`, but gives up after `limit`; `None` when it timed out.
    pub fn call_within(
        &self,
        method: &str,
        params: Value,
        limit: Option<std::time::Duration>,
    ) -> Option<Result<Value, Value>> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let line =
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string();
        {
            let mut stdin = self.stdin.lock().unwrap();
            if writeln!(stdin, "{line}")
                .and_then(|_| stdin.flush())
                .is_err()
            {
                self.pending.lock().unwrap().remove(&id);
                return Some(Err(err(
                    "GUI_CLI_EXITED",
                    "the nepomuk process is not running",
                )));
            }
        }
        match limit {
            None => Some(
                rx.recv()
                    .unwrap_or_else(|_| Err(err("GUI_CLI_EXITED", "the nepomuk process exited"))),
            ),
            Some(d) => match rx.recv_timeout(d) {
                Ok(r) => Some(r),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    Some(Err(err("GUI_CLI_EXITED", "the nepomuk process exited")))
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    self.pending.lock().unwrap().remove(&id);
                    None
                }
            },
        }
    }

    /// Ends the process now; it holds the unlocked identity only in memory.
    pub fn kill(&self) {
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        // Closing stdin ends `serve --stdio`, which forgets the identity.
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn rpc_error(e: &Value) -> Value {
    let data = e.get("data").cloned().unwrap_or(Value::Null);
    json!({
        "code": data.get("code").cloned().unwrap_or_else(|| json!("RPC_ERROR")),
        "message": e.get("message").cloned().unwrap_or_else(|| json!("error")),
        "details": data.get("details").cloned().unwrap_or_else(|| json!({})),
    })
}
