//! Clipboard for secrets (§13): excluded from clipboard history where the platform supports it
//! and cleared after a timeout if it still holds the copied value.

use std::sync::mpsc;
use std::time::Duration;

use zeroize::Zeroizing;

enum Msg {
    Copy {
        text: Zeroizing<String>,
        secret: bool,
        clear_after: Duration,
    },
}

pub struct SecretClipboard {
    tx: mpsc::Sender<Msg>,
}

impl SecretClipboard {
    pub fn start() -> SecretClipboard {
        let (tx, rx) = mpsc::channel::<Msg>();
        // One thread owns the clipboard: on X11 the content lives only as long as its owner.
        std::thread::spawn(move || {
            let Ok(mut cb) = arboard::Clipboard::new() else {
                return;
            };
            let mut armed: Option<(Zeroizing<String>, std::time::Instant)> = None;
            loop {
                let wait = armed
                    .as_ref()
                    .map(|(_, at)| at.saturating_duration_since(std::time::Instant::now()))
                    .unwrap_or(Duration::from_secs(3600));
                match rx.recv_timeout(wait) {
                    Ok(Msg::Copy {
                        text,
                        secret,
                        clear_after,
                    }) => {
                        let set = cb.set();
                        let set = if secret { exclude(set) } else { set };
                        if set.text(text.as_str()).is_ok() && secret {
                            armed = Some((text, std::time::Instant::now() + clear_after));
                        } else {
                            armed = None;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if let Some((value, _)) = armed.take() {
                            // Clear only if nothing else was copied meanwhile.
                            if cb
                                .get_text()
                                .map(Zeroizing::new)
                                .is_ok_and(|t| *t == *value)
                            {
                                let _ = cb.clear();
                            }
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
        SecretClipboard { tx }
    }

    pub fn copy_secret(&self, text: Zeroizing<String>, clear_after: Duration) {
        let _ = self.tx.send(Msg::Copy {
            text,
            secret: true,
            clear_after,
        });
    }

    pub fn copy_plain(&self, text: String) {
        let _ = self.tx.send(Msg::Copy {
            text: Zeroizing::new(text),
            secret: false,
            clear_after: Duration::ZERO,
        });
    }
}

#[cfg(target_os = "macos")]
fn exclude(set: arboard::Set<'_>) -> arboard::Set<'_> {
    use arboard::SetExtApple;
    set.exclude_from_history()
}

#[cfg(windows)]
fn exclude(set: arboard::Set<'_>) -> arboard::Set<'_> {
    use arboard::SetExtWindows;
    set.exclude_from_history()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn exclude(set: arboard::Set<'_>) -> arboard::Set<'_> {
    use arboard::SetExtLinux;
    set.exclude_from_history()
}
