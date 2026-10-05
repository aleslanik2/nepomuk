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
    /// Clears a copied secret now (the session got locked).
    ClearSecret,
    /// Clears a copied secret and reports back (the app quits).
    ClearAndAck(mpsc::Sender<()>),
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
                        let ok = if secret {
                            set_secret(&mut cb, &text)
                        } else {
                            cb.set().text(text.as_str()).is_ok()
                        };
                        if ok && secret {
                            armed = Some((text, std::time::Instant::now() + clear_after));
                        } else {
                            armed = None;
                        }
                    }
                    Ok(Msg::ClearSecret) | Err(mpsc::RecvTimeoutError::Timeout) => {
                        clear_if_unchanged(&mut cb, armed.take());
                    }
                    Ok(Msg::ClearAndAck(ack)) => {
                        clear_if_unchanged(&mut cb, armed.take());
                        let _ = ack.send(());
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

    /// Clears the clipboard now if it still holds a copied secret.
    pub fn clear_secret(&self) {
        let _ = self.tx.send(Msg::ClearSecret);
    }

    /// Clears a copied secret and waits (at most `limit`) until it is done: the clipboard
    /// outlives the app on macOS and Windows.
    pub fn clear_secret_now(&self, limit: Duration) {
        let (ack, done) = mpsc::channel();
        if self.tx.send(Msg::ClearAndAck(ack)).is_ok() {
            let _ = done.recv_timeout(limit);
        }
    }

    pub fn copy_plain(&self, text: String) {
        let _ = self.tx.send(Msg::Copy {
            text: Zeroizing::new(text),
            secret: false,
            clear_after: Duration::ZERO,
        });
    }
}

/// Clears the clipboard if it still holds `armed`, i.e. nothing else was copied meanwhile.
fn clear_if_unchanged(
    cb: &mut arboard::Clipboard,
    armed: Option<(Zeroizing<String>, std::time::Instant)>,
) {
    if let Some((value, _)) = armed
        && cb
            .get_text()
            .map(Zeroizing::new)
            .is_ok_and(|t| *t == *value)
    {
        let _ = cb.clear();
    }
}

/// macOS: arboard marks the item concealed only after writing it, and lets Universal
/// Clipboard hand it to the user's other devices. Written directly instead: for this Mac only,
/// with the concealed and transient markers in the same change.
#[cfg(target_os = "macos")]
fn set_secret(_cb: &mut arboard::Clipboard, text: &str) -> bool {
    set_secret_on(&objc2_app_kit::NSPasteboard::generalPasteboard(), text)
}

#[cfg(target_os = "macos")]
fn set_secret_on(pb: &objc2_app_kit::NSPasteboard, text: &str) -> bool {
    use objc2_app_kit::{NSPasteboardContentsOptions, NSPasteboardTypeString};
    use objc2_foundation::{NSData, NSString};
    pb.prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly);
    let ok = pb.setString_forType(&NSString::from_str(text), unsafe { NSPasteboardTypeString });
    let empty = NSData::new();
    for marker in [
        "org.nspasteboard.ConcealedType",
        "org.nspasteboard.TransientType",
    ] {
        pb.setData_forType(Some(&empty), &NSString::from_str(marker));
    }
    ok
}

#[cfg(windows)]
fn set_secret(cb: &mut arboard::Clipboard, text: &str) -> bool {
    use arboard::SetExtWindows;
    cb.set().exclude_from_history().text(text).is_ok()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn set_secret(cb: &mut arboard::Clipboard, text: &str) -> bool {
    use arboard::SetExtLinux;
    cb.set().exclude_from_history().text(text).is_ok()
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};

    #[test]
    fn secret_is_concealed_and_transient() {
        // A private pasteboard: the test must not touch the user's clipboard.
        let pb = NSPasteboard::pasteboardWithUniqueName();
        assert!(super::set_secret_on(&pb, "hunter2"));
        let s = pb.stringForType(unsafe { NSPasteboardTypeString }).unwrap();
        assert_eq!(s.to_string(), "hunter2");
        let types: Vec<String> = pb.types().unwrap().iter().map(|t| t.to_string()).collect();
        for marker in [
            "org.nspasteboard.ConcealedType",
            "org.nspasteboard.TransientType",
        ] {
            assert!(types.iter().any(|t| t == marker), "{types:?}");
        }
        pb.clearContents();
    }
}
