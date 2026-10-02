//! Record templates (§11.2): required fields and validation on save.

use std::collections::BTreeMap;
use std::process::{Command, Stdio};

use crate::error::{Code, Error, Result};
use crate::model::Field;

pub struct Template {
    pub name: &'static str,
    /// (field, binary?)
    pub fields: &'static [(&'static str, bool)],
}

pub const TEMPLATES: &[Template] = &[
    Template {
        name: "android-signing",
        fields: &[
            ("keystore", true),
            ("store_password", false),
            ("key_alias", false),
            ("key_password", false),
        ],
    },
    Template {
        name: "pkcs12-cert",
        fields: &[("bundle", true), ("password", false)],
    },
    Template {
        name: "generic",
        fields: &[],
    },
];

pub fn get(name: &str) -> Result<&'static Template> {
    TEMPLATES.iter().find(|t| t.name == name).ok_or_else(|| {
        Error::usage(format!(
            "unknown template {name:?} (available: android-signing, pkcs12-cert, generic)"
        ))
    })
}

fn invalid(m: impl Into<String>) -> Error {
    Error::new(Code::TemplateValidation, m)
}

fn text<'a>(fields: &'a BTreeMap<String, Field>, name: &str) -> Result<&'a str> {
    match fields.get(name) {
        Some(Field::Text { value }) => Ok(value),
        _ => Err(invalid(format!("field `{name}` must be text"))),
    }
}

fn binary<'a>(fields: &'a BTreeMap<String, Field>, name: &str) -> Result<&'a [u8]> {
    match fields.get(name) {
        Some(Field::Binary { data, .. }) => Ok(data),
        _ => Err(invalid(format!(
            "field `{name}` must be a file (use {name}=@path)"
        ))),
    }
}

pub struct Validation {
    pub not_after: Option<i64>,
    pub warnings: Vec<String>,
}

/// Validates the fields; returns the certificate validity when it could be determined.
pub fn validate(template: &str, fields: &BTreeMap<String, Field>) -> Result<Validation> {
    let t = get(template)?;
    for (name, is_binary) in t.fields {
        match (fields.get(*name), is_binary) {
            (None, _) => {
                return Err(invalid(format!(
                    "missing field `{name}` required by template {template}"
                )));
            }
            (Some(Field::Text { .. }), true) => {
                return Err(invalid(format!("field `{name}` must be a file")));
            }
            (Some(Field::Binary { .. }), false) => {
                return Err(invalid(format!("field `{name}` must be text")));
            }
            _ => {}
        }
    }
    match template {
        "android-signing" => {
            let ks = binary(fields, "keystore")?;
            let sp = text(fields, "store_password")?;
            let alias = text(fields, "key_alias")?;
            let kp = text(fields, "key_password")?;
            keytool_check(ks, sp, Some((alias, kp)), None)
        }
        "pkcs12-cert" => {
            let b = binary(fields, "bundle")?;
            let p = text(fields, "password")?;
            keytool_check(b, p, None, Some("PKCS12"))
        }
        _ => Ok(Validation {
            not_after: None,
            warnings: vec![],
        }),
    }
}

fn keytool_available() -> bool {
    Command::new("keytool")
        .arg("-help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn keytool(args: &[&str], env: &[(&str, &str)]) -> Result<(bool, String)> {
    let mut c = Command::new("keytool");
    c.args(["-J-Duser.language=en", "-J-Duser.country=US"])
        .args(args);
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c
        .stdin(Stdio::null())
        .output()
        .map_err(|e| Error::general(format!("keytool: {e}")))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok((out.status.success(), text))
}

/// Opens the keystore with keytool, checks the alias and key password, reads the validity.
fn keytool_check(
    keystore: &[u8],
    store_password: &str,
    key: Option<(&str, &str)>,
    storetype: Option<&str>,
) -> Result<Validation> {
    if !keytool_available() {
        return Ok(Validation {
            not_after: None,
            warnings: vec!["keytool not found – the keystore was not validated".into()],
        });
    }
    let dir = crate::exec::private_dir()?;
    let ks_path = dir.join("keystore");
    let result = (|| {
        crate::exec::write_private_file(&ks_path, keystore)?;
        let ks = ks_path.to_string_lossy().to_string();
        let mut args = vec![
            "-list",
            "-v",
            "-keystore",
            &ks,
            "-storepass:env",
            "NPK_STOREPASS",
        ];
        if let Some(t) = storetype {
            args.extend(["-storetype", t]);
        }
        if let Some((alias, _)) = key {
            args.extend(["-alias", alias]);
        }
        let (ok, out) = keytool(&args, &[("NPK_STOREPASS", store_password)])?;
        if !ok {
            let reason = out
                .lines()
                .find(|l| l.contains("error"))
                .unwrap_or("cannot open the keystore")
                .trim();
            return Err(invalid(format!("keystore validation failed: {reason}")));
        }
        let not_after = parse_until(&out);
        let mut warnings = Vec::new();
        if let Some((alias, kp)) = key {
            let kstype = out
                .lines()
                .find_map(|l| l.trim().strip_prefix("Keystore type:"))
                .map(|t| t.trim().to_uppercase())
                .unwrap_or_else(|| storetype.unwrap_or("PKCS12").to_uppercase());
            // Like Gradle: KeyStore.getKey(alias, keyPassword). keytool cannot do this for PKCS12
            // with a key password different from the store password (it ignores -keypass).
            match java_key_check(&dir, &ks, &kstype, alias, store_password, kp) {
                Some(JavaCheck::Ok) => {
                    return Ok(Validation {
                        not_after,
                        warnings,
                    });
                }
                Some(JavaCheck::WrongKeyPassword) => {
                    return Err(invalid("keystore validation failed: wrong key password"));
                }
                Some(JavaCheck::NoKey) => {
                    return Err(invalid(format!(
                        "keystore validation failed: alias {alias} has no private key"
                    )));
                }
                None if kstype != "JKS" && kstype != "JCEKS" => {
                    // keytool alone can verify the key password of a PKCS12 keystore only when it
                    // equals the store password.
                    if !certreq(&dir, &ks, alias, store_password, store_password)? {
                        warnings.push(
                            "the key password could not be verified: it differs from the store password and this needs Java 11+ (a JDK) to check; it is stored as entered".into(),
                        );
                    }
                    return Ok(Validation {
                        not_after,
                        warnings,
                    });
                }
                None => {}
            }
            let csr = dir.join("csr");
            let csr_s = csr.to_string_lossy().to_string();
            let args = [
                "-certreq",
                "-keystore",
                &ks,
                "-storepass:env",
                "NPK_STOREPASS",
                "-alias",
                alias,
                "-keypass:env",
                "NPK_KEYPASS",
                "-file",
                &csr_s,
            ];
            let (ok, _) = keytool(
                &args,
                &[("NPK_STOREPASS", store_password), ("NPK_KEYPASS", kp)],
            )?;
            if !ok {
                return Err(invalid("keystore validation failed: wrong key password"));
            }
        }
        Ok(Validation {
            not_after,
            warnings,
        })
    })();
    crate::exec::remove_dir(&dir);
    result
}

/// `keytool -certreq` needs the private key; true when it could be opened.
fn certreq(
    dir: &std::path::Path,
    ks: &str,
    alias: &str,
    store_password: &str,
    key_password: &str,
) -> Result<bool> {
    let csr = dir.join("csr-check");
    let csr_s = csr.to_string_lossy().to_string();
    let args = [
        "-certreq",
        "-keystore",
        ks,
        "-storepass:env",
        "NPK_STOREPASS",
        "-alias",
        alias,
        "-keypass:env",
        "NPK_KEYPASS",
        "-file",
        &csr_s,
    ];
    let (ok, _) = keytool(
        &args,
        &[
            ("NPK_STOREPASS", store_password),
            ("NPK_KEYPASS", key_password),
        ],
    )?;
    Ok(ok)
}

enum JavaCheck {
    Ok,
    WrongKeyPassword,
    NoKey,
}

const JAVA_KEY_CHECK: &str = r#"
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.UnrecoverableKeyException;

public class KeyCheck {
    public static void main(String[] a) throws Exception {
        KeyStore ks = KeyStore.getInstance(a[1]);
        try (FileInputStream in = new FileInputStream(a[0])) {
            ks.load(in, System.getenv("NPK_STOREPASS").toCharArray());
        }
        try {
            if (ks.getKey(a[2], System.getenv("NPK_KEYPASS").toCharArray()) == null) System.exit(3);
        } catch (UnrecoverableKeyException e) {
            System.exit(2);
        }
        System.exit(0);
    }
}
"#;

/// Opens the key the way Android builds do; None when Java 11+ cannot run the check.
fn java_key_check(
    dir: &std::path::Path,
    ks: &str,
    kstype: &str,
    alias: &str,
    sp: &str,
    kp: &str,
) -> Option<JavaCheck> {
    let src = dir.join("KeyCheck.java");
    std::fs::write(&src, JAVA_KEY_CHECK).ok()?;
    let out = Command::new("java")
        .arg(&src)
        .args([ks, kstype, alias])
        .env("NPK_STOREPASS", sp)
        .env("NPK_KEYPASS", kp)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    match out.code() {
        Some(0) => Some(JavaCheck::Ok),
        Some(2) => Some(JavaCheck::WrongKeyPassword),
        Some(3) => Some(JavaCheck::NoKey),
        _ => None,
    }
}

/// Earliest "until:" date of the certificates in `keytool -list -v` output.
fn parse_until(out: &str) -> Option<i64> {
    out.lines()
        .filter_map(|l| l.split("until: ").nth(1))
        .filter_map(|d| {
            let parts: Vec<&str> = d.split_whitespace().collect();
            if parts.len() != 6 {
                return None;
            }
            // "Fri Sep 24 12:00:00 CEST 2051" – weekday and zone abbreviation are dropped.
            let s = format!("{} {} {} {}", parts[1], parts[2], parts[3], parts[5]);
            chrono::NaiveDateTime::parse_from_str(&s, "%b %d %H:%M:%S %Y").ok()
        })
        .map(|d| d.and_utc().timestamp())
        .min()
}

#[cfg(test)]
mod tests {
    #[test]
    fn until() {
        let out =
            "Valid from: Mon Sep 30 12:00:00 CEST 2026 until: Fri Sep 24 12:00:00 CEST 2051\n";
        assert!(super::parse_until(out).is_some());
    }
}
