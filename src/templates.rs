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
        if let Some((alias, kp)) = key {
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
            warnings: vec![],
        })
    })();
    crate::exec::remove_dir(&dir);
    result
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
