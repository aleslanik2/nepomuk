//! Identities (§4): a 64-byte seed from which all key pairs are derived, identity files,
//! enrollment requests and unlocking.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::crypto::{self, KemPublic, KemSecret, PasswordSealed, SigPublic, SigSecret};
use crate::error::{Code, Error, Result};
use crate::format::{from_cbor, to_cbor};
use crate::memory::LockedSeed;
use crate::model::{IdentityKind, User};
use crate::verify::proof_data;

/// An unlocked identity: the seed and the key pairs derived from it.
pub struct Unlocked {
    pub name: String,
    pub kind: IdentityKind,
    pub seed: LockedSeed,
    pub kem: KemSecret,
    pub sig: SigSecret,
}

impl Unlocked {
    pub fn from_seed(seed: LockedSeed, name: &str, kind: IdentityKind) -> Self {
        let kem = KemSecret::from_seed(seed.as_ref(), "identity");
        let sig = SigSecret::from_seed(seed.as_ref(), "identity");
        Unlocked {
            name: name.to_string(),
            kind,
            seed,
            kem,
            sig,
        }
    }

    pub fn generate(name: &str, kind: IdentityKind) -> Self {
        Self::from_seed(LockedSeed::random(), name, kind)
    }

    pub fn fingerprint(&self) -> String {
        crypto::fingerprint(self.kem.public(), self.sig.public())
    }

    pub fn matches(&self, u: &User) -> bool {
        &u.kem == self.kem.public() && &u.sig == self.sig.public()
    }

    pub fn proof(&self, kind: IdentityKind, credential: Option<&PasswordSealed>) -> Vec<u8> {
        self.sig.sign(
            "request",
            &proof_data(
                &self.name,
                kind,
                self.kem.public(),
                self.sig.public(),
                credential,
            ),
        )
    }
}

/// What the rest of nepomuk needs from an unlocked identity. A local identity holds its seed;
/// one served by the Touch ID agent does not – the agent keeps the seed and only unwraps keys
/// for the caller, and never signs (writing needs a fresh unlock, see `Ctx::unlock_for_write`).
pub trait Keys {
    fn name(&self) -> &str;
    fn kind(&self) -> IdentityKind;
    fn kem_public(&self) -> &KemPublic;
    fn sig_public(&self) -> &SigPublic;
    /// Unwraps a secret wrapped for this identity with the hybrid KEM.
    fn unwrap(&self, w: &crypto::Wrapped, aad: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>>;
    /// Signs with the hybrid signature; only a local identity can.
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>>;

    fn fingerprint(&self) -> String {
        crypto::fingerprint(self.kem_public(), self.sig_public())
    }

    fn matches(&self, u: &User) -> bool {
        &u.kem == self.kem_public() && &u.sig == self.sig_public()
    }
}

impl Keys for Unlocked {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> IdentityKind {
        self.kind
    }
    fn kem_public(&self) -> &KemPublic {
        self.kem.public()
    }
    fn sig_public(&self) -> &SigPublic {
        self.sig.public()
    }
    fn unwrap(&self, w: &crypto::Wrapped, aad: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        crypto::unwrap(&self.kem, w, aad)
    }
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.sig.sign(label, data))
    }
}

pub fn credential_aad(name: &str) -> Vec<u8> {
    format!("nepomuk/credential/{}", name.to_lowercase()).into_bytes()
}

fn file_aad(name: &str) -> Vec<u8> {
    format!("nepomuk/identity-file/{name}").into_bytes()
}

/// Seals the seed of a password identity for storage in the vault.
pub fn password_credential(id: &Unlocked, password: &str) -> Result<PasswordSealed> {
    let p = crate::password::normalize(password);
    crypto::password_seal(p.as_bytes(), id.seed.as_ref(), &credential_aad(&id.name))
}

/// Unlocks a password identity stored in the vault.
pub fn unlock_password_user(user: &User, password: &str) -> Result<Unlocked> {
    let cred = user
        .credential
        .as_ref()
        .ok_or_else(|| Error::new(Code::BadCredentials, "this user has no password identity"))?;
    let p = crate::password::normalize(password);
    let seed = crypto::password_open(p.as_bytes(), cred, &credential_aad(&user.name))?;
    let id = Unlocked::from_seed(
        LockedSeed::from_slice(&seed)?,
        &user.name,
        IdentityKind::Password,
    );
    if !id.matches(user) {
        return Err(Error::bad_credentials());
    }
    Ok(id)
}

// ---------------------------------------------------------------- Armor

fn armor(label: &str, data: &[u8]) -> String {
    let b = base64::engine::general_purpose::STANDARD.encode(data);
    let mut out = format!("-----BEGIN NEPOMUK {label}-----\n");
    for chunk in b.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END NEPOMUK {label}-----\n"));
    out
}

/// Largest armored identity or request accepted (they are a few kilobytes).
const MAX_ARMORED: usize = 1 << 20;

fn dearmor(label: &str, text: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN NEPOMUK {label}-----");
    let what = label.to_lowercase();
    let text = text.trim();
    if text.is_empty() {
        return Err(Error::format(format!("empty nepomuk {what} file")));
    }
    if text.len() > MAX_ARMORED {
        return Err(Error::format(format!(
            "the nepomuk {what} file is too large"
        )));
    }
    if text.starts_with(&begin) {
        return dearmor_block(label, text);
    }
    // Bare base64 of an armored file (e.g. NEPOMUK_IDENTITY in CI): one layer, no more.
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(text.split_whitespace().collect::<String>())
        .map_err(|_| Error::format(format!("not a nepomuk {what} file")))?;
    let inner = String::from_utf8(decoded).map_err(|_| Error::format("bad identity encoding"))?;
    let inner = inner.trim();
    if !inner.starts_with(&begin) {
        return Err(Error::format(format!("not a nepomuk {what} file")));
    }
    dearmor_block(label, inner)
}

/// An armored block: the BEGIN line, base64, and the END line.
fn dearmor_block(label: &str, text: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN NEPOMUK {label}-----");
    let end = format!("-----END NEPOMUK {label}-----");
    let what = label.to_lowercase();
    let body = text
        .strip_prefix(&begin)
        .and_then(|rest| rest.split_once(&end).map(|(b, _)| b))
        .ok_or_else(|| Error::format(format!("malformed nepomuk {what}")))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body.split_whitespace().collect::<String>())
        .map_err(|_| Error::format(format!("malformed nepomuk {what}")))?;
    if bytes.is_empty() {
        return Err(Error::format(format!("empty nepomuk {what}")));
    }
    Ok(bytes)
}

#[cfg(test)]
mod armor_tests {
    use super::*;

    #[test]
    fn dearmor_rejects_empty_and_nested_input() {
        for bad in [
            "",
            "   \n\t",
            "AAAA",
            "-----BEGIN NEPOMUK IDENTITY-----\n-----END NEPOMUK IDENTITY-----",
        ] {
            assert!(dearmor("IDENTITY", bad).is_err(), "{bad:?}");
        }
        let armored = armor("IDENTITY", b"payload");
        assert_eq!(dearmor("IDENTITY", &armored).unwrap(), b"payload");
        let once = base64::engine::general_purpose::STANDARD.encode(&armored);
        assert_eq!(dearmor("IDENTITY", &once).unwrap(), b"payload");
        let twice = base64::engine::general_purpose::STANDARD.encode(&once);
        assert!(dearmor("IDENTITY", &twice).is_err());
        // Missing END line.
        let cut = armored.replace("-----END NEPOMUK IDENTITY-----\n", "");
        assert!(dearmor("IDENTITY", &cut).is_err());
    }
}

// ---------------------------------------------------------------- Identity files

#[derive(Serialize, Deserialize)]
pub struct IdentityFile {
    pub version: u8,
    pub name: String,
    pub kem: KemPublic,
    pub sig: SigPublic,
    pub seed: PasswordSealed,
}

impl IdentityFile {
    pub fn create(id: &Unlocked, passphrase: &str) -> Result<IdentityFile> {
        let p = crate::password::normalize(passphrase);
        Ok(IdentityFile {
            version: 1,
            name: id.name.clone(),
            kem: id.kem.public().clone(),
            sig: id.sig.public().clone(),
            seed: crypto::password_seal(p.as_bytes(), id.seed.as_ref(), &file_aad(&id.name))?,
        })
    }

    pub fn to_text(&self) -> String {
        armor("IDENTITY", &to_cbor(self))
    }

    pub fn parse(text: &str) -> Result<IdentityFile> {
        from_cbor(&dearmor("IDENTITY", text)?)
    }

    pub fn fingerprint(&self) -> String {
        crypto::fingerprint(&self.kem, &self.sig)
    }

    pub fn unlock(&self, passphrase: &str) -> Result<Unlocked> {
        let p = crate::password::normalize(passphrase);
        let seed = crypto::password_open(p.as_bytes(), &self.seed, &file_aad(&self.name))?;
        let id = Unlocked::from_seed(
            LockedSeed::from_slice(&seed)?,
            &self.name,
            IdentityKind::Local,
        );
        if id.kem.public() != &self.kem || id.sig.public() != &self.sig {
            return Err(Error::bad_credentials());
        }
        Ok(id)
    }
}

// ---------------------------------------------------------------- Enrollment requests

/// Version 2: the proof of possession also covers the credential.
pub const REQUEST_VERSION: u8 = 2;

/// What a new user sends to an administrator (§4.3). Contains no secrets in clear.
#[derive(Clone, Serialize, Deserialize)]
pub struct Request {
    pub version: u8,
    pub name: String,
    pub kind: IdentityKind,
    pub kem: KemPublic,
    pub sig: SigPublic,
    pub credential: Option<PasswordSealed>,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

impl Request {
    pub fn new(id: &Unlocked, credential: Option<PasswordSealed>) -> Request {
        Request {
            version: REQUEST_VERSION,
            name: id.name.clone(),
            kind: id.kind,
            kem: id.kem.public().clone(),
            sig: id.sig.public().clone(),
            proof: id.proof(id.kind, credential.as_ref()),
            credential,
        }
    }

    pub fn to_text(&self) -> String {
        armor("REQUEST", &to_cbor(self))
    }

    pub fn parse(text: &str) -> Result<Request> {
        let r: Request = from_cbor(&dearmor("REQUEST", text)?)?;
        if r.version != REQUEST_VERSION {
            return Err(Error::format(format!(
                "unsupported request version {} (create a new request with this version of nepomuk)",
                r.version
            )));
        }
        Ok(r)
    }

    pub fn fingerprint(&self) -> String {
        crypto::fingerprint(&self.kem, &self.sig)
    }

    pub fn verify(&self) -> Result<()> {
        if !crypto::verify(
            &self.sig,
            "request",
            &proof_data(
                &self.name,
                self.kind,
                &self.kem,
                &self.sig,
                self.credential.as_ref(),
            ),
            &self.proof,
        ) {
            return Err(Error::new(
                Code::SignatureInvalid,
                "the request's proof of possession is invalid",
            ));
        }
        match (self.kind, &self.credential) {
            (IdentityKind::Password, Some(c)) => c.check()?,
            (IdentityKind::Password, None) => {
                return Err(Error::format("password request without credential"));
            }
            (IdentityKind::Local, Some(_)) => {
                return Err(Error::format("local identity request with a credential"));
            }
            (IdentityKind::Local, None) => {}
        }
        crypto::check_kem_public(&self.kem)?;
        Ok(())
    }
}

pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 254
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || "@._+-".contains(c));
    if ok {
        Ok(())
    } else {
        Err(Error::usage(format!("invalid identity name: {name:?}")))
    }
}
