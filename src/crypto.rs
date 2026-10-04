//! Algorithm suite NPQ-1 (§3): hybrid ML-KEM-1024 + X25519, hybrid ML-DSA-65 + Ed25519,
//! XChaCha20-Poly1305, Argon2id, SHA3-256 / HKDF-SHA3-256.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::Signer;
use hkdf::SimpleHkdf;
use libcrux_ml_dsa::ml_dsa_65;
use libcrux_ml_kem::mlkem1024;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

pub const SUITE: &str = "NPQ-1";

pub const MLKEM_PK_LEN: usize = 1568;
pub const MLDSA_VK_LEN: usize = 1952;
pub const MLDSA_SIG_LEN: usize = 3309;
pub const MLKEM_CT_LEN: usize = 1568;

/// A 256-bit symmetric key that is wiped on drop.
pub type Key32 = Zeroizing<[u8; 32]>;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS CSPRNG unavailable");
    b
}

pub fn random_key() -> Key32 {
    Zeroizing::new(random_bytes::<32>())
}

pub fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// HKDF-SHA3-256 with a domain-separated label.
pub fn hkdf(ikm: &[u8], salt: &[u8], label: &str, out: &mut [u8]) {
    let hk = SimpleHkdf::<Sha3_256>::new(Some(salt), ikm);
    let info = format!("nepomuk/{SUITE}/{label}");
    hk.expand(info.as_bytes(), out).expect("HKDF output length");
}

pub fn derive_key(ikm: &[u8], label: &str) -> Key32 {
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf(ikm, &[], label, out.as_mut());
    out
}

// ---------------------------------------------------------------- AEAD

/// XChaCha20-Poly1305 ciphertext with its random 192-bit nonce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
}

pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Sealed {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = random_bytes::<24>();
    let ct = cipher
        .encrypt(
            &XNonce::try_from(&nonce[..]).unwrap(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AEAD encryption");
    Sealed {
        nonce: nonce.to_vec(),
        ct,
    }
}

pub fn open(key: &[u8; 32], sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.nonce.len() != 24 {
        return Err(Error::decrypt());
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &XNonce::try_from(&sealed.nonce[..]).unwrap(),
            Payload {
                msg: &sealed.ct,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::decrypt())
}

/// Seal with size padding (§3): next power of two, minimum 256 B, above 64 KiB multiples of 64 KiB.
pub fn seal_padded(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Sealed {
    let padded = pad(plaintext);
    seal(key, &padded, aad)
}

pub fn open_padded(key: &[u8; 32], sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let padded = open(key, sealed, aad)?;
    unpad(&padded)
}

pub fn padded_len(n: usize) -> usize {
    const MIN: usize = 256;
    const STEP: usize = 64 * 1024;
    if n <= MIN {
        MIN
    } else if n <= STEP {
        n.next_power_of_two()
    } else {
        n.div_ceil(STEP) * STEP
    }
}

fn pad(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let total = padded_len(data.len() + 4);
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out.resize(total, 0);
    out
}

fn unpad(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < 4 {
        return Err(Error::decrypt());
    }
    let n = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
    if n > data.len() - 4 {
        return Err(Error::decrypt());
    }
    Ok(Zeroizing::new(data[4..4 + n].to_vec()))
}

// ---------------------------------------------------------------- Argon2id

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Default parameters (§3): 256 MiB, t = 3, p = 1.
    pub fn default_params() -> Self {
        if insecure_test_kdf() {
            return KdfParams {
                m_cost: 64,
                t_cost: 1,
                p_cost: 1,
            };
        }
        KdfParams {
            m_cost: 256 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }

    pub fn weaker_than(&self, other: &KdfParams) -> bool {
        self.m_cost < other.m_cost || self.t_cost < other.t_cost
    }

    /// Bounds every client enforces on parameters read from a vault or identity file: a floor
    /// so that a crafted or buggy client cannot enroll a cheaply crackable credential, and a
    /// ceiling so that a crafted file cannot make the client allocate unbounded memory.
    pub fn check(&self) -> Result<()> {
        let (min_m, min_t) = if insecure_test_kdf() {
            (64, 1)
        } else {
            (KDF_MIN_M_COST, KDF_MIN_T_COST)
        };
        if self.m_cost < min_m || self.t_cost < min_t {
            return Err(Error::new(
                crate::error::Code::WeakPassword,
                format!(
                    "Argon2id parameters are too weak (m = {} KiB, t = {}; minimum m = {min_m} KiB, t = {min_t})",
                    self.m_cost, self.t_cost
                ),
            ));
        }
        if self.m_cost > KDF_MAX_M_COST
            || self.t_cost > KDF_MAX_T_COST
            || !(1..=KDF_MAX_P_COST).contains(&self.p_cost)
        {
            return Err(Error::format("Argon2id parameters are out of range"));
        }
        Ok(())
    }
}

/// 64 MiB, t = 2: the floor accepted from a vault (the default is 256 MiB, t = 3).
pub const KDF_MIN_M_COST: u32 = 64 * 1024;
pub const KDF_MIN_T_COST: u32 = 2;
/// 2 GiB, t = 64, p = 16: the ceiling accepted from a vault.
pub const KDF_MAX_M_COST: u32 = 2 * 1024 * 1024;
pub const KDF_MAX_T_COST: u32 = 64;
pub const KDF_MAX_P_COST: u32 = 16;
pub const KDF_SALT_LEN: usize = 16;

/// Cheap Argon2 parameters for the test suite; honoured only in debug builds.
fn insecure_test_kdf() -> bool {
    cfg!(debug_assertions) && std::env::var_os("NEPOMUK_INSECURE_TEST_KDF").is_some()
}

pub fn argon2id(password: &[u8], salt: &[u8], params: &KdfParams) -> Result<Key32> {
    let p = argon2::Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| Error::general(format!("invalid Argon2 parameters: {e}")))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(password, salt, out.as_mut())
        .map_err(|e| Error::general(format!("Argon2id failed: {e}")))?;
    Ok(out)
}

/// A secret encrypted under a password or passphrase via Argon2id.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordSealed {
    pub kdf: KdfParams,
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
    pub sealed: Sealed,
}

pub fn password_seal(password: &[u8], secret: &[u8], aad: &[u8]) -> Result<PasswordSealed> {
    let kdf = KdfParams::default_params();
    let salt = random_bytes::<16>().to_vec();
    let key = argon2id(password, &salt, &kdf)?;
    Ok(PasswordSealed {
        kdf,
        salt,
        sealed: seal(&key, secret, aad),
    })
}

impl PasswordSealed {
    /// Checks the KDF parameters and salt length (see [`KdfParams::check`]).
    pub fn check(&self) -> Result<()> {
        self.kdf.check()?;
        if self.salt.len() != KDF_SALT_LEN {
            return Err(Error::format("Argon2id salt must be 16 bytes"));
        }
        Ok(())
    }
}

pub fn password_open(
    password: &[u8],
    ps: &PasswordSealed,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    ps.check()?;
    let key = argon2id(password, &ps.salt, &ps.kdf)?;
    open(&key, &ps.sealed, aad).map_err(|_| Error::bad_credentials())
}

// ---------------------------------------------------------------- Hybrid keys

/// Public half of a hybrid KEM key pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemPublic {
    #[serde(with = "serde_bytes")]
    pub pq: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ec: Vec<u8>,
}

/// Public half of a hybrid signature key pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigPublic {
    #[serde(with = "serde_bytes")]
    pub pq: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ec: Vec<u8>,
}

pub const KEM_MATERIAL_LEN: usize = 96;

pub struct KemSecret {
    pq: mlkem1024::MlKem1024KeyPair,
    ec: x25519_dalek::StaticSecret,
    public: KemPublic,
}

impl KemSecret {
    /// Deterministically derives a hybrid KEM key pair from a seed.
    pub fn from_seed(seed: &[u8], label: &str) -> Self {
        Self::from_material(&Self::material(seed, label))
    }

    /// What the KEM key pair is generated from (ML-KEM randomness, then the X25519 secret):
    /// enough to decrypt, not to sign, unlike the seed.
    pub fn material(seed: &[u8], label: &str) -> Zeroizing<[u8; KEM_MATERIAL_LEN]> {
        let mut m = Zeroizing::new([0u8; KEM_MATERIAL_LEN]);
        hkdf(seed, &[], &format!("{label}/ml-kem-1024"), &mut m[..64]);
        hkdf(seed, &[], &format!("{label}/x25519"), &mut m[64..]);
        m
    }

    pub fn from_material(m: &[u8; KEM_MATERIAL_LEN]) -> Self {
        let mut pq_rand = Zeroizing::new([0u8; 64]);
        pq_rand.copy_from_slice(&m[..64]);
        let mut ec_bytes = Zeroizing::new([0u8; 32]);
        ec_bytes.copy_from_slice(&m[64..]);
        let pq = mlkem1024::generate_key_pair(*pq_rand);
        let ec = x25519_dalek::StaticSecret::from(*ec_bytes);
        let public = KemPublic {
            pq: pq.public_key().as_slice().to_vec(),
            ec: x25519_dalek::PublicKey::from(&ec).as_bytes().to_vec(),
        };
        KemSecret { pq, ec, public }
    }

    pub fn public(&self) -> &KemPublic {
        &self.public
    }
}

pub struct SigSecret {
    pq: ml_dsa_65::MLDSA65KeyPair,
    ec: ed25519_dalek::SigningKey,
    public: SigPublic,
}

impl SigSecret {
    pub fn from_seed(seed: &[u8], label: &str) -> Self {
        let mut pq_rand = Zeroizing::new([0u8; 32]);
        hkdf(seed, &[], &format!("{label}/ml-dsa-65"), pq_rand.as_mut());
        let mut ec_bytes = Zeroizing::new([0u8; 32]);
        hkdf(seed, &[], &format!("{label}/ed25519"), ec_bytes.as_mut());
        let pq = ml_dsa_65::generate_key_pair(*pq_rand);
        let ec = ed25519_dalek::SigningKey::from_bytes(&ec_bytes);
        let public = SigPublic {
            pq: pq.verification_key.as_slice().to_vec(),
            ec: ec.verifying_key().as_bytes().to_vec(),
        };
        SigSecret { pq, ec, public }
    }

    pub fn public(&self) -> &SigPublic {
        &self.public
    }

    /// `sig = ML-DSA-65.Sign(m) || Ed25519.Sign(m)`, `m = SHA3-256("nepomuk/NPQ-1/<type>" || data)`.
    pub fn sign(&self, kind: &str, data: &[u8]) -> Vec<u8> {
        let m = sig_message(kind, data);
        let pq = ml_dsa_65::sign(&self.pq.signing_key, &m, b"", random_bytes::<32>())
            .expect("ML-DSA signing");
        let ec = self.ec.sign(&m);
        let mut out = pq.as_slice().to_vec();
        out.extend_from_slice(&ec.to_bytes());
        out
    }
}

impl Drop for SigSecret {
    fn drop(&mut self) {
        // libcrux key types are plain arrays; wipe the signing key explicitly.
        self.pq.signing_key.as_ref_mut().zeroize();
    }
}

fn sig_message(kind: &str, data: &[u8]) -> [u8; 32] {
    sha3(&[format!("nepomuk/{SUITE}/{kind}").as_bytes(), data])
}

pub fn verify(public: &SigPublic, kind: &str, data: &[u8], sig: &[u8]) -> bool {
    if sig.len() != MLDSA_SIG_LEN + 64 || public.pq.len() != MLDSA_VK_LEN || public.ec.len() != 32 {
        return false;
    }
    let m = sig_message(kind, data);
    let vk = ml_dsa_65::MLDSA65VerificationKey::new(public.pq.clone().try_into().unwrap());
    let pq_sig = ml_dsa_65::MLDSA65Signature::new(sig[..MLDSA_SIG_LEN].try_into().unwrap());
    if ml_dsa_65::verify(&vk, &m, b"", &pq_sig).is_err() {
        return false;
    }
    let Ok(ec_vk) =
        ed25519_dalek::VerifyingKey::from_bytes(public.ec.as_slice().try_into().unwrap())
    else {
        return false;
    };
    let ec_sig = ed25519_dalek::Signature::from_bytes(sig[MLDSA_SIG_LEN..].try_into().unwrap());
    ec_vk.verify_strict(&m, &ec_sig).is_ok()
}

// ---------------------------------------------------------------- Hybrid KEM wrap

/// A secret wrapped for a recipient with the X-Wing-style hybrid KEM (§3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wrapped {
    #[serde(with = "serde_bytes")]
    pub ct_pq: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub eph: Vec<u8>,
    pub sealed: Sealed,
}

fn kem_combine(ss_pq: &[u8], ss_ec: &[u8], ct_pq: &[u8], eph: &[u8], pk: &KemPublic) -> Key32 {
    let ikm = Zeroizing::new([ss_pq, ss_ec].concat());
    let salt = [ct_pq, eph, &sha3(&[&pk.pq]), &pk.ec].concat();
    let mut kek = Zeroizing::new([0u8; 32]);
    hkdf(&ikm, &salt, "kem", kek.as_mut());
    kek
}

pub fn wrap(recipient: &KemPublic, secret: &[u8], aad: &[u8]) -> Result<Wrapped> {
    let pk_pq: [u8; MLKEM_PK_LEN] = recipient
        .pq
        .as_slice()
        .try_into()
        .map_err(|_| Error::format("bad ML-KEM public key"))?;
    let pk_pq = mlkem1024::MlKem1024PublicKey::from(pk_pq);
    if !mlkem1024::validate_public_key(&pk_pq) {
        return Err(Error::format("invalid ML-KEM public key"));
    }
    let pk_ec: [u8; 32] = recipient
        .ec
        .as_slice()
        .try_into()
        .map_err(|_| Error::format("bad X25519 public key"))?;
    let (ct_pq, ss_pq) = mlkem1024::encapsulate(&pk_pq, random_bytes::<32>());
    let ss_pq = Zeroizing::new(ss_pq);
    let eph_sk = x25519_dalek::StaticSecret::from(random_bytes::<32>());
    let eph_pk = x25519_dalek::PublicKey::from(&eph_sk);
    let ss_ec = eph_sk.diffie_hellman(&x25519_dalek::PublicKey::from(pk_ec));
    let kek = kem_combine(
        ss_pq.as_ref(),
        ss_ec.as_bytes(),
        ct_pq.as_ref(),
        eph_pk.as_bytes(),
        recipient,
    );
    Ok(Wrapped {
        ct_pq: ct_pq.as_ref().to_vec(),
        eph: eph_pk.as_bytes().to_vec(),
        sealed: seal(&kek, secret, aad),
    })
}

pub fn unwrap(me: &KemSecret, w: &Wrapped, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let ct: [u8; MLKEM_CT_LEN] = w
        .ct_pq
        .as_slice()
        .try_into()
        .map_err(|_| Error::decrypt())?;
    let eph: [u8; 32] = w.eph.as_slice().try_into().map_err(|_| Error::decrypt())?;
    let ss_pq = Zeroizing::new(mlkem1024::decapsulate(
        me.pq.private_key(),
        &mlkem1024::MlKem1024Ciphertext::from(ct),
    ));
    let ss_ec = me.ec.diffie_hellman(&x25519_dalek::PublicKey::from(eph));
    let kek = kem_combine(
        ss_pq.as_ref(),
        ss_ec.as_bytes(),
        &w.ct_pq,
        &w.eph,
        &me.public,
    );
    open(&kek, &w.sealed, aad)
}

// ---------------------------------------------------------------- Fingerprints

/// `npk1…` fingerprint (bech32 of SHA3-256 over the length-prefixed public keys).
pub fn fingerprint(kem: &KemPublic, sig: &SigPublic) -> String {
    let digest = sha3(&[
        b"nepomuk/fp/v2",
        &framed(&[&kem.pq, &kem.ec, &sig.pq, &sig.ec]),
    ]);
    bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse("npk").unwrap(), &digest).unwrap()
}

/// Concatenation with a 4-byte big-endian length before each part (unambiguous encoding).
pub fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// Checks the lengths of a hybrid KEM public key and that its ML-KEM part is well formed.
pub fn check_kem_public(k: &KemPublic) -> Result<()> {
    let pq: [u8; MLKEM_PK_LEN] =
        k.pq.as_slice()
            .try_into()
            .map_err(|_| Error::format("bad ML-KEM public key"))?;
    if !mlkem1024::validate_public_key(&mlkem1024::MlKem1024PublicKey::from(pq)) {
        return Err(Error::format("invalid ML-KEM public key"));
    }
    if k.ec.len() != 32 {
        return Err(Error::format("bad X25519 public key"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let s = SigSecret::from_seed(&[7u8; 64], "id");
        let sig = s.sign("commit", b"hello");
        assert!(verify(s.public(), "commit", b"hello", &sig));
        assert!(!verify(s.public(), "commit", b"hellO", &sig));
        assert!(!verify(s.public(), "checkpoint", b"hello", &sig));
        let mut bad = sig.clone();
        bad[MLDSA_SIG_LEN + 3] ^= 1;
        assert!(!verify(s.public(), "commit", b"hello", &bad));
        let mut bad = sig;
        bad[10] ^= 1;
        assert!(!verify(s.public(), "commit", b"hello", &bad));
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let k = KemSecret::from_seed(&[9u8; 64], "id");
        let w = wrap(k.public(), b"secret key", b"aad").unwrap();
        assert_eq!(&unwrap(&k, &w, b"aad").unwrap()[..], b"secret key");
        assert!(unwrap(&k, &w, b"other").is_err());
        let other = KemSecret::from_seed(&[1u8; 64], "id");
        assert!(unwrap(&other, &w, b"aad").is_err());
    }

    #[test]
    fn padding() {
        assert_eq!(padded_len(0), 256);
        assert_eq!(padded_len(257), 512);
        assert_eq!(padded_len(65536), 65536);
        assert_eq!(padded_len(65537), 131072);
        assert_eq!(padded_len(200_000), 4 * 65536);
        let k = random_key();
        let s = seal_padded(&k, b"abc", b"");
        assert_eq!(s.ct.len(), 256 + 16);
        assert_eq!(&open_padded(&k, &s, b"").unwrap()[..], b"abc");
    }
}
