//! Public vault state (§7) and the operations that change it (§8).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::{KemPublic, PasswordSealed, Sealed, SigPublic, Wrapped};

/// A random 128-bit identifier of a vault, user, group, node or grant.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Id(pub [u8; 16]);

impl Id {
    pub fn random() -> Self {
        Id(crate::crypto::random_bytes::<16>())
    }
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
    pub fn parse(s: &str) -> Option<Id> {
        let v = hex::decode(s).ok()?;
        Some(Id(v.try_into().ok()?))
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({})", self.short())
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v: serde_bytes::ByteBuf = Deserialize::deserialize(d)?;
        let a: [u8; 16] = v
            .into_vec()
            .try_into()
            .map_err(|_| serde::de::Error::custom("id must be 16 bytes"))?;
        Ok(Id(a))
    }
}

/// Tree rights (§5.1), ordered from weakest to strongest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Right {
    Read,
    Write,
    Share,
    Admin,
}

impl Right {
    pub fn as_str(self) -> &'static str {
        match self {
            Right::Read => "read",
            Right::Write => "write",
            Right::Share => "share",
            Right::Admin => "admin",
        }
    }
    pub fn parse(s: &str) -> Option<Right> {
        Some(match s {
            "read" => Right::Read,
            "write" => Right::Write,
            "share" => Right::Share,
            "admin" => Right::Admin,
            _ => return None,
        })
    }
}

/// System rights (§5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SysRight {
    Users,
    Groups,
    Audit,
    GroupAdmin(Id),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityKind {
    /// Email + password; the encrypted seed lives in the vault.
    Password,
    /// A local identity file unlocked by a passphrase (CI identities, master).
    Local,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Principal {
    User(Id),
    Group(Id),
}

impl Principal {
    pub fn id(&self) -> Id {
        match self {
            Principal::User(i) | Principal::Group(i) => *i,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: Id,
    /// Email or identity name – only an identifier.
    pub name: String,
    pub kind: IdentityKind,
    pub kem: KemPublic,
    pub sig: SigPublic,
    /// Password identities: the seed encrypted with Argon2id(password).
    pub credential: Option<PasswordSealed>,
    /// Proof of possession: the identity's signature over its request.
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
    pub disabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    pub id: Id,
    pub name: String,
    pub kem: KemPublic,
    /// The group seed wrapped for each member.
    pub members: BTreeMap<Id, Wrapped>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: Id,
    pub parent: Option<Id>,
    /// The node key wrapped under the parent's `wrap_key` (none for the root).
    pub wrapped_key: Option<Sealed>,
    /// Encrypted name (`blob_key`).
    pub name: Sealed,
    /// Commitment to the name, `SHA3(vault, node, name_salt, name)`: lets the holder of a grant
    /// deep in the tree check the path it was given without the ancestors' keys (§6).
    pub name_commit: [u8; 32],
    /// Encrypted, padded content (`blob_key`).
    pub content: Sealed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub id: Id,
    pub node: Id,
    pub to: Principal,
    pub right: Right,
    /// `GrantPayload` wrapped with the hybrid KEM for the recipient.
    pub wrapped: Wrapped,
}

impl Grant {
    /// The public part of a grant (everything except the ciphertext).
    pub fn same_meta(&self, other: &Grant) -> bool {
        self.id == other.id
            && self.node == other.node
            && self.to == other.to
            && self.right == other.right
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub vault_id: Id,
    pub master: Id,
    pub root: Id,
    pub users: BTreeMap<Id, User>,
    pub groups: BTreeMap<Id, Group>,
    pub nodes: BTreeMap<Id, Node>,
    pub grants: BTreeMap<Id, Grant>,
    /// user → system right → `+delegate`
    pub sysrights: BTreeMap<Id, BTreeMap<SysRight, bool>>,
    /// Nodes marked "pending rotation".
    pub rotation: BTreeSet<Id>,
    /// The master before the last `TransferMaster`, until the root is rekeyed: they held every
    /// node key at the time of the transfer (§8.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub former_master: Option<Id>,
    /// Nodes whose keys are still known to principals that lost access to them (a `Revoke` or a
    /// group removal without a `Rekey`, e.g. because its author lacked `admin` on the parent),
    /// until the node is rekeyed or the principal gets access again (§8.1).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rekey_pending: BTreeMap<Id, BTreeSet<Principal>>,
    /// Nodes whose keys are known to replaced identity keys (§4.4), by reason: the id of the
    /// replaced keys, or a group in `stale_groups` that can read the node. Unlike
    /// `rekey_pending`, granting access again never clears them – only a `Rekey` does, and a
    /// rekeyed node a stale group can still read is marked again.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub stale_keys: BTreeMap<Id, BTreeSet<Id>>,
    /// Groups whose current key is held by the replaced keys of a former member, until the
    /// group gets a new key (`RemoveMember`).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub stale_groups: BTreeSet<Id>,
}

/// A node rewritten by a `Rekey`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RekeyedNode {
    pub id: Id,
    pub wrapped_key: Option<Sealed>,
    pub name: Sealed,
    pub name_commit: [u8; 32],
    pub content: Sealed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Op {
    AddUser {
        user: User,
    },
    DisableUser {
        user: Id,
    },
    ReplaceIdentity {
        user: Id,
        kind: IdentityKind,
        kem: KemPublic,
        sig: SigPublic,
        credential: Option<PasswordSealed>,
        #[serde(with = "serde_bytes")]
        proof: Vec<u8>,
    },
    UpdateOwnCredential {
        credential: PasswordSealed,
    },
    /// A user replaces their own keys (§4.4): their grants and group memberships are re-wrapped
    /// for the new keys by themselves; whatever they leave out is dropped.
    RotateOwnKeys {
        kem: KemPublic,
        sig: SigPublic,
        credential: Option<PasswordSealed>,
        #[serde(with = "serde_bytes")]
        proof: Vec<u8>,
        grants: Vec<Grant>,
        memberships: BTreeMap<Id, Wrapped>,
    },
    CreateGroup {
        group: Group,
    },
    AddMember {
        group: Id,
        user: Id,
        wrapped: Wrapped,
    },
    RemoveMember {
        group: Id,
        user: Id,
        kem: KemPublic,
        members: BTreeMap<Id, Wrapped>,
        grants: Vec<Grant>,
    },
    CreateNode {
        node: Node,
    },
    UpdateNode {
        id: Id,
        content: Sealed,
    },
    RenameNode {
        id: Id,
        name: Sealed,
        name_commit: [u8; 32],
        grants: Vec<Grant>,
    },
    MoveNode {
        id: Id,
        parent: Id,
        wrapped_key: Sealed,
        name: Sealed,
        name_commit: [u8; 32],
        grants: Vec<Grant>,
    },
    DeleteNode {
        id: Id,
    },
    Grant {
        grant: Grant,
    },
    Revoke {
        grant: Id,
    },
    Rekey {
        node: Id,
        nodes: Vec<RekeyedNode>,
        grants: Vec<Grant>,
    },
    GrantSystemRight {
        user: Id,
        right: SysRight,
        delegate: bool,
    },
    RevokeSystemRight {
        user: Id,
        right: SysRight,
    },
    MarkRotation {
        node: Id,
    },
    ClearRotation {
        node: Id,
    },
    TransferMaster {
        user: Id,
    },
}

impl Op {
    pub fn name(&self) -> &'static str {
        match self {
            Op::AddUser { .. } => "AddUser",
            Op::DisableUser { .. } => "DisableUser",
            Op::ReplaceIdentity { .. } => "ReplaceIdentity",
            Op::UpdateOwnCredential { .. } => "UpdateOwnCredential",
            Op::RotateOwnKeys { .. } => "RotateOwnKeys",
            Op::CreateGroup { .. } => "CreateGroup",
            Op::AddMember { .. } => "AddMember",
            Op::RemoveMember { .. } => "RemoveMember",
            Op::CreateNode { .. } => "CreateNode",
            Op::UpdateNode { .. } => "UpdateNode",
            Op::RenameNode { .. } => "RenameNode",
            Op::MoveNode { .. } => "MoveNode",
            Op::DeleteNode { .. } => "DeleteNode",
            Op::Grant { .. } => "Grant",
            Op::Revoke { .. } => "Revoke",
            Op::Rekey { .. } => "Rekey",
            Op::GrantSystemRight { .. } => "GrantSystemRight",
            Op::RevokeSystemRight { .. } => "RevokeSystemRight",
            Op::MarkRotation { .. } => "MarkRotation",
            Op::ClearRotation { .. } => "ClearRotation",
            Op::TransferMaster { .. } => "TransferMaster",
        }
    }
}

// ---------------------------------------------------------------- Encrypted payloads

/// Content of a grant, readable only by its recipient (§6).
#[derive(Serialize, Deserialize)]
pub struct GrantPayload {
    #[serde(with = "serde_bytes")]
    pub node_key: Vec<u8>,
    pub path: String,
    /// Name salts of the nodes on the path below the root (outermost first, ending with the
    /// granted node): with the public name commitments they prove `path` (§6).
    pub salts: Vec<serde_bytes::ByteBuf>,
    pub right: Right,
}

impl Drop for GrantPayload {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.node_key);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Field {
    Text {
        value: String,
    },
    Binary {
        mime: String,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
}

impl Field {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Field::Text { value } => value.as_bytes(),
            Field::Binary { data, .. } => data,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Content {
    Folder,
    Text {
        value: String,
    },
    Binary {
        mime: String,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    Record {
        template: String,
        fields: BTreeMap<String, Field>,
    },
}

impl Content {
    pub fn type_name(&self) -> &'static str {
        match self {
            Content::Folder => "folder",
            Content::Text { .. } => "text",
            Content::Binary { .. } => "binary",
            Content::Record { .. } => "record",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub created: i64,
    pub updated: i64,
    /// Certificate validity (templates), unix seconds.
    pub not_after: Option<i64>,
    /// What the folder or secret is for; not secret, but sealed with the rest of the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeContent {
    pub content: Content,
    pub meta: Meta,
}

impl Drop for NodeContent {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match &mut self.content {
            Content::Text { value } => value.zeroize(),
            Content::Binary { data, .. } => data.zeroize(),
            Content::Record { fields, .. } => {
                for f in fields.values_mut() {
                    match f {
                        Field::Text { value } => value.zeroize(),
                        Field::Binary { data, .. } => data.zeroize(),
                    }
                }
            }
            Content::Folder => {}
        }
    }
}
