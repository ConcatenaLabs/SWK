//! Signatures for `OP_CHECKSIGFROMSTACK` over the Arca messages.
//!
//! An Arca script builds the message it verifies from what it can see: the
//! coin being spent, the outputs being created, a time, the chain. A signer for
//! such a script must therefore never sign a bare 32-byte hash, because a hash
//! says nothing a person can check. [`SwSigner::sign_csfs`] takes the message
//! as its fields, rebuilds the digest from them, refuses when the digest the
//! caller presents is not that one, and only then signs. The fields are what a
//! wallet shows before asking for approval ([`ArcaMessage::describe`]).
//!
//! Three messages are defined, as the Arca specification freezes them:
//!
//! | Message | Digest |
//! |---|---|
//! | [`RebindMessage`], the leaf's collaborative path | `SHA256(K ‖ asset_in ‖ 0x01 ‖ 0x01 ‖ value_in(8, LE) ‖ m ‖ SHA256(record 0) ‖ … ‖ SHA256(record m-1))` with `K = SHA256(SHA256("ArcaRbd1" ‖ genesis) ‖ salt)` |
//! | [`UnrollAuthorisation`], a member's consent to unroll a node | `SHA256("Arca/unroll" ‖ H ‖ t)`, `t` minimally encoded as a script number |
//! | [`ReleaseMessage`], an owner's release of a lowest node | `SHA256("Arca/release" ‖ genesis ‖ H)` |
//!
//! `H` is the SHA256 of the node's children's records in order. A record is the
//! form introspection gives an explicit output: `asset(32) ‖ 0x01 ‖ 0x01 ‖
//! value(8, LE) ‖ program ‖ (witness version + 2)`, where a script that is not
//! a witness program contributes its SHA256 and version −1. The genesis hash and
//! asset ids enter every message in internal byte order, the reverse of the
//! display hex `getblockhash` prints; the types here carry that order, so a
//! caller who parses display hex into them gets it right.
//!
//! Signatures are BIP340 over the 32-byte digest with no auxiliary randomness.
//!
//! # What the signer checks for a rebind
//!
//! A rebindable signature pair binds a coin's asset and amount, not its
//! outpoint, and the outputs it commits to account for only part of the coin:
//! whatever they leave uncommitted goes to whoever broadcasts the transaction.
//! So a rebind names the output it spends ([`RebindSource`]): the path (a
//! leaf's collaborative path, a checkpoint's, or one of `htlc-1`'s), the id of
//! the leaf, and the salt and chain that make the script's constant `K`. With
//! the `ark` feature it is built from the leaf's record
//! ([`RebindSource::leaf`]), and the signer then also checks that the
//! signing key is the record's owner key and that the coin is the record's
//! asset and value. [`SwSigner::sign_csfs`] takes a [`CsfsPolicy`] and
//! refuses a message for another chain than the wallet's and a rebind that
//! leaves more of the coin uncommitted than the policy's ceiling, by default
//! the specification's fee margin: four times the relay floor for the spend.
//! [`ArcaMessage::describe`] names the leaf, the path, and the amount in each
//! asset left to whoever broadcasts.

use elements_miniscript::elements::{
    bitcoin::bip32::{self, DerivationPath},
    encode::serialize,
    hashes::{sha256, Hash},
    secp256k1_zkp::{schnorr, Message, Secp256k1, Verification, XOnlyPublicKey},
    AssetId, BlockHash, Script,
};

use crate::SwSigner;

/// The tag folded into the leaf constant `K`.
pub const REBIND_TAG: &[u8] = b"ArcaRbd1";
/// The tag that begins an unroll authorisation.
pub const UNROLL_TAG: &[u8] = b"Arca/unroll";
/// The tag that begins a release.
pub const RELEASE_TAG: &[u8] = b"Arca/release";
/// The most outputs a leaf's collaborative path commits to.
pub const MAX_COMMITTED_OUTPUTS: usize = 4;
/// The largest stack element a script can build with `OP_CAT`, which caps the
/// children records a node's script concatenates.
pub const MAX_SCRIPT_ELEMENT: usize = 520;
/// Lock times at or above this value are median times, below it heights.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Errors from building or signing an Arca message.
#[derive(thiserror::Error, Debug)]
pub enum CsfsError {
    /// The digest presented is not the digest of the message's fields.
    #[error("digest {given} does not match the message, whose digest is {computed}")]
    DigestMismatch {
        /// The digest the caller presented.
        given: String,
        /// The digest rebuilt from the fields.
        computed: String,
    },

    /// A collaborative spend commits to no output, or to more than the script allows.
    #[error("a collaborative spend commits to 1 to {MAX_COMMITTED_OUTPUTS} outputs, not {0}")]
    OutputCount(usize),

    /// A node has no children.
    #[error("a node has at least one child")]
    NoChildren,

    /// The children's records are longer than a script can concatenate.
    #[error("the children's records are {0} bytes; a node's script concatenates at most {MAX_SCRIPT_ELEMENT}")]
    ChildrenTooLong(usize),

    /// The authorisation time is a height, not a median time.
    #[error("the authorisation time {0} is below {LOCKTIME_THRESHOLD}, so it would be a height, not a median time")]
    NotATime(u32),

    /// The signature does not verify.
    #[error("the signature does not verify for key {0}")]
    BadSignature(XOnlyPublicKey),

    /// The message is for another chain than the wallet's.
    #[error("the message is for the chain with genesis {message}, not this wallet's ({wallet})")]
    WrongChain {
        /// The genesis hash in the message, display hex.
        message: String,
        /// The wallet's genesis hash, display hex.
        wallet: String,
    },

    /// A rebind leaves more of the coin uncommitted than the ceiling.
    #[error("the committed outputs leave {uncommitted} atoms of asset {asset} uncommitted, for whoever broadcasts; the ceiling is {ceiling}")]
    AboveCeiling {
        /// The spent coin's asset, display hex.
        asset: String,
        /// The atoms left uncommitted.
        uncommitted: u64,
        /// The most the policy allows.
        ceiling: u64,
    },

    /// The signing key is not the owner key of the leaf's record.
    #[error("the key {key} is not the owner key {owner} of the leaf's record")]
    NotOwner {
        /// The key at the signing path, hex.
        key: String,
        /// The record's owner key, hex.
        owner: String,
    },

    /// The coin is not the one the leaf's record holds.
    #[error("the coin is {value_in} atoms of asset {asset_in}, but the leaf's record holds {value} atoms of asset {asset}")]
    NotTheLeafCoin {
        /// The message's coin asset, display hex.
        asset_in: String,
        /// The message's coin value.
        value_in: u64,
        /// The record's asset, display hex.
        asset: String,
        /// The record's value.
        value: u64,
    },

    /// The leaf's record cannot be read or rebuilt.
    #[error("the leaf's record: {0}")]
    Record(String),

    /// The path is not one a rebindable message can be for.
    #[error("unknown rebindable path {0:?} (leaf, checkpoint, htlc-claim, htlc-claim-both, htlc-refund-both)")]
    Path(String),

    /// Key derivation failed.
    #[error(transparent)]
    Bip32(#[from] bip32::Error),
}

/// An explicit output as an Arca script commits to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedOutput {
    /// The output's explicit asset.
    pub asset: AssetId,
    /// The output's explicit value, in atoms.
    pub value: u64,
    /// The output's scriptPubKey.
    pub script_pubkey: Script,
}

impl CommittedOutput {
    /// The output's record, exactly as the introspection opcodes leave it.
    pub fn record(&self) -> Vec<u8> {
        let mut r = serialize(&self.asset);
        r.push(0x01);
        r.push(0x01);
        r.extend_from_slice(&self.value.to_le_bytes());
        let (program, version) = witness_program(&self.script_pubkey);
        r.extend_from_slice(&program);
        r.push((version + 2) as u8);
        r
    }
}

/// The program and version `OP_INSPECTOUTPUTSCRIPTPUBKEY` pushes: the witness
/// program and its version for a witness output, otherwise the script's
/// SHA256 and −1. The rule is the node's `IsWitnessProgram`.
fn witness_program(spk: &Script) -> (Vec<u8>, i8) {
    let b = spk.as_bytes();
    let is_program = (4..=42).contains(&b.len())
        && (b[0] == 0x00 || (0x51..=0x60).contains(&b[0]))
        && b[1] as usize + 2 == b.len();
    if is_program {
        let version = if b[0] == 0 { 0 } else { (b[0] - 0x50) as i8 };
        (b[2..].to_vec(), version)
    } else {
        (sha256::Hash::hash(b).to_byte_array().to_vec(), -1)
    }
}

/// The rebindable paths of the Arca outputs a wallet holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RebindPath {
    /// A `vtxo-1` leaf's collaborative path, owner and operator.
    Leaf,
    /// A checkpoint's collaborative path, sender and operator.
    Checkpoint,
    /// `htlc-1`'s claim with the preimage, signed by the claimer alone.
    HtlcClaim,
    /// `htlc-1`'s claim with the preimage and both signatures.
    HtlcClaimBoth,
    /// `htlc-1`'s refund after the timeout, with both signatures.
    HtlcRefundBoth,
}

impl RebindPath {
    /// The path's name: `leaf`, `checkpoint`, `htlc-claim`, `htlc-claim-both`
    /// or `htlc-refund-both`.
    pub fn name(self) -> &'static str {
        match self {
            RebindPath::Leaf => "leaf",
            RebindPath::Checkpoint => "checkpoint",
            RebindPath::HtlcClaim => "htlc-claim",
            RebindPath::HtlcClaimBoth => "htlc-claim-both",
            RebindPath::HtlcRefundBoth => "htlc-refund-both",
        }
    }

    /// The path with this [`RebindPath::name`].
    pub fn from_name(name: &str) -> Result<RebindPath, CsfsError> {
        [
            RebindPath::Leaf,
            RebindPath::Checkpoint,
            RebindPath::HtlcClaim,
            RebindPath::HtlcClaimBoth,
            RebindPath::HtlcRefundBoth,
        ]
        .into_iter()
        .find(|p| p.name() == name)
        .ok_or_else(|| CsfsError::Path(name.to_string()))
    }

    fn what(self) -> &'static str {
        match self {
            RebindPath::Leaf => "the collaborative path of the Arca leaf",
            RebindPath::Checkpoint => "the collaborative path of a checkpoint from the Arca leaf",
            RebindPath::HtlcClaim => "the htlc-1 claim path, with the preimage, of an output from the Arca leaf",
            RebindPath::HtlcClaimBoth => {
                "the htlc-1 claim path with the preimage and both signatures, of an output from the Arca leaf"
            }
            RebindPath::HtlcRefundBoth => {
                "the htlc-1 refund path with both signatures, of an output from the Arca leaf"
            }
        }
    }

    /// The size in vbytes of a spend through this path that commits to `m`
    /// outputs and pays its fee from the margin, as measured on regtest: a
    /// leaf or checkpoint 280 vB for one output and 79 vB more for each
    /// further one; `htlc-1` 259, 284 and 267 vB. The fee margin is reckoned
    /// on it.
    pub fn spend_vsize(self, m: usize) -> u64 {
        let extra = 79 * (m.max(1) as u64 - 1);
        match self {
            RebindPath::Leaf | RebindPath::Checkpoint => 280 + extra,
            RebindPath::HtlcClaim => 259 + extra,
            RebindPath::HtlcClaimBoth => 284 + extra,
            RebindPath::HtlcRefundBoth => 267 + extra,
        }
    }
}

/// What the leaf's record says the leaf is.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordCoin {
    owner: XOnlyPublicKey,
    asset: AssetId,
    value: u64,
}

/// The output a rebindable message spends, named so a person can tell it from
/// any other: the path, the id of the leaf it is (or comes from), and the salt
/// and chain that make the script's constant `K`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebindSource {
    path: RebindPath,
    leaf_id: [u8; 32],
    genesis_hash: BlockHash,
    salt: [u8; 32],
    record: Option<RecordCoin>,
}

impl RebindSource {
    /// A rebindable path named by its leaf's id, with the salt and chain of the
    /// output being spent. For a checkpoint or an `htlc-1` output, `leaf_id`
    /// is the id of the leaf it was made from and `salt` the output's own.
    pub fn new(
        path: RebindPath,
        leaf_id: [u8; 32],
        genesis_hash: BlockHash,
        salt: [u8; 32],
    ) -> Self {
        RebindSource {
            path,
            leaf_id,
            genesis_hash,
            salt,
            record: None,
        }
    }

    /// A leaf's collaborative path, from the leaf's record. The id, the salt
    /// and the chain come from the record, and [`SwSigner::sign_csfs`] also
    /// checks that the signing key is the record's owner key and that the coin
    /// is the record's asset and value.
    #[cfg(feature = "ark")]
    pub fn leaf(record: &arca_covenant::LeafRecord) -> Result<Self, CsfsError> {
        let id = record
            .leaf_id()
            .map_err(|e| CsfsError::Record(e.to_string()))?;
        Ok(RebindSource {
            path: RebindPath::Leaf,
            leaf_id: id.0,
            genesis_hash: record.chain.genesis_hash(),
            salt: record.salt(),
            record: Some(RecordCoin {
                owner: record.owner,
                asset: record.asset,
                value: record.value,
            }),
        })
    }

    /// The path.
    pub fn path(&self) -> RebindPath {
        self.path
    }

    /// The leaf's id.
    pub fn leaf_id(&self) -> [u8; 32] {
        self.leaf_id
    }

    /// The genesis hash of the chain the output lives on.
    pub fn genesis_hash(&self) -> BlockHash {
        self.genesis_hash
    }

    /// The salt of the output being spent.
    pub fn salt(&self) -> [u8; 32] {
        self.salt
    }

    /// `K`, the constant the script pushes.
    pub fn leaf_constant(&self) -> [u8; 32] {
        leaf_constant(&self.genesis_hash, &self.salt)
    }

    /// True when built from the leaf's record.
    pub fn from_record(&self) -> bool {
        self.record.is_some()
    }
}

/// The spend of an Arca output through a rebindable path, which the parties
/// each sign: the coin being spent and the outputs it may move into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebindMessage {
    /// The output being spent and its path.
    pub source: RebindSource,
    /// The asset of the coin being spent.
    pub asset_in: AssetId,
    /// The value of the coin being spent, in atoms.
    pub value_in: u64,
    /// The outputs at indices `0..m`, in order.
    pub outputs: Vec<CommittedOutput>,
}

impl RebindMessage {
    /// The atoms of the coin's asset that the committed outputs leave
    /// uncommitted. Whoever broadcasts the transaction takes them, as its fee
    /// or as an output of their own.
    pub fn uncommitted(&self) -> u64 {
        let committed: u128 = self
            .outputs
            .iter()
            .filter(|o| o.asset == self.asset_in)
            .map(|o| o.value as u128)
            .sum();
        (self.value_in as u128).saturating_sub(committed) as u64
    }

    /// What the committed outputs take in each asset, the coin's asset first.
    pub fn committed_by_asset(&self) -> Vec<(AssetId, u128)> {
        let mut out: Vec<(AssetId, u128)> = vec![(self.asset_in, 0)];
        for o in &self.outputs {
            match out.iter_mut().find(|(a, _)| *a == o.asset) {
                Some((_, v)) => *v += o.value as u128,
                None => out.push((o.asset, o.value as u128)),
            }
        }
        out
    }
}

/// The specification's multiple of the relay floor that a pre-signed spend
/// leaves uncommitted as its fee.
pub const FEE_MARGIN_MULTIPLE: u64 = 4;

/// The specification's fee margin: four times the relay floor for a spend of
/// `vsize` vbytes, where `floor_per_kvb` is the floor in atoms of the spent
/// coin's asset per 1,000 vbytes, as the wallet's node values that asset.
pub fn fee_margin(floor_per_kvb: u64, vsize: u64) -> u64 {
    let floor = (vsize as u128 * floor_per_kvb as u128).div_ceil(1000);
    (floor * FEE_MARGIN_MULTIPLE as u128).min(u64::MAX as u128) as u64
}

/// How much of a coin a rebind may leave uncommitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceiling {
    /// The specification's fee margin for the spend ([`fee_margin`] at
    /// [`RebindPath::spend_vsize`]), at this relay floor in atoms of the
    /// spent coin's asset per 1,000 vbytes.
    FeeMargin {
        /// The relay floor, atoms of the coin's asset per 1,000 vbytes.
        floor_per_kvb: u64,
    },
    /// At most this many atoms of the spent coin's asset.
    Atoms(u64),
}

/// What [`SwSigner::sign_csfs`] accepts: the wallet's chain, and how much of a
/// coin a rebind may leave to whoever broadcasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsfsPolicy {
    /// The genesis hash of the wallet's network. A rebind or a release for
    /// any other chain is refused.
    pub genesis_hash: BlockHash,
    /// The ceiling on what a rebind leaves uncommitted.
    pub ceiling: Ceiling,
}

impl CsfsPolicy {
    /// The default: the wallet's chain, and the specification's fee margin at
    /// the relay floor the wallet's node gives the coin's asset.
    pub fn new(genesis_hash: BlockHash, floor_per_kvb: u64) -> Self {
        CsfsPolicy {
            genesis_hash,
            ceiling: Ceiling::FeeMargin { floor_per_kvb },
        }
    }

    /// The wallet's chain and a ceiling in atoms the caller sets.
    pub fn with_ceiling(genesis_hash: BlockHash, atoms: u64) -> Self {
        CsfsPolicy {
            genesis_hash,
            ceiling: Ceiling::Atoms(atoms),
        }
    }

    /// The most `message` may leave uncommitted.
    pub fn ceiling_for(&self, message: &RebindMessage) -> u64 {
        match self.ceiling {
            Ceiling::Atoms(a) => a,
            Ceiling::FeeMargin { floor_per_kvb } => fee_margin(
                floor_per_kvb,
                message.source.path.spend_vsize(message.outputs.len()),
            ),
        }
    }
}

/// A member's authorisation to unroll a node: the children the node must
/// create, and the median time before which the authorisation cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnrollAuthorisation {
    /// The node's children, in output order.
    pub children: Vec<CommittedOutput>,
    /// The median time `t`, at or above [`LOCKTIME_THRESHOLD`].
    pub time: u32,
}

/// An owner's release of a lowest node, which lets the operator reclaim it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseMessage {
    /// The genesis hash of the chain the node lives on.
    pub genesis_hash: BlockHash,
    /// The node's children, in output order.
    pub children: Vec<CommittedOutput>,
}

/// One of the three messages an Arca script verifies with
/// `OP_CHECKSIGFROMSTACK`.
// A rebind carries its source; messages are made one at a time, so the size
// of the largest variant costs nothing worth a box in every caller.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArcaMessage {
    /// The leaf's collaborative path.
    Rebind(RebindMessage),
    /// The unroll authorisation of a gated node.
    Unroll(UnrollAuthorisation),
    /// The release of a lowest node.
    Release(ReleaseMessage),
}

fn sha(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

/// `SHA256("ArcaRbd1" ‖ genesis)`, the part of `K` shared by every leaf on a chain.
pub fn chain_tag(genesis_hash: &BlockHash) -> [u8; 32] {
    let mut d = REBIND_TAG.to_vec();
    d.extend_from_slice(genesis_hash.as_byte_array());
    sha(&d)
}

/// `K = SHA256(chain_tag ‖ salt)`, the 32-byte constant in a leaf's script.
pub fn leaf_constant(genesis_hash: &BlockHash, leaf_salt: &[u8; 32]) -> [u8; 32] {
    let mut d = chain_tag(genesis_hash).to_vec();
    d.extend_from_slice(leaf_salt);
    sha(&d)
}

/// `H`, the SHA256 of a node's children's records in order. Refuses an empty
/// node and records longer than a node's script can concatenate.
pub fn children_hash(children: &[CommittedOutput]) -> Result<[u8; 32], CsfsError> {
    if children.is_empty() {
        return Err(CsfsError::NoChildren);
    }
    let records: Vec<u8> = children.iter().flat_map(CommittedOutput::record).collect();
    if records.len() > MAX_SCRIPT_ELEMENT {
        return Err(CsfsError::ChildrenTooLong(records.len()));
    }
    Ok(sha(&records))
}

/// The minimal script-number encoding of `n`: the bytes the stack element
/// holds, without a push prefix.
pub fn script_number(n: i64) -> Vec<u8> {
    let mut out = vec![];
    let neg = n < 0;
    let mut a = n.unsigned_abs();
    while a > 0 {
        out.push((a & 0xff) as u8);
        a >>= 8;
    }
    if let Some(last) = out.last_mut() {
        if *last & 0x80 != 0 {
            out.push(if neg { 0x80 } else { 0 });
        } else if neg {
            *last |= 0x80;
        }
    }
    out
}

impl ArcaMessage {
    /// The bytes the digest is the SHA256 of, after checking the fields are
    /// ones a script can produce.
    pub fn preimage(&self) -> Result<Vec<u8>, CsfsError> {
        match self {
            ArcaMessage::Rebind(m) => {
                let n = m.outputs.len();
                if n == 0 || n > MAX_COMMITTED_OUTPUTS {
                    return Err(CsfsError::OutputCount(n));
                }
                let mut p = m.source.leaf_constant().to_vec();
                p.extend_from_slice(&serialize(&m.asset_in));
                p.push(0x01);
                p.push(0x01);
                p.extend_from_slice(&m.value_in.to_le_bytes());
                p.push(n as u8);
                for o in &m.outputs {
                    p.extend_from_slice(&sha(&o.record()));
                }
                Ok(p)
            }
            ArcaMessage::Unroll(m) => {
                if m.time < LOCKTIME_THRESHOLD {
                    return Err(CsfsError::NotATime(m.time));
                }
                let mut p = UNROLL_TAG.to_vec();
                p.extend_from_slice(&children_hash(&m.children)?);
                p.extend_from_slice(&script_number(m.time as i64));
                Ok(p)
            }
            ArcaMessage::Release(m) => {
                let mut p = RELEASE_TAG.to_vec();
                p.extend_from_slice(m.genesis_hash.as_byte_array());
                p.extend_from_slice(&children_hash(&m.children)?);
                Ok(p)
            }
        }
    }

    /// The 32-byte digest the script verifies the signature against.
    pub fn digest(&self) -> Result<[u8; 32], CsfsError> {
        Ok(sha(&self.preimage()?))
    }

    /// The message's kind, as a short name.
    pub fn kind(&self) -> &'static str {
        match self {
            ArcaMessage::Rebind(_) => "rebind",
            ArcaMessage::Unroll(_) => "unroll",
            ArcaMessage::Release(_) => "release",
        }
    }

    /// What signing this message authorises, in plain words, one line per
    /// fact, for a wallet to show before it asks for approval. Asset ids and
    /// the genesis hash are in display hex.
    pub fn describe(&self) -> Vec<String> {
        fn out_line(i: usize, o: &CommittedOutput) -> String {
            format!(
                "output {i}: {} atoms of asset {} to script {}",
                o.value,
                o.asset,
                hex(o.script_pubkey.as_bytes())
            )
        }
        match self {
            ArcaMessage::Rebind(m) => {
                let src = &m.source;
                let mut v = vec![
                    format!(
                        "Spend {} {} (path {}), on the chain with genesis {}: a coin of {} atoms of asset {}.",
                        src.path.what(),
                        hex(&src.leaf_id),
                        src.path.name(),
                        src.genesis_hash,
                        m.value_in,
                        m.asset_in
                    ),
                    format!(
                        "It may move only into a transaction whose first {} outputs are exactly:",
                        m.outputs.len()
                    ),
                ];
                v.extend(m.outputs.iter().enumerate().map(|(i, o)| out_line(i, o)));
                for (asset, committed) in m.committed_by_asset() {
                    v.push(if asset != m.asset_in {
                        format!(
                            "Of asset {asset}, the committed outputs take {committed} atoms, which other inputs must pay; this coin holds none and leaves none uncommitted."
                        )
                    } else if committed >= m.value_in as u128 {
                        format!(
                            "Of asset {asset}, the committed outputs take {committed} atoms, the whole coin: none of it is left to whoever broadcasts."
                        )
                    } else {
                        format!(
                            "Of asset {asset}, the committed outputs take {committed} atoms and leave {} atoms uncommitted: whoever broadcasts the transaction takes them, as its fee or otherwise.",
                            m.uncommitted()
                        )
                    });
                }
                v.push(format!(
                    "The signature is valid for any coin of {} atoms of asset {} under this script; the leaf's salt {} makes the script unique to it.",
                    m.value_in,
                    m.asset_in,
                    hex(&src.salt)
                ));
                v
            }
            ArcaMessage::Unroll(m) => {
                let mut v = vec![format!(
                    "Authorise unrolling the Arca node with these {} children, usable by whoever holds it from median time {}:",
                    m.children.len(),
                    m.time
                )];
                v.extend(m.children.iter().enumerate().map(|(i, o)| out_line(i, o)));
                v
            }
            ArcaMessage::Release(m) => {
                let mut v = vec![format!(
                    "Release the Arca node with these {} children on the chain with genesis {}, so the operator may reclaim it now:",
                    m.children.len(),
                    m.genesis_hash
                )];
                v.extend(m.children.iter().enumerate().map(|(i, o)| out_line(i, o)));
                v
            }
        }
    }

    /// Verify a 64-byte BIP340 signature by `key` over this message.
    pub fn verify<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        key: &XOnlyPublicKey,
        signature: &[u8],
    ) -> Result<(), CsfsError> {
        let sig =
            schnorr::Signature::from_slice(signature).map_err(|_| CsfsError::BadSignature(*key))?;
        let msg = Message::from_digest(self.digest()?);
        secp.verify_schnorr(&sig, &msg, key)
            .map_err(|_| CsfsError::BadSignature(*key))
    }
}

fn hex(b: &[u8]) -> String {
    use elements_miniscript::elements::hex::ToHex;
    b.to_hex()
}

impl SwSigner {
    /// Sign an Arca message with the key at `path`, for
    /// `OP_CHECKSIGFROMSTACK`.
    ///
    /// `digest` is the hash the caller expects to be signed. The signer
    /// rebuilds it from the message's fields and refuses when the two differ,
    /// or when the fields are not ones a script can produce, so it never signs
    /// a hash whose meaning it has not checked. Returns a 64-byte BIP340
    /// signature made with no auxiliary randomness.
    ///
    /// `policy` names the wallet's chain, and a rebind or a release for any
    /// other chain is refused. A rebind is refused when it leaves more of the
    /// coin uncommitted than the policy's ceiling; when it was built from the
    /// leaf's record, also when the key at `path` is not the record's owner key
    /// or the coin is not the record's asset and value.
    pub fn sign_csfs(
        &self,
        path: &DerivationPath,
        message: &ArcaMessage,
        digest: &[u8; 32],
        policy: &CsfsPolicy,
    ) -> Result<schnorr::Signature, CsfsError> {
        let computed = message.digest()?;
        if &computed != digest {
            return Err(CsfsError::DigestMismatch {
                given: hex(digest),
                computed: hex(&computed),
            });
        }
        let chain = match message {
            ArcaMessage::Rebind(m) => Some(m.source.genesis_hash),
            ArcaMessage::Release(m) => Some(m.genesis_hash),
            ArcaMessage::Unroll(_) => None,
        };
        if let Some(g) = chain {
            if g != policy.genesis_hash {
                return Err(CsfsError::WrongChain {
                    message: g.to_string(),
                    wallet: policy.genesis_hash.to_string(),
                });
            }
        }
        let derived = self.xprv.derive_priv(&self.secp, path)?;
        let keypair = derived.to_keypair(&self.secp);
        if let ArcaMessage::Rebind(m) = message {
            if let Some(r) = &m.source.record {
                let (key, _) = keypair.x_only_public_key();
                if key != r.owner {
                    return Err(CsfsError::NotOwner {
                        key: key.to_string(),
                        owner: r.owner.to_string(),
                    });
                }
                if m.asset_in != r.asset || m.value_in != r.value {
                    return Err(CsfsError::NotTheLeafCoin {
                        asset_in: m.asset_in.to_string(),
                        value_in: m.value_in,
                        asset: r.asset.to_string(),
                        value: r.value,
                    });
                }
            }
            let ceiling = policy.ceiling_for(m);
            let uncommitted = m.uncommitted();
            if uncommitted > ceiling {
                return Err(CsfsError::AboveCeiling {
                    asset: m.asset_in.to_string(),
                    uncommitted,
                    ceiling,
                });
            }
        }
        Ok(self
            .secp
            .sign_schnorr_no_aux_rand(&Message::from_digest(computed), &keypair))
    }
}

#[cfg(test)]
mod tests {
    // The Arca golden vectors (see `tapscript.rs`): every collaborative,
    // unroll and release message in them is rebuilt here from its fields and
    // signed again with its test key; both must match byte for byte.

    use std::str::FromStr;

    use elements_miniscript::elements::{
        bitcoin::{
            bip32::{ChainCode, ChildNumber, Fingerprint, Xpriv},
            NetworkKind,
        },
        confidential,
        encode::deserialize,
        hex::{FromHex, ToHex},
        secp256k1_zkp::SecretKey,
        Transaction, TxOut,
    };
    use serde_json::Value;

    use super::*;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../test_data/arca_vectors.json")).unwrap()
    }

    fn bytes(s: &Value) -> Vec<u8> {
        Vec::<u8>::from_hex(s.as_str().unwrap()).unwrap()
    }

    fn signer_for(secret_hex: &str) -> SwSigner {
        let secret = SecretKey::from_slice(&Vec::<u8>::from_hex(secret_hex).unwrap()).unwrap();
        SwSigner::from_xprv(Xpriv {
            network: NetworkKind::Test,
            depth: 0,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::Normal { index: 0 },
            private_key: secret,
            chain_code: ChainCode::from([0u8; 32]),
        })
    }

    fn genesis(v: &Value) -> BlockHash {
        BlockHash::from_str(v["inputs"]["genesis_hash"]["display"].as_str().unwrap()).unwrap()
    }

    fn explicit(o: &TxOut) -> CommittedOutput {
        let (confidential::Asset::Explicit(asset), confidential::Value::Explicit(value)) =
            (o.asset, o.value)
        else {
            panic!("committed outputs are explicit");
        };
        CommittedOutput {
            asset,
            value,
            script_pubkey: o.script_pubkey.clone(),
        }
    }

    /// Children as the vectors give them: internal-order asset, value, and a
    /// witness v1 program.
    fn children(params: &Value) -> Vec<CommittedOutput> {
        params["children"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                let mut spk = vec![0x51, 0x20];
                spk.extend(bytes(&c["program"]));
                CommittedOutput {
                    asset: AssetId::from_slice(&bytes(&c["asset"])).unwrap(),
                    value: c["value"].as_u64().unwrap(),
                    script_pubkey: Script::from(spk),
                }
            })
            .collect()
    }

    /// Check one message against the vector's preimage and digest, then make
    /// and compare the signature of every labelled key.
    /// A policy for the vectors' chain that leaves the remainder unbounded, for
    /// reproducing the reference's signatures.
    fn open_policy(v: &Value) -> CsfsPolicy {
        CsfsPolicy::with_ceiling(genesis(v), u64::MAX)
    }

    fn check(
        v: &Value,
        msg: &ArcaMessage,
        preimage: &Value,
        digest: &Value,
        signatures: &[(&str, &Value)],
    ) -> usize {
        let secp = Secp256k1::new();
        let master = DerivationPath::master();
        assert_eq!(msg.preimage().unwrap().to_hex(), preimage.as_str().unwrap());
        let d = msg.digest().unwrap();
        assert_eq!(d.to_hex(), digest.as_str().unwrap());
        for (label, sig) in signatures {
            let signer = signer_for(v["inputs"]["keys"][label]["secret"].as_str().unwrap());
            let made = signer.sign_csfs(&master, msg, &d, &open_policy(v)).unwrap();
            assert_eq!(made.serialize().to_hex(), sig.as_str().unwrap(), "{label}");
            let key = signer.xonly_public_key(&master).unwrap();
            msg.verify(&secp, &key, &made.serialize()).unwrap();
        }
        signatures.len()
    }

    #[test]
    fn records_match_the_reference() {
        let v = vectors();
        for r in v["records"].as_array().unwrap() {
            let o = CommittedOutput {
                asset: AssetId::from_slice(&bytes(&r["asset"])).unwrap(),
                value: r["value"].as_u64().unwrap(),
                script_pubkey: Script::from(bytes(&r["script_pubkey"])),
            };
            assert_eq!(
                o.record().to_hex(),
                r["record"].as_str().unwrap(),
                "{}",
                r["name"]
            );
        }
        assert_eq!(v["records"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn script_numbers() {
        assert_eq!(script_number(0), Vec::<u8>::new());
        assert_eq!(script_number(1), vec![1]);
        assert_eq!(script_number(-1), vec![0x81]);
        assert_eq!(script_number(0x80), vec![0x80, 0]);
        assert_eq!(script_number(-0x80), vec![0x80, 0x80]);
        assert_eq!(script_number(1_791_000_000).to_hex(), "c07dc06a");
        assert_eq!(script_number(0x8000_0000).to_hex(), "0000008000");
    }

    #[test]
    fn messages_match_the_reference() {
        let v = vectors();
        let g = genesis(&v);
        assert_eq!(
            chain_tag(&g).to_hex(),
            v["inputs"]["chain_tag"].as_str().unwrap()
        );
        let (mut rebind, mut unroll, mut release, mut sigs) = (0, 0, 0, 0);
        for spend in v["spends"].as_array().unwrap() {
            let name = spend["name"].as_str().unwrap();
            let params = &v["outputs"][spend["output"].as_str().unwrap()]["params"];
            let labelled: Vec<(&str, &Value)> = spend
                .get("signatures")
                .and_then(Value::as_object)
                .map(|o| o.iter().map(|(k, s)| (k.as_str(), s)).collect())
                .unwrap_or_default();
            if let Some(k) = spend.get("K") {
                let tx: Transaction = deserialize(&bytes(&spend["tx"])).unwrap();
                let i = spend["input_index"].as_u64().unwrap() as usize;
                let coin: TxOut = deserialize(&bytes(&spend["prevouts"][i])).unwrap();
                let coin = explicit(&coin);
                let m = spend["m"].as_u64().unwrap() as usize;
                let salt = match params.get("salt") {
                    Some(s) => bytes(s),
                    None => bytes(&params["salts"][spend["leaf"].as_str().unwrap()]),
                };
                let salt: [u8; 32] = salt.try_into().unwrap();
                assert_eq!(
                    leaf_constant(&g, &salt).to_hex(),
                    k.as_str().unwrap(),
                    "{name}"
                );
                // The vectors' outputs are in no batch, so each is named here
                // by its own witness program.
                let id: [u8; 32] = coin.script_pubkey.as_bytes()[2..].try_into().unwrap();
                let source = RebindSource::new(vector_path(spend), id, g, salt);
                assert_eq!(source.leaf_constant().to_hex(), k.as_str().unwrap());
                let msg = ArcaMessage::Rebind(RebindMessage {
                    source,
                    asset_in: coin.asset,
                    value_in: coin.value,
                    outputs: tx.output[..m].iter().map(explicit).collect(),
                });
                sigs += check(&v, &msg, &spend["message"], &spend["digest"], &labelled);
                rebind += 1;
            } else if let Some(t) = spend.get("t") {
                let msg = ArcaMessage::Unroll(UnrollAuthorisation {
                    children: children(params),
                    time: t.as_u64().unwrap() as u32,
                });
                assert_eq!(
                    script_number(t.as_i64().unwrap()).to_hex(),
                    spend["t_bytes"].as_str().unwrap()
                );
                sigs += check(&v, &msg, &spend["message"], &spend["digest"], &labelled);
                unroll += 1;
            } else if spend.get("release_digest").is_some() {
                let owners: Vec<(&str, &Value)> =
                    labelled.into_iter().filter(|(k, _)| *k != "S").collect();
                let msg = ArcaMessage::Release(ReleaseMessage {
                    genesis_hash: g,
                    children: children(params),
                });
                sigs += check(
                    &v,
                    &msg,
                    &spend["release_message"],
                    &spend["release_digest"],
                    &owners,
                );
                release += 1;
            }
        }
        // The leaf at m = 1 (twice) and m = 4, the checkpoint at m = 2, and
        // htlc-1's three collaborative paths, all signed by owner and operator
        // except the claim, which the operator signs alone; the root, an inner
        // node and a watch service's timed authorisation; one release by four
        // owners.
        assert_eq!((rebind, unroll, release), (7, 3, 1));
        assert_eq!(sigs, 6 * 2 + 1 + 3 + 4);
    }

    /// The rebindable path a vector spend takes.
    fn vector_path(spend: &Value) -> RebindPath {
        match (
            spend["output"].as_str().unwrap(),
            spend["leaf"].as_str().unwrap(),
        ) {
            ("leaf", "collab") => RebindPath::Leaf,
            ("checkpoint", "collab") => RebindPath::Checkpoint,
            ("htlc", "claim") => RebindPath::HtlcClaim,
            ("htlc", "claim_both") => RebindPath::HtlcClaimBoth,
            ("htlc", "refund_both") => RebindPath::HtlcRefundBoth,
            other => panic!("no rebindable path {other:?}"),
        }
    }

    fn sample(v: &Value) -> (ArcaMessage, ArcaMessage, ArcaMessage) {
        let g = genesis(v);
        let kids = children(&v["outputs"]["lowest_node"]["params"]);
        let rebind = ArcaMessage::Rebind(RebindMessage {
            source: RebindSource::new(RebindPath::Leaf, [9; 32], g, [7; 32]),
            asset_in: kids[0].asset,
            value_in: kids[0].value,
            outputs: vec![kids[1].clone()],
        });
        let unroll = ArcaMessage::Unroll(UnrollAuthorisation {
            children: kids.clone(),
            time: 1_791_000_000,
        });
        let release = ArcaMessage::Release(ReleaseMessage {
            genesis_hash: g,
            children: kids,
        });
        (rebind, unroll, release)
    }

    #[test]
    fn mismatched_digests_are_refused() {
        let v = vectors();
        let signer = signer_for(v["inputs"]["keys"]["A5"]["secret"].as_str().unwrap());
        let master = DerivationPath::master();
        let policy = open_policy(&v);
        let (rebind, unroll, release) = sample(&v);
        for msg in [&rebind, &unroll, &release] {
            let good = msg.digest().unwrap();
            signer.sign_csfs(&master, msg, &good, &policy).unwrap();
            let mut other = good;
            other[31] ^= 1;
            let err = signer.sign_csfs(&master, msg, &other, &policy).unwrap_err();
            assert!(matches!(err, CsfsError::DigestMismatch { .. }), "{err}");
        }

        // The digest of one message presented with the fields of another.
        let err = signer
            .sign_csfs(&master, &unroll, &release.digest().unwrap(), &policy)
            .unwrap_err();
        assert!(matches!(err, CsfsError::DigestMismatch { .. }), "{err}");

        // A field one atom off, another time, another chain, the genesis hash
        // in display byte order: each digest moves, so the original is refused.
        let ArcaMessage::Rebind(r) = &rebind else {
            unreachable!()
        };
        let mut reversed = *r.source.genesis_hash().as_byte_array();
        reversed.reverse();
        let reversed = BlockHash::from_byte_array(reversed);
        let mut changed = vec![];
        let mut one_off = r.clone();
        one_off.outputs[0].value += 1;
        changed.push((rebind.clone(), ArcaMessage::Rebind(one_off)));
        let mut coin_off = r.clone();
        coin_off.value_in -= 1;
        changed.push((rebind.clone(), ArcaMessage::Rebind(coin_off)));
        let mut display = r.clone();
        display.source = RebindSource::new(RebindPath::Leaf, [9; 32], reversed, [7; 32]);
        changed.push((rebind.clone(), ArcaMessage::Rebind(display)));
        let ArcaMessage::Unroll(u) = &unroll else {
            unreachable!()
        };
        let mut later = u.clone();
        later.time += 1;
        changed.push((unroll.clone(), ArcaMessage::Unroll(later)));
        let mut swapped = u.clone();
        swapped.children.swap(0, 1);
        changed.push((unroll.clone(), ArcaMessage::Unroll(swapped)));
        let ArcaMessage::Release(rl) = &release else {
            unreachable!()
        };
        let mut elsewhere = rl.clone();
        elsewhere.genesis_hash = reversed;
        changed.push((release.clone(), ArcaMessage::Release(elsewhere)));
        for (original, altered) in changed {
            let err = signer
                .sign_csfs(&master, &altered, &original.digest().unwrap(), &policy)
                .unwrap_err();
            assert!(matches!(err, CsfsError::DigestMismatch { .. }), "{err}");
        }
    }

    #[test]
    fn impossible_fields_are_refused() {
        let v = vectors();
        let signer = signer_for(v["inputs"]["keys"]["A5"]["secret"].as_str().unwrap());
        let master = DerivationPath::master();
        let policy = open_policy(&v);
        let (rebind, unroll, release) = sample(&v);
        let any = [0u8; 32];

        let ArcaMessage::Rebind(r) = &rebind else {
            unreachable!()
        };
        for n in [0usize, 5] {
            let mut m = r.clone();
            m.outputs = vec![r.outputs[0].clone(); n];
            let err = signer
                .sign_csfs(&master, &ArcaMessage::Rebind(m), &any, &policy)
                .unwrap_err();
            assert!(matches!(err, CsfsError::OutputCount(k) if k == n), "{err}");
        }

        let ArcaMessage::Unroll(u) = &unroll else {
            unreachable!()
        };
        let mut height = u.clone();
        height.time = 899_999;
        let err = signer
            .sign_csfs(&master, &ArcaMessage::Unroll(height), &any, &policy)
            .unwrap_err();
        assert!(matches!(err, CsfsError::NotATime(899_999)), "{err}");

        let mut seven = u.clone();
        seven.children = vec![u.children[0].clone(); 7];
        let err = signer
            .sign_csfs(&master, &ArcaMessage::Unroll(seven), &any, &policy)
            .unwrap_err();
        assert!(matches!(err, CsfsError::ChildrenTooLong(525)), "{err}");

        let ArcaMessage::Release(rl) = &release else {
            unreachable!()
        };
        let mut empty = rl.clone();
        empty.children.clear();
        let err = signer
            .sign_csfs(&master, &ArcaMessage::Release(empty), &any, &policy)
            .unwrap_err();
        assert!(matches!(err, CsfsError::NoChildren), "{err}");
    }

    #[test]
    fn descriptions_name_what_is_authorised() {
        let v = vectors();
        let (rebind, unroll, release) = sample(&v);
        let asset = v["inputs"]["assets"]["X"].as_str().unwrap();
        let display = AssetId::from_slice(&Vec::<u8>::from_hex(asset).unwrap())
            .unwrap()
            .to_string();
        for msg in [&rebind, &unroll, &release] {
            let text = msg.describe().join("\n");
            assert!(text.contains(&display), "{text}");
            assert!(text.contains("10001000 atoms"), "{text}");
        }
        assert!(
            rebind.describe()[0].contains(v["inputs"]["genesis_hash"]["display"].as_str().unwrap())
        );
        assert!(unroll.describe()[0].contains("median time 1791000000"));
    }

    // Review R1's signer probes, which passed against the earlier signer,
    // turned around: each now shows the behaviour the review asked for.

    fn x_asset(v: &Value) -> AssetId {
        AssetId::from_slice(&bytes(&v["inputs"]["assets"]["X"])).unwrap()
    }

    #[test]
    fn the_uncommitted_remainder_is_named_and_capped() {
        // R1 probe: a 10,000,000-atom coin committing one 1,000-atom output was
        // signed, and the description never said where the other 9,999,000 go.
        let v = vectors();
        let g = genesis(&v);
        let signer = signer_for(v["inputs"]["keys"]["A5"]["secret"].as_str().unwrap());
        let master = DerivationPath::master();
        let x = x_asset(&v);
        let mine = Script::from(bytes(&v["inputs"]["operator_script_pubkey"]));
        let rebind = RebindMessage {
            source: RebindSource::new(RebindPath::Leaf, [5; 32], g, [7; 32]),
            asset_in: x,
            value_in: 10_000_000,
            outputs: vec![CommittedOutput {
                asset: x,
                value: 1_000,
                script_pubkey: mine,
            }],
        };
        assert_eq!(rebind.uncommitted(), 9_999_000);
        let msg = ArcaMessage::Rebind(rebind.clone());
        let text = msg.describe().join("\n");
        assert!(
            text.contains(
                "leave 9999000 atoms uncommitted: whoever broadcasts the transaction takes them"
            ),
            "{text}"
        );
        let d = msg.digest().unwrap();

        // The default ceiling, the specification's fee margin: at a floor of
        // 1,000 atoms per 1,000 vB, four times a 280 vB spend.
        let policy = CsfsPolicy::new(g, 1_000);
        assert_eq!(policy.ceiling_for(&rebind), 1_120);
        let err = signer.sign_csfs(&master, &msg, &d, &policy).unwrap_err();
        assert!(
            matches!(
                err,
                CsfsError::AboveCeiling {
                    uncommitted: 9_999_000,
                    ceiling: 1_120,
                    ..
                }
            ),
            "{err}"
        );

        // Within the margin it signs; a ceiling the caller sets is honoured.
        let mut fair = rebind.clone();
        fair.outputs[0].value = 10_000_000 - 1_120;
        let fair = ArcaMessage::Rebind(fair);
        signer
            .sign_csfs(&master, &fair, &fair.digest().unwrap(), &policy)
            .unwrap();
        let mut over = rebind.clone();
        over.outputs[0].value = 10_000_000 - 1_121;
        let over = ArcaMessage::Rebind(over);
        let err = signer
            .sign_csfs(&master, &over, &over.digest().unwrap(), &policy)
            .unwrap_err();
        assert!(
            matches!(
                err,
                CsfsError::AboveCeiling {
                    uncommitted: 1_121,
                    ..
                }
            ),
            "{err}"
        );
        signer
            .sign_csfs(&master, &msg, &d, &CsfsPolicy::with_ceiling(g, 9_999_000))
            .unwrap();

        // A coin committed whole leaves nothing, and says so.
        let mut whole = rebind.clone();
        whole.outputs[0].value = 10_000_000;
        assert!(ArcaMessage::Rebind(whole)
            .describe()
            .join("\n")
            .contains("the whole coin: none of it is left to whoever broadcasts"));
    }

    #[test]
    fn two_leaves_of_one_key_are_told_apart() {
        // R1 probe: two rebinds that differed only in salt differed in one line,
        // "Leaf salt 0101…" against "Leaf salt 0202…".
        let v = vectors();
        let g = genesis(&v);
        let x = x_asset(&v);
        let out = CommittedOutput {
            asset: x,
            value: 9_998_500,
            script_pubkey: Script::from(vec![0x51]),
        };
        let mk = |id: [u8; 32], salt: [u8; 32]| {
            ArcaMessage::Rebind(RebindMessage {
                source: RebindSource::new(RebindPath::Leaf, id, g, salt),
                asset_in: x,
                value_in: 10_000_000,
                outputs: vec![out.clone()],
            })
        };
        let (a, b) = (
            mk([0xa1; 32], [1; 32]).describe(),
            mk([0xb2; 32], [2; 32]).describe(),
        );
        let differing: Vec<_> = a.iter().zip(&b).filter(|(x, y)| x != y).collect();
        assert_eq!(differing.len(), 2, "{differing:?}");
        assert!(
            differing[0].0.contains(&"a1".repeat(32)),
            "{}",
            differing[0].0
        );
        assert!(
            differing[0].1.contains(&"b2".repeat(32)),
            "{}",
            differing[0].1
        );
        assert!(a[0].starts_with("Spend the collaborative path of the Arca leaf"));
    }

    #[test]
    fn paths_are_named() {
        // R1: the checkpoint and htlc-1 paths got the leaf's words.
        let v = vectors();
        let g = genesis(&v);
        let x = x_asset(&v);
        let mut firsts = vec![];
        for path in [
            RebindPath::Leaf,
            RebindPath::Checkpoint,
            RebindPath::HtlcClaim,
            RebindPath::HtlcClaimBoth,
            RebindPath::HtlcRefundBoth,
        ] {
            assert_eq!(RebindPath::from_name(path.name()).unwrap(), path);
            let msg = ArcaMessage::Rebind(RebindMessage {
                source: RebindSource::new(path, [3; 32], g, [4; 32]),
                asset_in: x,
                value_in: 5_000,
                outputs: vec![CommittedOutput {
                    asset: x,
                    value: 4_000,
                    script_pubkey: Script::from(vec![0x51]),
                }],
            });
            let first = msg.describe()[0].clone();
            assert!(
                first.contains(&format!("(path {})", path.name())),
                "{first}"
            );
            firsts.push(first);
        }
        firsts.sort();
        firsts.dedup();
        assert_eq!(firsts.len(), 5);
        assert!(matches!(
            RebindPath::from_name("exit"),
            Err(CsfsError::Path(_))
        ));
        assert_eq!(RebindPath::Leaf.spend_vsize(2), 359);
        assert_eq!(fee_margin(1_000, 359), 1_436);
        assert_eq!(fee_margin(1, 280), 4);
    }

    #[test]
    fn another_chain_is_refused() {
        // R1: the signer accepted whatever genesis hash the caller passed.
        let v = vectors();
        let g = genesis(&v);
        let signer = signer_for(v["inputs"]["keys"]["A5"]["secret"].as_str().unwrap());
        let master = DerivationPath::master();
        let mut reversed = *g.as_byte_array();
        reversed.reverse();
        let display_order = BlockHash::from_byte_array(reversed);
        let (rebind, unroll, release) = sample(&v);
        let ArcaMessage::Rebind(r) = &rebind else {
            unreachable!()
        };
        let mut r2 = r.clone();
        r2.source = RebindSource::new(RebindPath::Leaf, [9; 32], display_order, [7; 32]);
        let ArcaMessage::Release(rl) = &release else {
            unreachable!()
        };
        let mut rl2 = rl.clone();
        rl2.genesis_hash = display_order;
        let policy = open_policy(&v);
        for msg in [ArcaMessage::Rebind(r2), ArcaMessage::Release(rl2)] {
            let err = signer
                .sign_csfs(&master, &msg, &msg.digest().unwrap(), &policy)
                .unwrap_err();
            assert!(matches!(err, CsfsError::WrongChain { .. }), "{err}");
        }
        for msg in [&rebind, &release, &unroll] {
            signer
                .sign_csfs(&master, msg, &msg.digest().unwrap(), &policy)
                .unwrap();
        }
        // The wallet on another chain refuses this chain's messages.
        let elsewhere = CsfsPolicy::with_ceiling(display_order, u64::MAX);
        let err = signer
            .sign_csfs(&master, &rebind, &rebind.digest().unwrap(), &elsewhere)
            .unwrap_err();
        assert!(matches!(err, CsfsError::WrongChain { .. }), "{err}");
    }

    #[cfg(feature = "ark")]
    #[test]
    fn a_leaf_from_its_record() {
        use arca_covenant::{
            Chain, ClockSchedule, LeafSpec, MedianTime, RelativeTime, ReserveRule, Template, Tree,
            TreeParams,
        };
        let v = vectors();
        let g = genesis(&v);
        let x = x_asset(&v);
        let master = DerivationPath::master();
        let secp = Secp256k1::new();
        let owners: Vec<SwSigner> = ["A0", "A1", "A2", "A3", "A4"]
            .iter()
            .map(|l| signer_for(v["inputs"]["keys"][l]["secret"].as_str().unwrap()))
            .collect();
        let operator = signer_for(v["inputs"]["keys"]["S"]["secret"].as_str().unwrap());
        let s_key = operator.xonly_public_key(&master).unwrap();
        let delay = RelativeTime::from_seconds_ceil(36 * 3600).unwrap();
        let day = 86_400;
        let t0 = 1_800_000_000;
        let schedule = ClockSchedule::new(
            AssetId::from_slice(&[0x77; 32]).unwrap(),
            s_key,
            delay,
            (1..=3)
                .map(|k| MedianTime::from_consensus(t0 + 28 * day * k).unwrap())
                .collect(),
        )
        .unwrap();
        let leaves: Vec<LeafSpec> = owners
            .iter()
            .enumerate()
            .map(|(i, o)| LeafSpec {
                template: Template::Vtxo1,
                owner: o.xonly_public_key(&master).unwrap(),
                value: 1_000_000 + i as u64,
                owner_nonce: [i as u8 + 1; 32],
                operator_nonce: [i as u8 + 0x41; 32],
                exit_delay: delay,
                unlock_hash: [i as u8 + 0x81; 32],
            })
            .collect();
        let tree = Tree::build(
            TreeParams {
                asset: x,
                chain: Chain::new(g),
                schedule,
                burn: false,
                radix: 4,
                reserve: ReserveRule::Fixed {
                    node: 3_000,
                    entry: 1_000,
                },
                min_leaf: 1_000,
            },
            &leaves,
        )
        .unwrap();
        let records = tree.records();
        let rec = &records[2];
        let source = RebindSource::leaf(rec).unwrap();
        assert!(source.from_record());
        assert_eq!(source.leaf_id(), rec.leaf_id().unwrap().0);
        assert_eq!(source.salt(), rec.salt());
        assert_eq!(source.leaf_constant(), rec.leaf().leaf_constant());

        let out = CommittedOutput {
            asset: x,
            value: rec.value - 1_000,
            script_pubkey: Script::from(vec![0x51]),
        };
        let msg = |asset_in: AssetId, value_in: u64| {
            ArcaMessage::Rebind(RebindMessage {
                source: source.clone(),
                asset_in,
                value_in,
                outputs: vec![out.clone()],
            })
        };
        let good = msg(x, rec.value);
        // The digest is the one the leaf's own policy builds for the same spend.
        let reference = rec
            .leaf()
            .collab_message(
                x,
                rec.value,
                &[arca_covenant::ExplicitOutput::new(
                    x,
                    out.value,
                    out.script_pubkey.clone(),
                )],
            )
            .unwrap();
        assert_eq!(good.digest().unwrap(), reference.digest);
        let policy = CsfsPolicy::new(g, 1_000);
        let sig = owners[2]
            .sign_csfs(&master, &good, &good.digest().unwrap(), &policy)
            .unwrap();
        good.verify(&secp, &rec.owner, &sig.serialize()).unwrap();
        assert!(good.describe()[0].contains(&hex(&rec.leaf_id().unwrap().0)));

        // Another owner's key, even one under the same node, is refused.
        let err = owners[3]
            .sign_csfs(&master, &good, &good.digest().unwrap(), &policy)
            .unwrap_err();
        assert!(matches!(err, CsfsError::NotOwner { .. }), "{err}");
        // A coin of another value or asset under the same script is refused.
        for bad in [
            msg(x, rec.value + 5_000),
            msg(AssetId::from_slice(&[0x55; 32]).unwrap(), rec.value),
        ] {
            let err = owners[2]
                .sign_csfs(
                    &master,
                    &bad,
                    &bad.digest().unwrap(),
                    &CsfsPolicy::with_ceiling(g, u64::MAX),
                )
                .unwrap_err();
            assert!(matches!(err, CsfsError::NotTheLeafCoin { .. }), "{err}");
        }
    }
}
