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

/// The spend of an Arca leaf through its collaborative path, which the owner
/// and the operator each sign: the coin being spent and the outputs it may
/// move into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebindMessage {
    /// The genesis hash of the chain the leaf lives on.
    pub genesis_hash: BlockHash,
    /// The salt unique to this leaf instance.
    pub leaf_salt: [u8; 32],
    /// The asset of the coin being spent.
    pub asset_in: AssetId,
    /// The value of the coin being spent, in atoms.
    pub value_in: u64,
    /// The outputs at indices `0..m`, in order.
    pub outputs: Vec<CommittedOutput>,
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
                let mut p = leaf_constant(&m.genesis_hash, &m.leaf_salt).to_vec();
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
                let mut v = vec![
                    format!(
                        "Spend the Arca leaf holding {} atoms of asset {} on the chain with genesis {}, through its collaborative path.",
                        m.value_in, m.asset_in, m.genesis_hash
                    ),
                    format!(
                        "It may move only into a transaction whose first {} outputs are exactly:",
                        m.outputs.len()
                    ),
                ];
                v.extend(m.outputs.iter().enumerate().map(|(i, o)| out_line(i, o)));
                v.push(format!("Leaf salt {}.", hex(&m.leaf_salt)));
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
    pub fn sign_csfs(
        &self,
        path: &DerivationPath,
        message: &ArcaMessage,
        digest: &[u8; 32],
    ) -> Result<schnorr::Signature, CsfsError> {
        let computed = message.digest()?;
        if &computed != digest {
            return Err(CsfsError::DigestMismatch {
                given: hex(digest),
                computed: hex(&computed),
            });
        }
        let derived = self.xprv.derive_priv(&self.secp, path)?;
        let keypair = derived.to_keypair(&self.secp);
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
            let made = signer.sign_csfs(&master, msg, &d).unwrap();
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
                let msg = ArcaMessage::Rebind(RebindMessage {
                    genesis_hash: g,
                    leaf_salt: salt,
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

    fn sample(v: &Value) -> (ArcaMessage, ArcaMessage, ArcaMessage) {
        let g = genesis(v);
        let kids = children(&v["outputs"]["lowest_node"]["params"]);
        let rebind = ArcaMessage::Rebind(RebindMessage {
            genesis_hash: g,
            leaf_salt: [7; 32],
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
        let (rebind, unroll, release) = sample(&v);
        for msg in [&rebind, &unroll, &release] {
            let good = msg.digest().unwrap();
            signer.sign_csfs(&master, msg, &good).unwrap();
            let mut other = good;
            other[31] ^= 1;
            let err = signer.sign_csfs(&master, msg, &other).unwrap_err();
            assert!(matches!(err, CsfsError::DigestMismatch { .. }), "{err}");
        }

        // The digest of one message presented with the fields of another.
        let err = signer
            .sign_csfs(&master, &unroll, &release.digest().unwrap())
            .unwrap_err();
        assert!(matches!(err, CsfsError::DigestMismatch { .. }), "{err}");

        // A field one atom off, another time, another chain, the genesis hash
        // in display byte order: each digest moves, so the original is refused.
        let ArcaMessage::Rebind(r) = &rebind else {
            unreachable!()
        };
        let mut reversed = *r.genesis_hash.as_byte_array();
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
        display.genesis_hash = reversed;
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
                .sign_csfs(&master, &altered, &original.digest().unwrap())
                .unwrap_err();
            assert!(matches!(err, CsfsError::DigestMismatch { .. }), "{err}");
        }
    }

    #[test]
    fn impossible_fields_are_refused() {
        let v = vectors();
        let signer = signer_for(v["inputs"]["keys"]["A5"]["secret"].as_str().unwrap());
        let master = DerivationPath::master();
        let (rebind, unroll, release) = sample(&v);
        let any = [0u8; 32];

        let ArcaMessage::Rebind(r) = &rebind else {
            unreachable!()
        };
        for n in [0usize, 5] {
            let mut m = r.clone();
            m.outputs = vec![r.outputs[0].clone(); n];
            let err = signer
                .sign_csfs(&master, &ArcaMessage::Rebind(m), &any)
                .unwrap_err();
            assert!(matches!(err, CsfsError::OutputCount(k) if k == n), "{err}");
        }

        let ArcaMessage::Unroll(u) = &unroll else {
            unreachable!()
        };
        let mut height = u.clone();
        height.time = 899_999;
        let err = signer
            .sign_csfs(&master, &ArcaMessage::Unroll(height), &any)
            .unwrap_err();
        assert!(matches!(err, CsfsError::NotATime(899_999)), "{err}");

        let mut seven = u.clone();
        seven.children = vec![u.children[0].clone(); 7];
        let err = signer
            .sign_csfs(&master, &ArcaMessage::Unroll(seven), &any)
            .unwrap_err();
        assert!(matches!(err, CsfsError::ChildrenTooLong(525)), "{err}");

        let ArcaMessage::Release(rl) = &release else {
            unreachable!()
        };
        let mut empty = rl.clone();
        empty.children.clear();
        let err = signer
            .sign_csfs(&master, &ArcaMessage::Release(empty), &any)
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
}
