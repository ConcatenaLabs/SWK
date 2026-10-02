//! Taproot script-path signing over the Elements signature hash.
//!
//! [`SwSigner::sign_tapscript`] signs one input of a transaction through one
//! leaf of its taproot output, for any leaf version (`0xc4`, the Elements
//! tapscript version, included). The signature hash is the Elements one: the
//! `TapSighash/elements`, `TapLeaf/elements` and `TapBranch/elements` tagged
//! hashes, and the chain's genesis hash committed in the message, so a
//! signature made for one chain is void on every other.
//!
//! Before it signs, the signer checks what a caller could otherwise get wrong
//! without noticing:
//!
//! - the control block proves that the leaf is in the taproot output being
//!   spent, so the signature is for the coin the caller names and for no other
//!   script tree;
//! - the key at the given derivation path is pushed in the leaf and checked
//!   there by `OP_CHECKSIG`, `OP_CHECKSIGVERIFY` or `OP_CHECKSIGADD`, so the
//!   wallet signs only where an ordinary signature by its own key is asked for;
//! - the signature hash type is `SIGHASH_DEFAULT` or `SIGHASH_ALL`, which
//!   cover every input and every output. Any other type leaves outputs or
//!   inputs free: under `SIGHASH_NONE` an exit signature lets whoever holds it
//!   send the coin anywhere. [`SwSigner::sign_tapscript_allowing`] signs one
//!   other type, which the caller names.
//!
//! [`ScriptPathSpend::describe`] says, in plain lines, what a signature over a
//! spend authorises: the coin, the leaf, what the signature hash type covers,
//! the outputs, the fee and the locks.
//!
//! The signature is BIP340 with no auxiliary randomness: the nonce is derived
//! from the key and the message alone, so the same request always gives the
//! same 64 bytes, and two implementations can be compared byte for byte.
//!
//! The annex is not supported: a spend that carries one has a different
//! signature hash, and nothing on Sequentia uses it.

use elements_miniscript::elements::{
    bitcoin::bip32::{self, DerivationPath},
    confidential,
    hashes::Hash,
    hex::ToHex,
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_CHECKSIGVERIFY},
    schnorr::TweakedPublicKey,
    script::Instruction,
    secp256k1_zkp::{schnorr, Message, Secp256k1, Verification, XOnlyPublicKey},
    sighash::{Prevouts, ScriptPath, SighashCache},
    taproot::{ControlBlock, LeafVersion, TapLeafHash},
    BlockHash, LockTime, OutPoint, SchnorrSig, SchnorrSighashType, Script, Transaction, TxOut,
};

use crate::SwSigner;

/// Errors from building or signing a script-path spend.
#[derive(thiserror::Error, Debug)]
pub enum TapscriptError {
    /// The input index is not an input of the transaction.
    #[error("input index {index} out of range ({inputs} inputs)")]
    InputIndex {
        /// The requested index.
        index: usize,
        /// The number of inputs.
        inputs: usize,
    },

    /// The prevouts do not line up with the inputs.
    #[error("{prevouts} prevouts given for {inputs} inputs; they must align")]
    Prevouts {
        /// The number of prevouts given.
        prevouts: usize,
        /// The number of inputs.
        inputs: usize,
    },

    /// The output being spent is not a taproot output.
    #[error("the output spent by input {0} is not a taproot (witness v1, 32-byte) output")]
    NotTaproot(usize),

    /// The control block does not prove the leaf is in the output being spent.
    #[error("the control block does not commit the leaf to the output spent by input {0}")]
    LeafNotCommitted(usize),

    /// The signing key is not pushed in the leaf.
    #[error("the key {0} is not pushed in the leaf script")]
    KeyNotInLeaf(XOnlyPublicKey),

    /// The signing key is in the leaf, but no signature opcode checks it there.
    #[error("the key {0} is in the leaf script, but no OP_CHECKSIG, OP_CHECKSIGVERIFY or OP_CHECKSIGADD checks it, so an ordinary signature has no use in this leaf")]
    KeyNotChecked(XOnlyPublicKey),

    /// The signature hash type is not a defined BIP341 value.
    #[error("sighash type {0:#04x} is not defined")]
    SighashType(u8),

    /// The signature hash type is not a defined BIP341 name.
    #[error("sighash type {0:?} is not a name the signer knows (default, all, none, single, all|anyonecanpay, none|anyonecanpay, single|anyonecanpay)")]
    SighashName(String),

    /// The signature hash type leaves outputs or inputs free, and the caller
    /// did not name it.
    #[error("sighash type {} leaves {} free; the signer signs only SIGHASH_DEFAULT and SIGHASH_ALL unless the caller names the type it accepts", sighash_name(*.0), what_it_frees(*.0))]
    SighashNotAllowed(SchnorrSighashType),

    /// The signature does not verify.
    #[error("the signature does not verify for key {0}")]
    BadSignature(XOnlyPublicKey),

    /// The signature hash cannot be computed.
    #[error("tapscript sighash: {0}")]
    Sighash(#[from] elements_miniscript::elements::sighash::Error),

    /// Key derivation failed.
    #[error(transparent)]
    Bip32(#[from] bip32::Error),
}

/// One input of a transaction, spent through one leaf of its taproot output.
///
/// Every field is what a verifier sees: the transaction, the outputs its inputs
/// spend (all of them, in input order), the leaf script and its control block,
/// which also carries the leaf version.
#[derive(Debug, Clone, Copy)]
pub struct ScriptPathSpend<'a> {
    /// The transaction being signed.
    pub tx: &'a Transaction,
    /// The index of the input being signed.
    pub input_index: usize,
    /// The outputs spent by every input of `tx`, in input order.
    pub prevouts: &'a [TxOut],
    /// The leaf script the input is spent through.
    pub leaf_script: &'a Script,
    /// The control block of that leaf. Its first byte carries the leaf version.
    pub control_block: &'a ControlBlock,
    /// The signature hash type. [`SchnorrSighashType::Default`] gives a 64-byte
    /// signature; every other type appends its byte.
    pub sighash_type: SchnorrSighashType,
    /// The genesis hash of the chain the transaction is for.
    pub genesis_hash: BlockHash,
}

impl ScriptPathSpend<'_> {
    /// The leaf version, from the control block.
    pub fn leaf_version(&self) -> LeafVersion {
        self.control_block.leaf_version
    }

    /// The leaf hash, `TapLeaf/elements` over the leaf version and the script.
    pub fn leaf_hash(&self) -> TapLeafHash {
        TapLeafHash::from_script(self.leaf_script, self.leaf_version())
    }

    fn check_shape(&self) -> Result<(), TapscriptError> {
        let inputs = self.tx.input.len();
        if self.input_index >= inputs {
            return Err(TapscriptError::InputIndex {
                index: self.input_index,
                inputs,
            });
        }
        if self.prevouts.len() != inputs {
            return Err(TapscriptError::Prevouts {
                prevouts: self.prevouts.len(),
                inputs,
            });
        }
        Ok(())
    }

    /// Check that the control block commits the leaf to the taproot output
    /// this input spends.
    pub fn check_commitment<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<(), TapscriptError> {
        self.check_shape()?;
        let spk = &self.prevouts[self.input_index].script_pubkey;
        if !spk.is_v1_p2tr() {
            return Err(TapscriptError::NotTaproot(self.input_index));
        }
        let output_key = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..])
            .map_err(|_| TapscriptError::NotTaproot(self.input_index))?;
        if self.control_block.verify_taproot_commitment(
            secp,
            &TweakedPublicKey::new(output_key),
            self.leaf_script,
        ) {
            Ok(())
        } else {
            Err(TapscriptError::LeafNotCommitted(self.input_index))
        }
    }

    /// The BIP341 script-path signature hash with the Elements tagged hashes
    /// and the genesis hash, for this leaf at its own leaf version.
    pub fn sighash(&self) -> Result<[u8; 32], TapscriptError> {
        self.check_shape()?;
        let script_path =
            ScriptPath::new(self.leaf_script, 0xFFFF_FFFF, self.leaf_version().as_u8());
        let mut cache = SighashCache::new(self.tx);
        let hash = cache.taproot_script_spend_signature_hash(
            self.input_index,
            &Prevouts::All(self.prevouts),
            script_path,
            self.sighash_type,
            self.genesis_hash,
        )?;
        Ok(hash.to_byte_array())
    }

    /// Verify a script-path signature by `key` for this spend: a 64-byte
    /// signature for [`SchnorrSighashType::Default`], 65 bytes otherwise, with
    /// the type byte matching [`Self::sighash_type`].
    pub fn verify<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        key: &XOnlyPublicKey,
        signature: &[u8],
    ) -> Result<(), TapscriptError> {
        let sig =
            SchnorrSig::from_slice(signature).map_err(|_| TapscriptError::BadSignature(*key))?;
        if sig.hash_ty != self.sighash_type {
            return Err(TapscriptError::BadSignature(*key));
        }
        let msg = Message::from_digest(self.sighash()?);
        secp.verify_schnorr(&sig.sig, &msg, key)
            .map_err(|_| TapscriptError::BadSignature(*key))
    }
}

/// Parse a raw BIP341 signature hash type byte.
pub fn sighash_type_from_u8(byte: u8) -> Result<SchnorrSighashType, TapscriptError> {
    SchnorrSighashType::from_u8(byte).ok_or(TapscriptError::SighashType(byte))
}

/// The name of a signature hash type: `default`, `all`, `none`, `single`,
/// `all|anyonecanpay`, `none|anyonecanpay` or `single|anyonecanpay`.
pub fn sighash_name(ty: SchnorrSighashType) -> &'static str {
    match ty {
        SchnorrSighashType::Default => "default",
        SchnorrSighashType::All => "all",
        SchnorrSighashType::None => "none",
        SchnorrSighashType::Single => "single",
        SchnorrSighashType::AllPlusAnyoneCanPay => "all|anyonecanpay",
        SchnorrSighashType::NonePlusAnyoneCanPay => "none|anyonecanpay",
        SchnorrSighashType::SinglePlusAnyoneCanPay => "single|anyonecanpay",
        SchnorrSighashType::Reserved => "reserved",
    }
}

/// The signature hash type with this name ([`sighash_name`]), the way a caller
/// opts in to a type that leaves outputs or inputs free.
pub fn sighash_type_from_name(name: &str) -> Result<SchnorrSighashType, TapscriptError> {
    [
        SchnorrSighashType::Default,
        SchnorrSighashType::All,
        SchnorrSighashType::None,
        SchnorrSighashType::Single,
        SchnorrSighashType::AllPlusAnyoneCanPay,
        SchnorrSighashType::NonePlusAnyoneCanPay,
        SchnorrSighashType::SinglePlusAnyoneCanPay,
    ]
    .into_iter()
    .find(|t| sighash_name(*t) == name)
    .ok_or_else(|| TapscriptError::SighashName(name.to_string()))
}

/// What a signature hash type leaves out of the signature.
fn what_it_frees(ty: SchnorrSighashType) -> &'static str {
    match ty {
        SchnorrSighashType::Default | SchnorrSighashType::All => "nothing",
        SchnorrSighashType::None => "every output",
        SchnorrSighashType::Single => "every output but one",
        SchnorrSighashType::AllPlusAnyoneCanPay => "the other inputs",
        SchnorrSighashType::NonePlusAnyoneCanPay => "every output and the other inputs",
        SchnorrSighashType::SinglePlusAnyoneCanPay => "every output but one, and the other inputs",
        SchnorrSighashType::Reserved => "an undefined part of the transaction",
    }
}

/// True when `key` is pushed, as 32 bytes, anywhere in `script`.
pub fn script_pushes_key(script: &Script, key: &XOnlyPublicKey) -> bool {
    let key = key.serialize();
    script
        .instructions()
        .any(|ins| matches!(ins, Ok(Instruction::PushBytes(bytes)) if bytes == key.as_slice()))
}

/// True when `key` is pushed, as 32 bytes, and the next instruction is
/// `OP_CHECKSIG`, `OP_CHECKSIGVERIFY` or `OP_CHECKSIGADD`: the leaf checks an
/// ordinary signature by that key. A key that only `OP_CHECKSIGFROMSTACK`
/// checks is not enough.
pub fn script_checks_key(script: &Script, key: &XOnlyPublicKey) -> bool {
    let key = key.serialize();
    let ins: Vec<_> = script.instructions().collect();
    ins.windows(2).any(|w| match (&w[0], &w[1]) {
        (Ok(Instruction::PushBytes(bytes)), Ok(Instruction::Op(op))) => {
            *bytes == key.as_slice()
                && [OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD].contains(op)
        }
        _ => false,
    })
}

fn amount(asset: &confidential::Asset, value: &confidential::Value) -> String {
    match (asset.explicit(), value.explicit()) {
        (Some(a), Some(v)) => format!("{v} atoms of asset {a}"),
        (Some(a), None) => format!("a confidential amount of asset {a}"),
        (None, Some(v)) => format!("{v} atoms of a confidential asset"),
        (None, None) => "a confidential amount of a confidential asset".to_string(),
    }
}

fn output_line(i: usize, o: &TxOut) -> String {
    if o.is_fee() {
        format!("output {i}: the fee, {}", amount(&o.asset, &o.value))
    } else {
        format!(
            "output {i}: {} to script {}",
            amount(&o.asset, &o.value),
            o.script_pubkey.as_bytes().to_hex()
        )
    }
}

impl ScriptPathSpend<'_> {
    /// What a signature over this spend authorises, in plain lines, one fact
    /// per line, for a wallet to show before it asks for approval: the coin
    /// and the leaf, what the signature hash type covers, the outputs it
    /// covers, the fee and the locks. Asset ids and the genesis hash are in
    /// display hex.
    pub fn describe(&self) -> Result<Vec<String>, TapscriptError> {
        self.check_shape()?;
        let i = self.input_index;
        let input = &self.tx.input[i];
        let coin = &self.prevouts[i];
        let outputs = &self.tx.output;
        let mut v = vec![format!(
            "Sign input {i}, which spends {} holding {}, through a taproot script leaf of {} bytes at leaf version {:#04x}, on the chain with genesis {}.",
            OutPoint::new(input.previous_output.txid, input.previous_output.vout),
            amount(&coin.asset, &coin.value),
            self.leaf_script.len(),
            self.leaf_version().as_u8(),
            self.genesis_hash,
        )];
        v.push(format!("The leaf script: {}.", self.leaf_script.asm()));
        let ty = self.sighash_type;
        let anyone = matches!(
            ty,
            SchnorrSighashType::AllPlusAnyoneCanPay
                | SchnorrSighashType::NonePlusAnyoneCanPay
                | SchnorrSighashType::SinglePlusAnyoneCanPay
        );
        match ty {
            SchnorrSighashType::Default | SchnorrSighashType::All | SchnorrSighashType::AllPlusAnyoneCanPay => {
                v.push(format!(
                    "Signature hash type {}: the signature covers every output, so the coin moves only into these {} outputs:",
                    sighash_name(ty),
                    outputs.len()
                ));
                v.extend(outputs.iter().enumerate().map(|(j, o)| output_line(j, o)));
            }
            SchnorrSighashType::None | SchnorrSighashType::NonePlusAnyoneCanPay => v.push(format!(
                "Signature hash type {}: the signature covers no output, so whoever holds it can send this coin anywhere.",
                sighash_name(ty)
            )),
            SchnorrSighashType::Single | SchnorrSighashType::SinglePlusAnyoneCanPay => {
                match outputs.get(i) {
                    Some(o) => {
                        v.push(format!(
                            "Signature hash type {}: the signature covers output {i} only; whoever holds it may change or add every other output.",
                            sighash_name(ty)
                        ));
                        v.push(output_line(i, o));
                    }
                    None => v.push(format!(
                        "Signature hash type {}: there is no output {i} for the signature to cover, so no signature can be made.",
                        sighash_name(ty)
                    )),
                }
            }
            SchnorrSighashType::Reserved => v.push("Signature hash type reserved: undefined.".into()),
        }
        if anyone {
            v.push(
                "It covers this input only: whoever holds it may add or remove every other input."
                    .into(),
            );
        } else {
            v.push(format!(
                "It covers every one of the transaction's {} inputs.",
                self.tx.input.len()
            ));
        }
        let fees: Vec<String> = outputs
            .iter()
            .filter(|o| o.is_fee())
            .map(|o| amount(&o.asset, &o.value))
            .collect();
        if fees.is_empty() {
            v.push("The transaction pays no fee output.".into());
        } else {
            v.push(format!("The fee: {}.", fees.join(", ")));
        }
        let final_seq = input.sequence.0 == 0xffff_ffff;
        v.push(match self.tx.lock_time {
            _ if self.tx.input.iter().all(|x| x.sequence.0 == 0xffff_ffff) => {
                "No lock time applies.".to_string()
            }
            LockTime::Blocks(h) if h.to_consensus_u32() == 0 => "No lock time applies.".to_string(),
            LockTime::Blocks(h) => {
                format!("Not valid before block height {}.", h.to_consensus_u32())
            }
            LockTime::Seconds(t) => {
                format!("Not valid before median time {}.", t.to_consensus_u32())
            }
        });
        let seq = input.sequence.0;
        if !final_seq && self.tx.version >= 2 && seq & (1 << 31) == 0 {
            let n = seq & 0xffff;
            v.push(if seq & (1 << 22) != 0 {
                format!(
                    "This input waits {} seconds ({n} units of 512 s) after the coin it spends confirms.",
                    n as u64 * 512
                )
            } else {
                format!("This input waits {n} blocks after the coin it spends confirms.")
            });
        }
        Ok(v)
    }
}

impl SwSigner {
    /// The x-only public key at `path`, as a tapscript leaf names it.
    pub fn xonly_public_key(&self, path: &DerivationPath) -> Result<XOnlyPublicKey, bip32::Error> {
        let derived = self.xprv.derive_priv(&self.secp, path)?;
        Ok(derived.to_keypair(&self.secp).x_only_public_key().0)
    }

    /// Sign `spend` with the key at `path`: a BIP341 script-path signature
    /// over the Elements signature hash, with no auxiliary randomness.
    ///
    /// Refuses when the control block does not commit the leaf to the output
    /// being spent, when the key at `path` is not checked by a signature
    /// opcode in the leaf, and when the signature hash type is not
    /// [`SchnorrSighashType::Default`] or [`SchnorrSighashType::All`].
    /// Returns the signature as it goes in the witness: 64 bytes for
    /// [`SchnorrSighashType::Default`], 65 otherwise.
    pub fn sign_tapscript(
        &self,
        path: &DerivationPath,
        spend: &ScriptPathSpend<'_>,
    ) -> Result<SchnorrSig, TapscriptError> {
        self.sign_tapscript_inner(path, spend, None)
    }

    /// [`SwSigner::sign_tapscript`], also signing under `allow`, a signature
    /// hash type that leaves outputs or inputs free, named by the caller. The
    /// spend's type must still be `allow`, [`SchnorrSighashType::Default`] or
    /// [`SchnorrSighashType::All`]. Show [`ScriptPathSpend::describe`] first:
    /// under `SIGHASH_NONE` the signature lets whoever holds it send the coin
    /// anywhere.
    pub fn sign_tapscript_allowing(
        &self,
        path: &DerivationPath,
        spend: &ScriptPathSpend<'_>,
        allow: SchnorrSighashType,
    ) -> Result<SchnorrSig, TapscriptError> {
        self.sign_tapscript_inner(path, spend, Some(allow))
    }

    fn sign_tapscript_inner(
        &self,
        path: &DerivationPath,
        spend: &ScriptPathSpend<'_>,
        allow: Option<SchnorrSighashType>,
    ) -> Result<SchnorrSig, TapscriptError> {
        let ty = spend.sighash_type;
        let covers_all = matches!(ty, SchnorrSighashType::Default | SchnorrSighashType::All);
        if !covers_all && allow != Some(ty) {
            return Err(TapscriptError::SighashNotAllowed(ty));
        }
        spend.check_commitment(&self.secp)?;
        let derived = self.xprv.derive_priv(&self.secp, path)?;
        let keypair = derived.to_keypair(&self.secp);
        let (xonly, _) = keypair.x_only_public_key();
        if !script_pushes_key(spend.leaf_script, &xonly) {
            return Err(TapscriptError::KeyNotInLeaf(xonly));
        }
        if !script_checks_key(spend.leaf_script, &xonly) {
            return Err(TapscriptError::KeyNotChecked(xonly));
        }
        let msg = Message::from_digest(spend.sighash()?);
        let sig: schnorr::Signature = self.secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        Ok(SchnorrSig {
            sig,
            hash_ty: spend.sighash_type,
        })
    }
}

#[cfg(test)]
mod tests {
    // `SwSigner::sign_tapscript` against the Arca golden vectors.
    //
    // `tests/data/arca_vectors.json` is `regtest/vectors/arca.json` from the
    // `arca` repository, copied unchanged. It is generated by the Arca regtest
    // suite's Python reference from test keys only (`SHA256("Arca test vector
    // key/" + label)`), and every sample spend in it is verified by the node's own
    // interpreter there. Each script-path spend that carries a signature hash is
    // recomputed here and re-signed with the same test key: both must match the
    // reference byte for byte.

    use std::str::FromStr;

    use super::{
        script_checks_key, script_pushes_key, sighash_name, sighash_type_from_name,
        ScriptPathSpend, TapscriptError,
    };
    use crate::SwSigner;
    use elements_miniscript::elements::{
        bitcoin::{
            bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpriv},
            NetworkKind,
        },
        encode::deserialize,
        hashes::Hash,
        hex::{FromHex, ToHex},
        secp256k1_zkp::{Secp256k1, SecretKey, XOnlyPublicKey},
        taproot::{ControlBlock, LeafVersion, TaprootBuilder},
        AssetId, BlockHash, OutPoint, SchnorrSighashType, Script, Transaction, TxIn, TxOut,
    };
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../test_data/arca_vectors.json")).unwrap()
    }

    fn hex(s: &Value) -> Vec<u8> {
        Vec::<u8>::from_hex(s.as_str().unwrap()).unwrap()
    }

    /// A software signer whose master key is the given secret, so that the
    /// master path signs with exactly the vector's test key.
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

    struct Parsed {
        tx: Transaction,
        prevouts: Vec<TxOut>,
        leaf: Script,
        control_block: ControlBlock,
        input_index: usize,
    }

    fn parse_spend(spend: &Value) -> Parsed {
        let tx: Transaction = deserialize(&hex(&spend["tx"])).unwrap();
        let prevouts: Vec<TxOut> = spend["prevouts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| deserialize(&hex(p)).unwrap())
            .collect();
        let witness = spend["witness"].as_array().unwrap();
        let leaf = Script::from(hex(&witness[witness.len() - 2]));
        let control_block = ControlBlock::from_slice(&hex(&witness[witness.len() - 1])).unwrap();
        let input_index = spend["input_index"].as_u64().unwrap() as usize;
        Parsed {
            tx,
            prevouts,
            leaf,
            control_block,
            input_index,
        }
    }

    fn genesis(v: &Value) -> BlockHash {
        BlockHash::from_str(v["inputs"]["genesis_hash"]["display"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn tapscript_spends_match_the_reference() {
        let v = vectors();
        let secp = Secp256k1::new();
        let keys = &v["inputs"]["keys"];
        let master = DerivationPath::master();
        let mut checked_sighashes = 0;
        let mut checked_signatures = 0;
        for spend in v["spends"].as_array().unwrap() {
            let Some(expected) = spend.get("sighash") else {
                continue;
            };
            assert_eq!(spend["sighash_type"], "default");
            let p = parse_spend(spend);
            let s = ScriptPathSpend {
                tx: &p.tx,
                input_index: p.input_index,
                prevouts: &p.prevouts,
                leaf_script: &p.leaf,
                control_block: &p.control_block,
                sighash_type: SchnorrSighashType::Default,
                genesis_hash: genesis(&v),
            };
            let name = spend["name"].as_str().unwrap();
            assert_eq!(s.leaf_version().as_u8(), 0xc4, "{name}");
            s.check_commitment(&secp).unwrap();
            assert_eq!(
                s.sighash().unwrap().to_hex(),
                expected.as_str().unwrap(),
                "{name}"
            );
            checked_sighashes += 1;

            for (label, sig) in spend["signatures"].as_object().unwrap() {
                // A reclaim also carries the owners' release signatures, which are
                // message signatures, not signatures of this transaction.
                if spend.get("release_digest").is_some() && label != "S" {
                    continue;
                }
                let signer = signer_for(keys[label]["secret"].as_str().unwrap());
                let made = signer.sign_tapscript(&master, &s).unwrap();
                assert_eq!(
                    made.to_vec().to_hex(),
                    sig.as_str().unwrap(),
                    "{name} by {label}"
                );
                let xonly = signer.xonly_public_key(&master).unwrap();
                assert_eq!(
                    xonly.serialize().to_hex(),
                    keys[label]["xonly"].as_str().unwrap()
                );
                s.verify(&secp, &xonly, &made.to_vec()).unwrap();
                checked_signatures += 1;
            }
        }
        // Every script-path spend signed with an ordinary signature: the sweeps,
        // the clock steps, R, the exit claim, the reclaim's operator signature,
        // the forfeit's two paths and the htlc refund.
        assert_eq!(checked_sighashes, 16);
        assert_eq!(checked_signatures, 16);
    }

    fn spend_named<'a>(v: &'a Value, name: &str) -> &'a Value {
        v["spends"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == name)
            .unwrap()
    }

    #[test]
    fn exit_claim_refusals() {
        let v = vectors();
        let secp = Secp256k1::new();
        let keys = &v["inputs"]["keys"];
        let master = DerivationPath::master();
        let owner = signer_for(keys["A5"]["secret"].as_str().unwrap());
        let operator = signer_for(keys["S"]["secret"].as_str().unwrap());
        let exit = parse_spend(spend_named(&v, "leaf/exit"));
        let collab = parse_spend(spend_named(&v, "leaf/collab m=1, into the checkpoint"));
        let spend = ScriptPathSpend {
            tx: &exit.tx,
            input_index: 0,
            prevouts: &exit.prevouts,
            leaf_script: &exit.leaf,
            control_block: &exit.control_block,
            sighash_type: SchnorrSighashType::Default,
            genesis_hash: genesis(&v),
        };
        let good = owner.sign_tapscript(&master, &spend).unwrap();

        // The operator's key is not in the exit leaf.
        let err = operator.sign_tapscript(&master, &spend).unwrap_err();
        assert!(matches!(err, TapscriptError::KeyNotInLeaf(_)), "{err}");

        // The collaborative leaf's control block does not prove the exit leaf.
        let wrong_cb = ScriptPathSpend {
            control_block: &collab.control_block,
            ..spend
        };
        let err = owner.sign_tapscript(&master, &wrong_cb).unwrap_err();
        assert!(matches!(err, TapscriptError::LeafNotCommitted(0)), "{err}");

        // A leaf that is not in the tree at all, with the exit leaf's control block.
        let other_leaf =
            Script::from(hex(&v["outputs"]["checkpoint"]["leaves"]["sweep"]["script"]));
        let not_in_tree = ScriptPathSpend {
            leaf_script: &other_leaf,
            ..spend
        };
        let err = owner.sign_tapscript(&master, &not_in_tree).unwrap_err();
        assert!(matches!(err, TapscriptError::LeafNotCommitted(0)), "{err}");

        // The prevout is not a taproot output.
        let mut not_taproot = exit.prevouts.clone();
        not_taproot[0].script_pubkey = Script::from(
            vec![0x00, 0x14]
                .into_iter()
                .chain([7u8; 20])
                .collect::<Vec<_>>(),
        );
        let err = owner
            .sign_tapscript(
                &master,
                &ScriptPathSpend {
                    prevouts: &not_taproot,
                    ..spend
                },
            )
            .unwrap_err();
        assert!(matches!(err, TapscriptError::NotTaproot(0)), "{err}");

        // Prevouts that do not line up with the inputs, and an input that does not exist.
        let err = owner
            .sign_tapscript(
                &master,
                &ScriptPathSpend {
                    prevouts: &[],
                    ..spend
                },
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                TapscriptError::Prevouts {
                    prevouts: 0,
                    inputs: 1
                }
            ),
            "{err}"
        );
        let err = owner
            .sign_tapscript(
                &master,
                &ScriptPathSpend {
                    input_index: 1,
                    ..spend
                },
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                TapscriptError::InputIndex {
                    index: 1,
                    inputs: 1
                }
            ),
            "{err}"
        );

        // Another chain's genesis hash, and this one in display byte order, give
        // other signatures, and neither verifies for this chain.
        let mut reversed = *genesis(&v).as_raw_hash().as_byte_array();
        reversed.reverse();
        for other in [
            BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000042")
                .unwrap(),
            BlockHash::from_raw_hash(
                elements_miniscript::elements::hashes::sha256d::Hash::from_byte_array(reversed),
            ),
        ] {
            let elsewhere = ScriptPathSpend {
                genesis_hash: other,
                ..spend
            };
            let sig = owner.sign_tapscript(&master, &elsewhere).unwrap();
            assert_ne!(sig.to_vec(), good.to_vec());
            let key = owner.xonly_public_key(&master).unwrap();
            assert!(spend.verify(&secp, &key, &sig.to_vec()).is_err());
            elsewhere.verify(&secp, &key, &sig.to_vec()).unwrap();
        }

        // A non-default sighash type gives a 65-byte signature carrying its byte.
        let all = ScriptPathSpend {
            sighash_type: SchnorrSighashType::All,
            ..spend
        };
        let sig = owner.sign_tapscript(&master, &all).unwrap().to_vec();
        assert_eq!(sig.len(), 65);
        assert_eq!(sig[64], 0x01);
        all.verify(&secp, &owner.xonly_public_key(&master).unwrap(), &sig)
            .unwrap();
        assert!(spend
            .verify(&secp, &owner.xonly_public_key(&master).unwrap(), &sig)
            .is_err());
    }

    // Review R1's two tapscript probes, which passed against the earlier
    // signer, turned around.

    #[test]
    fn sighash_types_that_leave_outputs_free_are_refused() {
        // R1 probe: sign_tapscript signed the exit under SIGHASH_NONE and
        // NONE|ANYONECANPAY, and each signature still verified after every
        // output but the fee was redirected.
        let v = vectors();
        let secp = Secp256k1::new();
        let master = DerivationPath::master();
        let owner = signer_for(v["inputs"]["keys"]["A5"]["secret"].as_str().unwrap());
        let key = owner.xonly_public_key(&master).unwrap();
        let exit = parse_spend(spend_named(&v, "leaf/exit"));
        let base = ScriptPathSpend {
            tx: &exit.tx,
            input_index: 0,
            prevouts: &exit.prevouts,
            leaf_script: &exit.leaf,
            control_block: &exit.control_block,
            sighash_type: SchnorrSighashType::Default,
            genesis_hash: genesis(&v),
        };
        for ty in [
            SchnorrSighashType::None,
            SchnorrSighashType::NonePlusAnyoneCanPay,
            SchnorrSighashType::Single,
            SchnorrSighashType::SinglePlusAnyoneCanPay,
            SchnorrSighashType::AllPlusAnyoneCanPay,
        ] {
            let spend = ScriptPathSpend {
                sighash_type: ty,
                ..base
            };
            let err = owner.sign_tapscript(&master, &spend).unwrap_err();
            assert!(
                matches!(err, TapscriptError::SighashNotAllowed(t) if t == ty),
                "{err}"
            );
            assert!(err.to_string().contains(sighash_name(ty)), "{err}");
            // Opting in to another type does not admit this one.
            let other = if ty == SchnorrSighashType::None {
                SchnorrSighashType::Single
            } else {
                SchnorrSighashType::None
            };
            let err = owner
                .sign_tapscript_allowing(&master, &spend, other)
                .unwrap_err();
            assert!(matches!(err, TapscriptError::SighashNotAllowed(_)), "{err}");
        }
        for ty in [SchnorrSighashType::Default, SchnorrSighashType::All] {
            let spend = ScriptPathSpend {
                sighash_type: ty,
                ..base
            };
            owner.sign_tapscript(&master, &spend).unwrap();
        }

        // Named by the caller, SIGHASH_NONE is signed, and the description says
        // what the review showed: the signature covers no output.
        let none = ScriptPathSpend {
            sighash_type: sighash_type_from_name("none").unwrap(),
            ..base
        };
        let text = none.describe().unwrap().join("\n");
        assert!(
            text.contains("covers no output, so whoever holds it can send this coin anywhere"),
            "{text}"
        );
        let sig = owner
            .sign_tapscript_allowing(&master, &none, SchnorrSighashType::None)
            .unwrap()
            .to_vec();
        let mut moved = exit.tx.clone();
        for o in moved.output.iter_mut().filter(|o| !o.is_fee()) {
            o.script_pubkey = Script::from(vec![0x51]);
        }
        let moved_spend = ScriptPathSpend { tx: &moved, ..none };
        moved_spend.verify(&secp, &key, &sig).unwrap();

        assert!(matches!(
            sighash_type_from_name("NONE"),
            Err(TapscriptError::SighashName(_))
        ));
        for name in [
            "default",
            "all",
            "none",
            "single",
            "all|anyonecanpay",
            "none|anyonecanpay",
            "single|anyonecanpay",
        ] {
            assert_eq!(sighash_name(sighash_type_from_name(name).unwrap()), name);
        }
    }

    #[test]
    fn a_key_only_checked_by_checksigfromstack_is_refused() {
        // R1 probe: the key check passed for the collaborative leaf, where the
        // owner's key is only checked by OP_CHECKSIGFROMSTACK.
        let v = vectors();
        let master = DerivationPath::master();
        let owner = signer_for(v["inputs"]["keys"]["A5"]["secret"].as_str().unwrap());
        let p = parse_spend(spend_named(&v, "leaf/collab m=1, into the checkpoint"));
        let spend = ScriptPathSpend {
            tx: &p.tx,
            input_index: 0,
            prevouts: &p.prevouts,
            leaf_script: &p.leaf,
            control_block: &p.control_block,
            sighash_type: SchnorrSighashType::Default,
            genesis_hash: genesis(&v),
        };
        let key = owner.xonly_public_key(&master).unwrap();
        assert!(script_pushes_key(&p.leaf, &key));
        assert!(!script_checks_key(&p.leaf, &key));
        let err = owner.sign_tapscript(&master, &spend).unwrap_err();
        assert!(
            matches!(err, TapscriptError::KeyNotChecked(k) if k == key),
            "{err}"
        );
    }

    #[test]
    fn describe_names_the_coin_the_outputs_and_the_wait() {
        let v = vectors();
        let exit = parse_spend(spend_named(&v, "leaf/exit"));
        let spend = ScriptPathSpend {
            tx: &exit.tx,
            input_index: 0,
            prevouts: &exit.prevouts,
            leaf_script: &exit.leaf,
            control_block: &exit.control_block,
            sighash_type: SchnorrSighashType::Default,
            genesis_hash: genesis(&v),
        };
        let lines = spend.describe().unwrap();
        let text = lines.join("\n");
        let coin = exit.prevouts[0].value.explicit().unwrap();
        assert!(
            text.contains(&format!("holding {coin} atoms of asset")),
            "{text}"
        );
        assert!(text.contains("leaf version 0xc4"), "{text}");
        assert!(
            text.contains("the signature covers every output, so the coin moves only into these"),
            "{text}"
        );
        assert!(text.contains("output 0: "), "{text}");
        assert!(text.contains("The fee: "), "{text}");
        assert!(
            text.contains("units of 512 s) after the coin it spends confirms"),
            "{text}"
        );
        assert!(text.contains(v["inputs"]["genesis_hash"]["display"].as_str().unwrap()));
        let bad = ScriptPathSpend {
            input_index: 3,
            ..spend
        };
        assert!(matches!(
            bad.describe().unwrap_err(),
            TapscriptError::InputIndex { .. }
        ));
    }

    #[test]
    fn any_leaf_version() {
        // One script in two leaves of one tree, at 0xc4 (Elements tapscript) and at
        // 0xc0 (the Bitcoin tapscript version). Each control block proves only its
        // own version, and the two signature hashes differ.
        let secp = Secp256k1::new();
        let signer = signer_for("0101010101010101010101010101010101010101010101010101010101010101");
        let master = DerivationPath::master();
        let key: XOnlyPublicKey = signer.xonly_public_key(&master).unwrap();
        let mut leaf = vec![0x20];
        leaf.extend_from_slice(&key.serialize());
        leaf.push(0xac);
        let leaf = Script::from(leaf);
        assert!(script_pushes_key(&leaf, &key));
        let nums = XOnlyPublicKey::from_slice(
            &Vec::<u8>::from_hex(
                "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
            )
            .unwrap(),
        )
        .unwrap();
        let c4 = LeafVersion::default();
        let c0 = LeafVersion::from_u8(0xc0).unwrap();
        let info = TaprootBuilder::new()
            .add_leaf_with_ver(1, leaf.clone(), c4)
            .unwrap()
            .add_leaf_with_ver(1, leaf.clone(), c0)
            .unwrap()
            .finalize(&secp, nums)
            .unwrap();
        let spk = Script::new_v1_p2tr_tweaked(info.output_key());
        let asset = AssetId::from_slice(&[0x11; 32]).unwrap();
        let prevout = TxOut::new_fee(50_000, asset);
        let prevout = TxOut {
            script_pubkey: spk,
            ..prevout
        };
        let tx = Transaction {
            version: 2,
            lock_time: elements_miniscript::elements::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                ..Default::default()
            }],
            output: vec![TxOut::new_fee(1_000, asset)],
        };
        let genesis =
            BlockHash::from_str("00902a6b70c2ca83b5d9c815d96a0e2f4202179316970d14ea1847dae5b1ca21")
                .unwrap();
        let mut sighashes = vec![];
        for ver in [c4, c0] {
            let cb = info.control_block(&(leaf.clone(), ver)).unwrap();
            assert_eq!(cb.leaf_version, ver);
            let spend = ScriptPathSpend {
                tx: &tx,
                input_index: 0,
                prevouts: std::slice::from_ref(&prevout),
                leaf_script: &leaf,
                control_block: &cb,
                sighash_type: SchnorrSighashType::Default,
                genesis_hash: genesis,
            };
            let sig = signer.sign_tapscript(&master, &spend).unwrap();
            spend.verify(&secp, &key, &sig.to_vec()).unwrap();
            sighashes.push(spend.sighash().unwrap());

            // The other version's control block does not prove this leaf at this version.
            let mut forged = cb.clone();
            forged.leaf_version = if ver == c4 { c0 } else { c4 };
            let forged_spend = ScriptPathSpend {
                control_block: &forged,
                ..spend
            };
            assert!(matches!(
                signer.sign_tapscript(&master, &forged_spend).unwrap_err(),
                TapscriptError::LeafNotCommitted(0)
            ));
        }
        assert_ne!(sighashes[0], sighashes[1]);
    }
}
