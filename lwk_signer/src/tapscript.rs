//! Taproot script-path signing over the Elements signature hash.
//!
//! [`SwSigner::sign_tapscript`] signs one input of a transaction through one
//! leaf of its taproot output, for any leaf version (`0xc4`, the Elements
//! tapscript version, included). The signature hash is the Elements one: the
//! `TapSighash/elements`, `TapLeaf/elements` and `TapBranch/elements` tagged
//! hashes, and the chain's genesis hash committed in the message, so a
//! signature made for one chain is void on every other.
//!
//! Before it signs, the signer checks two things a caller could otherwise get
//! wrong without noticing:
//!
//! - the control block proves that the leaf is in the taproot output being
//!   spent, so the signature is for the coin the caller names and for no other
//!   script tree;
//! - the key at the given derivation path is pushed in the leaf, so the wallet
//!   signs only where its own key is asked for.
//!
//! The signature is BIP340 with no auxiliary randomness: the nonce is derived
//! from the key and the message alone, so the same request always gives the
//! same 64 bytes, and two implementations can be compared byte for byte.
//!
//! The annex is not supported: a spend that carries one has a different
//! signature hash, and nothing on Sequentia uses it.

use elements_miniscript::elements::{
    bitcoin::bip32::{self, DerivationPath},
    hashes::Hash,
    schnorr::TweakedPublicKey,
    script::Instruction,
    secp256k1_zkp::{schnorr, Message, Secp256k1, Verification, XOnlyPublicKey},
    sighash::{Prevouts, ScriptPath, SighashCache},
    taproot::{ControlBlock, LeafVersion, TapLeafHash},
    BlockHash, SchnorrSig, SchnorrSighashType, Script, Transaction, TxOut,
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

    /// The signature hash type is not a defined BIP341 value.
    #[error("sighash type {0:#04x} is not defined")]
    SighashType(u8),

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

/// True when `key` is pushed, as 32 bytes, anywhere in `script`.
pub fn script_pushes_key(script: &Script, key: &XOnlyPublicKey) -> bool {
    let key = key.serialize();
    script
        .instructions()
        .any(|ins| matches!(ins, Ok(Instruction::PushBytes(bytes)) if bytes == key.as_slice()))
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
    /// being spent, and when the key at `path` is not pushed in the leaf.
    /// Returns the signature as it goes in the witness: 64 bytes for
    /// [`SchnorrSighashType::Default`], 65 otherwise.
    pub fn sign_tapscript(
        &self,
        path: &DerivationPath,
        spend: &ScriptPathSpend<'_>,
    ) -> Result<SchnorrSig, TapscriptError> {
        spend.check_commitment(&self.secp)?;
        let derived = self.xprv.derive_priv(&self.secp, path)?;
        let keypair = derived.to_keypair(&self.secp);
        let (xonly, _) = keypair.x_only_public_key();
        if !script_pushes_key(spend.leaf_script, &xonly) {
            return Err(TapscriptError::KeyNotInLeaf(xonly));
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

    use super::{script_pushes_key, ScriptPathSpend, TapscriptError};
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
