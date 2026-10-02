use std::collections::HashMap;

use crate::{Bip, Error, Mnemonic, Network, Pset, WolletDescriptor, Xpub};
use lwk_common::Signer as SignerTrait;
use lwk_wollet::{
    bitcoin::bip32, bitcoin::sign_message::MessageSignature,
    elements::pset::PartiallySignedTransaction, elements_miniscript::slip77,
};
use wasm_bindgen::prelude::*;

/// A Software signer.
#[wasm_bindgen]
pub struct Signer {
    pub(crate) inner: lwk_signer::SwSigner,
}

#[wasm_bindgen]
impl Signer {
    /// Creates a `Signer`
    #[wasm_bindgen(constructor)]
    pub fn new(mnemonic: &Mnemonic, network: &Network) -> Result<Signer, Error> {
        let inner = lwk_signer::SwSigner::new(&mnemonic.to_string(), network.is_mainnet())?;
        Ok(Self { inner })
    }

    /// Sign and consume the given PSET, returning the signed one
    pub fn sign(&self, pset: Pset) -> Result<Pset, Error> {
        let mut pset: PartiallySignedTransaction = pset.into();
        let added = lwk_common::Signer::sign(&self.inner, &mut pset)?;
        if added == 0 {
            return Err(Error::Generic("No signature added".to_string()));
        }
        Ok(pset.into())
    }

    /// Sign a message with the master key, return the signature as a base64 string
    #[wasm_bindgen(js_name = signMessage)]
    pub fn sign_message(&self, message: &str) -> Result<String, Error> {
        // TODO: make path parameter
        let signature = self
            .inner
            .sign_message(message, &bip32::DerivationPath::master())?;
        Ok(signature.to_string())
    }

    /// Return the witness public key hash, slip77 descriptor of this signer
    #[wasm_bindgen(js_name = wpkhSlip77Descriptor)]
    pub fn wpkh_slip77_descriptor(&self) -> Result<WolletDescriptor, Error> {
        // TODO: make script_variant and blinding_variant parameters

        let script_variant = lwk_common::Singlesig::Wpkh;
        let blinding_variant = lwk_common::DescriptorBlindingKey::Slip77;
        let desc_str = lwk_common::singlesig_desc(&self.inner, script_variant, blinding_variant)
            .map_err(Error::Generic)?;

        WolletDescriptor::new(&desc_str)
    }

    /// Return the extended public key of the signer
    #[wasm_bindgen(js_name = getMasterXpub)]
    pub fn get_master_xpub(&self) -> Result<Xpub, Error> {
        Ok(self.inner.xpub().into())
    }

    /// Return a dedicated Sequentia staking public key (33-byte compressed hex)
    /// derived from the master key at m/2/0. The wallet controls the matching
    /// private key, so a stake bonded to this key can later be unbonded.
    #[wasm_bindgen(js_name = stakerPublicKey)]
    pub fn staker_public_key(&self) -> Result<String, Error> {
        use lwk_wollet::bitcoin::secp256k1::Secp256k1;
        let secp = Secp256k1::verification_only();
        let path = bip32::DerivationPath::from(vec![
            bip32::ChildNumber::Normal { index: 2 },
            bip32::ChildNumber::Normal { index: 0 },
        ]);
        let child = self
            .inner
            .xpub()
            .derive_pub(&secp, &path)
            .map_err(|e| Error::Generic(e.to_string()))?;
        Ok(child.public_key.to_string())
    }

    /// Sign a message with the Sequentia STAKING key (m/2/0), in exactly the
    /// form [`Self::sign_message`] returns for the master key: a recoverable
    /// ECDSA signature over the Bitcoin signed-message digest, base64.
    ///
    /// This exists so a wallet can prove it controls the key its stake is bonded
    /// to without the user copying anything by hand. The stake sits under
    /// m/2/0, so a signature from the master key proves control of a DIFFERENT
    /// key and says nothing about the stake; anyone verifying has to be able to
    /// recover this key specifically.
    ///
    /// The secret never leaves Rust, as with the OpenAMP identity below.
    #[wasm_bindgen(js_name = signMessageWithStakerKey)]
    pub fn sign_message_with_staker_key(&self, message: &str) -> Result<String, Error> {
        let path = bip32::DerivationPath::from(vec![
            bip32::ChildNumber::Normal { index: 2 },
            bip32::ChildNumber::Normal { index: 0 },
        ]);
        let signature = self.inner.sign_message(message, &path)?;
        Ok(signature.to_string())
    }

    /// Return keyorigin and xpub, like "[73c5da0a/84h/1h/0h]tpub..."
    #[wasm_bindgen(js_name = keyoriginXpub)]
    pub fn keyorigin_xpub(&self, bip: &Bip) -> Result<String, Error> {
        Ok(lwk_common::Signer::keyorigin_xpub(
            &self.inner,
            bip.into(),
            self.inner.is_mainnet(),
        )?)
    }

    /// Return the signer fingerprint
    pub fn fingerprint(&self) -> Result<String, Error> {
        Ok(self.inner.fingerprint().to_string())
    }

    /// Return the mnemonic of the signer
    pub fn mnemonic(&self) -> Mnemonic {
        self.inner
            .mnemonic()
            .expect("wasm bindings always create signer via mnemonic and not via xpriv")
            .into()
    }

    /// Return the derived BIP85 mnemonic
    pub fn derive_bip85_mnemonic(&self, index: u32, word_count: u32) -> Result<Mnemonic, Error> {
        Ok(self.inner.derive_bip85_mnemonic(index, word_count)?.into())
    }

    // ---- Script-path signing ------------------------------------------------

    /// The x-only public key (64 hex) at the BIP32 derivation `path`, such as
    /// `"m/6/0"`: the form in which a tapscript leaf names a key.
    #[wasm_bindgen(js_name = xonlyPublicKeyAt)]
    pub fn xonly_public_key_at(&self, path: &str) -> Result<String, Error> {
        use lwk_wollet::elements::hex::ToHex;
        let path = parse_path(path)?;
        Ok(self.inner.xonly_public_key(&path)?.serialize().to_hex())
    }

    /// Sign input `inputIndex` of `txHex` through one leaf of the taproot
    /// output it spends, with the key at `path`: a BIP341 script-path
    /// signature over the Elements signature hash (the Elements tagged hashes
    /// and the genesis hash), at the leaf version the control block carries,
    /// with no auxiliary randomness.
    ///
    /// - `prevoutsHex`: every input's spent output, consensus-serialised hex,
    ///   in input order.
    /// - `leafScriptHex`, `controlBlockHex`: the leaf and its control block,
    ///   as they go in the witness.
    /// - `sighashType`: the BIP341 type byte; 0 is `SIGHASH_DEFAULT`.
    /// - `genesisHex`: the chain's genesis hash, display hex.
    ///
    /// Refuses when the control block does not commit the leaf to the output
    /// the input spends, and when the key at `path` is not pushed in the leaf.
    /// Returns the witness signature as hex: 64 bytes for `SIGHASH_DEFAULT`,
    /// 65 otherwise.
    #[wasm_bindgen(js_name = signTapscript)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_tapscript(
        &self,
        path: &str,
        tx_hex: &str,
        input_index: u32,
        prevouts_hex: Vec<String>,
        leaf_script_hex: &str,
        control_block_hex: &str,
        sighash_type: u8,
        genesis_hex: &str,
    ) -> Result<String, Error> {
        use lwk_wollet::elements::hex::ToHex;
        let path = parse_path(path)?;
        let parts = crate::tapscript::SpendParts::parse(
            tx_hex,
            input_index,
            &prevouts_hex,
            leaf_script_hex,
            control_block_hex,
            sighash_type,
            genesis_hex,
        )?;
        let sig = self.inner.sign_tapscript(&path, &parts.spend())?;
        Ok(sig.to_vec().to_hex())
    }

    /// Sign an Arca message for `OP_CHECKSIGFROMSTACK` with the key at `path`.
    ///
    /// `message` is the message as its fields (see `csfsDescribe` for the
    /// shape) and `digestHex` the 32-byte hash the caller expects to be
    /// signed. The signer rebuilds the digest from the fields and refuses when
    /// the two differ, so it never signs a hash whose meaning it has not
    /// checked. Returns a 64-byte BIP340 signature as hex, made with no
    /// auxiliary randomness.
    #[wasm_bindgen(js_name = signCsfs)]
    pub fn sign_csfs(
        &self,
        path: &str,
        message: JsValue,
        digest_hex: &str,
    ) -> Result<String, Error> {
        use lwk_wollet::elements::hex::ToHex;
        let path = parse_path(path)?;
        let message = crate::csfs::parse_message(message)?;
        let digest: [u8; 32] = crate::tapscript::unhex(digest_hex, "digest")?
            .try_into()
            .map_err(|_| Error::Generic("digest must be 32 bytes".into()))?;
        let sig = self.inner.sign_csfs(&path, &message, &digest)?;
        Ok(sig.serialize().to_hex())
    }

    // ---- OpenAMP identity + signing (SWK-1) --------------------------------
    // The canonical OpenAMP enclave key is BIP32 m/5/0 (spec 1.1), matching Ambra
    // (m/2/0 = staker, m/3/0 = SeqDEX HTLC, m/5/0 = OpenAMP). The secret NEVER
    // leaves Rust: signing happens here, deterministically (no aux rand), so
    // signatures are cross-implementation reproducible against Ambra's
    // `openamp_sign_sighash`. This is deliberately NOT the m/3/0 `htlcKeypair` the
    // web wallet reused (WW-1 security bug), and NOT the randomized-aux
    // `Keypair.signSchnorr`.

    fn openamp_keypair(
        &self,
    ) -> Result<lwk_wollet::bitcoin::secp256k1::Keypair, Error> {
        use lwk_wollet::bitcoin::secp256k1::{Keypair, Secp256k1};
        let path = bip32::DerivationPath::from(vec![
            bip32::ChildNumber::Normal { index: 5 },
            bip32::ChildNumber::Normal { index: 0 },
        ]);
        let xprv = self
            .inner
            .derive_xprv(&path)
            .map_err(|e| Error::Generic(e.to_string()))?;
        let secp = Secp256k1::new();
        Ok(Keypair::from_secret_key(&secp, &xprv.private_key))
    }

    /// The wallet's OpenAMP identity: the x-only pubkey of the m/5/0 key, 64-hex.
    /// This is the pubkey registered with openampd (`POST /v1/users`) and the one
    /// the local AID is computed from.
    #[wasm_bindgen(js_name = openampXonlyPubkey)]
    pub fn openamp_xonly_pubkey(&self) -> Result<String, Error> {
        use lwk_wollet::elements::hex::ToHex;
        let keypair = self.openamp_keypair()?;
        let (xonly, _parity) = keypair.x_only_public_key();
        Ok(xonly.serialize().to_hex())
    }

    /// Sign a 32-byte Elements taproot enclave sighash (given as 64-hex) with the
    /// m/5/0 key, returning a 128-hex plain (untagged) BIP340 signature (spec
    /// 0.4(1)). DETERMINISTIC: aux rand is all-zeros, so the signature matches
    /// Ambra byte-for-byte.
    ///
    /// SAFETY: the caller MUST have recomputed this digest itself from the
    /// transaction and prevouts (SWK-6, `enclaveSighash`) and shown the decoded
    /// effects; this method never inspects what it signs (spec 0.4(3)). It is only
    /// reached by the hosted-send / settlement path, never a deep link.
    #[wasm_bindgen(js_name = openampSignSighash)]
    pub fn openamp_sign_sighash(&self, digest_hex: &str) -> Result<String, Error> {
        use lwk_wollet::bitcoin::secp256k1::{Message, Secp256k1};
        use lwk_wollet::elements::hex::{FromHex, ToHex};
        let bytes = Vec::<u8>::from_hex(digest_hex)
            .map_err(|e| Error::Generic(format!("invalid digest hex: {e}")))?;
        let digest: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Generic("digest must be 32 bytes".into()))?;
        let keypair = self.openamp_keypair()?;
        let secp = Secp256k1::new();
        let msg = Message::from_digest(digest);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        Ok(sig.serialize().to_hex())
    }

    /// Sign a TAGGED message with the m/5/0 key (spec 0.4(2)): computes
    /// `tagged_hash(tag, message) = sha256(sha256(tag)||sha256(tag)||message)` then
    /// plain BIP340 over that, returning 128-hex. `message_hex` is the message
    /// bytes as hex (the UTF-8 challenge string for `openamp-challenge-v1`, or the
    /// 32-byte document hash for `openamp-document-v1`).
    ///
    /// This surface can NEVER authorize an enclave spend: it has no raw-digest
    /// mode, and the tagged hash domain-separates it from any transfer sighash.
    #[wasm_bindgen(js_name = openampSignTagged)]
    pub fn openamp_sign_tagged(&self, tag: &str, message_hex: &str) -> Result<String, Error> {
        use lwk_wollet::bitcoin::secp256k1::{Message, Secp256k1};
        use lwk_wollet::elements::hex::{FromHex, ToHex};
        let message = Vec::<u8>::from_hex(message_hex)
            .map_err(|e| Error::Generic(format!("invalid message hex: {e}")))?;
        let digest = lwk_wollet::tagged_hash(tag, &message);
        let keypair = self.openamp_keypair()?;
        let secp = Secp256k1::new();
        let msg = Message::from_digest(digest);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        Ok(sig.serialize().to_hex())
    }

    /// Sign a tagged UTF-8 challenge string directly (convenience over
    /// [`Self::openamp_sign_tagged`] for the common challenge case): the message is
    /// the raw UTF-8 bytes of `challenge` under the `openamp-challenge-v1` tag.
    #[wasm_bindgen(js_name = openampSignChallenge)]
    pub fn openamp_sign_challenge(&self, challenge: &str) -> Result<String, Error> {
        use lwk_wollet::bitcoin::secp256k1::{Message, Secp256k1};
        use lwk_wollet::elements::hex::ToHex;
        let digest = lwk_wollet::tagged_hash(lwk_wollet::TAG_CHALLENGE, challenge.as_bytes());
        let keypair = self.openamp_keypair()?;
        let secp = Secp256k1::new();
        let msg = Message::from_digest(digest);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        Ok(sig.serialize().to_hex())
    }
}

fn parse_path(path: &str) -> Result<bip32::DerivationPath, Error> {
    use std::str::FromStr;
    Ok(bip32::DerivationPath::from_str(path)?)
}

#[allow(dead_code)]
#[derive(Debug)]
// Used internally to emulate a sync signer for some methods
pub(crate) struct FakeSigner {
    pub(crate) paths: HashMap<bip32::DerivationPath, bip32::Xpub>,
    pub(crate) slip77: slip77::MasterBlindingKey,
}

impl lwk_common::Signer for FakeSigner {
    type Error = String;

    fn sign(&self, _pset: &mut PartiallySignedTransaction) -> Result<u32, Self::Error> {
        unimplemented!()
    }

    fn derive_xpub(&self, path: &bip32::DerivationPath) -> Result<bip32::Xpub, Self::Error> {
        self.paths
            .get(path)
            .cloned()
            .ok_or("Should contain all needed derivations".to_string())
    }

    fn slip77_master_blinding_key(&self) -> Result<slip77::MasterBlindingKey, Self::Error> {
        Ok(self.slip77)
    }

    fn sign_message(
        &self,
        _message: &str,
        _path: &bip32::DerivationPath,
    ) -> Result<MessageSignature, Self::Error> {
        unimplemented!()
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use crate::{Bip, Mnemonic, Pset, Signer};
    use lwk_wollet::elements;
    use std::str::FromStr;
    use wasm_bindgen_test::*;

    pub fn regtest_policy_asset() -> elements::AssetId {
        elements::AssetId::from_str(
            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
        )
        .unwrap()
    }

    pub fn network_regtest() -> lwk_common::Network {
        let policy_asset = regtest_policy_asset();
        lwk_common::Network::CustomElements(
            lwk_common::ElementsParamsBuilder::new()
                .with_policy_asset(policy_asset.into())
                .build()
                .expect("static"),
        )
    }

    #[wasm_bindgen_test]
    fn signer() {
        let mnemonic_str =  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::new(mnemonic_str).unwrap();
        let network: crate::Network = network_regtest().into();

        let signer = Signer::new(&mnemonic, &network).unwrap();

        let pset_string =
            include_str!("../../lwk_jade/test_data/pset_to_be_signed.base64").to_string();
        let pset = Pset::new(&pset_string).unwrap();

        let signed_pset = signer.sign(pset.clone()).unwrap();

        assert_ne!(pset, signed_pset);

        assert_eq!(signer.get_master_xpub().unwrap().fingerprint(), "73c5da0a");

        assert_eq!(signer.keyorigin_xpub(&Bip::bip49()).unwrap(), "[73c5da0a/49h/1h/0h]tpubDD7tXK8KeQ3YY83yWq755fHY2JW8Ha8Q765tknUM5rSvjPcGWfUppDFMpQ1ScziKfW3ZNtZvAD7M3u7bSs7HofjTD3KP3YxPK7X6hwV8Rk2");

        assert_eq!(signer.keyorigin_xpub(&Bip::bip86()).unwrap(), "[73c5da0a/86h/1h/0h]tpubDDfvzhdVV4unsoKt5aE6dcsNsfeWbTgmLZPi8LQDYU2xixrYemMfWJ3BaVneH3u7DBQePdTwhpybaKRU95pi6PMUtLPBJLVQRpzEnjfjZzX");

        assert_eq!(signer.mnemonic(), mnemonic);

        assert_eq!(signer.sign_message("Hello, world!").unwrap(), "Hwlg40qLYZXEj9AoA3oZpfJMJPxaXzBL0+siHAJRhTIvSFiwSdtCsqxqB7TxgWfhqIr/YnGE4nagWzPchFJElTo=");

        // The staking signature must recover to the STAKING key, not the master
        // one: proving control of the wrong key would let a wallet claim a
        // stake it does not own, or fail to claim one it does.
        let staker_sig = signer.sign_message_with_staker_key("Hello, world!").unwrap();
        assert_ne!(staker_sig, signer.sign_message("Hello, world!").unwrap());
        let parsed = lwk_wollet::bitcoin::sign_message::MessageSignature::from_base64(&staker_sig)
            .expect("staker signature parses");
        let secp = lwk_wollet::bitcoin::secp256k1::Secp256k1::new();
        let digest = lwk_wollet::bitcoin::sign_message::signed_msg_hash("Hello, world!");
        let recovered = parsed
            .recover_pubkey(&secp, digest)
            .expect("staker signature recovers");
        assert_eq!(recovered.to_string(), signer.staker_public_key().unwrap());

        // Test BIP85 derivation
        assert_eq!(
            signer.derive_bip85_mnemonic(0, 12).unwrap().to_string(),
            "prosper short ramp prepare exchange stove life snack client enough purpose fold"
        );

        assert_eq!(signer.derive_bip85_mnemonic(0, 24).unwrap().to_string(), "stick exact spice sock filter ginger museum horse kit multiply manual wear grief demand derive alert quiz fault december lava picture immune decade jaguar");

        assert_ne!(
            signer.derive_bip85_mnemonic(0, 12).unwrap().to_string(),
            signer.derive_bip85_mnemonic(1, 12).unwrap().to_string()
        );

        assert_eq!(
            signer.derive_bip85_mnemonic(0, 12).unwrap().to_string(),
            signer.derive_bip85_mnemonic(0, 12).unwrap().to_string()
        );
    }
}
