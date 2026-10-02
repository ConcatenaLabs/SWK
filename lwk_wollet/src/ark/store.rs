//! The wallet's Arca leaves, kept over the kit's store.
//!
//! [`ArkStore`] keeps, under keys that begin `ark/`, what a wallet needs to
//! take each of its leaves on-chain alone, and to never sign for two leaves
//! with one key, that the mnemonic cannot give it back:
//!
//! - the leaf's record, in its binary form, by leaf id;
//! - the round transaction's id and the batch output's index it was verified
//!   against, so a rollback that replaces the round is noticed;
//! - the entry's unlock preimage, once the wallet has it;
//! - unroll authorisations for the nodes above the leaf;
//! - the owner nonces of leaves the wallet has asked for whose records have
//!   not arrived yet;
//! - every owner nonce and owner key it has ever kept a leaf under, with the
//!   leaf, marked once the leaf is removed rather than forgotten.
//!
//! Nothing is kept that the mnemonic rebuilds: a leaf's private key follows
//! from the owner nonce in its record ([`super::keys`]) and is never stored;
//! the owner keys it remembers are the public ones its records name. None of
//! what is kept is secret: the preimage is published when the operator claims
//! a forfeit, and an unroll authorisation lets whoever holds it do only what
//! any member of the node can. Wrap the store in an encrypting one for
//! privacy. The marks of removed leaves are state too: a wallet restored into
//! an empty store has none of them, so back the store up with the mnemonic.
//!
//! The store refuses what would hurt the wallet:
//!
//! - a leaf under an owner nonce or key it has ever kept another leaf under,
//!   or a leaf it has removed: one key would then sign for two leaves, and an
//!   old signature made under the leaf's salt would fit the new one, which
//!   lets the operator take it;
//! - a leaf whose owner nonce the wallet is not waiting on
//!   ([`ArkStore::put_pending`]), except in a restore
//!   ([`ArkStore::put_restored_leaf`]), so that a record a server sends
//!   unasked is never taken as the wallet's;
//! - a preimage that does not open the record's unlock hash, and an unroll
//!   authorisation that the record's owner key did not sign for a node on the
//!   leaf's path.

use std::collections::BTreeMap;
use std::sync::Arc;

use elements::hashes::{sha256, Hash};
use elements::hex::{FromHex, ToHex};
use elements::secp256k1_zkp::{schnorr, Message, Secp256k1};
use elements::Txid;
use lwk_common::DynStore;
use serde::{Deserialize, Serialize};

use super::keys::OwnerNonce;
use super::verify::VerifiedLeaf;
use super::{LeafId, LeafRecord, MedianTime, RecordError};

const INDEX: &str = "ark/leaves";
const PENDING: &str = "ark/pending";
const USED: &str = "ark/used";

fn leaf_key(id: &LeafId) -> String {
    format!("ark/leaf/{id}")
}

/// Errors from the Arca store.
#[derive(thiserror::Error, Debug)]
pub enum ArkStoreError {
    /// The underlying store failed.
    #[error("store: {0}")]
    Store(String),

    /// A stored value does not parse.
    #[error("stored value under {key}: {reason}")]
    Corrupt {
        /// The store key.
        key: String,
        /// What is wrong.
        reason: String,
    },

    /// The record is malformed.
    #[error(transparent)]
    Record(#[from] RecordError),

    /// The verification is for another leaf than the record.
    #[error("the verification is for leaf {verified}, the record for leaf {record}")]
    NotThisLeaf {
        /// The verified leaf id.
        verified: String,
        /// The record's leaf id.
        record: String,
    },

    /// Another leaf the store has kept, now or before, has the same owner
    /// nonce or key.
    #[error("leaf {other} already has owner nonce {nonce} or its key: one key would sign for two leaves")]
    NonceReused {
        /// The other leaf's id.
        other: String,
        /// The owner nonce, hex.
        nonce: String,
    },

    /// The leaf was kept and then removed; its nonce and key are not used
    /// again.
    #[error("leaf {0} was removed from the store; it is not kept again")]
    Removed(String),

    /// The owner nonce is not one the wallet is waiting on.
    #[error("owner nonce {0} is not one this wallet is waiting on: a leaf is kept only for a nonce the wallet published, or in a restore")]
    NotPending(String),

    /// No leaf with this id is stored.
    #[error("no leaf {0} in the store")]
    Unknown(String),

    /// The preimage does not open the record's unlock hash.
    #[error("the preimage does not hash to the leaf's unlock hash")]
    WrongPreimage,

    /// The path has no node at this level.
    #[error("the leaf's path has {levels} nodes, so no node at level {level}")]
    Level {
        /// The level asked for.
        level: usize,
        /// The nodes on the path.
        levels: usize,
    },

    /// The authorisation is not the record owner's signature for the node.
    #[error("the signature is not the owner's unroll authorisation for the node at level {0}")]
    BadAuthorisation(usize),
}

fn store_err(e: impl std::fmt::Display) -> ArkStoreError {
    ArkStoreError::Store(e.to_string())
}

/// An unroll authorisation for one node above the leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnrollAuthorisation {
    /// The node's level on the path, 0 for the batch output.
    pub level: usize,
    /// The median time from which it can be used.
    pub time: u32,
    /// The owner's BIP340 signature over the node's unroll message, hex.
    pub signature: String,
}

/// A leaf as the store keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLeaf {
    /// The record.
    pub record: LeafRecord,
    /// The leaf's id.
    pub leaf_id: LeafId,
    /// The round the leaf was last verified against.
    pub round_txid: Txid,
    /// The batch output's index in that round.
    pub batch_vout: u32,
    /// The entry's unlock preimage, once known.
    pub preimage: Option<[u8; 32]>,
    /// Unroll authorisations, by node level.
    pub unroll: Vec<UnrollAuthorisation>,
}

/// What the store remembers of an owner nonce it has kept a leaf under.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Used {
    /// The owner key, hex.
    key: String,
    /// The leaf's id.
    leaf: String,
    /// True once the leaf is removed.
    #[serde(default)]
    removed: bool,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    record: String,
    round_txid: String,
    batch_vout: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preimage: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    unroll: Vec<UnrollAuthorisation>,
}

/// The wallet's Arca leaves over any store of the kit.
#[derive(Debug, Clone)]
pub struct ArkStore {
    store: Arc<dyn DynStore>,
}

impl ArkStore {
    /// An Arca store over `store`, which it shares with whatever else uses it:
    /// every key it writes begins `ark/`.
    pub fn new(store: Arc<dyn DynStore>) -> Self {
        ArkStore { store }
    }

    fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<Option<T>, ArkStoreError> {
        match self.store.get(key).map_err(store_err)? {
            None => Ok(None),
            Some(bytes) => {
                serde_json::from_slice(&bytes)
                    .map(Some)
                    .map_err(|e| ArkStoreError::Corrupt {
                        key: key.into(),
                        reason: e.to_string(),
                    })
            }
        }
    }

    fn put_json<T: Serialize>(&self, key: &str, value: &T) -> Result<(), ArkStoreError> {
        let bytes = serde_json::to_vec(value).map_err(store_err)?;
        self.store.put(key, &bytes).map_err(store_err)
    }

    /// The ids of every leaf in the store, in id order.
    pub fn leaf_ids(&self) -> Result<Vec<LeafId>, ArkStoreError> {
        let ids: Vec<String> = self.get_json(INDEX)?.unwrap_or_default();
        ids.iter()
            .map(|s| {
                s.parse().map_err(|_| ArkStoreError::Corrupt {
                    key: INDEX.into(),
                    reason: format!("{s} is not a leaf id"),
                })
            })
            .collect()
    }

    fn put_index(&self, ids: &[LeafId]) -> Result<(), ArkStoreError> {
        let mut ids: Vec<String> = ids.iter().map(|i| i.to_string()).collect();
        ids.sort();
        ids.dedup();
        self.put_json(INDEX, &ids)
    }

    fn entry(&self, id: &LeafId) -> Result<Entry, ArkStoreError> {
        self.get_json(&leaf_key(id))?
            .ok_or_else(|| ArkStoreError::Unknown(id.to_string()))
    }

    fn parse(&self, id: &LeafId, e: Entry) -> Result<StoredLeaf, ArkStoreError> {
        let key = leaf_key(id);
        let corrupt = |reason: String| ArkStoreError::Corrupt {
            key: key.clone(),
            reason,
        };
        let bytes = Vec::<u8>::from_hex(&e.record).map_err(|e| corrupt(e.to_string()))?;
        let record = LeafRecord::from_bytes(&bytes)?;
        let preimage = match e.preimage {
            None => None,
            Some(h) => Some(
                Vec::<u8>::from_hex(&h)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| corrupt("the preimage is not 32 bytes of hex".into()))?,
            ),
        };
        Ok(StoredLeaf {
            record,
            leaf_id: *id,
            round_txid: e
                .round_txid
                .parse()
                .map_err(|_| corrupt("round txid".into()))?,
            batch_vout: e.batch_vout,
            preimage,
            unroll: e.unroll,
        })
    }

    /// The stored leaf with this id, if any.
    pub fn leaf(&self, id: &LeafId) -> Result<Option<StoredLeaf>, ArkStoreError> {
        match self.get_json::<Entry>(&leaf_key(id))? {
            None => Ok(None),
            Some(e) => Ok(Some(self.parse(id, e)?)),
        }
    }

    /// Every stored leaf.
    pub fn leaves(&self) -> Result<Vec<StoredLeaf>, ArkStoreError> {
        self.leaf_ids()?
            .iter()
            .map(|id| self.parse(id, self.entry(id)?))
            .collect()
    }

    fn used(&self) -> Result<BTreeMap<String, Used>, ArkStoreError> {
        Ok(self.get_json(USED)?.unwrap_or_default())
    }

    /// Refuses `record` (leaf `id`) when the store has kept another leaf
    /// under its owner nonce or key, or has removed this one. Leaves kept
    /// before the store remembered nonces are found through the index.
    fn check_unused(&self, record: &LeafRecord, id: &LeafId) -> Result<(), ArkStoreError> {
        let nonce = record.owner_nonce.to_hex();
        let key = record.owner.serialize().to_hex();
        for (n, u) in self.used()? {
            if n == nonce || u.key == key {
                if u.leaf != id.to_string() {
                    return Err(ArkStoreError::NonceReused {
                        other: u.leaf,
                        nonce,
                    });
                }
                if u.removed {
                    return Err(ArkStoreError::Removed(u.leaf));
                }
            }
        }
        for other in self.leaf_ids()? {
            if other == *id {
                continue;
            }
            let o = self.parse(&other, self.entry(&other)?)?;
            if o.record.owner_nonce == record.owner_nonce || o.record.owner == record.owner {
                return Err(ArkStoreError::NonceReused {
                    other: other.to_string(),
                    nonce,
                });
            }
        }
        Ok(())
    }

    fn mark_used(
        &self,
        record: &LeafRecord,
        id: &LeafId,
        removed: bool,
    ) -> Result<(), ArkStoreError> {
        let mut used = self.used()?;
        used.insert(
            record.owner_nonce.to_hex(),
            Used {
                key: record.owner.serialize().to_hex(),
                leaf: id.to_string(),
                removed,
            },
        );
        self.put_json(USED, &used)
    }

    /// Keep a leaf the wallet has verified ([`super::verify`]), whose owner
    /// nonce it is waiting on ([`ArkStore::put_pending`]). Refuses a
    /// verification of another leaf, a leaf under an owner nonce or key the
    /// store has kept another leaf under (now or before), a leaf it has
    /// removed, and a nonce it is not waiting on. Storing a leaf it holds
    /// again keeps its preimage and authorisations and takes the new round.
    /// The nonce leaves the pending list.
    pub fn put_leaf(
        &self,
        record: &LeafRecord,
        verified: &VerifiedLeaf,
    ) -> Result<(), ArkStoreError> {
        self.keep(record, verified, false)
    }

    /// Keep a leaf found in a restore: the wallet, restored from its
    /// mnemonic, rebuilt the leaf's key from the record's owner nonce
    /// ([`super::keys::restore_key`]) and verified it. The same as
    /// [`ArkStore::put_leaf`] except that the nonce need not be pending; a
    /// nonce or key the store has kept another leaf under, and a leaf it has
    /// removed, are still refused.
    pub fn put_restored_leaf(
        &self,
        record: &LeafRecord,
        verified: &VerifiedLeaf,
    ) -> Result<(), ArkStoreError> {
        self.keep(record, verified, true)
    }

    fn keep(
        &self,
        record: &LeafRecord,
        verified: &VerifiedLeaf,
        restore: bool,
    ) -> Result<(), ArkStoreError> {
        let id = record.leaf_id()?;
        if id != verified.leaf_id {
            return Err(ArkStoreError::NotThisLeaf {
                verified: verified.leaf_id.to_string(),
                record: id.to_string(),
            });
        }
        self.check_unused(record, &id)?;
        let mut ids = self.leaf_ids()?;
        let held = ids.contains(&id);
        if !held && !restore {
            let waiting = self
                .pending()?
                .iter()
                .any(|(n, _)| *n == record.owner_nonce);
            if !waiting {
                return Err(ArkStoreError::NotPending(record.owner_nonce.to_hex()));
            }
        }
        let previous = self.get_json::<Entry>(&leaf_key(&id))?;
        let entry = Entry {
            record: record.to_bytes()?.to_hex(),
            round_txid: verified.round_txid.to_string(),
            batch_vout: verified.batch_vout,
            preimage: previous.as_ref().and_then(|p| p.preimage.clone()),
            unroll: previous.map(|p| p.unroll).unwrap_or_default(),
        };
        self.mark_used(record, &id, false)?;
        self.put_json(&leaf_key(&id), &entry)?;
        ids.push(id);
        self.put_index(&ids)?;
        self.remove_pending(&record.owner_nonce)
    }

    /// Take the round a leaf was verified against anew, after
    /// [`super::verify::recheck`] found another transaction in its place.
    pub fn set_round(&self, verified: &VerifiedLeaf) -> Result<(), ArkStoreError> {
        let mut e = self.entry(&verified.leaf_id)?;
        e.round_txid = verified.round_txid.to_string();
        e.batch_vout = verified.batch_vout;
        self.put_json(&leaf_key(&verified.leaf_id), &e)
    }

    /// Keep the entry's unlock preimage. Refuses one that does not hash to
    /// the record's unlock hash.
    pub fn put_preimage(&self, id: &LeafId, preimage: &[u8; 32]) -> Result<(), ArkStoreError> {
        let mut e = self.entry(id)?;
        let leaf = self.parse(id, self.entry(id)?)?;
        if sha256::Hash::hash(preimage).to_byte_array() != leaf.record.unlock_hash {
            return Err(ArkStoreError::WrongPreimage);
        }
        e.preimage = Some(preimage.to_hex());
        self.put_json(&leaf_key(id), &e)
    }

    /// Keep an unroll authorisation for the node at `level` on the leaf's
    /// path (0 is the batch output), usable from median time `time`. Refuses a
    /// signature that is not the record's owner key's over that node's unroll
    /// message. One authorisation per level is kept; a new one replaces it.
    pub fn put_unroll_authorisation(
        &self,
        id: &LeafId,
        level: usize,
        time: MedianTime,
        signature: &[u8],
    ) -> Result<(), ArkStoreError> {
        let mut e = self.entry(id)?;
        let leaf = self.parse(id, self.entry(id)?)?;
        let branch = leaf.record.branch()?;
        let node = branch.nodes.get(level).ok_or(ArkStoreError::Level {
            level,
            levels: branch.nodes.len(),
        })?;
        let digest = node.unroll_authorisation(time).digest;
        let sig = schnorr::Signature::from_slice(signature)
            .map_err(|_| ArkStoreError::BadAuthorisation(level))?;
        Secp256k1::verification_only()
            .verify_schnorr(&sig, &Message::from_digest(digest), &leaf.record.owner)
            .map_err(|_| ArkStoreError::BadAuthorisation(level))?;
        e.unroll.retain(|a| a.level != level);
        e.unroll.push(UnrollAuthorisation {
            level,
            time: time.to_consensus_u32(),
            signature: signature.to_hex(),
        });
        e.unroll.sort_by_key(|a| a.level);
        self.put_json(&leaf_key(id), &e)
    }

    /// Remove a leaf, once it is spent and settled. Its record goes; its
    /// owner nonce and key stay marked as used, with the leaf's id, so that
    /// neither is kept again.
    pub fn remove_leaf(&self, id: &LeafId) -> Result<(), ArkStoreError> {
        if let Some(leaf) = self.leaf(id)? {
            self.mark_used(&leaf.record, id, true)?;
        }
        self.store.remove(&leaf_key(id)).map_err(store_err)?;
        let ids: Vec<LeafId> = self.leaf_ids()?.into_iter().filter(|i| i != id).collect();
        self.put_index(&ids)
    }

    /// Remember the owner nonce of a leaf the wallet has asked for, or
    /// published in a receive request, until its record arrives. Refuses a
    /// nonce the store has kept a leaf under.
    pub fn put_pending(&self, nonce: &OwnerNonce, note: &str) -> Result<(), ArkStoreError> {
        let hex = nonce.to_hex();
        if let Some(u) = self.used()?.remove(&hex) {
            return Err(ArkStoreError::NonceReused {
                other: u.leaf,
                nonce: hex,
            });
        }
        for id in self.leaf_ids()? {
            if self.parse(&id, self.entry(&id)?)?.record.owner_nonce == *nonce {
                return Err(ArkStoreError::NonceReused {
                    other: id.to_string(),
                    nonce: hex,
                });
            }
        }
        let mut p: BTreeMap<String, String> = self.get_json(PENDING)?.unwrap_or_default();
        p.insert(nonce.to_hex(), note.to_string());
        self.put_json(PENDING, &p)
    }

    /// The owner nonces the wallet is waiting on, with their notes.
    pub fn pending(&self) -> Result<Vec<(OwnerNonce, String)>, ArkStoreError> {
        let p: BTreeMap<String, String> = self.get_json(PENDING)?.unwrap_or_default();
        p.into_iter()
            .map(|(n, note)| {
                let nonce = Vec::<u8>::from_hex(&n)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| ArkStoreError::Corrupt {
                        key: PENDING.into(),
                        reason: format!("{n} is not an owner nonce"),
                    })?;
                Ok((nonce, note))
            })
            .collect()
    }

    /// Stop waiting on an owner nonce.
    pub fn remove_pending(&self, nonce: &OwnerNonce) -> Result<(), ArkStoreError> {
        let mut p: BTreeMap<String, String> = self.get_json(PENDING)?.unwrap_or_default();
        if p.remove(&nonce.to_hex()).is_some() {
            self.put_json(PENDING, &p)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use elements::encode::deserialize;
    use elements::secp256k1_zkp::XOnlyPublicKey;
    use elements::{BlockHash, Script, Transaction};
    use lwk_common::MemoryStore;
    use lwk_signer::csfs::{
        ArcaMessage, CommittedOutput, CsfsPolicy, UnrollAuthorisation as Unroll,
    };
    use lwk_signer::SwSigner;
    use serde_json::Value as Json;

    use super::*;
    use crate::ark::keys::{fresh_leaf_key, LeafKey};
    use crate::ark::verify::verify_leaf;
    use crate::ark::{covenant, Chain, ClockSchedule, RelativeTime, WalletPolicy};

    fn vectors() -> Json {
        serde_json::from_str(include_str!("../../tests/data/arca_records.json")).unwrap()
    }

    fn hex(s: &Json) -> Vec<u8> {
        Vec::<u8>::from_hex(s.as_str().unwrap()).unwrap()
    }

    /// A record of the vectors, its round, and its verification.
    fn vector_leaf(v: &Json, b: usize, r: usize) -> (LeafRecord, VerifiedLeaf) {
        let batch = &v["batches"][b];
        let rec = &batch["records"][r];
        let leaf = &batch["inputs"]["leaves"][rec["leaf"].as_u64().unwrap() as usize];
        let record = LeafRecord::from_bytes(&hex(&rec["binary"])).unwrap();
        let round: Transaction = deserialize(&hex(&batch["round"]["tx"])).unwrap();
        let genesis = BlockHash::from_str(v["inputs"]["genesis_hash"].as_str().unwrap()).unwrap();
        let e0 = batch["inputs"]["expiries"][0].as_u64().unwrap() as u32;
        let policy = WalletPolicy::new(
            Chain::new(genesis),
            XOnlyPublicKey::from_str(v["inputs"]["operator"].as_str().unwrap()).unwrap(),
            MedianTime::from_consensus(e0 - 28 * 86_400).unwrap(),
        );
        let owner = XOnlyPublicKey::from_str(leaf["owner"].as_str().unwrap()).unwrap();
        let nonce: OwnerNonce = hex(&leaf["owner_nonce"]).try_into().unwrap();
        let verified = verify_leaf(&record, &round, &policy, &owner, &nonce).unwrap();
        (record, verified)
    }

    /// A memory store that records every key written to it.
    #[derive(Debug, Default)]
    struct Recorder {
        inner: MemoryStore,
        keys: std::sync::Mutex<Vec<String>>,
    }

    impl lwk_common::Store for Recorder {
        type Error = <MemoryStore as lwk_common::Store>::Error;
        fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<Vec<u8>>, Self::Error> {
            lwk_common::Store::get(&self.inner, key)
        }
        fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&self, key: K, value: V) -> Result<(), Self::Error> {
            self.keys
                .lock()
                .unwrap()
                .push(String::from_utf8(key.as_ref().to_vec()).unwrap());
            lwk_common::Store::put(&self.inner, key, value)
        }
        fn remove<K: AsRef<[u8]>>(&self, key: K) -> Result<(), Self::Error> {
            lwk_common::Store::remove(&self.inner, key)
        }
    }

    fn store() -> ArkStore {
        ArkStore::new(Arc::new(MemoryStore::new()))
    }

    #[test]
    fn leaves_round_trip() {
        let v = vectors();
        let recorder = Arc::new(Recorder::default());
        let s = ArkStore::new(recorder.clone());
        let (r0, v0) = vector_leaf(&v, 2, 0);
        let (r1, v1) = vector_leaf(&v, 2, 7);
        s.put_pending(&r0.owner_nonce, "receive 1").unwrap();
        s.put_pending(&[9; 32], "a request still open").unwrap();
        assert_eq!(s.pending().unwrap().len(), 2);
        s.put_leaf(&r0, &v0).unwrap();
        s.put_restored_leaf(&r1, &v1).unwrap();
        // The nonce whose record arrived is no longer pending.
        assert_eq!(
            s.pending().unwrap(),
            vec![([9; 32], "a request still open".to_string())]
        );
        let mut ids = vec![v0.leaf_id, v1.leaf_id];
        ids.sort();
        assert_eq!(s.leaf_ids().unwrap(), ids);
        let got = s.leaf(&v0.leaf_id).unwrap().unwrap();
        assert_eq!(got.record, r0);
        assert_eq!(got.round_txid, v0.round_txid);
        assert_eq!(got.batch_vout, v0.batch_vout);
        assert_eq!(s.leaves().unwrap().len(), 2);

        // The verification of one leaf does not store another.
        assert!(matches!(
            s.put_leaf(&r0, &v1),
            Err(ArkStoreError::NotThisLeaf { .. })
        ));

        // A replaced round is taken anew.
        let mut moved = v0.clone();
        moved.round_txid = Txid::from_byte_array([5; 32]);
        s.set_round(&moved).unwrap();
        assert_eq!(
            s.leaf(&v0.leaf_id).unwrap().unwrap().round_txid,
            moved.round_txid
        );

        s.remove_leaf(&v0.leaf_id).unwrap();
        assert_eq!(s.leaf_ids().unwrap(), vec![v1.leaf_id]);
        assert!(s.leaf(&v0.leaf_id).unwrap().is_none());
        // Every key the store wrote begins ark/.
        let keys = recorder.keys.lock().unwrap();
        assert!(!keys.is_empty());
        assert!(keys.iter().all(|k| k.starts_with("ark/")), "{keys:?}");
    }

    #[test]
    fn a_second_leaf_under_one_nonce_is_refused() {
        let v = vectors();
        let s = store();
        let (r0, v0) = vector_leaf(&v, 2, 0);
        s.put_pending(&r0.owner_nonce, "receive").unwrap();
        s.put_leaf(&r0, &v0).unwrap();
        // The same record again is the same leaf: allowed.
        s.put_leaf(&r0, &v0).unwrap();
        // Another leaf (another batch) with the same owner nonce and key.
        let (mut other, _) = vector_leaf(&v, 1, 0);
        other.owner_nonce = r0.owner_nonce;
        let mut fake = v0.clone();
        fake.leaf_id = other.leaf_id().unwrap();
        let err = s.put_leaf(&other, &fake).unwrap_err();
        assert!(matches!(err, ArkStoreError::NonceReused { .. }), "{err}");
        let err = s.put_restored_leaf(&other, &fake).unwrap_err();
        assert!(matches!(err, ArkStoreError::NonceReused { .. }), "{err}");
    }

    /// A leaf of the vectors as another batch could carry it: the same owner
    /// nonce and key, so the same leaf script, under another leaf id.
    fn replayed(
        v: &Json,
        record: &LeafRecord,
        verified: &VerifiedLeaf,
    ) -> (LeafRecord, VerifiedLeaf) {
        let (mut other, _) = vector_leaf(v, 1, 0);
        other.owner_nonce = record.owner_nonce;
        other.owner = record.owner;
        let mut fake = verified.clone();
        fake.leaf_id = other.leaf_id().unwrap();
        assert_ne!(fake.leaf_id, verified.leaf_id);
        (other, fake)
    }

    #[test]
    fn a_removed_leaf_and_its_nonce_are_never_kept_again() {
        // Review R4, F8: the store compared a new leaf only with the leaves
        // it still held, so a leaf stored, removed and stored again was
        // accepted, and so was a replayed salt of a spent leaf.
        let v = vectors();
        let inner: Arc<dyn DynStore> = Arc::new(MemoryStore::new());
        let s = ArkStore::new(inner.clone());
        let (r0, v0) = vector_leaf(&v, 2, 0);
        s.put_pending(&r0.owner_nonce, "receive").unwrap();
        s.put_leaf(&r0, &v0).unwrap();
        s.remove_leaf(&v0.leaf_id).unwrap();
        assert!(s.leaf(&v0.leaf_id).unwrap().is_none());
        assert!(s.leaf_ids().unwrap().is_empty());

        // The same record, as a new leaf, in a restore, or with its nonce
        // waited on again: each refused.
        let err = s.put_leaf(&r0, &v0).unwrap_err();
        assert!(
            matches!(err, ArkStoreError::Removed(ref id) if *id == v0.leaf_id.to_string()),
            "{err}"
        );
        let err = s.put_restored_leaf(&r0, &v0).unwrap_err();
        assert!(matches!(err, ArkStoreError::Removed(_)), "{err}");
        let err = s.put_pending(&r0.owner_nonce, "again").unwrap_err();
        assert!(matches!(err, ArkStoreError::NonceReused { .. }), "{err}");
        assert!(s.pending().unwrap().is_empty());

        // The same nonce and key under another leaf id: the operator
        // replaying the salt of a spent leaf. Refused even in a restore.
        let (other, fake) = replayed(&v, &r0, &v0);
        let err = s.put_restored_leaf(&other, &fake).unwrap_err();
        assert!(
            matches!(err, ArkStoreError::NonceReused { ref other, .. } if *other == v0.leaf_id.to_string()),
            "{err}"
        );
        // The same key under another nonce is refused too.
        let (mut key_only, _) = vector_leaf(&v, 1, 0);
        key_only.owner = r0.owner;
        let mut fake = v0.clone();
        fake.leaf_id = key_only.leaf_id().unwrap();
        let err = s.put_restored_leaf(&key_only, &fake).unwrap_err();
        assert!(matches!(err, ArkStoreError::NonceReused { .. }), "{err}");

        // The marks are kept in the underlying store: a new ArkStore over it
        // refuses the same.
        let reopened = ArkStore::new(inner);
        let err = reopened.put_restored_leaf(&r0, &v0).unwrap_err();
        assert!(matches!(err, ArkStoreError::Removed(_)), "{err}");
    }

    #[test]
    fn a_leaf_is_kept_only_for_a_nonce_the_wallet_waits_on() {
        let v = vectors();
        let s = store();
        let (r0, v0) = vector_leaf(&v, 2, 0);
        // A record nobody asked for.
        let err = s.put_leaf(&r0, &v0).unwrap_err();
        assert!(
            matches!(err, ArkStoreError::NotPending(ref n) if *n == r0.owner_nonce.to_hex()),
            "{err}"
        );
        assert!(s.leaf_ids().unwrap().is_empty());
        // Waited on, it is kept, and stops being waited on.
        s.put_pending(&r0.owner_nonce, "receive").unwrap();
        s.put_leaf(&r0, &v0).unwrap();
        assert!(s.pending().unwrap().is_empty());
        // A nonce the store holds a leaf under is not waited on again.
        let err = s.put_pending(&r0.owner_nonce, "again").unwrap_err();
        assert!(matches!(err, ArkStoreError::NonceReused { .. }), "{err}");
        // In a restore no nonce is pending.
        let (r1, v1) = vector_leaf(&v, 2, 7);
        assert!(matches!(
            s.put_leaf(&r1, &v1),
            Err(ArkStoreError::NotPending(_))
        ));
        s.put_restored_leaf(&r1, &v1).unwrap();
        assert_eq!(s.leaf_ids().unwrap().len(), 2);
    }

    #[test]
    fn a_store_written_before_nonces_were_remembered() {
        // A leaf kept before the store recorded nonces: no entry under
        // ark/used. The index still refuses its nonce; removing it marks it.
        let v = vectors();
        let inner: Arc<dyn DynStore> = Arc::new(MemoryStore::new());
        let s = ArkStore::new(inner.clone());
        let (r0, v0) = vector_leaf(&v, 2, 0);
        s.put_restored_leaf(&r0, &v0).unwrap();
        inner.remove(USED).unwrap();
        let (other, fake) = replayed(&v, &r0, &v0);
        let err = s.put_restored_leaf(&other, &fake).unwrap_err();
        assert!(matches!(err, ArkStoreError::NonceReused { .. }), "{err}");
        assert!(matches!(
            s.put_pending(&r0.owner_nonce, "again"),
            Err(ArkStoreError::NonceReused { .. })
        ));
        s.remove_leaf(&v0.leaf_id).unwrap();
        let err = s.put_restored_leaf(&r0, &v0).unwrap_err();
        assert!(matches!(err, ArkStoreError::Removed(_)), "{err}");
    }

    #[test]
    fn preimages_and_authorisations_are_checked_before_they_are_kept() {
        // A leaf of the wallet's own key, so it can sign authorisations.
        let signer = SwSigner::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            false,
        )
        .unwrap();
        let key: LeafKey = fresh_leaf_key(&signer, 0).unwrap();
        let other_key = fresh_leaf_key(&signer, 0).unwrap();
        let genesis =
            BlockHash::from_str("16af270696dbd3a65ed61a2f48459c8d8e9110c0c9937938109e7d7c87e8e42c")
                .unwrap();
        let asset = elements::AssetId::from_slice(&[0x28; 32]).unwrap();
        let s_key = fresh_leaf_key(
            &SwSigner::new(
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                false,
            )
            .unwrap(),
            0,
        )
        .unwrap()
        .key;
        let delay = RelativeTime::from_seconds_ceil(36 * 3600).unwrap();
        let schedule = ClockSchedule::new(
            elements::AssetId::from_slice(&[0x77; 32]).unwrap(),
            s_key,
            delay,
            vec![MedianTime::from_consensus(1_900_000_000).unwrap()],
        )
        .unwrap();
        let preimage = [0x33; 32];
        let leaves: Vec<covenant::LeafSpec> = [&key, &other_key]
            .iter()
            .enumerate()
            .map(|(i, k)| covenant::LeafSpec {
                template: covenant::Template::Vtxo1,
                owner: k.key,
                value: 1_000_000,
                owner_nonce: k.owner_nonce,
                operator_nonce: [i as u8 + 1; 32],
                exit_delay: delay,
                unlock_hash: sha256::Hash::hash(&preimage).to_byte_array(),
            })
            .collect();
        let tree = covenant::Tree::build(
            covenant::TreeParams {
                asset,
                chain: Chain::new(genesis),
                schedule,
                burn: false,
                radix: 4,
                reserve: covenant::ReserveRule::Fixed {
                    node: 3_000,
                    entry: 1_000,
                },
                min_leaf: 1_000,
            },
            &leaves,
        )
        .unwrap();
        let record = tree.records()[0].clone();
        let id = record.leaf_id().unwrap();
        // The store keeps what verification gave; here the tree's own word.
        let verified = VerifiedLeaf {
            leaf_id: id,
            round_txid: Txid::from_byte_array([1; 32]),
            batch_vout: 0,
            asset,
            value: record.value,
            expiries: record.schedule.expiries().to_vec(),
            notice: record.schedule.notice,
            exit_delay: record.exit_delay,
            owned: true,
        };
        let s = store();
        s.put_pending(&record.owner_nonce, "receive").unwrap();
        s.put_leaf(&record, &verified).unwrap();

        assert!(matches!(
            s.put_preimage(&id, &[0x34; 32]),
            Err(ArkStoreError::WrongPreimage)
        ));
        s.put_preimage(&id, &preimage).unwrap();
        assert_eq!(s.leaf(&id).unwrap().unwrap().preimage, Some(preimage));

        // The owner's authorisation for the batch output, signed by the kit's
        // own message signer: its digest is the covenant's.
        let branch = record.branch().unwrap();
        let t = MedianTime::from_consensus(1_800_000_000).unwrap();
        let node = &branch.nodes[0];
        let msg = ArcaMessage::Unroll(Unroll {
            children: node
                .children
                .iter()
                .map(|c| CommittedOutput {
                    asset: c.asset,
                    value: c.value,
                    script_pubkey: Script::from([&[0x51, 0x20][..], &c.program[..]].concat()),
                })
                .collect(),
            time: t.to_consensus_u32(),
        });
        let digest = msg.digest().unwrap();
        assert_eq!(digest, node.unroll_authorisation(t).digest);
        let policy = CsfsPolicy::with_ceiling(genesis, 0);
        let sig = signer.sign_csfs(&key.path, &msg, &digest, &policy).unwrap();
        s.put_unroll_authorisation(&id, 0, t, &sig.serialize())
            .unwrap();
        let kept = s.leaf(&id).unwrap().unwrap().unroll;
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].time, t.to_consensus_u32());

        // Another key's signature, another time, or a level off the path.
        let theirs = signer
            .sign_csfs(&other_key.path, &msg, &digest, &policy)
            .unwrap();
        assert!(matches!(
            s.put_unroll_authorisation(&id, 0, t, &theirs.serialize()),
            Err(ArkStoreError::BadAuthorisation(0))
        ));
        let later = MedianTime::from_consensus(1_800_000_001).unwrap();
        assert!(matches!(
            s.put_unroll_authorisation(&id, 0, later, &sig.serialize()),
            Err(ArkStoreError::BadAuthorisation(0))
        ));
        assert!(matches!(
            s.put_unroll_authorisation(&id, 9, t, &sig.serialize()),
            Err(ArkStoreError::Level { level: 9, .. })
        ));
    }
}
