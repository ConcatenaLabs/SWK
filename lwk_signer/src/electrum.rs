//! Electrum seed phrases.
//!
//! An Electrum seed is not a BIP39 mnemonic. It carries no checksum: its type is
//! the version prefix of `HMAC-SHA512("Seed version", phrase)` in hex, and the
//! BIP32 seed is `PBKDF2-HMAC-SHA512(phrase, "electrum" + passphrase, 2048)`.
//! Both run on the phrase after Electrum's own text normalization, ported here
//! from `electrum/mnemonic.py`.
//!
//! Only seeds since Electrum 2.0 are recognised. Electrum 1.x ("old") seeds use
//! another word list and another derivation, and are not handled.

use elements_miniscript::bitcoin::{
    bip32::{ChildNumber, DerivationPath},
    hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine},
};
use unicode_normalization::{char::canonical_combining_class, UnicodeNormalization};

/// The type an Electrum seed declares through its version prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElectrumSeedType {
    /// Prefix `01`: p2pkh addresses at `m/0/i` (receive) and `m/1/i` (change).
    Standard,
    /// Prefix `100`: p2wpkh addresses at `m/0'/0/i` and `m/0'/1/i`.
    Segwit,
    /// Prefix `101`: a TrustedCoin 2-of-3 wallet.
    TwoFa,
    /// Prefix `102`: a TrustedCoin 2-of-3 segwit wallet.
    TwoFaSegwit,
}

impl ElectrumSeedType {
    /// The name Electrum gives this seed type.
    pub fn as_str(&self) -> &'static str {
        match self {
            ElectrumSeedType::Standard => "standard",
            ElectrumSeedType::Segwit => "segwit",
            ElectrumSeedType::TwoFa => "2fa",
            ElectrumSeedType::TwoFaSegwit => "2fa_segwit",
        }
    }

    /// The account the addresses of a single-signature seed derive from: the
    /// master key for `standard`, `m/0'` for `segwit`. None for the 2FA types,
    /// whose wallets are multisig with a key held by TrustedCoin.
    pub fn account_path(&self) -> Option<DerivationPath> {
        match self {
            ElectrumSeedType::Standard => Some(DerivationPath::master()),
            ElectrumSeedType::Segwit => Some(DerivationPath::from(vec![ChildNumber::Hardened {
                index: 0,
            }])),
            ElectrumSeedType::TwoFa | ElectrumSeedType::TwoFaSegwit => None,
        }
    }
}

// Code point ranges Electrum treats as CJK: whitespace between two of them is dropped.
const CJK_INTERVALS: &[(u32, u32)] = &[
    (0x4E00, 0x9FFF),
    (0x3400, 0x4DBF),
    (0x20000, 0x2A6DF),
    (0x2A700, 0x2B73F),
    (0x2B740, 0x2B81F),
    (0xF900, 0xFAFF),
    (0x2F800, 0x2FA1D),
    (0x3190, 0x319F),
    (0x2E80, 0x2EFF),
    (0x2F00, 0x2FDF),
    (0x31C0, 0x31EF),
    (0x2FF0, 0x2FFF),
    (0xE0100, 0xE01EF),
    (0x3100, 0x312F),
    (0x31A0, 0x31BF),
    (0xFF00, 0xFFEF),
    (0x3040, 0x309F),
    (0x30A0, 0x30FF),
    (0x31F0, 0x31FF),
    (0x1B000, 0x1B0FF),
    (0xAC00, 0xD7AF),
    (0x1100, 0x11FF),
    (0xA960, 0xA97F),
    (0xD7B0, 0xD7FF),
    (0x3130, 0x318F),
    (0xA4D0, 0xA4FF),
    (0x16F00, 0x16F9F),
    (0xA000, 0xA48F),
    (0xA490, 0xA4CF),
];

fn is_cjk(c: char) -> bool {
    let n = c as u32;
    CJK_INTERVALS.iter().any(|&(lo, hi)| lo <= n && n <= hi)
}

/// Electrum's `normalize_text`: NFKD, lower case, accents removed, runs of
/// whitespace collapsed to one space, and no space left between two CJK characters.
pub fn normalize_text(text: &str) -> String {
    let lowered = text.nfkd().collect::<String>().to_lowercase();
    let stripped: String = lowered
        .chars()
        .filter(|&c| canonical_combining_class(c) == 0)
        .collect();
    let chars: Vec<char> = stripped
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .collect();
    chars
        .iter()
        .enumerate()
        .filter(|&(i, &c)| {
            // After the join, a space is never first or last.
            !(c == ' ' && is_cjk(chars[i - 1]) && is_cjk(chars[i + 1]))
        })
        .map(|(_, &c)| c)
        .collect()
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut engine = HmacEngine::<sha512::Hash>::new(key);
    engine.input(data);
    Hmac::<sha512::Hash>::from_engine(engine).to_byte_array()
}

/// The type `phrase` declares, or None when it is not an Electrum seed.
///
/// Follows Electrum's `calc_seed_type`, old seeds aside: prefixes are tried in
/// the order `01`, `100`, `101`, `102`, and a `101` seed counts as 2FA only with
/// 12 or at least 20 words.
pub fn electrum_seed_type(phrase: &str) -> Option<ElectrumSeedType> {
    let normalized = normalize_text(phrase);
    if normalized.is_empty() {
        return None;
    }
    let version = hmac_sha512(b"Seed version", normalized.as_bytes());
    // The prefixes are hex digits: "01" is the first byte, "10x" the first byte and a nibble.
    let third_nibble = version[1] >> 4;
    let words = phrase.split_whitespace().count();
    if version[0] == 0x01 {
        Some(ElectrumSeedType::Standard)
    } else if version[0] == 0x10 && third_nibble == 0 {
        Some(ElectrumSeedType::Segwit)
    } else if version[0] == 0x10 && third_nibble == 1 && (words == 12 || words >= 20) {
        Some(ElectrumSeedType::TwoFa)
    } else if version[0] == 0x10 && third_nibble == 2 {
        Some(ElectrumSeedType::TwoFaSegwit)
    } else {
        None
    }
}

/// The 64-byte BIP32 seed of an Electrum phrase:
/// `PBKDF2-HMAC-SHA512(phrase, "electrum" + passphrase, 2048)`, both normalized.
///
/// It does not check that `phrase` is an Electrum seed; see [`electrum_seed_type`].
pub fn electrum_seed(phrase: &str, passphrase: &str) -> [u8; 64] {
    let password = normalize_text(phrase);
    let mut salt = b"electrum".to_vec();
    salt.extend_from_slice(normalize_text(passphrase).as_bytes());
    // PBKDF2 with a 64-byte output is a single block of SHA-512.
    salt.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha512(password.as_bytes(), &salt);
    let mut out = u;
    for _ in 1..2048 {
        u = hmac_sha512(password.as_bytes(), &u);
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // From Electrum's tests/test_wallet_vertical.py.
    pub(crate) const UNICODE_HORROR_HEX: &str = "e282bf20f09f988020f09f98882020202020e3818620e38191e3819fe381be20e3828fe3828b2077cda2cda2cd9d68cda16fcda2cda120ccb8cda26bccb5cd9f6eccb4cd98c7ab77ccb8cc9b73cd9820cc80cc8177cd98cda2e1b8a9ccb561d289cca1cda27420cca7cc9568cc816fccb572cd8fccb5726f7273cca120ccb6cda1cda06cc4afccb665cd9fcd9f20ccb6cd9d696ecda220cd8f74cc9568ccb7cca1cd9f6520cd9fcd9f64cc9b61cd9c72cc95cda16bcca2cca820cda168ccb465cd8f61ccb7cca2cca17274cc81cd8f20ccb4ccb7cda0c3b2ccb5ccb666ccb82075cca7cd986ec3adcc9bcd9c63cda2cd8f6fccb7cd8f64ccb8cda265cca1cd9d3fcd9e";

    fn unicode_horror() -> String {
        String::from_utf8(unhex(UNICODE_HORROR_HEX)).unwrap()
    }

    #[test]
    fn mnemonic_to_seed_basic() {
        // Electrum's test_mnemonic_to_seed_basic: not a valid Electrum seed.
        assert_eq!(
            hex(&electrum_seed("foobar", "none")),
            "741b72fd15effece6bfe5a26a52184f66811bd2be363190e07a42cca442b1a5bb22b3ad0eb338197287e6d314866c7fba863ac65d3f156087a5052ebc7157fce"
        );
        assert_eq!(electrum_seed_type("foobar"), None);
    }

    #[test]
    fn seed_test_cases() {
        use ElectrumSeedType::*;
        // Electrum's SEED_TEST_CASES in tests/test_mnemonic.py:
        // (words as utf-8 hex, passphrase, seed type, bip32 seed).
        let horror = unicode_horror();
        let cases: &[(&str, &str, ElectrumSeedType, &str)] = &[
            (
                "wild father tree among universe such mobile favorite target dynamic credit identify",
                "",
                Segwit,
                "aac2a6302e48577ab4b46f23dbae0774e2e62c796f797d0a1b5faeb528301e3064342dafb79069e7c4c6b8c38ae11d7a973bec0d4f70626f8cc5184a8d0b0756",
            ),
            (
                "wild father tree among universe such mobile favorite target dynamic credit identify",
                "Did you ever hear the tragedy of Darth Plagueis the Wise?",
                Segwit,
                "4aa29f2aeb0127efb55138ab9e7be83b36750358751906f86c662b21a1ea1370f949e6d1a12fa56d3d93cadda93038c76ac8118597364e46f5156fde6183c82f",
            ),
            (
                "なのか ひろい しなん まなぶ つぶす さがす おしゃれ かわく おいかける けさき かいとう さたん",
                "",
                Standard,
                "d3eaf0e44ddae3a5769cb08a26918e8b308258bcb057bb704c6f69713245c0b35cb92c03df9c9ece5eff826091b4e74041e010b701d44d610976ce8bfb66a8ad",
            ),
            (
                "なのか ひろい しなん まなぶ つぶす さがす おしゃれ かわく おいかける けさき かいとう さたん",
                &horror,
                Standard,
                "251ee6b45b38ba0849e8f40794540f7e2c6d9d604c31d68d3ac50c034f8b64e4bc037c5e1e985a2fed8aad23560e690b03b120daf2e84dceb1d7857dda042457",
            ),
            (
                "眼 悲 叛 改 节 跃 衡 响 疆 股 遂 冬",
                "",
                Segwit,
                "0b9077db7b5a50dbb6f61821e2d35e255068a5847e221138048a20e12d80b673ce306b6fe7ac174ebc6751e11b7037be6ee9f17db8040bb44f8466d519ce2abf",
            ),
            (
                "眼 悲 叛 改 节 跃 衡 响 疆 股 遂 冬",
                "给我一些测试向量谷歌",
                Segwit,
                "6c03dd0615cf59963620c0af6840b52e867468cc64f20a1f4c8155705738e87b8edb0fc8a6cee4085776cb3a629ff88bb1a38f37085efdbf11ce9ec5a7fa5f71",
            ),
            (
                // Combining accents, as in Electrum's words_hex.
                "almi\u{301}bar tibio superar vencer hacha peato\u{301}n pri\u{301}ncipe matar consejo polen vehi\u{301}culo odisea",
                "",
                Standard,
                "18bffd573a960cc775bbd80ed60b7dc00bc8796a186edebe7fc7cf1f316da0fe937852a969c5c79ded8255cdf54409537a16339fbe33fb9161af793ea47faa7a",
            ),
            (
                "almi\u{301}bar tibio superar vencer hacha peato\u{301}n pri\u{301}ncipe matar consejo polen vehi\u{301}culo odisea",
                "aran\u{303}a difi\u{301}cil solucio\u{301}n te\u{301}rmino ca\u{301}rcel",
                Standard,
                "363dec0e575b887cfccebee4c84fca5a3a6bed9d0e099c061fa6b85020b031f8fe3636d9af187bf432d451273c625e20f24f651ada41aae2c4ea62d87e9fa44c",
            ),
            (
                "equipo fiar auge langosta hacha calor trance cubrir carro pulmo\u{301}n oro a\u{301}spero",
                "",
                Segwit,
                "001ebce6bfde5851f28a0d44aae5ae0c762b600daf3b33fc8fc630aee0d207646b6f98b18e17dfe3be0a5efe2753c7cdad95860adbbb62cecad4dedb88e02a64",
            ),
            (
                "vidrio jabo\u{301}n muestra pa\u{301}jaro capucha eludir feliz rotar fogata pez rezar oi\u{301}r",
                "¡Viva España! repiten veinte pueblos y al hablar dan fe del ánimo español... ¡Marquen arado martillo y clarín",
                Segwit,
                "c274665e5453c72f82b8444e293e048d700c59bf000cacfba597629d202dcf3aab1cf9c00ba8d3456b7943428541fed714d01d8a0a4028fc3a9bb33d981cb49f",
            ),
        ];
        for (words, passphrase, seed_type, seed) in cases {
            assert_eq!(electrum_seed_type(words), Some(*seed_type), "{words}");
            assert_eq!(hex(&electrum_seed(words, passphrase)), *seed, "{words}");
        }
    }

    #[test]
    fn precomposed_accents_normalize_like_combining_ones() {
        let combining = "almi\u{301}bar tibio superar vencer hacha peato\u{301}n pri\u{301}ncipe matar consejo polen vehi\u{301}culo odisea";
        let precomposed = "almíbar  tibio superar vencer hacha peatón príncipe matar consejo polen VEHÍCULO odisea";
        assert_eq!(normalize_text(combining), normalize_text(precomposed));
        assert_eq!(electrum_seed(combining, ""), electrum_seed(precomposed, ""));
    }

    #[test]
    fn wallet_vertical_seed_types() {
        // Electrum's test_electrum_seed_standard / _segwit.
        assert_eq!(
            electrum_seed_type(
                "cycle rocket west magnet parrot shuffle foot correct salt library feed song"
            ),
            Some(ElectrumSeedType::Standard)
        );
        assert_eq!(
            electrum_seed_type(
                "bitter grass shiver impose acquire brush forget axis eager alone wine silver"
            ),
            Some(ElectrumSeedType::Segwit)
        );
        // A BIP39 phrase from this repo's tests is no Electrum seed.
        assert_eq!(
            electrum_seed_type("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
            None
        );
    }
}
