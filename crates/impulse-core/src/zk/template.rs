// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! ImpulseVaultV3 instantiation (spec/V3-ZK.md section 6). The compiled template is embedded and
//! checked against `contracts/TEMPLATE_HASH_V3` and `circuits/IMAGE_ID` before first use. A leg's
//! redeem script is the template prefix, the terms v3 and the leg index encoded as the contract
//! state, then the template suffix; its P2SH scriptPubKey is what the leg's depositor funds.
//! Decoding reverses the splice and accepts only scripts that instantiation would produce byte
//! for byte.
//!
//! The state is the v1 state with `version` 3 and two fields inserted after `fundingMode`, so the
//! v1 mapping (`crate::template::state`) serves the shared fields and this module adds the two
//! new ones. Adapted from `crate::template` (relicensed, see NOTICE). Keyless: nothing here signs
//! or holds a private key.

use super::terms::{TermsV3, ValidatedTermsV3};
use super::ZkError;
use crate::template::state::{self, Kind, LAYOUT};
use crate::template::{LegIndex, TemplateError};
use crate::terms::{CreationContext, LegKind, Network};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript::pay_to_script_hash_script;
use silverscript_abi::{
    decode_runtime_state_script, encode_runtime_state_script, template_hash, ArtifactValue,
    RuntimeStateArtifact, SilAbiArtifact, TypeArtifact,
};
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// The contract name in the artifact.
pub const CONTRACT_NAME_V3: &str = "ImpulseVaultV3";

/// The state version byte of template v3.
pub const STATE_VERSION_V3: u8 = 3;

#[cfg(impulse_v3_artifact)]
const ARTIFACT_JSON: &str = include_str!("../../../../contracts/compiled/impulse_vault.v3.json");
#[cfg(impulse_v3_artifact)]
const TEMPLATE_HASH_FILE: &str = include_str!("../../../../contracts/TEMPLATE_HASH_V3");
#[cfg(impulse_v3_artifact)]
const IMAGE_ID_FILE: &str = include_str!("../../../../circuits/IMAGE_ID");

type Checked = Result<TemplateV3, ZkError>;

static TEMPLATE: LazyLock<Checked> = LazyLock::new(|| {
    #[cfg(impulse_v3_artifact)]
    {
        TemplateV3::load(ARTIFACT_JSON, TEMPLATE_HASH_FILE, IMAGE_ID_FILE)
    }
    #[cfg(not(impulse_v3_artifact))]
    {
        Err(ZkError::ArtifactInvalid {
            reason: "this build embeds no template v3 (contracts/compiled/impulse_vault.v3.json, \
                     contracts/TEMPLATE_HASH_V3 or circuits/IMAGE_ID was missing at build time)"
                .into(),
        })
    }
});

/// The startup check: loads the embedded template once and returns it, or the reason it is
/// unusable. Every instantiation and decode goes through it, so a template that fails the check
/// never produces or accepts a script.
pub fn check() -> Result<&'static TemplateV3, ZkError> {
    TEMPLATE.as_ref().map_err(Clone::clone)
}

/// The checked ImpulseVaultV3 template: the bytes around the state span, their template hash,
/// the image ID the contract pins, and the artifact's state layout.
#[derive(Debug)]
pub struct TemplateV3 {
    abi: SilAbiArtifact,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    hash: [u8; 32],
    image_id: [u8; 32],
}

/// The v3 state layout: the v1 fields up to `fundingMode`, then `listIssuerKey`, `listRoot`, and
/// the v1 `tradeRef` and `legIndex` (spec section 6.2).
fn layout() -> Vec<(&'static str, Kind)> {
    let mut fields: Vec<(&'static str, Kind)> = LAYOUT[..LAYOUT.len() - 2].to_vec();
    fields.push(("listIssuerKey", Kind::Pubkey));
    fields.push(("listRoot", Kind::Fixed(32)));
    fields.extend_from_slice(&LAYOUT[LAYOUT.len() - 2..]);
    fields
}

fn check_layout(state: &RuntimeStateArtifact) -> Result<(), String> {
    let found: Vec<(&str, &TypeArtifact)> = state
        .fields
        .iter()
        .map(|f| (f.name.as_str(), &f.ty))
        .collect();
    let expected: Vec<(&str, TypeArtifact)> =
        layout().iter().map(|(n, k)| (*n, k.artifact())).collect();
    let same = found.len() == expected.len()
        && found
            .iter()
            .zip(&expected)
            .all(|((fn_, ft), (en, et))| fn_ == en && *ft == et);
    if same {
        Ok(())
    } else {
        Err(format!(
            "state layout {found:?} is not the ImpulseVaultV3 layout this crate maps"
        ))
    }
}

/// 64 lowercase hex digits and an optional final newline.
fn parse_hash(text: &str) -> Option<[u8; 32]> {
    let hex = text.strip_suffix('\n').unwrap_or(text);
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn occurrences(haystack: &[u8], needle: &[u8; 32]) -> usize {
    haystack.windows(32).filter(|w| *w == needle).count()
}

impl TemplateV3 {
    /// Parses and checks an artifact against the `TEMPLATE_HASH_V3` and `IMAGE_ID` files, in this
    /// order: the artifact parses with the supported schema and holds exactly ImpulseVaultV3; its
    /// state layout is the one this crate maps; its prefix and suffix hash to its declared hash
    /// and to `TEMPLATE_HASH_V3` (`ZK_TEMPLATE_HASH_MISMATCH`); the image ID of `circuits/IMAGE_ID`
    /// occurs in them exactly once (`ZK_IMAGE_ID_MISMATCH`); it is otherwise self-consistent.
    pub(crate) fn load(
        artifact_json: &str,
        template_hash_file: &str,
        image_id_file: &str,
    ) -> Result<Self, ZkError> {
        let invalid = |reason: String| ZkError::ArtifactInvalid { reason };
        let abi: SilAbiArtifact = serde_json::from_str(artifact_json)
            .map_err(|e| invalid(format!("artifact does not parse: {e}")))?;
        abi.check_schema_version()
            .map_err(|e| invalid(e.to_string()))?;
        if abi.contracts.len() != 1 || !abi.contracts.contains_key(CONTRACT_NAME_V3) {
            return Err(invalid(format!(
                "artifact must hold exactly {CONTRACT_NAME_V3}, found {:?}",
                abi.contracts.keys().collect::<Vec<_>>()
            )));
        }
        let contract = &abi.contracts[CONTRACT_NAME_V3];
        check_layout(&contract.runtime_state).map_err(invalid)?;

        let compiled = &contract.compiled;
        let (prefix, _example_state, suffix) = compiled
            .script_parts(&compiled.bytecode)
            .ok_or_else(|| invalid("state span lies outside the bytecode".into()))?;
        if prefix.is_empty() || suffix.is_empty() {
            return Err(invalid("template prefix or suffix is empty".into()));
        }
        let hash = template_hash(prefix, suffix);
        if hash != compiled.template_hash {
            return Err(ZkError::TemplateHashMismatch {
                expected: compiled.template_hash,
                found: hash,
            });
        }
        let pinned = parse_hash(template_hash_file)
            .ok_or_else(|| invalid("TEMPLATE_HASH_V3 is not 64 lowercase hex digits".into()))?;
        if hash != pinned {
            return Err(ZkError::TemplateHashMismatch {
                expected: pinned,
                found: hash,
            });
        }
        let image_id = parse_hash(image_id_file)
            .ok_or_else(|| invalid("circuits/IMAGE_ID is not 64 lowercase hex digits".into()))?;
        let seen = occurrences(prefix, &image_id) + occurrences(suffix, &image_id);
        if seen != 1 {
            return Err(ZkError::ImageIdMismatch {
                reason: format!(
                    "the image ID of circuits/IMAGE_ID occurs {seen} times in template v3, \
                     where it must occur once"
                ),
            });
        }
        abi.check_consistency()
            .map_err(|e| invalid(e.to_string()))?;
        let (prefix, suffix) = (prefix.to_vec(), suffix.to_vec());
        Ok(Self {
            abi,
            prefix,
            suffix,
            hash,
            image_id,
        })
    }

    /// The template hash (silverscript's blake3 over the length-prefixed prefix and suffix).
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The list guest's image ID the template pins (`circuits/IMAGE_ID`).
    pub fn image_id(&self) -> [u8; 32] {
        self.image_id
    }

    /// Template bytes before the state span.
    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    /// Template bytes after the state span.
    pub fn suffix(&self) -> &[u8] {
        &self.suffix
    }

    /// The artifact's ABI: the builders encode `settle` and `refund` calls with it.
    pub(crate) fn abi(&self) -> &SilAbiArtifact {
        &self.abi
    }

    fn runtime_state(&self) -> &RuntimeStateArtifact {
        &self.abi.contracts[CONTRACT_NAME_V3].runtime_state
    }

    fn state_span<'a>(&self, script: &'a [u8]) -> Option<&'a [u8]> {
        let (p, s) = (self.prefix.len(), self.suffix.len());
        if script.len() < p + s
            || !script.starts_with(&self.prefix)
            || !script.ends_with(&self.suffix)
        {
            return None;
        }
        Some(&script[p..script.len() - s])
    }
}

/// A template refusal as a `ZK_` refusal where section 12 has the code, else as itself.
fn from_template(e: TemplateError) -> ZkError {
    match e {
        TemplateError::StateMalformed { reason } => ZkError::StateMalformed { reason },
        TemplateError::StateInvalid { field } => ZkError::StateInvalid {
            reason: format!("state field {field} holds a value outside the terms"),
        },
        TemplateError::Terms(e) => ZkError::Terms(e),
        TemplateError::ArtifactInvalid { reason } => ZkError::ArtifactInvalid { reason },
        other => ZkError::Template(other),
    }
}

/// One leg's vault: the redeem script instantiated from structure-checked terms v3, and its P2SH.
/// It serves an existing trade and has no funding address; see [`FundableVaultV3`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultV3 {
    network: Network,
    leg: LegIndex,
    redeem_script: Vec<u8>,
}

impl VaultV3 {
    /// The vault of `leg` of an existing trade (settle, refund, verify, decode). No creation
    /// checks run, so a trade past its expiry still yields its vaults for refunds. Refuses a leg
    /// that has no vault under the terms (`TEMPLATE_NO_VAULT`).
    pub fn instantiate_existing(terms: &ValidatedTermsV3, leg: LegIndex) -> Result<Self, ZkError> {
        instantiate_with(&TEMPLATE, terms, leg)
    }

    /// The vault of `leg` for a trade being created or accepted: runs the creation checks first,
    /// then [`VaultV3::instantiate_existing`].
    pub fn instantiate_for_creation(
        terms: &ValidatedTermsV3,
        leg: LegIndex,
        ctx: &CreationContext,
    ) -> Result<FundableVaultV3, ZkError> {
        terms.validate_creation(ctx)?;
        Ok(FundableVaultV3(Self::instantiate_existing(terms, leg)?))
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn leg(&self) -> LegIndex {
        self.leg
    }

    /// The redeem script a spend of this vault reveals.
    pub fn redeem_script(&self) -> &[u8] {
        &self.redeem_script
    }

    /// The vault's P2SH scriptPubKey: OpBlake2b OpData32 <script hash> OpEqual.
    pub fn script_public_key(&self) -> ScriptPublicKey {
        pay_to_script_hash_script(&self.redeem_script)
    }

    /// blake2b-256 of the redeem script, read back out of the P2SH scriptPubKey. It is also the
    /// KCC-20 SCRIPT_HASH owner identifier of the leg's escrowed token, and the vault script hash
    /// of the journal.
    pub fn script_hash(&self) -> [u8; 32] {
        let spk = self.script_public_key();
        let mut out = [0u8; 32];
        out.copy_from_slice(&spk.script()[2..34]);
        out
    }
}

/// A v3 vault whose terms passed the creation checks as well as the structure checks. Only
/// [`VaultV3::instantiate_for_creation`] makes one, and only this type has a funding address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundableVaultV3(VaultV3);

impl FundableVaultV3 {
    pub fn vault(&self) -> &VaultV3 {
        &self.0
    }

    pub fn into_vault(self) -> VaultV3 {
        self.0
    }
}

/// The funding address of a creation-checked v3 vault: version ScriptHash, payload the script
/// hash, with the prefix of the network the terms name.
pub fn vault_address_v3(vault: &FundableVaultV3) -> String {
    let vault = vault.vault();
    kaspa_addresses::Address::new(
        crate::address::prefix(vault.network()),
        kaspa_addresses::Version::ScriptHash,
        &vault.script_hash(),
    )
    .to_string()
}

/// Decodes a revealed redeem script back to the terms v3 and the leg index. Accepts only a script
/// that [`VaultV3::instantiate_existing`] produces from the decoded terms, byte for byte
/// (`ZK_NONCANONICAL` otherwise); a script of another template is `ZK_NOT_V3_VAULT`.
pub fn decode(redeem_script: &[u8]) -> Result<(ValidatedTermsV3, LegIndex), ZkError> {
    decode_with(&TEMPLATE, redeem_script)
}

/// The template hash recomputed from a script's own prefix and suffix bytes, at the template's
/// prefix and suffix lengths, without trusting any declared hash. Equal to the checked template
/// hash for every v3 vault, whatever its state.
pub fn template_hash_of_instance(script: &[u8]) -> Result<[u8; 32], ZkError> {
    let template = check()?;
    let (p, s) = (template.prefix.len(), template.suffix.len());
    if script.len() < p + s {
        return Err(ZkError::NotV3Vault);
    }
    Ok(template_hash(&script[..p], &script[script.len() - s..]))
}

/// Direct terms escrow nothing (terms v3 are never Direct); external cash has no cash vault.
fn has_vault(terms: &TermsV3, leg: LegIndex) -> Result<(), ZkError> {
    if leg == LegIndex::Cash && terms.fields.cash_leg.kind == LegKind::External {
        return Err(ZkError::Template(TemplateError::NoVault {
            leg,
            reason: "external cash settles off chain",
        }));
    }
    Ok(())
}

/// The state values of `leg` under `terms`: the v1 values with version 3 and the two new fields.
fn state_values(
    terms: &TermsV3,
    leg: LegIndex,
) -> Result<BTreeMap<String, ArtifactValue>, ZkError> {
    let mut values = state::values(&terms.fields, leg).map_err(from_template)?;
    values.insert("version".into(), ArtifactValue::Byte(STATE_VERSION_V3));
    values.insert(
        "listIssuerKey".into(),
        ArtifactValue::Bytes(terms.list_issuer_key.to_vec()),
    );
    values.insert(
        "listRoot".into(),
        ArtifactValue::Bytes(terms.list_root.to_vec()),
    );
    Ok(values)
}

fn instantiate_with(
    template: &Checked,
    terms: &ValidatedTermsV3,
    leg: LegIndex,
) -> Result<VaultV3, ZkError> {
    let template = template.as_ref().map_err(Clone::clone)?;
    let t = terms.terms();
    has_vault(t, leg)?;
    let values = state_values(t, leg)?;
    let state = encode_runtime_state_script(&template.abi, template.runtime_state(), &values)
        .map_err(|e| ZkError::StateMalformed {
            reason: e.to_string(),
        })?;
    let mut redeem_script =
        Vec::with_capacity(template.prefix.len() + state.len() + template.suffix.len());
    redeem_script.extend_from_slice(&template.prefix);
    redeem_script.extend_from_slice(&state);
    redeem_script.extend_from_slice(&template.suffix);
    Ok(VaultV3 {
        network: t.fields.network,
        leg,
        redeem_script,
    })
}

fn decode_with(
    template: &Checked,
    redeem_script: &[u8],
) -> Result<(ValidatedTermsV3, LegIndex), ZkError> {
    let loaded = template.as_ref().map_err(Clone::clone)?;
    let span = loaded
        .state_span(redeem_script)
        .ok_or(ZkError::NotV3Vault)?;
    let mut values = decode_runtime_state_script(&loaded.abi, loaded.runtime_state(), span)
        .map_err(|e| ZkError::StateMalformed {
            reason: e.to_string(),
        })?;
    // The two v3 fields and the version, then the v1 mapping for the rest.
    let fixed32 = |value: Option<ArtifactValue>, field: &str| -> Result<[u8; 32], ZkError> {
        match value {
            Some(ArtifactValue::Bytes(b)) => b.try_into().map_err(|_| ZkError::StateMalformed {
                reason: format!("field {field} has the wrong length"),
            }),
            _ => Err(ZkError::StateMalformed {
                reason: format!("field {field} is missing or has the wrong type"),
            }),
        }
    };
    let issuer = fixed32(values.remove("listIssuerKey"), "listIssuerKey")?;
    let root = fixed32(values.remove("listRoot"), "listRoot")?;
    match values.get("version") {
        Some(ArtifactValue::Byte(STATE_VERSION_V3)) => {}
        Some(ArtifactValue::Byte(_)) => {
            return Err(ZkError::StateInvalid {
                reason: "state field version is not 3".into(),
            })
        }
        _ => {
            return Err(ZkError::StateMalformed {
                reason: "field version is missing or has the wrong type".into(),
            })
        }
    }
    values.insert(
        "version".into(),
        ArtifactValue::Byte(crate::terms::TERMS_VERSION),
    );
    let (fields, leg) = state::terms(&values).map_err(from_template)?;
    let terms = TermsV3::new(fields, issuer, root).validate_structure()?;
    let vault = instantiate_with(template, &terms, leg)?;
    if vault.redeem_script != redeem_script {
        return Err(ZkError::Noncanonical);
    }
    Ok((terms, leg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_v3_layout_is_the_v1_layout_with_two_more_fields() {
        let l = layout();
        assert_eq!(l.len(), 36);
        let names: Vec<&str> = l.iter().map(|(n, _)| *n).collect();
        assert_eq!(names[31], "fundingMode");
        assert_eq!(names[32], "listIssuerKey");
        assert_eq!(names[33], "listRoot");
        assert_eq!(names[34], "tradeRef");
        assert_eq!(names[35], "legIndex");
    }

    #[test]
    fn hash_files_are_strict() {
        assert!(parse_hash(&"ab".repeat(32)).is_some());
        assert!(parse_hash(&format!("{}\n", "ab".repeat(32))).is_some());
        assert!(parse_hash(&"AB".repeat(32)).is_none());
        assert!(parse_hash(&"ab".repeat(31)).is_none());
        assert!(parse_hash("").is_none());
    }

    /// With the three files present at build time the embedded template passes every check; if
    /// any was missing the crate built without it and this test fails (fail closed).
    #[test]
    fn the_v3_template_is_embedded_and_passes_its_checks() {
        let t = check().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(t.image_id().len(), 32);
        assert!(!t.prefix().is_empty() && !t.suffix().is_empty());
    }

    #[cfg(impulse_v3_artifact)]
    mod with_artifact {
        use super::*;
        use crate::terms::golden::{vectors, CREATION_DAA};
        use crate::terms::{FundingMode, SettlementMode};
        use crate::zk::terms::tests::sample;

        fn load(json: &str, hash: &str, image: &str) -> Result<TemplateV3, ZkError> {
            TemplateV3::load(json, hash, image)
        }

        #[test]
        fn load_refuses_a_wrong_pin_or_image() {
            let good_hash = std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../contracts/TEMPLATE_HASH_V3"
            ))
            .unwrap();
            let good_image = std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../circuits/IMAGE_ID"
            ))
            .unwrap();
            let json = ARTIFACT_JSON;
            load(json, &good_hash, &good_image).unwrap();
            let other = "00".repeat(32);
            assert_eq!(
                load(json, &other, &good_image).unwrap_err().code(),
                "ZK_TEMPLATE_HASH_MISMATCH"
            );
            assert_eq!(
                load(json, &good_hash, &other).unwrap_err().code(),
                "ZK_IMAGE_ID_MISMATCH"
            );
            assert_eq!(
                load(json, "zz", &good_image).unwrap_err().code(),
                "ZK_ARTIFACT_INVALID"
            );
            assert_eq!(
                load("{}", &good_hash, &good_image).unwrap_err().code(),
                "ZK_ARTIFACT_INVALID"
            );
            // The v1 artifact holds ImpulseVault, not ImpulseVaultV3.
            let v1 = include_str!("../../../../contracts/compiled/impulse_vault.v1.json");
            assert_eq!(
                load(v1, &good_hash, &good_image).unwrap_err().code(),
                "ZK_ARTIFACT_INVALID"
            );
        }

        #[test]
        fn a_missing_template_refuses_every_use() {
            let missing: Checked = Err(ZkError::ArtifactInvalid { reason: "x".into() });
            let terms = sample().validate_structure().unwrap();
            assert_eq!(
                instantiate_with(&missing, &terms, LegIndex::Asset)
                    .unwrap_err()
                    .code(),
                "ZK_ARTIFACT_INVALID"
            );
            assert_eq!(
                decode_with(&missing, &[1, 2, 3]).unwrap_err().code(),
                "ZK_ARTIFACT_INVALID"
            );
        }

        #[test]
        fn instantiate_and_decode_round_trip_every_terms_v3_sample() {
            for leg in LegIndex::ALL {
                let terms = sample().validate_structure().unwrap();
                let vault = VaultV3::instantiate_existing(&terms, leg).unwrap();
                let (decoded, decoded_leg) = decode(vault.redeem_script()).unwrap();
                assert_eq!(decoded, terms);
                assert_eq!(decoded_leg, leg);
                assert_eq!(
                    template_hash_of_instance(vault.redeem_script()).unwrap(),
                    check().unwrap().hash()
                );
                assert_eq!(vault.script_public_key().script().len(), 35);
            }
        }

        #[test]
        fn the_two_legs_and_the_two_roots_have_different_addresses() {
            let a = sample().validate_structure().unwrap();
            let mut other = sample();
            other.list_root = [0x43; 32];
            let b = other.validate_structure().unwrap();
            let h = |t: &ValidatedTermsV3, l| {
                VaultV3::instantiate_existing(t, l).unwrap().script_hash()
            };
            assert_ne!(h(&a, LegIndex::Asset), h(&a, LegIndex::Cash));
            assert_ne!(h(&a, LegIndex::Asset), h(&b, LegIndex::Asset));
            let mut other = sample();
            other.list_issuer_key = other.fields.seller_key;
            let c = other.validate_structure().unwrap();
            assert_ne!(h(&a, LegIndex::Asset), h(&c, LegIndex::Asset));
        }

        #[test]
        fn external_cash_has_no_cash_vault() {
            let mut t = sample();
            let ext = vectors()
                .into_iter()
                .find(|v| matches!(v.terms.cash_leg.kind, LegKind::External))
                .unwrap()
                .terms;
            t.fields = ext;
            let terms = TermsV3::new(t.fields, t.list_issuer_key, t.list_root)
                .validate_structure()
                .unwrap();
            VaultV3::instantiate_existing(&terms, LegIndex::Asset).unwrap();
            assert_eq!(
                VaultV3::instantiate_existing(&terms, LegIndex::Cash)
                    .unwrap_err()
                    .code(),
                "TEMPLATE_NO_VAULT"
            );
        }

        #[test]
        fn creation_checks_gate_the_funding_address() {
            let terms = sample().validate_structure().unwrap();
            let ctx = CreationContext::new(terms.terms().fields.network, CREATION_DAA);
            let fundable = VaultV3::instantiate_for_creation(&terms, LegIndex::Asset, &ctx)
                .expect("creation checks pass for the sample");
            let text = vault_address_v3(&fundable);
            assert!(text.starts_with("kaspa:p"), "{text}");
            let wrong = CreationContext::new(Network::Testnet, CREATION_DAA);
            assert_eq!(
                VaultV3::instantiate_for_creation(&terms, LegIndex::Asset, &wrong)
                    .unwrap_err()
                    .code(),
                "TERMS_NETWORK_MISMATCH"
            );
            let _ = (FundingMode::Revocable, SettlementMode::Vault);
        }

        #[test]
        fn v1_and_v3_scripts_do_not_cross() {
            let terms = sample().validate_structure().unwrap();
            let v3 = VaultV3::instantiate_existing(&terms, LegIndex::Asset).unwrap();
            // The v1 decoder refuses a v3 script.
            assert_eq!(
                crate::template::decode(v3.redeem_script())
                    .unwrap_err()
                    .code(),
                "TEMPLATE_NOT_IMPULSE_VAULT"
            );
            // The v3 decoder refuses a v1 script.
            let v1 =
                crate::template::Vault::instantiate_existing(terms.v1_fields(), LegIndex::Asset)
                    .unwrap();
            assert_eq!(
                decode(v1.redeem_script()).unwrap_err().code(),
                "ZK_NOT_V3_VAULT"
            );
            assert_eq!(
                template_hash_of_instance(&[0u8; 10]).unwrap_err().code(),
                "ZK_NOT_V3_VAULT"
            );
        }

        /// The sample asset vault's script, with the first state byte at `start`.
        fn sample_script() -> (Vec<u8>, usize) {
            let terms = sample().validate_structure().unwrap();
            let v3 = VaultV3::instantiate_existing(&terms, LegIndex::Asset).unwrap();
            (v3.redeem_script().to_vec(), check().unwrap().prefix().len())
        }

        /// The state starts with the push of the version byte (`01 03`).
        #[test]
        fn a_version_byte_other_than_3_is_state_invalid() {
            let (mut s, start) = sample_script();
            assert_eq!(&s[start..start + 2], &[0x01, 0x03]);
            for v in [0u8, 1, 2, 4, 0x80] {
                s[start + 1] = v;
                assert_eq!(decode(&s).unwrap_err().code(), "ZK_STATE_INVALID", "{v}");
            }
        }

        #[test]
        fn a_mistyped_or_cut_state_is_state_malformed() {
            let (s, start) = sample_script();
            // The first push opcode (`01`, a one-byte push) replaced by OP_0: the version field
            // is no longer a byte.
            let mut m = s.clone();
            m[start] = 0x00;
            assert_eq!(decode(&m).unwrap_err().code(), "ZK_STATE_MALFORMED");
            // The state cut short: fields are missing.
            let t = check().unwrap();
            let end = s.len() - t.suffix().len();
            let mut cut = s[..end - 40].to_vec();
            cut.extend_from_slice(&s[end..]);
            assert_eq!(decode(&cut).unwrap_err().code(), "ZK_STATE_MALFORMED");
        }

        /// A script whose state decodes to valid terms but is not the canonical encoding of them.
        #[test]
        fn a_valid_state_in_another_encoding_is_noncanonical() {
            let (s, start) = sample_script();
            let t = check().unwrap();
            let end = s.len() - t.suffix().len();
            let mut found = Vec::new();
            for i in start..end {
                for x in [1u8, 0x80] {
                    let mut m = s.clone();
                    m[i] ^= x;
                    if matches!(decode(&m), Err(ZkError::Noncanonical)) {
                        found.push(i - start);
                    }
                }
            }
            assert!(!found.is_empty(), "no flip reaches ZK_NONCANONICAL");
            let mut m = s.clone();
            m[start + found[0]] ^= 1;
            let e = decode(&m).unwrap_err();
            assert_eq!(e.code(), "ZK_NONCANONICAL");
            // The unmodified script is accepted.
            decode(&s).unwrap();
        }

        #[test]
        fn a_changed_state_byte_is_noncanonical_or_refused() {
            let terms = sample().validate_structure().unwrap();
            let v3 = VaultV3::instantiate_existing(&terms, LegIndex::Asset).unwrap();
            let t = check().unwrap();
            let start = t.prefix().len();
            let end = v3.redeem_script().len() - t.suffix().len();
            let mut refused = 0;
            for i in start..end {
                let mut s = v3.redeem_script().to_vec();
                s[i] ^= 1;
                match decode(&s) {
                    Ok((again, leg)) => {
                        // A flip that still decodes must decode to other terms or another leg.
                        assert!(again != terms || leg != LegIndex::Asset, "byte {i}");
                    }
                    Err(e) => {
                        refused += 1;
                        assert!(
                            e.code().starts_with("ZK_")
                                || e.code().starts_with("TERMS_")
                                || e.code().starts_with("TEMPLATE_"),
                            "{e}"
                        );
                    }
                }
            }
            assert!(refused > 0);
        }
    }
}
