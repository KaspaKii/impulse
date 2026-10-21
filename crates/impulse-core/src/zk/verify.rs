// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The v3 verifier (spec/V3-ZK.md section 11, mirroring spec/VERIFY.md). Before funding: recompute
//! both legs' vault addresses from the agreed terms v3 and compare them with the addresses
//! offered; check the list manifest against the issuer key; check a member's path against the
//! delivery owner and the root. After a spend: check a revealed redeem script against the pinned
//! template v3 and the agreed terms.
//!
//! Every check takes structure-checked terms and fails closed with a stable code. What the
//! checks say is exactly what they test: they say nothing about whether a list is a good list,
//! who the issuer is, or whether any member is eligible for anything (spec section 9.5). Keyless.

use super::list::MemberPath;
use super::manifest::Manifest;
use super::template::{
    check as check_template, decode, template_hash_of_instance, vault_address_v3, VaultV3,
};
use super::terms::ValidatedTermsV3;
use super::ZkError;
use crate::address::prefix;
use crate::template::{LegIndex, TemplateError};
use crate::terms::{CreationContext, Kcc20Owner};
use crate::verify::parsable_address;
use kaspa_addresses::{Address, Version};

/// The addresses a depositor was offered for funding, one per leg. A leg the terms give no vault
/// (the cash leg of external cash) must have none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OfferedAddressesV3<'a> {
    pub asset: Option<&'a str>,
    pub cash: Option<&'a str>,
}

impl<'a> OfferedAddressesV3<'a> {
    fn get(&self, leg: LegIndex) -> Option<&'a str> {
        match leg {
            LegIndex::Asset => self.asset,
            LegIndex::Cash => self.cash,
        }
    }
}

/// A leg's funding address, recomputed from the terms and equal to the one offered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAddressV3 {
    pub leg: LegIndex,
    pub address: String,
    pub script_hash: [u8; 32],
}

/// Recomputes each leg's funding address from the terms v3 and compares it with the one offered.
/// Both legs instantiate for creation first, so the creation checks run against `ctx`
/// (`TERMS_NETWORK_MISMATCH`, `TERMS_EXPIRY_*`). A leg with no vault must have no address, a leg
/// with a vault must have one that parses, carries the terms' network prefix and pays that leg's
/// vault; anything else is `ZK_VERIFY_ADDRESS_MISMATCH` (the other leg's vault included).
pub fn verify_addresses_v3(
    terms: &ValidatedTermsV3,
    ctx: &CreationContext,
    offered: &OfferedAddressesV3<'_>,
) -> Result<Vec<VerifiedAddressV3>, ZkError> {
    let mut vaults = [None, None];
    for leg in LegIndex::ALL {
        match VaultV3::instantiate_for_creation(terms, leg, ctx) {
            Ok(fundable) => vaults[usize::from(leg.index())] = Some(fundable),
            // External cash: the cash leg settles off chain and has no vault.
            Err(ZkError::Template(TemplateError::NoVault { .. })) if leg == LegIndex::Cash => {}
            Err(e) => return Err(e),
        }
    }
    let network = terms.terms().fields.network;
    let mut verified = Vec::new();
    for leg in LegIndex::ALL {
        let (fundable, text) = match (&vaults[usize::from(leg.index())], offered.get(leg)) {
            (None, None) => continue,
            (None, Some(_)) | (Some(_), None) => return Err(ZkError::VerifyAddressMismatch),
            (Some(fundable), Some(text)) => (fundable, text),
        };
        if !parsable_address(text) {
            return Err(ZkError::VerifyAddressMismatch);
        }
        let parsed = Address::try_from(text).map_err(|_| ZkError::VerifyAddressMismatch)?;
        if parsed.prefix != prefix(network)
            || parsed.version != Version::ScriptHash
            || parsed.payload.as_slice() != fundable.vault().script_hash()
        {
            return Err(ZkError::VerifyAddressMismatch);
        }
        verified.push(VerifiedAddressV3 {
            leg,
            address: vault_address_v3(fundable),
            script_hash: fundable.vault().script_hash(),
        });
    }
    Ok(verified)
}

/// Checks a redeem script revealed by a spend against the agreed terms v3 and leg. Accepts
/// exactly the script [`VaultV3::instantiate_existing`] makes from them. A script that does not
/// run the pinned template v3, hash recomputed from its own bytes, is
/// `ZK_VERIFY_TEMPLATE_MISMATCH`; a v3 vault of other terms or of the other leg is
/// `ZK_VERIFY_ADDRESS_MISMATCH` (it is not this trade's vault).
pub fn verify_revealed_script_v3(
    terms: &ValidatedTermsV3,
    leg: LegIndex,
    redeem_script: &[u8],
) -> Result<(), ZkError> {
    let expected = VaultV3::instantiate_existing(terms, leg)?;
    if expected.redeem_script() == redeem_script {
        return Ok(());
    }
    let pinned = check_template()?.hash();
    if template_hash_of_instance(redeem_script).ok() != Some(pinned) {
        return Err(ZkError::VerifyTemplateMismatch);
    }
    match decode(redeem_script) {
        Ok(_) => Err(ZkError::VerifyAddressMismatch),
        Err(e) => Err(e),
    }
}

/// What `verify` found about the list manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestStatus {
    /// No manifest was supplied: nothing ties the root to the issuer key.
    NoneSupplied,
    /// The manifest names this root and network and its signature verifies under the issuer key.
    Signed(Manifest),
}

/// Checks a manifest and its signature against the terms: the network and root it names and the
/// signature under `list_issuer_key` (`ZK_MANIFEST_INVALID`).
pub fn check_manifest(
    terms: &ValidatedTermsV3,
    manifest: &Manifest,
    signature: &[u8; 64],
) -> Result<ManifestStatus, ZkError> {
    let t = terms.terms();
    manifest.check_binding(t.fields.network, &t.list_root)?;
    manifest.verify_signature(&t.list_issuer_key, signature)?;
    Ok(ManifestStatus::Signed(manifest.clone()))
}

/// What `verify` found about a member's path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathStatus {
    /// No path file was supplied: the buyer cannot settle without the issuer's path.
    NoneSupplied,
    /// The path leads from the buyer delivery owner's salted leaf to the terms' list root.
    Leads,
}

/// Checks a path file against the terms' delivery owner and root (`ZK_PATH_INVALID`).
pub fn check_path(terms: &ValidatedTermsV3, path: &MemberPath) -> Result<PathStatus, ZkError> {
    path.check(&terms.delivery_owner(), &terms.terms().list_root)?;
    Ok(PathStatus::Leads)
}

/// Everything `verify` reports about v3 terms, in the order of spec section 11.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyReportV3 {
    pub addresses: Vec<VerifiedAddressV3>,
    pub list_root: [u8; 32],
    pub list_issuer_key: [u8; 32],
    pub manifest: ManifestStatus,
    /// The issuer key equals the seller key: the seller curates this list.
    pub issuer_is_seller: bool,
    /// The buyer delivery owner, public on chain.
    pub delivery_owner: Kcc20Owner,
    pub path: PathStatus,
    /// The terms name an authority.
    pub has_authority: bool,
}

/// The full check before funding: the addresses, the manifest when supplied, the path when
/// supplied. First failure returned in that order.
pub fn verify_v3(
    terms: &ValidatedTermsV3,
    ctx: &CreationContext,
    offered: &OfferedAddressesV3<'_>,
    manifest: Option<(&Manifest, &[u8; 64])>,
    path: Option<&MemberPath>,
) -> Result<VerifyReportV3, ZkError> {
    let addresses = verify_addresses_v3(terms, ctx, offered)?;
    let manifest = match manifest {
        Some((m, sig)) => check_manifest(terms, m, sig)?,
        None => ManifestStatus::NoneSupplied,
    };
    let path = match path {
        Some(p) => check_path(terms, p)?,
        None => PathStatus::NoneSupplied,
    };
    let t = terms.terms();
    Ok(VerifyReportV3 {
        addresses,
        list_root: t.list_root,
        list_issuer_key: t.list_issuer_key,
        manifest,
        issuer_is_seller: t.list_issuer_key == t.fields.seller_key,
        delivery_owner: terms.delivery_owner(),
        path,
        has_authority: t.fields.authority_key.is_some(),
    })
}

#[cfg(all(test, impulse_v3_artifact))]
mod tests {
    use super::*;
    use crate::terms::golden::CREATION_DAA;
    use crate::zk::terms::tests::sample;
    use crate::zk::vault_address_v3;
    use crate::zk::ListTree;

    fn addresses(terms: &ValidatedTermsV3) -> (String, String) {
        let ctx = CreationContext::new(terms.terms().fields.network, CREATION_DAA);
        let a = VaultV3::instantiate_for_creation(terms, LegIndex::Asset, &ctx).unwrap();
        let c = VaultV3::instantiate_for_creation(terms, LegIndex::Cash, &ctx).unwrap();
        (vault_address_v3(&a), vault_address_v3(&c))
    }

    #[test]
    fn the_right_addresses_verify_and_swapped_or_foreign_ones_do_not() {
        let terms = sample().validate_structure().unwrap();
        let ctx = CreationContext::new(terms.terms().fields.network, CREATION_DAA);
        let (a, c) = addresses(&terms);
        let ok = verify_addresses_v3(
            &terms,
            &ctx,
            &OfferedAddressesV3 {
                asset: Some(&a),
                cash: Some(&c),
            },
        )
        .unwrap();
        assert_eq!(ok.len(), 2);
        let code = |asset: Option<&str>, cash: Option<&str>| {
            verify_addresses_v3(&terms, &ctx, &OfferedAddressesV3 { asset, cash })
                .unwrap_err()
                .code()
        };
        assert_eq!(code(Some(&c), Some(&a)), "ZK_VERIFY_ADDRESS_MISMATCH");
        assert_eq!(code(Some(&a), None), "ZK_VERIFY_ADDRESS_MISMATCH");
        assert_eq!(code(None, Some(&c)), "ZK_VERIFY_ADDRESS_MISMATCH");
        assert_eq!(
            code(Some("nonsense"), Some(&c)),
            "ZK_VERIFY_ADDRESS_MISMATCH"
        );
        // Another root is another vault.
        let mut other = sample();
        other.list_root = [0x43; 32];
        let other = other.validate_structure().unwrap();
        let (oa, oc) = addresses(&other);
        assert_eq!(code(Some(&oa), Some(&oc)), "ZK_VERIFY_ADDRESS_MISMATCH");
        // The v1 vault of the same fields is not a v3 vault.
        let v1 = crate::template::Vault::instantiate_for_creation(
            terms.v1_fields(),
            LegIndex::Asset,
            &ctx,
        )
        .unwrap();
        let v1_address = crate::address::vault_address(&v1);
        assert_eq!(
            code(Some(&v1_address), Some(&c)),
            "ZK_VERIFY_ADDRESS_MISMATCH"
        );
        // The gate binds the asset vault only (spec 6.5, D64): a v1 vault at the CASH position
        // is refused too, so a buyer who verifies both addresses before funding cash never
        // funds against an asset vault that is not this trade's v3 vault.
        let v1_cash = crate::template::Vault::instantiate_for_creation(
            terms.v1_fields(),
            LegIndex::Cash,
            &ctx,
        )
        .unwrap();
        let v1_cash_address = crate::address::vault_address(&v1_cash);
        assert_eq!(
            code(Some(&a), Some(&v1_cash_address)),
            "ZK_VERIFY_ADDRESS_MISMATCH"
        );
        // Past its horizon the creation checks refuse before any address is compared.
        let late = CreationContext::new(terms.terms().fields.network, u64::MAX / 2);
        assert!(verify_addresses_v3(
            &terms,
            &late,
            &OfferedAddressesV3 {
                asset: Some(&a),
                cash: Some(&c)
            }
        )
        .unwrap_err()
        .code()
        .starts_with("TERMS_"));
    }

    #[test]
    fn revealed_scripts() {
        let terms = sample().validate_structure().unwrap();
        let asset = VaultV3::instantiate_existing(&terms, LegIndex::Asset).unwrap();
        let cash = VaultV3::instantiate_existing(&terms, LegIndex::Cash).unwrap();
        verify_revealed_script_v3(&terms, LegIndex::Asset, asset.redeem_script()).unwrap();
        // The other leg's script is a v3 vault, but not this leg's.
        assert_eq!(
            verify_revealed_script_v3(&terms, LegIndex::Asset, cash.redeem_script())
                .unwrap_err()
                .code(),
            "ZK_VERIFY_ADDRESS_MISMATCH"
        );
        // A v1 vault, and bytes that are no vault at all.
        let v1 = crate::template::Vault::instantiate_existing(terms.v1_fields(), LegIndex::Asset)
            .unwrap();
        assert_eq!(
            verify_revealed_script_v3(&terms, LegIndex::Asset, v1.redeem_script())
                .unwrap_err()
                .code(),
            "ZK_VERIFY_TEMPLATE_MISMATCH"
        );
        assert_eq!(
            verify_revealed_script_v3(&terms, LegIndex::Asset, &[1, 2, 3])
                .unwrap_err()
                .code(),
            "ZK_VERIFY_TEMPLATE_MISMATCH"
        );
    }

    #[test]
    fn manifest_and_path_statuses() {
        // No key exists here (rule 1, docs/ENGINEERING-RULES.md), so no signature verifies: the refusals and the
        // statuses that need none are checked, and the signed manifest is checked end to end in
        // impulse-cli/src/zk_tests.rs.
        let owner = crate::terms::Kcc20Owner {
            identifier_type: crate::terms::IdentifierType::ScriptHash,
            identifier: [0x11; 32],
        };
        let tree = ListTree::build_with_salts(
            vec![
                crate::terms::Kcc20Owner {
                    identifier_type: crate::terms::IdentifierType::ScriptHash,
                    identifier: [0x22; 32],
                },
                owner,
            ],
            &[[1; 32], [2; 32]],
        )
        .unwrap();
        let mut t = sample();
        t.list_root = tree.root();
        if let crate::terms::Destination::Kcc20(o) = &mut t.fields.buyer_delivery {
            *o = owner;
        }
        let terms = t.validate_structure().unwrap();
        let ctx = CreationContext::new(terms.terms().fields.network, CREATION_DAA);
        let (a, c) = addresses(&terms);
        let offered = OfferedAddressesV3 {
            asset: Some(&a),
            cash: Some(&c),
        };
        let path = tree.member_path(&owner).unwrap();

        let report = verify_v3(&terms, &ctx, &offered, None, Some(&path)).unwrap();
        assert_eq!(report.manifest, ManifestStatus::NoneSupplied);
        assert_eq!(report.path, PathStatus::Leads);
        assert!(!report.issuer_is_seller);
        assert!(report.has_authority);
        assert_eq!(report.delivery_owner, owner);

        let bare = verify_v3(&terms, &ctx, &offered, None, None).unwrap();
        assert_eq!(bare.path, PathStatus::NoneSupplied);

        // A manifest for another root or network, a signature that is none, a path of another
        // member.
        let m = Manifest::new(
            terms.terms().fields.network,
            "list",
            1,
            1_760_000_000,
            tree.root(),
        )
        .unwrap();
        let code = |m: &Manifest, p: Option<&MemberPath>| {
            verify_v3(&terms, &ctx, &offered, Some((m, &[0x11; 64])), p)
                .unwrap_err()
                .code()
        };
        let other_root = Manifest::new(m.network, "list", 1, 0, [9; 32]).unwrap();
        assert_eq!(code(&other_root, None), "ZK_MANIFEST_INVALID");
        let mut other_net = m.clone();
        other_net.network = crate::terms::Network::Testnet;
        assert_eq!(code(&other_net, None), "ZK_MANIFEST_INVALID");
        assert_eq!(
            code(&m, None),
            "ZK_MANIFEST_INVALID",
            "an invented signature"
        );
        // A path of another member is refused when the manifest passes; here the manifest comes
        // first, so check the path alone.
        let other_member = tree.path(0).unwrap();
        assert_eq!(
            check_path(&terms, &other_member).unwrap_err().code(),
            "ZK_PATH_INVALID"
        );
    }

    #[test]
    fn the_seller_as_issuer_is_reported() {
        let mut t = sample();
        t.list_issuer_key = t.fields.seller_key;
        let terms = t.validate_structure().unwrap();
        let ctx = CreationContext::new(terms.terms().fields.network, CREATION_DAA);
        let (a, c) = addresses(&terms);
        let r = verify_v3(
            &terms,
            &ctx,
            &OfferedAddressesV3 {
                asset: Some(&a),
                cash: Some(&c),
            },
            None,
            None,
        )
        .unwrap();
        assert!(r.issuer_is_seller);
    }
}
