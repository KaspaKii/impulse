// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Funding addresses (spec/TEMPLATE.md, "Script hash, scriptPubKey and address"): the Kaspa
//! P2SH address of a leg's vault, with the prefix of the network its terms name, `kaspa` for
//! mainnet and `kaspatest` for every testnet. An address is shown only for a [`FundableVault`],
//! a vault whose terms passed the creation checks; an existing trade's [`Vault`] (for refunds
//! and decoding) has none, so an expired or mis-networked trade is never offered for funding.
//!
//! [`Vault`]: crate::template::Vault

use crate::template::FundableVault;
use crate::terms::Network;
use kaspa_addresses::{Address, Prefix, Version};

/// The address prefix of a network.
pub fn prefix(network: Network) -> Prefix {
    match network {
        Network::Mainnet => Prefix::Mainnet,
        Network::Testnet => Prefix::Testnet,
    }
}

/// The address a depositor funds for this vault: version ScriptHash, payload the script hash.
///
/// Takes only a creation-checked vault:
///
/// ```
/// use impulse_core::address::vault_address;
/// use impulse_core::template::{LegIndex, Vault};
/// use impulse_core::terms::{CreationContext, ValidatedTerms};
///
/// fn funding_address(terms: &ValidatedTerms, ctx: &CreationContext) -> Option<String> {
///     let vault = Vault::instantiate_for_creation(terms, LegIndex::Asset, ctx).ok()?;
///     Some(vault_address(&vault))
/// }
/// ```
///
/// An existing trade's vault has no funding address, so this does not compile:
///
/// ```compile_fail
/// use impulse_core::address::vault_address;
/// use impulse_core::template::{LegIndex, Vault};
/// use impulse_core::terms::{CreationContext, ValidatedTerms};
///
/// fn funding_address(terms: &ValidatedTerms, ctx: &CreationContext) -> Option<String> {
///     let vault = Vault::instantiate_existing(terms, LegIndex::Asset).ok()?;
///     Some(vault_address(&vault))
/// }
/// ```
pub fn vault_address(vault: &FundableVault) -> String {
    let vault = vault.vault();
    Address::new(
        prefix(vault.network()),
        Version::ScriptHash,
        &vault.script_hash(),
    )
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::{LegIndex, Vault};
    use crate::terms::golden::{vectors, CREATION_DAA};
    use crate::terms::{CreationContext, Terms};
    use kaspa_txscript::pay_to_address_script;

    fn vault(t: &Terms, leg: LegIndex) -> FundableVault {
        let ctx = CreationContext::new(t.network, CREATION_DAA);
        Vault::instantiate_for_creation(&t.clone().validate_structure().unwrap(), leg, &ctx)
            .unwrap()
    }

    #[test]
    fn the_address_pays_the_vault_script() {
        for v in vectors() {
            for leg in LegIndex::ALL {
                let checked = v.terms.clone().validate_structure().expect(v.name);
                let ctx = CreationContext::new(v.terms.network, CREATION_DAA);
                let Ok(fundable) = Vault::instantiate_for_creation(&checked, leg, &ctx) else {
                    continue;
                };
                let text = vault_address(&fundable);
                let vault = fundable.vault();
                let parsed = Address::try_from(text.as_str()).expect("the address parses");
                assert_eq!(parsed.prefix, prefix(v.terms.network));
                assert_eq!(parsed.version, Version::ScriptHash);
                assert_eq!(parsed.payload.as_slice(), &vault.script_hash());
                // Funding the address funds exactly the vault's P2SH scriptPubKey.
                assert_eq!(pay_to_address_script(&parsed), vault.script_public_key());
            }
        }
    }

    #[test]
    fn mainnet_and_testnet_addresses() {
        let mainnet = vectors().remove(1).terms; // vector 2
        assert_eq!(mainnet.network, Network::Mainnet);
        let mut testnet = mainnet.clone();
        testnet.network = Network::Testnet;
        for leg in LegIndex::ALL {
            let m = vault_address(&vault(&mainnet, leg));
            let t = vault_address(&vault(&testnet, leg));
            assert!(m.starts_with("kaspa:p"), "{m}");
            assert!(t.starts_with("kaspatest:p"), "{t}");
            // The network is in the state, so the script and the payload differ too.
            assert_ne!(m.split_once(':').unwrap().1, t.split_once(':').unwrap().1);
        }
    }

    #[test]
    fn address_known_answer() {
        // Computed independently in Python with the encoder scripts/vectors.sh carries, which
        // also reproduces rusty-kaspa a41a333's own ScriptHash address test vectors.
        let hash = [0x11; 32];
        let addr = |p| Address::new(p, Version::ScriptHash, &hash).to_string();
        assert_eq!(
            addr(Prefix::Mainnet),
            "kaspa:pqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3z6465ykr3"
        );
        assert_eq!(
            addr(Prefix::Testnet),
            "kaspatest:pqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zmnu0tgj4"
        );
    }
}
