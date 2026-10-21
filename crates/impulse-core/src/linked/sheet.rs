// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The linked sheet, the terms v2 extension `linked` (spec/V2.md sections 17.2 to 17.5): one
//! term sheet from which an opening trade and a return trade are derived, both ordinary two-leg
//! terms v2 whose trade_ref is the sheet's hash. The sheet is canonical bytes under the keyed
//! hash `Impulse/terms/v2/linked`; terms v2 itself and its frozen vectors are untouched.

use super::{LinkedError, Role};
use crate::terms::{CreationContext, Leg};
use crate::v2::{LegV2, TermsV2, ValidatedTermsV2, TERMS_V2_VERSION};

/// The sheet encoding version.
pub const LINKED_VERSION: u8 = 1;

/// blake2b-256 key of the sheet hash: the tag's 23 ASCII bytes as they are (spec/V2.md 17.2).
pub const LINKED_HASH_DOMAIN: &[u8] = b"Impulse/terms/v2/linked";

/// The agreed sheet, field for field as spec/V2.md 17.2. A plain value: anything that decodes.
/// Builders take [`ValidatedLinked`] instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedSheet {
    /// `LINKED_VERSION`.
    pub version: u8,
    /// The opening trade, with a zero trade_ref (the sheet's hash is written into it on chain).
    pub opening: TermsV2,
    /// The amount of asset 0 and of asset 1 the return moves back.
    pub return_amounts: [u64; 2],
    pub return_earliest_daa: u64,
    pub return_expiry_daa: u64,
}

impl LinkedSheet {
    /// Canonical bytes (spec/V2.md 17.2). Refuses a version other than 1.
    pub fn encode(&self) -> Result<Vec<u8>, LinkedError> {
        if self.version != LINKED_VERSION {
            return Err(LinkedError::Version {
                version: self.version,
            });
        }
        let opening = self.opening.encode()?;
        let len = u16::try_from(opening.len()).map_err(|_| LinkedError::Truncated {
            field: "opening_len",
        })?;
        let mut out = Vec::with_capacity(35 + opening.len());
        out.push(self.version);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&opening);
        for amount in self.return_amounts {
            out.extend_from_slice(&amount.to_le_bytes());
        }
        out.extend_from_slice(&self.return_earliest_daa.to_le_bytes());
        out.extend_from_slice(&self.return_expiry_daa.to_le_bytes());
        Ok(out)
    }

    /// Parses canonical bytes, first failure returned: the version byte (`LINKED_VERSION`),
    /// input that ends inside a field (`LINKED_TRUNCATED`), the opening's own decoding (the
    /// `TERMS_` codes), bytes after the last field (`LINKED_TRAILING_BYTES`). The result may
    /// still fail [`LinkedSheet::validate`].
    pub fn decode(bytes: &[u8]) -> Result<Self, LinkedError> {
        let Some((&version, rest)) = bytes.split_first() else {
            return Err(LinkedError::Truncated {
                field: "link_version",
            });
        };
        if version != LINKED_VERSION {
            return Err(LinkedError::Version { version });
        }
        let mut r = Reader { bytes: rest };
        let len = usize::from(u16::from_le_bytes(r.array("opening_len")?));
        let opening = TermsV2::decode(r.take(len, "opening")?)?;
        let return_amounts = [
            u64::from_le_bytes(r.array("return_amount_0")?),
            u64::from_le_bytes(r.array("return_amount_1")?),
        ];
        let return_earliest_daa = u64::from_le_bytes(r.array("return_earliest_daa")?);
        let return_expiry_daa = u64::from_le_bytes(r.array("return_expiry_daa")?);
        if !r.bytes.is_empty() {
            return Err(LinkedError::TrailingBytes {
                count: r.bytes.len(),
            });
        }
        Ok(Self {
            version,
            opening,
            return_amounts,
            return_earliest_daa,
            return_expiry_daa,
        })
    }

    /// blake2b-256, keyed with `LINKED_HASH_DOMAIN`, over the canonical bytes.
    pub fn linked_hash(&self) -> Result<[u8; 32], LinkedError> {
        Ok(hash_canonical(&self.encode()?))
    }

    /// The sheet checks of spec/V2.md 17.4, in order, first failure returned. The only way to
    /// obtain [`ValidatedLinked`].
    pub fn validate(self) -> Result<ValidatedLinked, LinkedError> {
        // 1. Version (encode checks it again below, but the order is the spec's).
        if self.version != LINKED_VERSION {
            return Err(LinkedError::Version {
                version: self.version,
            });
        }
        // 2. The opening's structure checks.
        self.opening.clone().validate_structure()?;
        // 3. Two legs. 4. No partial. 5. A zero trade_ref.
        if self.opening.legs.len() != 2 {
            return Err(LinkedError::LegCount {
                count: self.opening.legs.len(),
            });
        }
        if self.opening.partial.is_some() {
            return Err(LinkedError::Partial);
        }
        if self.opening.trade_ref != [0u8; 32] {
            return Err(LinkedError::TradeRefSet);
        }
        // 6. The return starts after the opening can no longer settle.
        if self.return_earliest_daa <= self.opening.expiry_daa {
            return Err(LinkedError::ReturnNotLater {
                return_earliest_daa: self.return_earliest_daa,
                opening_expiry_daa: self.opening.expiry_daa,
            });
        }
        let canonical = self.encode()?;
        let hash = hash_canonical(&canonical);
        // 7. The derived return's structure checks.
        let ret = derive_return(&self, hash).validate_structure()?;
        let mut opening = self.opening.clone();
        opening.trade_ref = hash;
        let opening = opening.validate_structure()?;
        Ok(ValidatedLinked {
            sheet: self,
            canonical,
            hash,
            opening,
            ret,
        })
    }
}

/// A sheet that passed [`LinkedSheet::validate`], with its canonical bytes, its hash and the two
/// derived trades. The fields are private, so a value of this type always holds checked data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedLinked {
    sheet: LinkedSheet,
    canonical: Vec<u8>,
    hash: [u8; 32],
    opening: ValidatedTermsV2,
    ret: ValidatedTermsV2,
}

impl ValidatedLinked {
    /// Decodes canonical bytes and runs the sheet checks.
    pub fn decode(bytes: &[u8]) -> Result<Self, LinkedError> {
        LinkedSheet::decode(bytes)?.validate()
    }

    pub fn sheet(&self) -> &LinkedSheet {
        &self.sheet
    }

    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    /// The sheet's hash: also the trade_ref of both derived trades.
    pub fn linked_hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The derived terms v2 of `role`.
    pub fn terms(&self, role: Role) -> &ValidatedTermsV2 {
        match role {
            Role::Opening => &self.opening,
            Role::Return => &self.ret,
        }
    }

    /// The terms v2 hash of `role`'s trade.
    pub fn terms_hash(&self, role: Role) -> [u8; 32] {
        self.terms(role).terms_hash()
    }

    /// The creation checks of `role`'s trade (v1's, unchanged: spec/V2.md 17.4), at the DAA score
    /// of that trade's own creation.
    pub fn validate_creation(&self, role: Role, ctx: &CreationContext) -> Result<(), LinkedError> {
        Ok(self.terms(role).validate_creation(ctx)?)
    }

    /// Checks that `offered` are the derived terms of `role` (spec/V2.md 17.5). In order: equal,
    /// accepted; equal to the other role's trade, `LINKED_ROLE_MISMATCH`; equal to `role`'s trade
    /// except for trade_ref, `LINKED_TRADE_REF`; anything else `LINKED_NOT_A_LEG`.
    pub fn verify_terms(&self, role: Role, offered: &TermsV2) -> Result<(), LinkedError> {
        let bytes = offered.encode()?;
        if bytes == self.terms(role).canonical() {
            return Ok(());
        }
        if bytes == self.terms(role.other()).canonical() {
            return Err(LinkedError::RoleMismatch { role });
        }
        let mut with_ref = offered.clone();
        with_ref.trade_ref = self.hash;
        if with_ref.encode()? == self.terms(role).canonical() {
            return Err(LinkedError::TradeRef { role });
        }
        Err(LinkedError::NotALeg { role })
    }
}

/// The return trade derived from a sheet (spec/V2.md 17.3), unchecked: leg i is deposited by the
/// opening's other party, delivered to the opening's refund destination of leg i, and refunded to
/// the opening's delivery destination of leg i.
fn derive_return(sheet: &LinkedSheet, linked_hash: [u8; 32]) -> TermsV2 {
    let open = &sheet.opening;
    let legs = (0..2)
        .map(|i| LegV2 {
            depositor_key: open.legs[1 - i].depositor_key,
            asset: Leg {
                kind: open.legs[i].asset.kind,
                amount: sheet.return_amounts[i],
            },
            delivery: open.legs[i].refund,
            refund: open.legs[i].delivery,
        })
        .collect();
    TermsV2 {
        version: TERMS_V2_VERSION,
        network: open.network,
        nonce: open.nonce,
        authority_key: open.authority_key,
        legs,
        earliest_daa: Some(sheet.return_earliest_daa),
        expiry_daa: sheet.return_expiry_daa,
        funding_mode: open.funding_mode,
        partial: None,
        trade_ref: linked_hash,
    }
}

fn hash_canonical(canonical: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .key(LINKED_HASH_DOMAIN)
        .hash(canonical);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], LinkedError> {
        if self.bytes.len() < n {
            return Err(LinkedError::Truncated { field });
        }
        let (head, tail) = self.bytes.split_at(n);
        self.bytes = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N], LinkedError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N, field)?);
        Ok(out)
    }
}
