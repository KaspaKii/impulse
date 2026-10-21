// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Reading a vault spend from its signature script. A spend of an ImpulseVault P2SH input is a
//! push-only signature script: the entry's arguments, the entry's dispatch tag, then the redeem
//! script (silverscript-abi `encode_entry_sig_script`, then the P2SH reveal). Consensus refuses a
//! signature script that is not push-only, so every accepted vault spend parses.

/// silverscript dispatch tag of `settle` in the ImpulseVault v1 artifact
/// (contracts/compiled/impulse_vault.v1.json; a test pins it to that file).
pub const SETTLE_TAG: [u8; 4] = [0xbd, 0x01, 0xfa, 0xf3];

/// silverscript dispatch tag of `refund`, pinned the same way.
pub const REFUND_TAG: [u8; 4] = [0xac, 0xb3, 0x73, 0x30];

/// silverscript dispatch tag of `settle` in the ImpulseVault v2 artifact
/// (contracts/compiled/impulse_vault.v2.json; a test pins it to that file).
pub const SETTLE_TAG_V2: [u8; 4] = [0x8f, 0xb0, 0x4e, 0x80];

/// silverscript dispatch tag of `refund` in the v2 artifact, pinned the same way.
pub const REFUND_TAG_V2: [u8; 4] = [0x99, 0x9b, 0xa3, 0xbe];

/// The ImpulseVault entry a spend called.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Entry {
    Settle,
    Refund,
}

/// The data pushes of a push-only script, in order; `None` if any opcode is not a push or a
/// push runs past the end.
pub fn pushes(script: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let len = match op {
            0x00 => 0,
            0x01..=0x4b => op as usize,
            0x4c => {
                let n = *script.get(i)? as usize;
                i += 1;
                n
            }
            0x4d => {
                let b = script.get(i..i + 2)?;
                i += 2;
                u16::from_le_bytes([b[0], b[1]]) as usize
            }
            0x4e => {
                let b = script.get(i..i + 4)?;
                i += 4;
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
            }
            // OP_1NEGATE and OP_1 to OP_16 push a small number.
            0x4f => {
                out.push(vec![0x81]);
                continue;
            }
            0x51..=0x60 => {
                out.push(vec![op - 0x50]);
                continue;
            }
            _ => return None,
        };
        let end = i.checked_add(len)?;
        out.push(script.get(i..end)?.to_vec());
        i = end;
    }
    Some(out)
}

/// The entry a vault spend called, read from the push before the redeem script; `None` if that
/// push is not one of the two tags.
pub fn entry_of(pushes: &[Vec<u8>]) -> Option<Entry> {
    let tag = pushes.len().checked_sub(2).map(|i| pushes[i].as_slice())?;
    if tag == SETTLE_TAG {
        Some(Entry::Settle)
    } else if tag == REFUND_TAG {
        Some(Entry::Refund)
    } else {
        None
    }
}

/// As [`entry_of`] for a spend of an ImpulseVault v2 vault, with the v2 tags.
pub fn entry_of_v2(pushes: &[Vec<u8>]) -> Option<Entry> {
    let tag = pushes.iter().rev().nth(1).map(Vec::as_slice)?;
    if tag == SETTLE_TAG_V2 {
        Some(Entry::Settle)
    } else if tag == REFUND_TAG_V2 {
        Some(Entry::Refund)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_txscript::script_builder::ScriptBuilder;
    use kaspa_txscript::EngineFlags;

    #[test]
    fn the_tags_are_the_artifacts() {
        // The committed artifact is the one impulse-core embeds and checks against TEMPLATE_HASH.
        let artifact: serde_json::Value = serde_json::from_str(include_str!(
            "../../../contracts/compiled/impulse_vault.v1.json"
        ))
        .unwrap();
        let entries = &artifact["contracts"]["ImpulseVault"]["entries"];
        let tag = |name: &str| entries[name]["dispatch_tag"].as_str().unwrap().to_string();
        let hex = |b: [u8; 4]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(tag("settle"), hex(SETTLE_TAG));
        assert_eq!(tag("refund"), hex(REFUND_TAG));
        assert_eq!(entries.as_object().unwrap().len(), 2);
        let pinned = include_str!("../../../contracts/TEMPLATE_HASH").trim();
        let embedded = impulse_core::template::check().unwrap().hash();
        let embedded: String = embedded.iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!(embedded, pinned, "the tags above belong to this template");
    }

    #[test]
    fn the_v2_tags_are_the_v2_artifacts() {
        let artifact: serde_json::Value = serde_json::from_str(include_str!(
            "../../../contracts/compiled/impulse_vault.v2.json"
        ))
        .unwrap();
        let entries = &artifact["contracts"]["ImpulseVaultV2"]["entries"];
        let tag = |name: &str| entries[name]["dispatch_tag"].as_str().unwrap().to_string();
        let hex = |b: [u8; 4]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(tag("settle"), hex(SETTLE_TAG_V2));
        assert_eq!(tag("refund"), hex(REFUND_TAG_V2));
        assert_eq!(entries.as_object().unwrap().len(), 2);
        let pinned = include_str!("../../../contracts/TEMPLATE_HASH_V2").trim();
        let embedded = impulse_core::v2::check_template().unwrap().hash();
        let embedded: String = embedded.iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!(embedded, pinned, "the tags above belong to this template");
        // A v1 tag is no v2 entry, and a v2 tag no v1 entry.
        let spend = |tag: [u8; 4]| vec![vec![1], tag.to_vec(), vec![2]];
        assert_eq!(entry_of_v2(&spend(SETTLE_TAG)), None);
        assert_eq!(entry_of(&spend(SETTLE_TAG_V2)), None);
        assert_eq!(entry_of_v2(&spend(REFUND_TAG_V2)), Some(Entry::Refund));
    }

    #[test]
    fn pushes_reads_every_push_size_a_script_builder_writes() {
        let data: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x07],
            vec![0xaa; 4],
            vec![0xbb; 75],
            vec![0xcc; 76],
            vec![0xdd; 255],
            vec![0xee; 256],
            vec![0x11; 3_000],
        ];
        // Covenant-era limits, under which a 3,000-byte redeem script push is canonical.
        let mut builder = ScriptBuilder::with_flags(EngineFlags {
            covenants_enabled: true,
            ..Default::default()
        });
        for d in &data {
            builder.add_data(d).unwrap();
        }
        let script = builder.drain();
        // ScriptBuilder writes [0x07] as OP_7, which reads back as the same byte.
        assert_eq!(pushes(&script).unwrap(), data);
    }

    #[test]
    fn pushes_refuses_a_non_push_or_a_short_push() {
        assert_eq!(pushes(&[0x76]), None, "OP_DUP");
        assert_eq!(
            pushes(&[0x04, 0x01, 0x02]),
            None,
            "four bytes promised, two given"
        );
        assert_eq!(pushes(&[0x4d, 0x01]), None, "a cut PUSHDATA2 length");
        // Control: complete pushes.
        assert_eq!(
            pushes(&[0x02, 0x01, 0x02, 0x00]).unwrap(),
            vec![vec![1, 2], vec![]]
        );
    }

    #[test]
    fn entry_of_reads_the_push_before_the_redeem_script() {
        let redeem = vec![0x99; 10];
        let call = |tag: &[u8]| vec![vec![0x5a; 65], tag.to_vec(), redeem.clone()];
        assert_eq!(entry_of(&call(&SETTLE_TAG)), Some(Entry::Settle));
        assert_eq!(entry_of(&call(&REFUND_TAG)), Some(Entry::Refund));
        assert_eq!(entry_of(&call(&[0xde, 0xad, 0xbe, 0xef])), None);
        assert_eq!(entry_of(&[redeem]), None, "no tag at all");
    }
}
