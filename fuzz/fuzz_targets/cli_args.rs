// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The CLI's text arguments: addresses (`--pay-from`, `--change`, destination pins), funding
//! URIs, outpoints and token outpoints (`--token`, the lines `impulse token list` prints), and
//! node URLs. The first byte picks the parser and the network, the rest is the text. Oracles: an
//! accepted outpoint or token prints back to the text it was read from; an accepted URI's address
//! is the canonical form of itself; an accepted address belongs to the network asked for.
#![no_main]

use impulse_cli::funds::{
    outpoint_text, parse_change, parse_outpoint, parse_pay_from, parse_token, p2pk_address,
};
use impulse_cli::node::{check_transport, check_url};
use impulse_cli::summary::parse_pin;
use impulse_cli::uri;
use impulse_core::address::prefix;
use impulse_core::terms::Network;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let network = if which & 0x80 == 0 {
        Network::Mainnet
    } else {
        Network::Testnet
    };
    match which & 0x7f {
        0 => {
            if let Ok(a) = parse_pay_from(text, network) {
                assert_eq!(a.prefix, prefix(network));
                let key: [u8; 32] = a.payload.as_slice().try_into().expect("P2PK payload");
                assert_eq!(p2pk_address(&key, network), a);
            }
        }
        1 => {
            let _ = parse_change(text, network);
        }
        2 => {
            let _ = parse_pin("--pin", text, network);
        }
        3 => {
            if let Ok(u) = uri::parse(text) {
                assert!(text.starts_with(&u.address));
            }
        }
        4 => {
            if let Ok(o) = parse_outpoint("--outpoint", text) {
                assert_eq!(outpoint_text(&o), text);
            }
        }
        5 => {
            if let Ok((o, amount)) = parse_token("--token", text) {
                assert_eq!(format!("{}:{amount}", outpoint_text(&o)), text);
            }
        }
        _ => {
            let url_ok = check_url(text).is_ok();
            if check_transport(text, network).is_ok() {
                assert!(url_ok);
            }
        }
    }
});
