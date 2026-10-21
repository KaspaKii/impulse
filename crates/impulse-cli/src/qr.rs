// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terminal QR code of a funding URI: Unicode half blocks, two modules per character cell, light
//! modules (and the quiet zone) drawn as blocks, so the code scans on a dark terminal background.
//! On a light background it reads inverted; use `--no-qr` and the printed URI there.

use crate::error::CliError;
use qrcode::render::unicode::Dense1x2;
use qrcode::QrCode;

/// The QR code of `text` as terminal lines.
pub fn render(text: &str) -> Result<String, CliError> {
    let code = QrCode::new(text.as_bytes()).map_err(|e| CliError::new("CLI_QR", e.to_string()))?;
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_funding_uri_renders_as_half_blocks() {
        let uri = format!(
            "kaspa:pqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3z6465ykr3?amount=2500000000000&impulse={}",
            "ab".repeat(32)
        );
        let art = render(&uri).unwrap();
        let width = QrCode::new(uri.as_bytes()).unwrap().width() + 8; // quiet zone 4 each side
        let lines: Vec<&str> = art.lines().collect();
        assert_eq!(lines.len(), width.div_ceil(2));
        assert!(lines.iter().all(|l| l.chars().count() == width));
        assert!(art
            .chars()
            .all(|c| matches!(c, ' ' | '\u{2580}' | '\u{2584}' | '\u{2588}' | '\n')));
        assert_eq!(render(&uri).unwrap(), art, "deterministic");
    }

    /// The expected rendering, built independently from the code's module matrix: a 4-module
    /// quiet zone, light modules inked, rows paired top and bottom into half blocks.
    fn expected(text: &str) -> String {
        let code = QrCode::new(text.as_bytes()).unwrap();
        let w = code.width();
        let colors = code.to_colors();
        let size = w + 8;
        let ink = |x: usize, y: usize| -> bool {
            if x < 4 || y < 4 || x >= w + 4 || y >= w + 4 {
                return true; // quiet zone is light
            }
            colors[(y - 4) * w + (x - 4)] == qrcode::Color::Light
        };
        let mut lines = Vec::new();
        for top in (0..size).step_by(2) {
            let line: String = (0..size)
                .map(|x| {
                    let bottom = top + 1 < size && ink(x, top + 1);
                    match (ink(x, top), bottom) {
                        (true, true) => '\u{2588}',
                        (true, false) => '\u{2580}',
                        (false, true) => '\u{2584}',
                        (false, false) => ' ',
                    }
                })
                .collect();
            lines.push(line);
        }
        lines.join("\n")
    }

    #[test]
    fn the_rendering_is_the_uri_with_light_modules_inked() {
        let uri = format!(
            "kaspatest:pqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zmnu0tgj4?amount=100000000&impulse={}",
            "cd".repeat(32)
        );
        assert_eq!(render(&uri).unwrap(), expected(&uri));
        // Another amount is another code: the rendering is bound to the whole URI.
        let other = uri.replace("amount=100000000", "amount=1000000000");
        assert_ne!(render(&other).unwrap(), render(&uri).unwrap());
        assert_eq!(render(&other).unwrap(), expected(&other));
    }

    #[test]
    fn data_beyond_qr_capacity_is_refused() {
        assert!(render("x").is_ok(), "control");
        assert_eq!(render(&"x".repeat(8_000)).unwrap_err().code(), "CLI_QR");
    }
}
