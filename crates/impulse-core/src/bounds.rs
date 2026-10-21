// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Input bounds of the vault templates (spec/TEMPLATE.md, "Inputs outside the layout"). Each
//! template refuses, in every settle and refund, an input carrying a covenant the layout does
//! not name (known limitation L20, the part this closes), and the loop that checks the inputs is
//! bounded, so a spend has at most this many inputs. The builders refuse more
//! (`TX_TOO_MANY_INPUTS`).

/// Inputs of a settle or refund of a vault of template v1, v3 or the hashlock template, at most;
/// also of a template v2 refund.
pub const MAX_VAULT_SPEND_INPUTS: usize = 12;

/// Inputs after the N vault inputs of a template v2 settle, at most.
pub const MAX_V2_SETTLE_INPUTS_AFTER_VAULTS: usize = 18;

/// The most inputs a template v2 settle of `legs` legs may have.
pub fn max_v2_settle_inputs(legs: usize) -> usize {
    legs + MAX_V2_SETTLE_INPUTS_AFTER_VAULTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bounds_are_the_templates() {
        assert_eq!(MAX_VAULT_SPEND_INPUTS, 12);
        assert_eq!(max_v2_settle_inputs(10), 28);
    }
}
