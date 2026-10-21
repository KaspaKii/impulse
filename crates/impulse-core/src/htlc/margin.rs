// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The margin rule of spec/V2.md section 10.5, checked when hashlock terms are created
//! (`HTLC_TIMEOUT_MARGIN`): the wall-clock time at which expiry_daa is reached, estimated early on
//! purpose from the current virtual DAA score and `DAA_RATE_MAX`, must be at least the
//! counterpart timeout T_C plus the margin Δ.
//!
//! `DAA_RATE_MAX` (D45): 1.5 times the highest rate over any 10-minute window of a recorded sample
//! of at least 7 days, and never below the network's target rate; on mainnet the sample is
//! required, at most 30 days old, taken at the network's blocks-per-second, and with a mean rate
//! of at least half the target (`HTLC_DAA_SAMPLE`); without one, on testnet only, 2 times the
//! target rate. A sample is read from a public node and could lie; a slow one would make the
//! estimate late, the unsafe direction, so the floor and the mean check fail safe. Δ (D32, D45) is the D18 finality depth at `DAA_RATE_MAX`, plus the time the buyer
//! needs to see the reveal at counterpart-final, plus a retry window, and never less than one
//! hour.
//!
//! The estimate is not a guarantee: a DAA rate above `DAA_RATE_MAX` makes expiry arrive earlier.
//! All arithmetic is exact integer arithmetic; nothing here reads a clock or a node.

use super::{HtlcError, HtlcTerms};
use crate::terms::{CreationContext, Network};
use kaspa_consensus_core::config::params::{Params, MAINNET_PARAMS, TESTNET_PARAMS};

/// The watcher's finality depth, D18 as changed by the owner on 2026-10-12: 600 DAA scores (about
/// 60 s at 10 BPS, mainnet and TN10). A policy, not a guarantee of the network.
pub const FINALITY_DEPTH_DAA: u64 = 600;

/// Δ is never less than one hour (spec/V2.md section 10.5).
pub const MIN_DELTA_SECS: u64 = 3_600;

/// The default retry window for the Kaspa claim, 30 minutes (spec/V2.md section 10.5).
pub const DEFAULT_RETRY_SECS: u64 = 1_800;

/// The window the highest DAA rate is taken over: 10 minutes (D45).
pub const RATE_WINDOW_SECS: u64 = 600;

/// A sample covers at least 7 days (D45).
pub const MIN_SAMPLE_SECS: u64 = 7 * 86_400;

/// A sample is refused when its last point is more than 30 days old (D45).
pub const MAX_SAMPLE_AGE_SECS: u64 = 30 * 86_400;

/// Consecutive points of a sample are at most 10 minutes apart (D51). The rate is taken over
/// fixed 10-minute windows with the DAA score read linearly between points, so a burst shorter
/// than one gap is spread over that gap: the finer the sampling, the closer the measured peak.
pub const MAX_SAMPLE_GAP_SECS: u64 = 600;

/// A sample whose mean DAA rate is below this fraction of the target rate (the network's
/// blocks-per-second, per second) is refused: it is not a sample of a live network at that rate.
/// Half is a conservative bound: a real network's mean over 7 days stays near its target.
pub const MIN_SAMPLE_MEAN_OF_TARGET: (u64, u64) = (1, 2);

/// A recorded DAA rate sample: the virtual DAA score of a public node against wall-clock time,
/// read only, oldest point first (spec/V2.md section 12, step 1). The file form is the sampling
/// script's; this is what the creation check reads from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaaRateSample {
    /// The blocks-per-second the node reported while the sample was taken.
    pub bps: u64,
    /// `(unix seconds, virtual DAA score)`, strictly increasing in time.
    pub points: Vec<(u64, u64)>,
}

/// The inputs of the margin rule besides the terms and the current DAA score.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarginContext<'a> {
    /// Wall-clock time of the check, unix seconds.
    pub now_unix: u64,
    /// The time the buyer needs to see the reveal at counterpart-final, as the counterpart source
    /// reports its time to finalized commitment.
    pub counterpart_final_secs: u64,
    /// The retry window for the Kaspa claim; [`DEFAULT_RETRY_SECS`] unless the caller sets one.
    pub retry_secs: u64,
    /// The recorded DAA rate sample; required on mainnet.
    pub sample: Option<&'a DaaRateSample>,
}

/// A DAA rate, `daa` per `secs` seconds, both above zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaaRate {
    pub daa: u128,
    pub secs: u128,
}

/// What the margin rule computed: `DAA_RATE_MAX`, the estimated arrival of expiry_daa, Δ, and the
/// time expiry must reach (T_C plus Δ).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarginEstimate {
    pub daa_rate_max: DaaRate,
    pub expiry_estimate_unix: u64,
    pub delta_secs: u64,
    pub required_unix: u64,
}

/// The pinned worst case, twice the network's blocks-per-second. It needs no sample, so it is the
/// rate for advice that must never block (the time left in `xchain claim`); creation and verify
/// still take `daa_rate_max`, which on mainnet demands a sample.
pub fn pinned_daa_rate(network: Network) -> DaaRate {
    DaaRate {
        daa: 2 * u128::from(params(network).bps()),
        secs: 1,
    }
}

/// `DAA_RATE_MAX` for `network` (D45): from the sample when one is given, refused on mainnet
/// without one, else 2 times the target rate. The sample checks, in order, first failure
/// returned (`HTLC_DAA_SAMPLE`): at least two points, strictly increasing in time with a DAA score
/// that never falls; no gap above 10 minutes; at least 7 days long; taken at the network's
/// blocks-per-second; its last point not after `now_unix` and at most 30 days before it; a mean
/// rate over the whole sample of at least half the target; some DAA progress in its busiest
/// window. The busiest window is the fixed 10-minute window, anywhere inside the sample, with the
/// highest DAA gain, the DAA score read linearly between points. The result is 1.5 times that
/// window's rate, raised to the target rate if below it.
pub fn daa_rate_max(
    network: Network,
    sample: Option<&DaaRateSample>,
    now_unix: u64,
) -> Result<DaaRate, HtlcError> {
    let bps = params(network).bps();
    let refuse = |reason| Err(HtlcError::DaaSample { reason });
    let Some(sample) = sample else {
        if network == Network::Mainnet {
            return refuse("no DAA rate sample is given; mainnet creation needs one");
        }
        return Ok(pinned_daa_rate(network));
    };
    let points = &sample.points;
    if points.len() < 2 {
        return refuse("the sample has fewer than two points");
    }
    for pair in points.windows(2) {
        let ((t0, d0), (t1, d1)) = (pair[0], pair[1]);
        if t1 <= t0 || d1 < d0 {
            return refuse("the sample's points are not in time order with a rising DAA score");
        }
        if t1 - t0 > MAX_SAMPLE_GAP_SECS {
            return refuse("the sample has a gap of more than 10 minutes");
        }
    }
    let (first, last) = (points[0].0, points[points.len() - 1].0);
    if last - first < MIN_SAMPLE_SECS {
        return refuse("the sample covers less than 7 days");
    }
    if sample.bps != bps {
        return refuse("the sample was taken at another blocks-per-second than the network's");
    }
    if last > now_unix {
        return refuse("the sample ends after the time of the check");
    }
    if now_unix - last > MAX_SAMPLE_AGE_SECS {
        return refuse("the sample is older than 30 days");
    }
    let gained = u128::from(points[points.len() - 1].1 - points[0].1);
    let (num, den) = MIN_SAMPLE_MEAN_OF_TARGET;
    if gained * u128::from(den) < u128::from(bps * num) * u128::from(last - first) {
        return refuse("the sample's mean DAA rate is below half the network's target rate");
    }
    // The busiest window: every fixed 10-minute window [t, t + 600] inside the sample, with the
    // DAA score read linearly between points. The DAA gained over the window is piecewise linear
    // in t, so its maximum is at a window that starts or ends on a point.
    let mut best: Option<DaaRate> = None;
    let starts = points.iter().map(|p| p.0);
    let ends = points.iter().map(|p| p.0.wrapping_sub(RATE_WINDOW_SECS));
    for t in starts.chain(ends) {
        if t < first || t > last - RATE_WINDOW_SECS {
            continue;
        }
        let ((n0, g0), (n1, g1)) = (daa_at(points, t), daa_at(points, t + RATE_WINDOW_SECS));
        let rate = DaaRate {
            daa: n1 * g0 - n0 * g1,
            secs: u128::from(RATE_WINDOW_SECS) * g0 * g1,
        };
        if best.is_none_or(|b| rate.daa * b.secs > b.daa * rate.secs) {
            best = Some(rate);
        }
    }
    let target = DaaRate {
        daa: u128::from(bps),
        secs: 1,
    };
    match best {
        Some(b) if b.daa > 0 => {
            let r = reduced(3 * b.daa, 2 * b.secs);
            Ok(if r.daa * target.secs < target.daa * r.secs {
                target
            } else {
                r
            })
        }
        _ => refuse("the sample shows no DAA progress"),
    }
}

/// The DAA score at `x`, read linearly between the points around it, as the fraction
/// `(numerator, denominator)`. `x` lies within the sample, whose gaps are at most 600 s.
fn daa_at(points: &[(u64, u64)], x: u64) -> (u128, u128) {
    let k = points.partition_point(|p| p.0 <= x) - 1;
    let (t0, d0) = points[k];
    if t0 == x {
        return (u128::from(d0), 1);
    }
    let (t1, d1) = points[k + 1];
    let gap = u128::from(t1 - t0);
    (
        u128::from(d0) * gap + u128::from(d1 - d0) * u128::from(x - t0),
        gap,
    )
}

/// `daa / secs` in lowest terms.
fn reduced(daa: u128, secs: u128) -> DaaRate {
    let (mut a, mut b) = (daa, secs);
    while b != 0 {
        (a, b) = (b, a % b);
    }
    DaaRate {
        daa: daa / a,
        secs: secs / a,
    }
}

/// The margin rule's figures for terms `t` at the current virtual DAA score `current_daa`, on the
/// terms' network.
pub fn estimate(
    t: &HtlcTerms,
    current_daa: u64,
    ctx: &MarginContext<'_>,
) -> Result<MarginEstimate, HtlcError> {
    let rate = daa_rate_max(t.network, ctx.sample, ctx.now_unix)?;
    // Early on purpose: the fastest rate, rounded down.
    let to_expiry = u128::from(t.expiry_daa.saturating_sub(current_daa)) * rate.secs / rate.daa;
    let expiry_estimate_unix = u128::from(ctx.now_unix)
        .saturating_add(to_expiry)
        .min(u128::from(u64::MAX)) as u64;
    // The finality depth at the fastest rate, rounded up.
    let finality = (u128::from(FINALITY_DEPTH_DAA) * rate.secs).div_ceil(rate.daa);
    let sum = finality
        .saturating_add(u128::from(ctx.counterpart_final_secs))
        .saturating_add(u128::from(ctx.retry_secs))
        .min(u128::from(u64::MAX)) as u64;
    let delta_secs = sum.max(MIN_DELTA_SECS);
    Ok(MarginEstimate {
        daa_rate_max: rate,
        expiry_estimate_unix,
        delta_secs,
        required_unix: t.counterpart.timeout.saturating_add(delta_secs),
    })
}

/// The creation check: the DAA rate, then the margin (`HTLC_TIMEOUT_MARGIN`).
pub(super) fn check(
    t: &HtlcTerms,
    creation: &CreationContext,
    ctx: &MarginContext<'_>,
) -> Result<(), HtlcError> {
    let e = estimate(t, creation.creation_daa, ctx)?;
    if e.expiry_estimate_unix < e.required_unix {
        return Err(HtlcError::TimeoutMargin {
            expiry_estimate_unix: e.expiry_estimate_unix,
            required_unix: e.required_unix,
        });
    }
    Ok(())
}

/// Consensus parameters of a network: mainnet, or testnet (TN10).
pub(super) fn params(network: Network) -> &'static Params {
    match network {
        Network::Mainnet => &MAINNET_PARAMS,
        Network::Testnet => &TESTNET_PARAMS,
    }
}
