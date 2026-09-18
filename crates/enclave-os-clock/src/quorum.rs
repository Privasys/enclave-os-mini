// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! NTS quorum: two servers picked at random must agree within 2 s. If they
//! do not, a third is asked and the majority (the closest agreeing pair)
//! wins. No agreeing pair, or not enough servers answering, is an error.
//!
//! The servers of one round are sampled together (the caller sends all the
//! NTP requests before reading any reply), so their timestamps are
//! comparable without the enclave having to measure elapsed time. A server
//! that fails is replaced by the next one in the random order.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::{abs_diff, ClockError};

/// Two samples closer than this agree.
pub const AGREE_MS: i64 = 2_000;

/// Most sampling rounds in one quorum.
pub const MAX_ROUNDS: usize = 4;

/// A quorum result: the agreed time and the servers that agreed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtsSample {
    /// Mean of the agreeing pair, Unix ms.
    pub time_ms: i64,
    /// Hostnames of the agreeing pair.
    pub servers: Vec<String>,
}

/// Run the quorum over `servers`.
///
/// `random` yields uniform `u32`s for the shuffle. `sample` is given a set
/// of hosts and returns one result per host, in order, all taken in the
/// same round.
pub fn run<R, S>(servers: &[&str], mut random: R, mut sample: S) -> Result<NtsSample, ClockError>
where
    R: FnMut() -> u32,
    S: FnMut(&[&str]) -> Vec<Result<i64, String>>,
{
    let mut order: Vec<&str> = servers.to_vec();
    // Fisher-Yates.
    for i in (1..order.len()).rev() {
        let j = (random() as usize) % (i + 1);
        order.swap(i, j);
    }
    let mut next = 0usize;
    let mut target = 2usize;
    let mut chosen: Vec<&str> = Vec::new();
    let mut last_errors: Vec<String> = Vec::new();

    for _ in 0..MAX_ROUNDS {
        while chosen.len() < target && next < order.len() {
            chosen.push(order[next]);
            next += 1;
        }
        if chosen.len() < 2 {
            break;
        }
        let results = sample(&chosen);
        let mut ok: Vec<(&str, i64)> = Vec::new();
        last_errors.clear();
        for (host, r) in chosen.iter().zip(results.into_iter()) {
            match r {
                Ok(t) => ok.push((host, t)),
                Err(e) => last_errors.push(format!("{host}: {e}")),
            }
        }
        if let Some(found) = closest_agreeing_pair(&ok) {
            return Ok(found);
        }
        if ok.len() >= 3 {
            return Err(ClockError::Nts("no two of three servers agree".to_string()));
        }
        if ok.len() == 2 {
            // Disagreement: bring in a third.
            target = 3;
        }
        chosen = ok.iter().map(|(h, _)| *h).collect();
    }
    if last_errors.is_empty() {
        Err(ClockError::Nts("not enough servers answered".to_string()))
    } else {
        Err(ClockError::Nts(format!("not enough servers answered ({})", last_errors.join("; "))))
    }
}

fn closest_agreeing_pair(ok: &[(&str, i64)]) -> Option<NtsSample> {
    let mut best: Option<(i64, usize, usize)> = None;
    for i in 0..ok.len() {
        for j in (i + 1)..ok.len() {
            let d = abs_diff(ok[i].1, ok[j].1);
            if d <= AGREE_MS && best.map_or(true, |(bd, _, _)| d < bd) {
                best = Some((d, i, j));
            }
        }
    }
    best.map(|(_, i, j)| NtsSample {
        time_ms: ((ok[i].1 as i128 + ok[j].1 as i128) / 2) as i64,
        servers: alloc::vec![ok[i].0.to_string(), ok[j].0.to_string()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec;

    const HOSTS: [&str; 5] = ["a", "b", "c", "d", "e"];

    fn fixed(times: &[(&'static str, Result<i64, &'static str>)]) -> BTreeMap<&'static str, Result<i64, String>> {
        times.iter().map(|(h, r)| (*h, r.map_err(|e| e.to_string()))).collect()
    }

    /// Identity order (random() = 0 swaps index i with 0 ... keep it simple
    /// by returning i each time).
    fn run_with(times: BTreeMap<&'static str, Result<i64, String>>) -> (Result<NtsSample, ClockError>, Vec<Vec<String>>) {
        let mut rounds = Vec::new();
        let mut i = HOSTS.len() as u32;
        let r = run(
            &HOSTS,
            || {
                // Pick j = i each time: no swaps, identity order.
                i -= 1;
                i
            },
            |hosts| {
                rounds.push(hosts.iter().map(|h| h.to_string()).collect());
                hosts.iter().map(|h| times.get(h).cloned().unwrap_or(Err("down".to_string()))).collect()
            },
        );
        (r, rounds)
    }

    #[test]
    fn two_agree() {
        let (r, rounds) = run_with(fixed(&[("a", Ok(1_000_000)), ("b", Ok(1_001_500))]));
        let s = r.unwrap();
        assert_eq!(s.time_ms, 1_000_750);
        assert_eq!(s.servers, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(rounds.len(), 1);
    }

    #[test]
    fn disagreement_brings_a_third_and_majority_wins() {
        let (r, rounds) = run_with(fixed(&[("a", Ok(1_000_000)), ("b", Ok(9_000_000)), ("c", Ok(1_000_400))]));
        let s = r.unwrap();
        assert_eq!(s.time_ms, 1_000_200);
        assert_eq!(s.servers, vec!["a".to_string(), "c".to_string()]);
        assert_eq!(rounds, vec![vec!["a", "b"], vec!["a", "b", "c"]]);
    }

    #[test]
    fn no_majority_is_an_error() {
        let (r, _) = run_with(fixed(&[("a", Ok(1_000_000)), ("b", Ok(5_000_000)), ("c", Ok(9_000_000))]));
        assert!(matches!(r, Err(ClockError::Nts(_))));
    }

    #[test]
    fn failed_server_is_replaced() {
        let (r, rounds) = run_with(fixed(&[("a", Ok(1_000_000)), ("b", Err("timeout")), ("c", Ok(1_000_100))]));
        assert_eq!(r.unwrap().servers, vec!["a".to_string(), "c".to_string()]);
        assert_eq!(rounds, vec![vec!["a", "b"], vec!["a", "c"]]);
    }

    #[test]
    fn all_down_is_an_error() {
        let (r, rounds) = run_with(BTreeMap::new());
        assert!(matches!(r, Err(ClockError::Nts(_))));
        assert!(rounds.len() <= MAX_ROUNDS);
    }

    #[test]
    fn shuffle_uses_randomness() {
        let mut seen = BTreeMap::new();
        for seed in 0..50u32 {
            let mut s = seed.wrapping_mul(2_654_435_761);
            let r = run(
                &HOSTS,
                || {
                    s ^= s << 13;
                    s ^= s >> 17;
                    s ^= s << 5;
                    s
                },
                |hosts| hosts.iter().map(|_| Ok(1_000)).collect(),
            )
            .unwrap();
            *seen.entry(r.servers[0].clone()).or_insert(0) += 1;
        }
        assert!(seen.len() > 2, "{seen:?}");
    }
}
