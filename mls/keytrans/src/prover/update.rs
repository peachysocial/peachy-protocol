// SPDX-License-Identifier: MIT
//! Updating a label (§9, §13.5), from the owner's side: being told about
//! the versions created after the greatest one it knows.
//!
//! This log takes new versions only through
//! [`Prover::append`](super::Prover::append), so an [`UpdateRequest`] with
//! values is refused; one without values gets an [`UpdateResponse`] for
//! each later entry that created versions of the label, oldest first, up to
//! a limit. They are processed in series (§13.5): the first carries the
//! full tree head for the request's `last`, the rest `same`.
//!
//! For new versions `G+1..=G'` created at entry `P`, the order a verifier
//! asks in, after the update view:
//!
//! 1. the distinguished walk (rule 3 of [`crate::prover`]) to `P-1` (when
//!    `P > 0`), then to `P` (§12.3.7);
//! 2. §9.1 step 2: along `frontier(P)` from its first entry that is not
//!    distinguished, a search ladder at every entry with target `G` (0 if
//!    there is no `G`), omitting inclusions shown to the left. Step 2.1's
//!    skip of entries on `frontier(p_G)`, `p_G` being where `G` was
//!    created, is not taken: an owner that learned `G` from owner
//!    initialization (§8.3) knows neither `p_G` nor what those entries
//!    hold, and the request does not say how `G` was learned, so both sides
//!    walk every entry. That only adds ladders the owner checks; a ladder
//!    left of `p_G` shows `G` absent, which is consistent, and none may
//!    show a version above `G`;
//! 3. if `P` is distinguished (step 3): one prefix proof at `P` for the new
//!    versions outside `base_binary_ladder(G')`, ascending, if there are
//!    any; else (step 4): a search ladder at `P` with target `G'`,
//!    continuing the same omissions, then one prefix proof at `P` for the
//!    new versions outside `base_binary_ladder(G')`, ascending, if any.
//!
//! `binary_ladder` (§9.1, ascending): `base_binary_ladder(G')`, plus every
//! new version when there is more than one, minus `base_binary_ladder(G)`
//! (minus just version 0 when there is no `G`), each with its commitment
//! when it is at most `G`.

use std::collections::BTreeSet;

use super::proof::{base_ladder, Builder, Label, Omission};
use super::storage::Storage;
use super::Prover;
use crate::error::{Error, Result};
use crate::implicit::frontier;
use crate::ladder::LadderKind;
use crate::wire::{LabelValue, UpdateInfo, UpdateRequest, UpdateResponse};

impl<S: Storage> Prover<S> {
    /// Answers an update request that carries no values (§13.5) with up to
    /// `max_responses` responses; none when the owner is up to date.
    pub fn update(
        &self,
        request: &UpdateRequest,
        max_responses: usize,
    ) -> Result<Vec<UpdateResponse>> {
        if !request.values.is_empty() {
            return Err(Error::InvalidArgument(
                "this log creates versions only through its own appends",
            ));
        }
        let n = self.served_size()?;
        let mut label = Label::load(self, &request.label, n)?;
        if let Some(g) = request.greatest_version {
            if label.greatest().is_none_or(|have| g > have) {
                return Err(Error::InvalidArgument("advertised version does not exist"));
            }
        }
        let mut known = request.greatest_version;
        let mut last = request.last;
        let mut out = Vec::new();
        while out.len() < max_responses {
            let next = match known {
                Some(g) => match g.checked_add(1) {
                    Some(v) => v,
                    None => break,
                },
                None => 0,
            };
            let Ok(first) = label.record(next) else {
                break;
            };
            let position = first.position;
            let mut newest = next;
            while label
                .record(newest + 1)
                .is_ok_and(|r| r.position == position)
            {
                newest += 1;
            }
            out.push(self.one_update(&mut label, n, last, known, position, next, newest)?);
            known = Some(newest);
            last = Some(n);
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn one_update(
        &self,
        label: &mut Label<'_, S>,
        n: u64,
        last: Option<u64>,
        known: Option<u32>,
        position: u64,
        first_new: u32,
        newest: u32,
    ) -> Result<UpdateResponse> {
        let (full_tree_head, extra) = self.full_tree_head(n, last)?;
        let mut b = Builder::new(self, n, last)?;
        b.update_view()?;

        if position > 0 {
            b.is_distinguished(position - 1)?;
        }
        let here_distinguished = b.is_distinguished(position)?;

        // Step 1 and step 2 (every entry; see the module docs on step 2.1).
        let previous = frontier(position);
        let mut from = previous.len();
        for (i, &y) in previous.iter().enumerate() {
            if !b.is_distinguished(y)? {
                from = i;
                break;
            }
        }
        let target = known.unwrap_or(0);
        let mut omit = Omission::left_inclusions();
        for &y in previous.iter().skip(from) {
            label.ladder(&mut b, y, LadderKind::Search { target }, Some(&mut omit))?;
        }

        // Step 3 or step 4.
        let ladder_versions = base_ladder(newest);
        if !here_distinguished {
            label.ladder(
                &mut b,
                position,
                LadderKind::Search { target: newest },
                Some(&mut omit),
            )?;
        }
        let outside: Vec<u32> = (first_new..=newest)
            .filter(|v| !ladder_versions.contains(v))
            .collect();
        if !outside.is_empty() {
            let keys = outside
                .iter()
                .map(|&v| label.output(v))
                .collect::<Result<Vec<_>>>()?;
            b.prefix(position, &keys)?;
        }

        // The VRF proofs.
        let mut versions: BTreeSet<u32> = ladder_versions.into_iter().collect();
        if newest > first_new {
            versions.extend(first_new..=newest);
        }
        let known_already: Vec<u32> = match known {
            Some(g) => base_ladder(g),
            None => vec![0],
        };
        let versions: Vec<u32> = versions
            .into_iter()
            .filter(|v| !known_already.contains(v))
            .collect();
        let binary_ladder = label.steps(&versions, |v| known.is_some_and(|g| v <= g))?;

        let mut values = Vec::new();
        let mut info = Vec::new();
        for v in first_new..=newest {
            let r = label.record(v)?;
            values.push(LabelValue {
                value: r.value.value.clone(),
            });
            info.push(UpdateInfo { opening: r.opening });
        }
        if values.len() > 0xff {
            return Err(Error::Encode(
                "too many versions in one entry for one response",
            ));
        }
        Ok(UpdateResponse {
            full_tree_head,
            position,
            values,
            info,
            binary_ladder,
            update: b.finish(&extra)?,
        })
    }
}
