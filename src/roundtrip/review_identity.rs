//! Shared fresh review, entry, and event identifier authority.
//!
//! review reporting and approval approval both consume this index. It contains no
//! reporting diff and is never persisted as a restoration mapping.

use std::collections::{BTreeMap, BTreeSet};

use super::classify::{PreparedReviewAuthority, ReviewEntryAuthorityKind};
use super::review_ids::{baseline_entry_id, new_entry_id, ReviewEntryKind};
use super::{Error, Result};

#[derive(Clone, Copy)]
pub(crate) struct EventIdentity {
    pub(crate) event_index: usize,
    pub(crate) owner_index: usize,
    pub(crate) event_id: [u8; 16],
}

/// Transaction-local identity index. Deliberately no `Debug`: path-keyed maps
/// are confidential even though the public identifiers themselves are opaque.
pub(crate) struct ReviewIdentityIndex {
    review_id: [u8; 16],
    entry_ids: Vec<[u8; 16]>,
    before_paths: BTreeMap<Vec<u8>, usize>,
    after_paths: BTreeMap<Vec<u8>, usize>,
    events: Vec<EventIdentity>,
    event_by_id: BTreeMap<[u8; 16], usize>,
}

impl ReviewIdentityIndex {
    pub(crate) fn derive(authority: &PreparedReviewAuthority) -> Result<Self> {
        let schedule = authority.owner.key_schedule();
        let review_id = authority.events.review_id(
            &schedule,
            &authority.original_tree_commitment,
            &authority.report.edited_tree_commitment,
            authority.report.profile,
            authority.report.ruleset_id,
        )?;

        let mut entry_ids = Vec::new();
        entry_ids
            .try_reserve_exact(authority.entries.len())
            .map_err(|_| Error::BoundExceeded)?;
        let mut before_paths = BTreeMap::new();
        let mut after_paths = BTreeMap::new();
        let mut unique_ids = BTreeSet::new();
        for (index, entry) in authority.entries.iter().enumerate() {
            let kind = entry_kind(entry.kind);
            let entry_id = match entry.original_path.as_deref() {
                Some(original_path) => baseline_entry_id(
                    &schedule,
                    &authority.original_tree_commitment,
                    kind,
                    original_path,
                )?,
                None => new_entry_id(
                    &schedule,
                    &review_id,
                    kind,
                    entry
                        .safe_path_after
                        .as_deref()
                        .ok_or(Error::InvalidState)?,
                )?,
            };
            if !unique_ids.insert(entry_id)
                || entry
                    .safe_path_before
                    .as_ref()
                    .is_some_and(|path| before_paths.insert(path.clone(), index).is_some())
                || entry
                    .safe_path_after
                    .as_ref()
                    .is_some_and(|path| after_paths.insert(path.clone(), index).is_some())
            {
                return Err(Error::InvalidState);
            }
            entry_ids.push(entry_id);
        }

        let mut events = Vec::new();
        events
            .try_reserve_exact(authority.events.events().len())
            .map_err(|_| Error::BoundExceeded)?;
        let mut event_by_id = BTreeMap::new();
        for (event_index, event) in authority.events.events().iter().enumerate() {
            let owner_index = owning_entry_index(event, &before_paths, &after_paths)?;
            let owner_id = entry_ids.get(owner_index).ok_or(Error::InvalidState)?;
            let event_id = event.event_id(&schedule, &review_id, owner_id)?;
            let identity_index = events.len();
            if event_by_id.insert(event_id, identity_index).is_some() {
                return Err(Error::InvalidState);
            }
            events.push(EventIdentity {
                event_index,
                owner_index,
                event_id,
            });
        }

        Ok(Self {
            review_id,
            entry_ids,
            before_paths,
            after_paths,
            events,
            event_by_id,
        })
    }

    pub(crate) const fn review_id(&self) -> [u8; 16] {
        self.review_id
    }

    pub(crate) fn entry_id(&self, index: usize) -> Result<[u8; 16]> {
        self.entry_ids
            .get(index)
            .copied()
            .ok_or(Error::InvalidState)
    }

    pub(crate) fn event(&self, index: usize) -> Result<EventIdentity> {
        self.events.get(index).copied().ok_or(Error::InvalidState)
    }

    pub(crate) fn event_by_id(&self, event_id: &[u8; 16]) -> Option<EventIdentity> {
        self.event_by_id
            .get(event_id)
            .and_then(|index| self.events.get(*index))
            .copied()
    }

    pub(crate) fn before_entry_id(&self, path: Option<&[u8]>) -> Option<[u8; 16]> {
        self.path_entry_id(&self.before_paths, path)
    }

    pub(crate) fn after_entry_id(&self, path: Option<&[u8]>) -> Option<[u8; 16]> {
        self.path_entry_id(&self.after_paths, path)
    }

    fn path_entry_id(
        &self,
        paths: &BTreeMap<Vec<u8>, usize>,
        path: Option<&[u8]>,
    ) -> Option<[u8; 16]> {
        path.and_then(|value| paths.get(value))
            .and_then(|index| self.entry_ids.get(*index))
            .copied()
    }
}

fn owning_entry_index(
    event: &super::events::CanonicalEvent,
    before: &BTreeMap<Vec<u8>, usize>,
    after: &BTreeMap<Vec<u8>, usize>,
) -> Result<usize> {
    if let Some(index) = event.before_path.as_ref().and_then(|path| before.get(path)) {
        return Ok(*index);
    }
    event
        .after_path
        .as_ref()
        .and_then(|path| after.get(path))
        .copied()
        .ok_or(Error::InvalidState)
}

const fn entry_kind(kind: ReviewEntryAuthorityKind) -> ReviewEntryKind {
    match kind {
        ReviewEntryAuthorityKind::File => ReviewEntryKind::File,
        ReviewEntryAuthorityKind::Directory => ReviewEntryKind::Directory,
    }
}
