//! Sensitive-candidate apply lifecycle.

use std::fmt;
use std::path::Path;

use super::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplyCheckpoint {
    BeforeApplyArmedCommit,
    AfterApplyArmedCommit,
    BeforeCandidateRootCreate,
    CandidateRootCreateUncertain,
    IncompleteMarkerCreate,
    IncompleteMarkerWrite,
    BeforeApplyIncompleteCommit,
    AfterApplyIncompleteCommit,
    FirstSensitiveWrite,
    CandidateDirectoryCreate,
    CandidateFileCreate,
    ReconstructedWrite,
    OriginalOnlyStreamingWrite,
    PerFileVerify,
    PostcheckRawOccurrenceGraph,
    PostcheckProjectedRetokenization,
    PostcheckOriginalOnly,
    PostcheckFullCandidate,
    PostcheckCompletePrecondition,
    PostcheckFinalOriginal,
    ApplyResultManifestCommit,
    CompleteMarkerCreate,
    CompleteMarkerWrite,
    CompleteMarkerCommit,
    BeforeAppliedCompleteCommit,
    AfterAppliedCompleteCommit,
    FinalVerification,
}

#[cfg(test)]
type TestHook = Box<dyn FnMut(ApplyCheckpoint) -> Result<()>>;

#[cfg(test)]
std::thread_local! {
    static TEST_HOOK: std::cell::RefCell<Option<TestHook>> =
        std::cell::RefCell::new(None);
}

pub(super) fn checkpoint(point: ApplyCheckpoint) -> Result<()> {
    #[cfg(test)]
    {
        TEST_HOOK.with(|slot| {
            let mut slot = slot
                .try_borrow_mut()
                .map_err(|_| super::Error::InvalidState)?;
            match slot.as_mut() {
                Some(hook) => hook(point),
                None => Ok(()),
            }
        })
    }
    #[cfg(not(test))]
    {
        let _ = point;
        Ok(())
    }
}

/// Unforgeable within sibling modules: released only by a fresh authenticated
/// read of the committed APPLY_INCOMPLETE head.
pub(super) struct ApplyIncompleteAuthorization {
    _seal: (),
}

/// Released only after the encrypted APPLY_RESULT has been reopened,
/// authenticated, decoded, and semantically revalidated.
pub(super) struct ApplyResultAuthorization {
    _seal: (),
}

#[cfg(test)]
pub(crate) struct TestHookGuard;

#[cfg(test)]
impl Drop for TestHookGuard {
    fn drop(&mut self) {
        TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
pub(crate) fn install_test_hook(
    hook: impl FnMut(ApplyCheckpoint) -> Result<()> + 'static,
) -> TestHookGuard {
    TEST_HOOK.with(|slot| {
        let prior = slot.borrow_mut().replace(Box::new(hook));
        assert!(prior.is_none(), "nested apply test hook");
    });
    TestHookGuard
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyPublicationState {
    AppliedComplete,
    CompletedReplay,
    SplitCommitRecovered,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyReport {
    pub state: ApplyPublicationState,
    pub apply_id: [u8; 16],
    pub candidate_tree_commitment: [u8; 32],
    pub candidate_entries: u32,
    pub preserved_original_only_files: u32,
    pub preserved_original_only_bytes: u64,
    pub semantic_safety_assessed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyFailureState {
    DefinitePreCandidate,
    DisarmedReadyToApply,
    ManualIncomplete,
    StateCommitUncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyFailure {
    error: Error,
    state: ApplyFailureState,
}

impl ApplyFailure {
    pub const fn error(self) -> Error {
        self.error
    }

    pub const fn state(self) -> ApplyFailureState {
        self.state
    }
}

impl fmt::Display for ApplyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "round-trip apply failed: {}", self.error)
    }
}

impl std::error::Error for ApplyFailure {}

pub type ApplyResult<T> = std::result::Result<T, ApplyFailure>;

#[cfg(not(windows))]
pub fn apply_session(
    _original: &Path,
    _ai_workspace: &Path,
    _private_state: &Path,
    _candidate: &Path,
) -> ApplyResult<ApplyReport> {
    Err(definite(Error::UnsupportedPlatform))
}

const fn definite(error: Error) -> ApplyFailure {
    ApplyFailure {
        error,
        state: ApplyFailureState::DefinitePreCandidate,
    }
}

#[cfg(windows)]
fn disarmed(error: Error) -> ApplyFailure {
    ApplyFailure {
        error,
        state: ApplyFailureState::DisarmedReadyToApply,
    }
}

#[cfg(windows)]
fn manual(error: Error) -> ApplyFailure {
    ApplyFailure {
        error,
        state: ApplyFailureState::ManualIncomplete,
    }
}

#[cfg(windows)]
fn uncertain(error: Error) -> ApplyFailure {
    ApplyFailure {
        error,
        state: ApplyFailureState::StateCommitUncertain,
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::roundtrip::baseline::StreamEncoder;
    use crate::roundtrip::candidate::{
        verify_existing_complete, CandidateRoot, EmptyCandidate, VerifiedCandidateFacts,
    };
    use crate::roundtrip::candidate_identity::{self, CandidatePhysicalCommitments};
    use crate::roundtrip::classify::CandidateSelection;
    use crate::roundtrip::crypto::{
        constant_time_equal, constant_time_equal_option_fixed, leftmost_16, KeyPurpose,
    };
    use crate::roundtrip::dpapi::{protect_next_apply_manifest, protect_next_live_capsule};
    use crate::roundtrip::manifest::{
        validate_changed_manifest_v1, ChangedManifestPhaseV1, ChangedManifestV1,
    };
    use crate::roundtrip::manifest_projection::project_apply_result;
    use crate::roundtrip::reconstruct::{
        prepare_apply_reconstruction_model, AuthorizedReconstructionModel,
    };
    use crate::roundtrip::schema::{
        ApplyAuthorityV1, ApplyState, CapsuleV1, ManifestPhase, ReviewAuthorityV1, SessionState,
    };
    use crate::roundtrip::token::{ENGINE_VERSION, POLICY_ID, TOKEN_SUITE_ID};

    pub(super) fn apply_session(
        original: &Path,
        ai_workspace: &Path,
        private_state: &Path,
        candidate_path: &Path,
    ) -> ApplyResult<ApplyReport> {
        let (mut model, candidate_parent, candidate_leaf, selection) =
            prepare_apply_reconstruction_model(
                original,
                ai_workspace,
                private_state,
                candidate_path,
            )
            .map_err(definite)?;
        let state = model.authority.owner.capsule().session_state;
        match state {
            SessionState::ReadyToApply => {
                let CandidateSelection::Absent(absent) = selection else {
                    return Err(definite(Error::CreateConflict));
                };
                apply_new(&mut model, candidate_parent, candidate_leaf, absent)
            }
            SessionState::ApplyArmed => Err(manual(Error::CandidateIncomplete)),
            SessionState::ApplyIncomplete => {
                let CandidateSelection::Existing(root) = selection else {
                    return Err(manual(Error::CandidateIncomplete));
                };
                recover_split_commit(&mut model, root)
            }
            SessionState::AppliedComplete => {
                let CandidateSelection::Existing(root) = selection else {
                    return Err(manual(Error::CandidateVerificationFailed));
                };
                replay_complete(&mut model, root)
            }
            SessionState::ActiveUnreviewed
            | SessionState::ReviewedRejected
            | SessionState::Reviewed
            | SessionState::ApprovedPartial => Err(definite(Error::InvalidState)),
        }
    }

    fn apply_new(
        model: &mut AuthorizedReconstructionModel,
        candidate_parent: crate::roundtrip::observe::QualifiedDirectory,
        candidate_leaf: std::ffi::OsString,
        absent: crate::roundtrip::observe::ValidatedLeaf,
    ) -> ApplyResult<ApplyReport> {
        let apply_id = derive_apply_id(model).map_err(definite)?;
        checkpoint(ApplyCheckpoint::BeforeApplyArmedCommit).map_err(definite)?;
        let armed = next_apply_capsule(
            model.authority.owner.capsule(),
            SessionState::ApplyArmed,
            ApplyAuthorityV1 {
                apply_id,
                state: ApplyState::Armed,
                review_id: current_review(model).map_err(definite)?.review_id,
                edited_tree_commitment: model.authority.report.edited_tree_commitment,
                candidate_tree_commitment: None,
                candidate_volume_identity: None,
                candidate_root_file_id: None,
                final_manifest_commitment: None,
                manual_reason_code: None,
                semantic_safety_assessed: false,
            },
        )
        .map_err(definite)?;
        armed.validate_capsule_state().map_err(definite)?;
        append_capsule(model, armed, None).map_err(uncertain)?;
        if let Err(error) = checkpoint(ApplyCheckpoint::AfterApplyArmedCommit) {
            return Err(uncertain(error));
        }

        candidate_parent.requery_policy().map_err(uncertain)?;
        if let Err(error) = checkpoint(ApplyCheckpoint::BeforeCandidateRootCreate) {
            return handle_definite_root_creation_failure(
                model,
                &candidate_parent,
                &candidate_leaf,
                error,
            );
        }
        let root = match candidate_parent.create_candidate_root(absent) {
            Ok(root) => root,
            Err(error) => {
                return handle_definite_root_creation_failure(
                    model,
                    &candidate_parent,
                    &candidate_leaf,
                    error,
                );
            }
        };
        checkpoint(ApplyCheckpoint::CandidateRootCreateUncertain).map_err(manual)?;
        let root =
            CandidateRoot::<EmptyCandidate>::from_created(root, candidate_parent, candidate_leaf)
                .map_err(manual)?;
        let root = {
            let schedule = model.authority.owner.key_schedule();
            root.create_incomplete_marker(
                &schedule,
                apply_id,
                &model.authority.owner.capsule().ruleset_id,
            )
            .map_err(manual)?
        };
        let physical = root
            .root()
            .observe_candidate_physical_source()
            .map_err(manual)?;
        let commitments = {
            let schedule = model.authority.owner.key_schedule();
            candidate_identity::derive(&schedule, apply_id, &physical).map_err(manual)?
        };

        checkpoint(ApplyCheckpoint::BeforeApplyIncompleteCommit).map_err(manual)?;
        let incomplete = next_apply_capsule(
            model.authority.owner.capsule(),
            SessionState::ApplyIncomplete,
            ApplyAuthorityV1 {
                apply_id,
                state: ApplyState::Incomplete,
                review_id: current_review(model).map_err(manual)?.review_id,
                edited_tree_commitment: model.authority.report.edited_tree_commitment,
                candidate_tree_commitment: None,
                candidate_volume_identity: Some(commitments.volume),
                candidate_root_file_id: Some(commitments.root),
                final_manifest_commitment: None,
                manual_reason_code: None,
                semantic_safety_assessed: false,
            },
        )
        .map_err(manual)?;
        incomplete.validate_capsule_state().map_err(manual)?;
        append_capsule(model, incomplete, None).map_err(uncertain)?;
        checkpoint(ApplyCheckpoint::AfterApplyIncompleteCommit).map_err(manual)?;
        let population_authorization = authenticate_apply_incomplete_head(model).map_err(manual)?;

        // This is the sole transition which enables sensitive child writes.
        let populated = root
            .authorize_population(population_authorization)
            .materialize(model)
            .map_err(manual)?;
        let (verified, facts) = populated.verify_six(model).map_err(manual)?;

        let (apply_manifest, manifest_commitment, evidence, manifest_authorization) =
            persist_apply_result(model, &facts).map_err(manual)?;
        let complete = {
            let schedule = model.authority.owner.key_schedule();
            verified
                .create_complete_marker(
                    &schedule,
                    apply_id,
                    &model.authority.owner.capsule().ruleset_id,
                    facts.candidate_commitment,
                    manifest_authorization,
                )
                .map_err(manual)?
        };

        checkpoint(ApplyCheckpoint::BeforeAppliedCompleteCommit).map_err(manual)?;
        complete.verify_selected_root().map_err(manual)?;
        let precommit_facts =
            verify_existing_complete(complete.root(), model, apply_id, facts.candidate_commitment)
                .map_err(manual)?;
        if !same_facts(&precommit_facts, &facts) {
            return Err(manual(Error::CandidateVerificationFailed));
        }
        let mut next = next_apply_capsule(
            model.authority.owner.capsule(),
            SessionState::AppliedComplete,
            ApplyAuthorityV1 {
                apply_id,
                state: ApplyState::Complete,
                review_id: current_review(model).map_err(manual)?.review_id,
                edited_tree_commitment: model.authority.report.edited_tree_commitment,
                candidate_tree_commitment: Some(facts.candidate_commitment),
                candidate_volume_identity: Some(commitments.volume),
                candidate_root_file_id: Some(commitments.root),
                final_manifest_commitment: Some(manifest_commitment),
                manual_reason_code: None,
                semantic_safety_assessed: false,
            },
        )
        .map_err(manual)?;
        install_apply_review(&mut next, manifest_commitment).map_err(manual)?;
        append_capsule(model, next, Some(&evidence)).map_err(uncertain)?;
        let post_commit_fault = checkpoint(ApplyCheckpoint::AfterAppliedCompleteCommit).err();
        let (final_facts, final_manifest) = final_verify(
            model,
            complete.root(),
            commitments,
            facts.candidate_commitment,
        )
        .map_err(uncertain)?;
        if final_manifest != apply_manifest || !same_facts(&final_facts, &facts) {
            return Err(uncertain(Error::StateCommitUncertain));
        }
        complete.verify_selected_root().map_err(uncertain)?;
        if let Some(error) = post_commit_fault {
            // The authenticated final read resolves a post-commit injected
            // uncertainty to complete rather than rewriting candidate state.
            let _ = error;
        }
        Ok(report(
            ApplyPublicationState::AppliedComplete,
            apply_id,
            &final_facts,
        ))
    }

    fn replay_complete(
        model: &mut AuthorizedReconstructionModel,
        root: crate::roundtrip::observe::QualifiedDirectory,
    ) -> ApplyResult<ApplyReport> {
        let apply = model
            .authority
            .owner
            .capsule()
            .apply_authority
            .clone()
            .ok_or_else(|| manual(Error::InvalidState))?;
        let expected_tree = apply
            .candidate_tree_commitment
            .ok_or_else(|| manual(Error::InvalidState))?;
        if !constant_time_equal(&expected_tree, &model.expected_candidate_tree_commitment()) {
            return Err(manual(Error::CandidateVerificationFailed));
        }
        let commitments = derive_and_verify_physical(&root, model, &apply).map_err(manual)?;
        let (facts, _) = final_verify(model, &root, commitments, expected_tree).map_err(manual)?;
        Ok(report(
            ApplyPublicationState::CompletedReplay,
            apply.apply_id,
            &facts,
        ))
    }

    fn recover_split_commit(
        model: &mut AuthorizedReconstructionModel,
        root: crate::roundtrip::observe::QualifiedDirectory,
    ) -> ApplyResult<ApplyReport> {
        let apply = model
            .authority
            .owner
            .capsule()
            .apply_authority
            .clone()
            .ok_or_else(|| manual(Error::InvalidState))?;
        let commitments = derive_and_verify_physical(&root, model, &apply).map_err(manual)?;
        let expected_tree = model.expected_candidate_tree_commitment();
        let facts = verify_existing_complete(&root, model, apply.apply_id, expected_tree)
            .map_err(manual)?;
        let (manifest, manifest_commitment, evidence) =
            authenticate_split_apply_result(model, &facts).map_err(manual)?;
        checkpoint(ApplyCheckpoint::BeforeAppliedCompleteCommit).map_err(manual)?;
        let precommit_facts = verify_existing_complete(&root, model, apply.apply_id, expected_tree)
            .map_err(manual)?;
        if !same_facts(&precommit_facts, &facts) {
            return Err(manual(Error::CandidateVerificationFailed));
        }
        let mut next = next_apply_capsule(
            model.authority.owner.capsule(),
            SessionState::AppliedComplete,
            ApplyAuthorityV1 {
                apply_id: apply.apply_id,
                state: ApplyState::Complete,
                review_id: apply.review_id,
                edited_tree_commitment: apply.edited_tree_commitment,
                candidate_tree_commitment: Some(expected_tree),
                candidate_volume_identity: Some(commitments.volume),
                candidate_root_file_id: Some(commitments.root),
                final_manifest_commitment: Some(manifest_commitment),
                manual_reason_code: None,
                semantic_safety_assessed: false,
            },
        )
        .map_err(manual)?;
        install_apply_review(&mut next, manifest_commitment).map_err(manual)?;
        append_capsule(model, next, Some(&evidence)).map_err(uncertain)?;
        checkpoint(ApplyCheckpoint::AfterAppliedCompleteCommit).ok();
        let (final_facts, final_manifest) =
            final_verify(model, &root, commitments, expected_tree).map_err(uncertain)?;
        if final_manifest != manifest || !same_facts(&final_facts, &facts) {
            return Err(uncertain(Error::StateCommitUncertain));
        }
        Ok(report(
            ApplyPublicationState::SplitCommitRecovered,
            apply.apply_id,
            &final_facts,
        ))
    }

    fn derive_apply_id(model: &AuthorizedReconstructionModel) -> Result<[u8; 16]> {
        let capsule = model.authority.owner.capsule();
        let review = capsule.current_review.as_ref().ok_or(Error::InvalidState)?;
        let schedule = model.authority.owner.key_schedule();
        let mut value =
            StreamEncoder::new(&schedule, KeyPurpose::EventId, b"safeclone/rt1/apply-id")?;
        value.bytes(schedule.session_id().as_bytes())?;
        value.bytes(&review.review_id)?;
        value.bytes(&review.edited_tree_commitment)?;
        value.bytes(&capsule.approval_set.approval_set_tag)?;
        value.u8(capsule.review_profile as u8);
        value.bytes(ENGINE_VERSION.as_bytes())?;
        value.bytes(POLICY_ID.as_bytes())?;
        value.bytes(capsule.ruleset_id.as_bytes())?;
        value.u16(TOKEN_SUITE_ID);
        Ok(leftmost_16(&value.finish()))
    }

    fn next_apply_capsule(
        prior: &CapsuleV1,
        state: SessionState,
        apply: ApplyAuthorityV1,
    ) -> Result<CapsuleV1> {
        let mut next = prior.clone();
        next.generation = prior.generation.checked_add(1).ok_or(Error::InvalidState)?;
        next.session_state = state;
        next.apply_authority = Some(apply);
        next.orphan_count_at_commit = 0;
        next.semantic_safety_assessed = false;
        Ok(next)
    }

    fn disarm_ready(model: &mut AuthorizedReconstructionModel) -> Result<()> {
        let prior = model.authority.owner.capsule();
        if prior.session_state != SessionState::ApplyArmed {
            return Err(Error::InvalidState);
        }
        let mut next = prior.clone();
        next.generation = prior.generation.checked_add(1).ok_or(Error::InvalidState)?;
        next.session_state = SessionState::ReadyToApply;
        next.apply_authority = None;
        next.validate_capsule_state()?;
        append_capsule(model, next, None)
    }

    fn handle_definite_root_creation_failure(
        model: &mut AuthorizedReconstructionModel,
        parent: &crate::roundtrip::observe::QualifiedDirectory,
        leaf: &std::ffi::OsStr,
        error: Error,
    ) -> ApplyResult<ApplyReport> {
        match parent
            .classify_directory_leaf(leaf, crate::roundtrip::observe::NamespaceScope::Workspace)
        {
            Ok(Err(_)) => {
                disarm_ready(model).map_err(uncertain)?;
                Err(disarmed(error))
            }
            Ok(Ok(_)) | Err(_) => Err(uncertain(Error::CandidateIncomplete)),
        }
    }

    fn append_capsule(
        model: &mut AuthorizedReconstructionModel,
        next: CapsuleV1,
        manifest: Option<&crate::roundtrip::capsule::ReviewManifestEvidence>,
    ) -> Result<()> {
        let protected = protect_next_live_capsule(&model.authority.owner, &next)?;
        match manifest {
            Some(evidence) => model.authority.store.append_apply_capsule_generation(
                &mut model.authority.lock,
                &protected,
                evidence,
            )?,
            None => model
                .authority
                .store
                .append_capsule_generation(&mut model.authority.lock, &protected)?,
        };
        let observation = model
            .authority
            .store
            .read_while_locked(&mut model.authority.lock)?;
        if observation.classification
            != crate::roundtrip::capsule::StoreClassification::AuthoritativeLive
            || observation.orphan_count != 0
        {
            return Err(Error::StateCommitUncertain);
        }
        let owner = observation
            .into_live_head()
            .ok_or(Error::StateCommitUncertain)?;
        if owner.capsule() != &next {
            return Err(Error::StateCommitUncertain);
        }
        model.authority.owner = owner;
        Ok(())
    }

    fn authenticate_current_head(
        model: &mut AuthorizedReconstructionModel,
        expected: SessionState,
    ) -> Result<()> {
        let state = model
            .authority
            .store
            .read_while_locked(&mut model.authority.lock)?;
        let live = state.live_head().ok_or(Error::InvalidState)?;
        if state.classification != crate::roundtrip::capsule::StoreClassification::AuthoritativeLive
            || state.orphan_count != 0
            || live.capsule() != model.authority.owner.capsule()
            || !constant_time_equal(live.tag(), model.authority.owner.tag())
            || live.capsule().session_state != expected
        {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    fn authenticate_apply_incomplete_head(
        model: &mut AuthorizedReconstructionModel,
    ) -> Result<ApplyIncompleteAuthorization> {
        authenticate_current_head(model, SessionState::ApplyIncomplete)?;
        Ok(ApplyIncompleteAuthorization { _seal: () })
    }

    fn persist_apply_result(
        model: &mut AuthorizedReconstructionModel,
        facts: &VerifiedCandidateFacts,
    ) -> Result<(
        ChangedManifestV1,
        [u8; 32],
        crate::roundtrip::capsule::ReviewManifestEvidence,
        ApplyResultAuthorization,
    )> {
        checkpoint(ApplyCheckpoint::ApplyResultManifestCommit)?;
        let review = read_bound_review_manifest(model)?;
        let owning_generation = model
            .authority
            .owner
            .capsule()
            .generation
            .checked_add(1)
            .ok_or(Error::InvalidState)?;
        let apply = project_apply_result(
            &review,
            owning_generation,
            facts.preserved_original_only_files,
            facts.preserved_original_only_bytes,
        )?;
        let payload = apply.encode_canonical()?;
        let protected = protect_next_apply_manifest(&model.authority.owner, &payload)?;
        let commitment = *protected.commitment();
        let review_id = current_review(model)?.review_id;
        let evidence = model.authority.store.persist_next_apply_manifest(
            &mut model.authority.lock,
            &model.authority.owner,
            review_id,
            commitment,
            protected.as_bytes(),
        )?;
        let (generation, authenticated) = model.authority.store.read_review_manifest(
            &mut model.authority.lock,
            &model.authority.owner,
            review_id,
            ManifestPhase::ApplyResult,
        )?;
        if generation != owning_generation
            || !constant_time_equal(authenticated.commitment(), &commitment)
            || authenticated.as_bytes() != payload
            || ChangedManifestV1::decode_canonical(authenticated.as_bytes())? != apply
        {
            return Err(Error::PrivateOrphansPresent);
        }
        Ok((
            apply,
            commitment,
            evidence,
            ApplyResultAuthorization { _seal: () },
        ))
    }

    fn read_bound_review_manifest(
        model: &mut AuthorizedReconstructionModel,
    ) -> Result<ChangedManifestV1> {
        let current = current_review(model)?.clone();
        if current.manifest_phase != ManifestPhase::Review {
            return Err(Error::InvalidState);
        }
        let (generation, authenticated) = model.authority.store.read_review_manifest(
            &mut model.authority.lock,
            &model.authority.owner,
            current.review_id,
            ManifestPhase::Review,
        )?;
        if generation == 0
            || generation > model.authority.owner.capsule().generation
            || !constant_time_equal(authenticated.commitment(), &current.manifest_commitment)
        {
            return Err(Error::CorruptState);
        }
        let manifest = ChangedManifestV1::decode_canonical(authenticated.as_bytes())?;
        validate_review_binding(model, &manifest, current.review_id)?;
        Ok(manifest)
    }

    fn validate_review_binding(
        model: &AuthorizedReconstructionModel,
        manifest: &ChangedManifestV1,
        review_id: [u8; 16],
    ) -> Result<()> {
        validate_changed_manifest_v1(manifest)?;
        require_review_manifest_commitments(
            &manifest.edited_tree_commitment,
            &manifest.event_set_commitment,
            &model.authority.report.edited_tree_commitment,
            &model.authority.event_set_commitment,
        )?;
        if manifest.manifest_phase != ChangedManifestPhaseV1::Review
            || manifest.session_id != *model.authority.owner.capsule().session_id.as_bytes()
            || manifest.review_id != review_id
            || manifest.review_profile != model.inputs.profile
            || manifest.ruleset_id != model.authority.owner.capsule().ruleset_id
            || manifest.summary.automatic_events != model.authority.events.automatic()
            || manifest.summary.approval_eligible_events
                != model.authority.events.approval_required()
            || manifest.summary.unconditional_rejects != 0
        {
            return Err(Error::CorruptState);
        }
        Ok(())
    }

    pub(super) fn require_review_manifest_commitments(
        manifest_edited: &[u8; 32],
        manifest_events: &[u8; 32],
        fresh_edited: &[u8; 32],
        fresh_events: &[u8; 32],
    ) -> Result<()> {
        if !constant_time_equal(manifest_edited, fresh_edited)
            || !constant_time_equal(manifest_events, fresh_events)
        {
            return Err(Error::CorruptState);
        }
        Ok(())
    }

    fn install_apply_review(next: &mut CapsuleV1, commitment: [u8; 32]) -> Result<()> {
        let prior = next.current_review.as_ref().ok_or(Error::InvalidState)?;
        next.current_review = Some(ReviewAuthorityV1 {
            review_id: prior.review_id,
            edited_tree_commitment: prior.edited_tree_commitment,
            event_set_commitment: prior.event_set_commitment,
            manifest_commitment: commitment,
            manifest_phase: ManifestPhase::ApplyResult,
            automatic_event_count: prior.automatic_event_count,
            approval_eligible_count: prior.approval_eligible_count,
            unconditional_reject_count: prior.unconditional_reject_count,
            reviewed_epoch_seconds: prior.reviewed_epoch_seconds,
        });
        next.validate_capsule_state()
    }

    fn derive_and_verify_physical(
        root: &crate::roundtrip::observe::QualifiedDirectory,
        model: &AuthorizedReconstructionModel,
        apply: &ApplyAuthorityV1,
    ) -> Result<CandidatePhysicalCommitments> {
        let source = root.observe_candidate_physical_source()?;
        let schedule = model.authority.owner.key_schedule();
        let actual = candidate_identity::derive(&schedule, apply.apply_id, &source)?;
        candidate_identity::verify(
            actual,
            apply
                .candidate_volume_identity
                .as_ref()
                .ok_or(Error::InvalidState)?,
            apply
                .candidate_root_file_id
                .as_ref()
                .ok_or(Error::InvalidState)?,
        )?;
        Ok(actual)
    }

    fn authenticate_apply_result(
        model: &mut AuthorizedReconstructionModel,
        facts: &VerifiedCandidateFacts,
    ) -> Result<ChangedManifestV1> {
        let current = current_review(model)?.clone();
        if current.manifest_phase != ManifestPhase::ApplyResult {
            return Err(Error::InvalidState);
        }
        let review = read_historical_review_manifest(model, current.review_id)?;
        let (generation, authenticated) = model.authority.store.read_review_manifest(
            &mut model.authority.lock,
            &model.authority.owner,
            current.review_id,
            ManifestPhase::ApplyResult,
        )?;
        if !constant_time_equal(authenticated.commitment(), &current.manifest_commitment) {
            return Err(Error::AuthenticationFailed);
        }
        let actual = ChangedManifestV1::decode_canonical(authenticated.as_bytes())?;
        let expected = project_apply_result(
            &review,
            generation,
            facts.preserved_original_only_files,
            facts.preserved_original_only_bytes,
        )?;
        if actual != expected {
            return Err(Error::CorruptState);
        }
        Ok(actual)
    }

    fn authenticate_split_apply_result(
        model: &mut AuthorizedReconstructionModel,
        facts: &VerifiedCandidateFacts,
    ) -> Result<(
        ChangedManifestV1,
        [u8; 32],
        crate::roundtrip::capsule::ReviewManifestEvidence,
    )> {
        let review_id = current_review(model)?.review_id;
        let review = read_bound_review_manifest(model)?;
        let (generation, authenticated) = model.authority.store.read_review_manifest(
            &mut model.authority.lock,
            &model.authority.owner,
            review_id,
            ManifestPhase::ApplyResult,
        )?;
        let commitment = *authenticated.commitment();
        let actual = ChangedManifestV1::decode_canonical(authenticated.as_bytes())?;
        let expected = project_apply_result(
            &review,
            generation,
            facts.preserved_original_only_files,
            facts.preserved_original_only_bytes,
        )?;
        if actual != expected {
            return Err(Error::CorruptState);
        }
        drop(authenticated);
        let evidence = model.authority.store.recover_next_apply_manifest_evidence(
            &mut model.authority.lock,
            &model.authority.owner,
            review_id,
            commitment,
        )?;
        Ok((actual, commitment, evidence))
    }

    fn read_historical_review_manifest(
        model: &mut AuthorizedReconstructionModel,
        review_id: [u8; 16],
    ) -> Result<ChangedManifestV1> {
        let (_, authenticated) = model.authority.store.read_review_manifest(
            &mut model.authority.lock,
            &model.authority.owner,
            review_id,
            ManifestPhase::Review,
        )?;
        let manifest = ChangedManifestV1::decode_canonical(authenticated.as_bytes())?;
        validate_review_binding(model, &manifest, review_id)?;
        Ok(manifest)
    }

    fn final_verify(
        model: &mut AuthorizedReconstructionModel,
        root: &crate::roundtrip::observe::QualifiedDirectory,
        commitments: CandidatePhysicalCommitments,
        candidate_commitment: [u8; 32],
    ) -> Result<(VerifiedCandidateFacts, ChangedManifestV1)> {
        checkpoint(ApplyCheckpoint::FinalVerification)?;
        authenticate_current_head(model, SessionState::AppliedComplete)?;
        let apply = model
            .authority
            .owner
            .capsule()
            .apply_authority
            .clone()
            .ok_or(Error::InvalidState)?;
        let fresh_commitments = derive_and_verify_physical(root, model, &apply)?;
        candidate_identity::verify(fresh_commitments, &commitments.volume, &commitments.root)?;
        candidate_identity::verify(
            commitments,
            apply
                .candidate_volume_identity
                .as_ref()
                .ok_or(Error::InvalidState)?,
            apply
                .candidate_root_file_id
                .as_ref()
                .ok_or(Error::InvalidState)?,
        )?;
        require_completed_apply_commitments(
            apply.candidate_tree_commitment.as_ref(),
            Some(&candidate_commitment),
            apply.final_manifest_commitment.as_ref(),
            model
                .authority
                .owner
                .capsule()
                .current_review
                .as_ref()
                .map(|review| &review.manifest_commitment),
        )?;
        let facts = verify_existing_complete(root, model, apply.apply_id, candidate_commitment)?;
        let manifest = authenticate_apply_result(model, &facts)?;
        if manifest.semantic_safety_assessed {
            return Err(Error::InvalidState);
        }
        model.authority.verify_selected_roots()?;
        root.requery_policy()?;
        Ok((facts, manifest))
    }

    pub(super) fn require_completed_apply_commitments(
        stored_candidate: Option<&[u8; 32]>,
        fresh_candidate: Option<&[u8; 32]>,
        stored_manifest: Option<&[u8; 32]>,
        current_manifest: Option<&[u8; 32]>,
    ) -> Result<()> {
        if !constant_time_equal_option_fixed(stored_candidate, fresh_candidate)
            || !constant_time_equal_option_fixed(stored_manifest, current_manifest)
        {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    fn current_review(model: &AuthorizedReconstructionModel) -> Result<&ReviewAuthorityV1> {
        model
            .authority
            .owner
            .capsule()
            .current_review
            .as_ref()
            .ok_or(Error::InvalidState)
    }

    fn report(
        state: ApplyPublicationState,
        apply_id: [u8; 16],
        facts: &VerifiedCandidateFacts,
    ) -> ApplyReport {
        ApplyReport {
            state,
            apply_id,
            candidate_tree_commitment: facts.candidate_commitment,
            candidate_entries: facts.candidate_entries,
            preserved_original_only_files: facts.preserved_original_only_files,
            preserved_original_only_bytes: facts.preserved_original_only_bytes,
            semantic_safety_assessed: false,
        }
    }

    fn same_facts(left: &VerifiedCandidateFacts, right: &VerifiedCandidateFacts) -> bool {
        constant_time_equal(&left.candidate_commitment, &right.candidate_commitment)
            && left.candidate_entries == right.candidate_entries
            && left.preserved_original_only_files == right.preserved_original_only_files
            && left.preserved_original_only_bytes == right.preserved_original_only_bytes
    }
}

#[cfg(windows)]
pub fn apply_session(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
    candidate: &Path,
) -> ApplyResult<ApplyReport> {
    windows::apply_session(original, ai_workspace, private_state, candidate)
}

#[cfg(all(test, windows))]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::roundtrip::approve::approve_review_event;
    use crate::roundtrip::create::create_session;
    use crate::roundtrip::review::{review_session, ReviewOutcome};
    use crate::roundtrip::schema::SessionState;
    use crate::roundtrip::status::{status_session, StatusState};
    use crate::roundtrip::token::{decode_base32_128, ReviewProfile, TOKEN_PREFIX, TOKEN_SUFFIX};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    static APPLY_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn fresh_apply_authority_mismatches_keep_existing_fail_closed_errors() {
        let edited = [0x31; 32];
        let events = [0x32; 32];
        assert!(
            windows::require_review_manifest_commitments(&edited, &events, &edited, &events,)
                .is_ok()
        );
        let mut edited_mismatch = edited;
        edited_mismatch[7] ^= 1;
        assert_eq!(
            windows::require_review_manifest_commitments(
                &edited,
                &events,
                &edited_mismatch,
                &events,
            ),
            Err(Error::CorruptState)
        );
        let mut event_mismatch = events;
        event_mismatch[19] ^= 1;
        assert_eq!(
            windows::require_review_manifest_commitments(
                &edited,
                &events,
                &edited,
                &event_mismatch,
            ),
            Err(Error::CorruptState)
        );

        let candidate = [0x41; 32];
        let manifest = [0x42; 32];
        assert!(windows::require_completed_apply_commitments(
            Some(&candidate),
            Some(&candidate),
            Some(&manifest),
            Some(&manifest),
        )
        .is_ok());
        let mut candidate_mismatch = candidate;
        candidate_mismatch[3] ^= 1;
        assert_eq!(
            windows::require_completed_apply_commitments(
                Some(&candidate),
                Some(&candidate_mismatch),
                Some(&manifest),
                Some(&manifest),
            ),
            Err(Error::InvalidState)
        );
        assert_eq!(
            windows::require_completed_apply_commitments(
                Some(&candidate),
                Some(&candidate),
                Some(&manifest),
                None,
            ),
            Err(Error::InvalidState)
        );
    }

    struct Fixture {
        root: PathBuf,
        original: PathBuf,
        ai: PathBuf,
        state: PathBuf,
        candidate: PathBuf,
    }

    impl Fixture {
        fn new(profile: ReviewProfile, setup: impl FnOnce(&Path)) -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("safeclone-apply-{}-{serial}", std::process::id()));
            let original = root.join("OriginalWorkspaceLongName");
            let ai = root.join("AiWorkspaceLongName");
            let state = root.join("PrivateSessionLongName");
            let candidate = root.join("SensitiveCandidateWorkspaceLongName");
            fs::create_dir_all(&original).expect("create apply Original fixture");
            setup(&original);
            create_session(&original, &ai, &state, profile).expect("create apply session");
            Self {
                root,
                original,
                ai,
                state,
                candidate,
            }
        }

        fn review_and_approve_all(&self) {
            let reviewed = review_session(&self.original, &self.ai, &self.state)
                .expect("review apply fixture");
            self.approve_all(&reviewed);
            let ready = review_session(&self.original, &self.ai, &self.state)
                .expect("authenticate ready apply session");
            assert_eq!(ready.report().session_state, SessionState::ReadyToApply);
        }

        fn approve_all(&self, reviewed: &ReviewOutcome) {
            let review_id = decode_base32_128(&reviewed.report().review_id).expect("review id");
            for event in &reviewed.report().approval_events {
                if !event.approved {
                    approve_review_event(
                        &self.original,
                        &self.ai,
                        &self.state,
                        review_id,
                        decode_base32_128(&event.event_id).expect("event id"),
                        event.required_reason,
                    )
                    .expect("approve apply event");
                }
            }
        }

        fn private_artifact_count(&self) -> usize {
            fs::read_dir(&self.state)
                .expect("read private state")
                .count()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn token_file(value: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for index in 0..12 {
            bytes.extend_from_slice(format!("before-{index:02}\n").as_bytes());
        }
        bytes.extend_from_slice(format!("contact={value}\n").as_bytes());
        for index in 0..12 {
            bytes.extend_from_slice(format!("after-{index:02}\n").as_bytes());
        }
        bytes
    }

    fn remove_all_canonical_tokens(path: &Path) -> usize {
        let mut bytes = fs::read(path).expect("read AI token file");
        let mut removed = 0usize;
        while let Some(start) = bytes
            .windows(TOKEN_PREFIX.len())
            .position(|window| window == TOKEN_PREFIX.as_bytes())
        {
            let suffix_start = start + TOKEN_PREFIX.len();
            let suffix = bytes[suffix_start..]
                .windows(TOKEN_SUFFIX.len())
                .position(|window| window == TOKEN_SUFFIX.as_bytes())
                .expect("canonical token suffix");
            let end = suffix_start + suffix + TOKEN_SUFFIX.len();
            bytes.drain(start..end);
            removed += 1;
        }
        fs::write(path, bytes).expect("write exact token deletion");
        removed
    }

    fn populated_fixture(profile: ReviewProfile) -> Fixture {
        Fixture::new(profile, |original| {
            fs::create_dir(original.join("nested")).expect("create nested Original");
            fs::write(
                original.join("nested").join("main.txt"),
                token_file("rt7.fixture@example.invalid"),
            )
            .expect("write token-bearing Original");
            fs::write(
                original.join("nested").join("opaque.bin"),
                b"opaque\0original-only",
            )
            .expect("write original-only fixture");
        })
    }

    fn approved_exact_deletion_fixture() -> Fixture {
        let fixture = Fixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(
                original.join("main.txt"),
                token_file("rt9.replay@example.invalid"),
            )
            .expect("write exact-deletion replay fixture");
        });
        assert_eq!(remove_all_canonical_tokens(&fixture.ai.join("main.txt")), 1);
        fixture.review_and_approve_all();
        fixture
    }

    fn reject_candidate_write_checkpoints(point: ApplyCheckpoint) -> Result<()> {
        if matches!(
            point,
            ApplyCheckpoint::FirstSensitiveWrite
                | ApplyCheckpoint::CandidateDirectoryCreate
                | ApplyCheckpoint::CandidateFileCreate
                | ApplyCheckpoint::ReconstructedWrite
                | ApplyCheckpoint::OriginalOnlyStreamingWrite
                | ApplyCheckpoint::CompleteMarkerCreate
                | ApplyCheckpoint::CompleteMarkerWrite
                | ApplyCheckpoint::CompleteMarkerCommit
        ) {
            Err(Error::FilesystemFailure)
        } else {
            Ok(())
        }
    }

    fn snapshot_tree(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        fn visit(root: &Path, current: &Path, output: &mut Vec<(PathBuf, Option<Vec<u8>>)>) {
            let mut children = fs::read_dir(current)
                .expect("read candidate snapshot")
                .map(|entry| entry.expect("candidate snapshot entry").path())
                .collect::<Vec<_>>();
            children.sort();
            for child in children {
                let relative = child
                    .strip_prefix(root)
                    .expect("candidate snapshot relative path")
                    .to_path_buf();
                if child.is_dir() {
                    output.push((relative, None));
                    visit(root, &child, output);
                } else {
                    output.push((
                        relative,
                        Some(fs::read(&child).expect("candidate snapshot bytes")),
                    ));
                }
            }
        }
        let mut output = Vec::new();
        visit(root, root, &mut output);
        output
    }

    #[test]
    fn standard_v2_full_apply_and_completed_replay_are_exact() {
        let _serial = APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(
                original.join("main.txt"),
                b"contact=rt7.standard@example.invalid\n",
            )
            .expect("write token-bearing Original");
            fs::write(original.join("opaque.bin"), b"opaque\0original-only")
                .expect("write original-only fixture");
        });
        fixture.review_and_approve_all();

        let applied = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect("complete StandardV2 apply");
        assert_eq!(applied.state, ApplyPublicationState::AppliedComplete);
        assert!(!applied.semantic_safety_assessed);
        assert_eq!(
            fs::read(fixture.candidate.join("main.txt")).expect("read candidate main"),
            b"contact=rt7.standard@example.invalid\n"
        );
        assert_eq!(
            fs::read(fixture.candidate.join("opaque.bin")).expect("read original-only"),
            b"opaque\0original-only"
        );
        let apply_manifests = fs::read_dir(&fixture.state)
            .expect("read private apply artifacts")
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry.file_name().to_str().is_some_and(|name| {
                    name.starts_with("manifest-") && name.ends_with("-apply.scdp")
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(apply_manifests.len(), 1);
        let protected_manifest =
            fs::read(apply_manifests[0].path()).expect("read protected APPLY_RESULT");
        assert!(!protected_manifest
            .windows(b"rt7.standard@example.invalid".len())
            .any(|window| window == b"rt7.standard@example.invalid"));
        assert!(!protected_manifest
            .windows(b"opaque\0original-only".len())
            .any(|window| window == b"opaque\0original-only"));

        let private_count = fixture.private_artifact_count();
        let replay = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect("read-only completed replay");
        assert_eq!(replay.state, ApplyPublicationState::CompletedReplay);
        assert_eq!(replay.apply_id, applied.apply_id);
        assert_eq!(
            replay.candidate_tree_commitment,
            applied.candidate_tree_commitment
        );
        assert_eq!(fixture.private_artifact_count(), private_count);
    }

    #[test]
    fn standard_v2_exact_token_deletion_reaches_applied_complete() {
        let _serial = APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(
                original.join("main.txt"),
                token_file("rt9.standard@example.invalid"),
            )
            .expect("write StandardV2 deletion fixture");
        });
        assert_eq!(remove_all_canonical_tokens(&fixture.ai.join("main.txt")), 1);
        let reviewed = review_session(&fixture.original, &fixture.ai, &fixture.state)
            .expect("review StandardV2 exact deletion");
        assert_eq!(reviewed.report().session_state, SessionState::Reviewed);
        assert_eq!(reviewed.report().approval_eligible_events, 1);
        assert_eq!(reviewed.report().remaining_approval_events, 1);
        fixture.approve_all(&reviewed);
        assert_eq!(
            review_session(&fixture.original, &fixture.ai, &fixture.state)
                .expect("authenticate StandardV2 READY_TO_APPLY")
                .report()
                .session_state,
            SessionState::ReadyToApply
        );

        let expected = fs::read(fixture.ai.join("main.txt")).expect("read deleted AI projection");
        let applied = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect("complete StandardV2 exact deletion");
        assert_eq!(applied.state, ApplyPublicationState::AppliedComplete);
        assert_eq!(
            fs::read(fixture.candidate.join("main.txt")).expect("read deletion candidate"),
            expected
        );
        assert!(!expected
            .windows(b"rt9.standard@example.invalid".len())
            .any(|window| window == b"rt9.standard@example.invalid"));
        assert_eq!(
            status_session(&fixture.state)
                .expect("status APPLIED_COMPLETE")
                .session_state,
            StatusState::AppliedComplete
        );
    }

    #[test]
    fn strict_token_files_v2_exact_token_deletion_reaches_applied_complete() {
        let _serial = APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::new(ReviewProfile::StrictTokenFilesV2, |original| {
            fs::write(
                original.join("strict.txt"),
                token_file("rt9.strict@example.invalid"),
            )
            .expect("write Strict deletion fixture");
        });
        assert_eq!(
            remove_all_canonical_tokens(&fixture.ai.join("strict.txt")),
            1
        );
        let reviewed = review_session(&fixture.original, &fixture.ai, &fixture.state)
            .expect("review Strict exact deletion");
        assert_eq!(reviewed.report().session_state, SessionState::Reviewed);
        assert_eq!(reviewed.report().approval_eligible_events, 2);
        assert_eq!(reviewed.report().remaining_approval_events, 2);
        fixture.approve_all(&reviewed);
        assert_eq!(
            review_session(&fixture.original, &fixture.ai, &fixture.state)
                .expect("authenticate Strict READY_TO_APPLY")
                .report()
                .session_state,
            SessionState::ReadyToApply
        );

        let expected = fs::read(fixture.ai.join("strict.txt")).expect("read strict AI deletion");
        let applied = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect("complete Strict exact deletion");
        assert_eq!(applied.state, ApplyPublicationState::AppliedComplete);
        assert_eq!(
            fs::read(fixture.candidate.join("strict.txt")).expect("read strict candidate"),
            expected
        );
        assert_eq!(
            status_session(&fixture.state)
                .expect("status Strict APPLIED_COMPLETE")
                .session_state,
            StatusState::AppliedComplete
        );
    }

    #[test]
    fn token_bearing_file_deletion_requires_file_and_every_token_approval() {
        let _serial = APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::new(ReviewProfile::StandardV2, |original| {
            let mut bytes = token_file("rt9.one@example.invalid");
            bytes.extend_from_slice(&token_file("rt9.two@example.invalid"));
            fs::write(original.join("main.txt"), bytes)
                .expect("write token-bearing file deletion fixture");
        });
        fs::remove_file(fixture.ai.join("main.txt")).expect("delete token-bearing AI file");
        let reviewed = review_session(&fixture.original, &fixture.ai, &fixture.state)
            .expect("review token-bearing file deletion");
        assert_eq!(reviewed.report().session_state, SessionState::Reviewed);
        assert_eq!(reviewed.report().approval_eligible_events, 3);
        assert_eq!(reviewed.report().approval_events.len(), 3);
        let review_id = decode_base32_128(&reviewed.report().review_id).expect("review id");
        for event in reviewed.report().approval_events.iter().take(2) {
            approve_review_event(
                &fixture.original,
                &fixture.ai,
                &fixture.state,
                review_id,
                decode_base32_128(&event.event_id).expect("event id"),
                event.required_reason,
            )
            .expect("approve proper subset");
        }
        let partial = review_session(&fixture.original, &fixture.ai, &fixture.state)
            .expect("authenticate partial file deletion approvals");
        assert_eq!(
            partial.report().session_state,
            SessionState::ApprovedPartial
        );
        assert_eq!(partial.report().approved_events, 2);
        assert_eq!(partial.report().remaining_approval_events, 1);
        let missing = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect_err("missing constituent approval cannot apply");
        assert_eq!(missing.state(), ApplyFailureState::DefinitePreCandidate);
        assert!(!fixture.candidate.exists());

        fixture.approve_all(&partial);
        let applied = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect("complete fully approved token-bearing file deletion");
        assert_eq!(applied.state, ApplyPublicationState::AppliedComplete);
        assert!(!fixture.candidate.join("main.txt").exists());
        assert_eq!(
            status_session(&fixture.state)
                .expect("status file deletion APPLIED_COMPLETE")
                .session_state,
            StatusState::AppliedComplete
        );
    }

    #[test]
    fn strict_token_files_v2_full_apply_restores_original_occurrence() {
        let _serial = APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::new(ReviewProfile::StrictTokenFilesV2, |original| {
            fs::write(
                original.join("strict.txt"),
                token_file("rt7.strict@example.invalid"),
            )
            .expect("write strict Original");
        });
        let baseline_ai = fs::read(fixture.ai.join("strict.txt")).expect("read strict AI");
        let mut edited = b"safe insertion\n".to_vec();
        edited.extend_from_slice(&baseline_ai);
        fs::write(fixture.ai.join("strict.txt"), edited).expect("edit strict AI");
        fixture.review_and_approve_all();

        let applied = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect("complete StrictTokenFilesV2 apply");
        assert_eq!(applied.state, ApplyPublicationState::AppliedComplete);
        let mut expected = b"safe insertion\n".to_vec();
        expected.extend_from_slice(&token_file("rt7.strict@example.invalid"));
        assert_eq!(
            fs::read(fixture.candidate.join("strict.txt")).expect("read strict candidate"),
            expected
        );
    }

    #[test]
    fn complete_marker_and_apply_result_are_the_sole_split_commit_recovery() {
        let _serial = APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = populated_fixture(ReviewProfile::StandardV2);
        fixture.review_and_approve_all();
        let _hook = install_test_hook(|point| {
            if point == ApplyCheckpoint::BeforeAppliedCompleteCommit {
                Err(Error::FilesystemFailure)
            } else {
                Ok(())
            }
        });
        let interrupted = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect_err("split commit interruption");
        assert_eq!(interrupted.state(), ApplyFailureState::ManualIncomplete);
        drop(_hook);
        assert!(fixture
            .candidate
            .join(crate::roundtrip::observe::CANDIDATE_COMPLETE_LEAF)
            .is_file());

        let recovered = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect("append only missing APPLIED_COMPLETE capsule");
        assert_eq!(recovered.state, ApplyPublicationState::SplitCommitRecovered);
        let replay = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect("replay recovered candidate");
        assert_eq!(replay.state, ApplyPublicationState::CompletedReplay);
    }

    #[test]
    fn exact_token_deletion_commit_boundaries_and_replays_write_no_candidate_bytes() {
        let _serial = APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        for point in [
            ApplyCheckpoint::ApplyResultManifestCommit,
            ApplyCheckpoint::CompleteMarkerCreate,
        ] {
            let fixture = approved_exact_deletion_fixture();
            let hook = install_test_hook(move |actual| {
                if actual == point {
                    Err(Error::FilesystemFailure)
                } else {
                    Ok(())
                }
            });
            let interrupted = apply_session(
                &fixture.original,
                &fixture.ai,
                &fixture.state,
                &fixture.candidate,
            )
            .expect_err("deletion apply interruption must fail closed");
            assert_eq!(interrupted.state(), ApplyFailureState::ManualIncomplete);
            drop(hook);
            let before = snapshot_tree(&fixture.candidate);
            let replay = apply_session(
                &fixture.original,
                &fixture.ai,
                &fixture.state,
                &fixture.candidate,
            )
            .expect_err("genuine APPLY_INCOMPLETE must not resume");
            assert_eq!(replay.state(), ApplyFailureState::ManualIncomplete);
            assert_eq!(snapshot_tree(&fixture.candidate), before, "{point:?}");
        }

        let split = approved_exact_deletion_fixture();
        let hook = install_test_hook(|point| {
            if point == ApplyCheckpoint::BeforeAppliedCompleteCommit {
                Err(Error::FilesystemFailure)
            } else {
                Ok(())
            }
        });
        let interrupted = apply_session(&split.original, &split.ai, &split.state, &split.candidate)
            .expect_err("interrupt before APPLIED_COMPLETE capsule");
        assert_eq!(interrupted.state(), ApplyFailureState::ManualIncomplete);
        drop(hook);
        let complete_candidate = snapshot_tree(&split.candidate);
        assert!(split
            .candidate
            .join(crate::roundtrip::observe::CANDIDATE_COMPLETE_LEAF)
            .is_file());
        let no_write = install_test_hook(reject_candidate_write_checkpoints);
        let recovered = apply_session(&split.original, &split.ai, &split.state, &split.candidate)
            .expect("recover split commit without candidate write");
        assert_eq!(recovered.state, ApplyPublicationState::SplitCommitRecovered);
        drop(no_write);
        assert_eq!(snapshot_tree(&split.candidate), complete_candidate);

        let write_attempts = Arc::new(AtomicU64::new(0));
        let observed = Arc::clone(&write_attempts);
        let no_write = install_test_hook(move |point| {
            if reject_candidate_write_checkpoints(point).is_err() {
                observed.fetch_add(1, Ordering::Relaxed);
                Err(Error::FilesystemFailure)
            } else {
                Ok(())
            }
        });
        let replay = apply_session(&split.original, &split.ai, &split.state, &split.candidate)
            .expect("completed exact-deletion replay");
        drop(no_write);
        assert_eq!(replay.state, ApplyPublicationState::CompletedReplay);
        assert_eq!(write_attempts.load(Ordering::Relaxed), 0);
        assert_eq!(snapshot_tree(&split.candidate), complete_candidate);
    }

    #[test]
    fn every_security_checkpoint_has_a_closed_fault_classification() {
        let _serial = APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cases = [
            (
                ApplyCheckpoint::BeforeApplyArmedCommit,
                Some(ApplyFailureState::DefinitePreCandidate),
                false,
            ),
            (
                ApplyCheckpoint::AfterApplyArmedCommit,
                Some(ApplyFailureState::StateCommitUncertain),
                false,
            ),
            (
                ApplyCheckpoint::BeforeCandidateRootCreate,
                Some(ApplyFailureState::DisarmedReadyToApply),
                false,
            ),
            (
                ApplyCheckpoint::CandidateRootCreateUncertain,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::IncompleteMarkerCreate,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::IncompleteMarkerWrite,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::BeforeApplyIncompleteCommit,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::AfterApplyIncompleteCommit,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::FirstSensitiveWrite,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::CandidateDirectoryCreate,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::CandidateFileCreate,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::ReconstructedWrite,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::OriginalOnlyStreamingWrite,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::PerFileVerify,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::PostcheckRawOccurrenceGraph,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::PostcheckProjectedRetokenization,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::PostcheckOriginalOnly,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::PostcheckFullCandidate,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::PostcheckCompletePrecondition,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::PostcheckFinalOriginal,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::ApplyResultManifestCommit,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::CompleteMarkerCreate,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::CompleteMarkerWrite,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::CompleteMarkerCommit,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (
                ApplyCheckpoint::BeforeAppliedCompleteCommit,
                Some(ApplyFailureState::ManualIncomplete),
                true,
            ),
            (ApplyCheckpoint::AfterAppliedCompleteCommit, None, true),
            (
                ApplyCheckpoint::FinalVerification,
                Some(ApplyFailureState::StateCommitUncertain),
                true,
            ),
        ];

        for (point, expected_failure, candidate_exists) in cases {
            let fixture = populated_fixture(ReviewProfile::StandardV2);
            fixture.review_and_approve_all();
            let hook = install_test_hook(move |actual| {
                if actual == point {
                    Err(Error::FilesystemFailure)
                } else {
                    Ok(())
                }
            });
            let result = apply_session(
                &fixture.original,
                &fixture.ai,
                &fixture.state,
                &fixture.candidate,
            );
            drop(hook);
            match expected_failure {
                Some(expected) => assert_eq!(
                    result.expect_err("checkpoint must stop apply").state(),
                    expected,
                    "fault classification at {point:?}"
                ),
                None => assert_eq!(
                    result
                        .expect("post-commit fault resolves by final read")
                        .state,
                    ApplyPublicationState::AppliedComplete,
                    "resolved completion at {point:?}"
                ),
            }
            assert_eq!(
                fixture.candidate.exists(),
                candidate_exists,
                "candidate existence at {point:?}"
            );
            if matches!(
                point,
                ApplyCheckpoint::CandidateRootCreateUncertain
                    | ApplyCheckpoint::IncompleteMarkerCreate
                    | ApplyCheckpoint::IncompleteMarkerWrite
                    | ApplyCheckpoint::BeforeApplyIncompleteCommit
                    | ApplyCheckpoint::AfterApplyIncompleteCommit
            ) {
                let snapshot = snapshot_tree(&fixture.candidate);
                assert!(
                    snapshot.iter().all(|(path, _)|
                        path == Path::new(crate::roundtrip::observe::CANDIDATE_INCOMPLETE_LEAF)),
                    "no sensitive candidate plaintext may exist before authenticated APPLY_INCOMPLETE at {point:?}"
                );
            }
        }
    }

    #[test]
    fn incomplete_candidate_is_never_resumed_or_repaired() {
        let _serial = APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = populated_fixture(ReviewProfile::StandardV2);
        fixture.review_and_approve_all();
        let hook = install_test_hook(|point| {
            if point == ApplyCheckpoint::FirstSensitiveWrite {
                Err(Error::FilesystemFailure)
            } else {
                Ok(())
            }
        });
        let first = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect_err("first sensitive-write interruption");
        assert_eq!(first.state(), ApplyFailureState::ManualIncomplete);
        drop(hook);
        let before = snapshot_tree(&fixture.candidate);

        let second = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect_err("incomplete candidate must not resume");
        assert_eq!(second.state(), ApplyFailureState::ManualIncomplete);
        assert_eq!(snapshot_tree(&fixture.candidate), before);
        assert!(!fixture
            .candidate
            .join(crate::roundtrip::observe::CANDIDATE_COMPLETE_LEAF)
            .exists());
    }

    #[test]
    fn same_volume_rename_preserves_physical_commitments_but_new_root_object_rejects() {
        let _serial = APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = populated_fixture(ReviewProfile::StandardV2);
        fixture.review_and_approve_all();
        let applied = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect("complete identity fixture");

        let renamed = fixture.root.join("RenamedSensitiveCandidateLongName");
        fs::rename(&fixture.candidate, &renamed).expect("same-volume candidate rename");
        let replay = apply_session(&fixture.original, &fixture.ai, &fixture.state, &renamed)
            .expect("freshly qualify renamed same object");
        assert_eq!(replay.state, ApplyPublicationState::CompletedReplay);
        assert_eq!(replay.apply_id, applied.apply_id);

        let retained_actual = fixture.root.join("RetainedActualCandidateLongName");
        fs::rename(&renamed, &retained_actual).expect("retain actual candidate object");
        fs::create_dir(&renamed).expect("create different same-volume root object");
        let mismatch = apply_session(&fixture.original, &fixture.ai, &fixture.state, &renamed)
            .expect_err("different same-volume root must reject");
        assert_eq!(mismatch.state(), ApplyFailureState::ManualIncomplete);
        assert_eq!(mismatch.error(), Error::CandidateRootIdentityMismatch);
        let raw_free = format!("{mismatch:?} {mismatch}");
        assert!(!raw_free.contains("RenamedSensitiveCandidateLongName"));
        assert!(!raw_free.contains("Volume{"));

        fs::remove_dir(&renamed).expect("remove synthetic mismatch root");
        fs::rename(&retained_actual, &renamed).expect("restore actual candidate object");
        assert_eq!(
            apply_session(&fixture.original, &fixture.ai, &fixture.state, &renamed,)
                .expect("actual candidate still replays")
                .state,
            ApplyPublicationState::CompletedReplay
        );
    }

    #[test]
    fn enabled_ntfs_candidate_creation_observes_aliases_and_stable_same_handle_identity() {
        let _serial = APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = populated_fixture(ReviewProfile::StandardV2);
        fixture.review_and_approve_all();
        apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect("complete alias evidence fixture");

        let (model, parent, leaf, selection) =
            crate::roundtrip::reconstruct::prepare_apply_reconstruction_model(
                &fixture.original,
                &fixture.ai,
                &fixture.state,
                &fixture.candidate,
            )
            .expect("qualify complete candidate for evidence");
        assert_eq!(
            parent.short_name_mode(),
            crate::roundtrip::observe::ShortNameMode::Enabled
        );
        let leaf_name = leaf.to_str().expect("ASCII fixture leaf");
        assert!(parent
            .observe()
            .expect("observe candidate parent")
            .find_exact_long(leaf_name)
            .expect("candidate root record")
            .alias_present());
        let crate::roundtrip::classify::CandidateSelection::Existing(root) = selection else {
            panic!("completed candidate root must exist")
        };
        let root_entries = root.observe().expect("observe candidate root");
        for marker in [
            crate::roundtrip::observe::CANDIDATE_INCOMPLETE_LEAF,
            crate::roundtrip::observe::CANDIDATE_COMPLETE_LEAF,
        ] {
            assert!(root_entries
                .find_exact_long(marker)
                .expect("candidate marker record")
                .alias_present());
        }

        let apply = model
            .authority
            .owner
            .capsule()
            .apply_authority
            .as_ref()
            .expect("complete apply authority");
        let schedule = model.authority.owner.key_schedule();
        let first = crate::roundtrip::candidate_identity::derive(
            &schedule,
            apply.apply_id,
            &root
                .observe_candidate_physical_source()
                .expect("first same-handle identity"),
        )
        .expect("first physical commitments");
        let second = crate::roundtrip::candidate_identity::derive(
            &schedule,
            apply.apply_id,
            &root
                .observe_candidate_physical_source()
                .expect("second same-handle identity"),
        )
        .expect("second physical commitments");
        assert_eq!(first.volume, second.volume);
        assert_eq!(first.root, second.root);
    }

    #[test]
    fn original_and_edited_mutations_after_arm_never_complete() {
        let _serial = APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        for point in [
            ApplyCheckpoint::AfterApplyArmedCommit,
            ApplyCheckpoint::AfterApplyIncompleteCommit,
            ApplyCheckpoint::PostcheckFinalOriginal,
        ] {
            let fixture = populated_fixture(ReviewProfile::StandardV2);
            fixture.review_and_approve_all();
            let target = fixture.original.join("nested").join("main.txt");
            let hook = install_test_hook(move |actual| {
                if actual == point {
                    let mut bytes = fs::read(&target).map_err(|_| Error::FilesystemFailure)?;
                    bytes.extend_from_slice(b"original mutation\n");
                    fs::write(&target, bytes).map_err(|_| Error::FilesystemFailure)?;
                }
                Ok(())
            });
            let failure = apply_session(
                &fixture.original,
                &fixture.ai,
                &fixture.state,
                &fixture.candidate,
            )
            .expect_err("Original mutation must prevent completion");
            drop(hook);
            assert!(matches!(
                failure.state(),
                ApplyFailureState::ManualIncomplete | ApplyFailureState::StateCommitUncertain
            ));
            assert!(!fixture
                .candidate
                .join(crate::roundtrip::observe::CANDIDATE_COMPLETE_LEAF)
                .exists());
        }

        for point in [
            ApplyCheckpoint::AfterApplyArmedCommit,
            ApplyCheckpoint::AfterApplyIncompleteCommit,
            ApplyCheckpoint::PostcheckProjectedRetokenization,
        ] {
            let fixture = populated_fixture(ReviewProfile::StandardV2);
            fixture.review_and_approve_all();
            let target = fixture.ai.join("nested").join("main.txt");
            let hook = install_test_hook(move |actual| {
                if actual == point {
                    let mut bytes = fs::read(&target).map_err(|_| Error::FilesystemFailure)?;
                    bytes.extend_from_slice(b"edited mutation\n");
                    fs::write(&target, bytes).map_err(|_| Error::FilesystemFailure)?;
                }
                Ok(())
            });
            let failure = apply_session(
                &fixture.original,
                &fixture.ai,
                &fixture.state,
                &fixture.candidate,
            )
            .expect_err("Edited mutation must prevent completion");
            drop(hook);
            assert!(matches!(
                failure.state(),
                ApplyFailureState::ManualIncomplete | ApplyFailureState::StateCommitUncertain
            ));
            assert!(!fixture
                .candidate
                .join(crate::roundtrip::observe::CANDIDATE_COMPLETE_LEAF)
                .exists());
        }
    }

    #[test]
    fn active_candidate_root_rename_is_manual_and_never_committed() {
        let _serial = APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = populated_fixture(ReviewProfile::StandardV2);
        fixture.review_and_approve_all();
        let selected = fixture.candidate.clone();
        let moved = fixture
            .root
            .join("RenamedSensitiveCandidateWorkspaceLongName");
        let moved_by_hook = moved.clone();
        let hook = install_test_hook(move |point| {
            if point == ApplyCheckpoint::PostcheckCompletePrecondition {
                fs::rename(&selected, &moved_by_hook).map_err(|_| Error::FilesystemFailure)?;
            }
            Ok(())
        });
        let failure = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect_err("active candidate root rename must block completion");
        drop(hook);
        assert_eq!(failure.state(), ApplyFailureState::ManualIncomplete);
        assert!(!fixture.candidate.exists());
        assert!(moved
            .join(crate::roundtrip::observe::CANDIDATE_INCOMPLETE_LEAF)
            .is_file());
        assert!(!moved
            .join(crate::roundtrip::observe::CANDIDATE_COMPLETE_LEAF)
            .exists());

        // Test-fixture cleanup only. Runtime never moves or deletes an
        // incomplete candidate.
        fs::rename(&moved, &fixture.candidate).expect("restore synthetic fixture for Drop");
    }

    #[test]
    fn candidate_mutation_after_complete_marker_blocks_capsule_completion() {
        let _serial = APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = populated_fixture(ReviewProfile::StandardV2);
        fixture.review_and_approve_all();
        let target = fixture.candidate.join("nested").join("main.txt");
        let hook = install_test_hook(move |point| {
            if point == ApplyCheckpoint::BeforeAppliedCompleteCommit {
                let mut bytes = fs::read(&target).map_err(|_| Error::FilesystemFailure)?;
                bytes.extend_from_slice(b"candidate mutation\n");
                fs::write(&target, bytes).map_err(|_| Error::FilesystemFailure)?;
            }
            Ok(())
        });
        let failure = apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect_err("post-marker candidate mutation must block APPLIED_COMPLETE");
        drop(hook);
        assert_eq!(failure.state(), ApplyFailureState::ManualIncomplete);
        assert!(fixture
            .candidate
            .join(crate::roundtrip::observe::CANDIDATE_COMPLETE_LEAF)
            .is_file());
        let before = snapshot_tree(&fixture.candidate);
        assert_eq!(
            apply_session(
                &fixture.original,
                &fixture.ai,
                &fixture.state,
                &fixture.candidate,
            )
            .expect_err("tampered split candidate cannot recover")
            .state(),
            ApplyFailureState::ManualIncomplete
        );
        assert_eq!(snapshot_tree(&fixture.candidate), before);
    }
}
