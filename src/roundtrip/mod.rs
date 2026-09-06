//! Authenticated private round-trip and session-create primitives.
//!
//! Command-line dispatch remains in `crate::cli`; filesystem, cryptographic,
//! review, approval, reconstruction, apply, status, and close policy remain in
//! this library boundary. One-way pipeline integration is deliberately absent.

use std::fmt;

pub(crate) mod anchor;
pub mod apply;
#[cfg(windows)]
pub(crate) mod approval;
pub mod approve;
#[cfg(windows)]
pub(crate) mod baseline;
#[cfg(windows)]
pub(crate) mod candidate;
#[cfg(windows)]
pub(crate) mod candidate_identity;
#[cfg(windows)]
pub(crate) mod candidate_marker;
#[cfg(windows)]
pub(crate) mod candidate_model;
pub mod canonical;
#[cfg(windows)]
pub mod capsule;
pub mod classify;
pub mod close;
pub mod create;
pub mod crypto;
#[cfg(windows)]
pub mod dpapi;
#[cfg(windows)]
pub(crate) mod edited;
#[cfg(windows)]
pub(crate) mod events;
#[cfg(windows)]
pub(crate) mod manifest;
#[cfg(windows)]
pub(crate) mod manifest_projection;
#[cfg(windows)]
pub(crate) mod observe;
#[cfg(windows)]
pub mod reconstruct;
#[cfg(windows)]
pub(crate) mod reconstruction_reference;
// Reporting-only exact line diff consumed by review manifest projection. It is
// never classification, identifier, approval, or reconstruction authority.
pub(crate) mod report_diff;
pub mod review;
#[cfg(windows)]
pub(crate) mod review_identity;
#[cfg(windows)]
pub(crate) mod review_ids;
pub mod ruleset;
pub mod schema;
pub mod status;
pub mod token;
#[cfg(windows)]
pub(crate) mod tokenize;
#[cfg(windows)]
pub(crate) mod workspace;

/// Fixed, raw-free failures for private round-trip primitives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedPlatform,
    RandomGenerationFailed,
    KeyDerivationFailed,
    AuthenticationFailed,
    InvalidCanonicalInput,
    BoundExceeded,
    ChangeReportBoundExceeded,
    AnchorAmbiguous,
    AnchorResourceLimitExceeded,
    AnchorEncodingInvalid,
    InvalidToken,
    InvalidEnvelope,
    InvalidSchema,
    InvalidState,
    DpapiFailed,
    FilesystemFailure,
    LockContention,
    PrivateOrphansPresent,
    CreateIncomplete,
    UnsupportedAliasNamespace,
    AliasNamespaceAmbiguous,
    AliasIdentityMismatch,
    CaseSensitiveDirectoryUnsupported,
    PersistentVolumeQueryFailed,
    PersistentVolumeStateAmbiguous,
    StateCommitUncertain,
    CorruptState,
    CreateConflict,
    OriginalWorkspaceRejected,
    WorkspaceVerificationFailed,
    WorkspaceUnstable,
    OriginalBaselineMismatch,
    UnsafeWorkspaceOverlap,
    ApprovalStale,
    ApprovalEventInvalid,
    ApprovalEventIneligible,
    ApprovalReasonMismatch,
    ApprovalConflict,
    ReconstructionRejected,
    ProjectedRetokenizationMismatch,
    OccurrenceGraphMismatch,
    CandidateNamespaceCollision,
    CandidateVolumeIdentityMismatch,
    CandidateRootIdentityMismatch,
    CandidateMarkerAuthenticationFailed,
    CandidateVerificationFailed,
    CandidateIncomplete,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => "round-trip primitive is unavailable on this platform",
            Self::RandomGenerationFailed => "secure random generation failed",
            Self::KeyDerivationFailed => "round-trip key derivation failed",
            Self::AuthenticationFailed => "private artifact authentication failed",
            Self::InvalidCanonicalInput => "canonical input is invalid",
            Self::BoundExceeded => "round-trip resource bound exceeded",
            Self::ChangeReportBoundExceeded => "review change-report bound exceeded",
            Self::AnchorAmbiguous => "relative content anchor is ambiguous",
            Self::AnchorResourceLimitExceeded => "relative content anchor resource bound exceeded",
            Self::AnchorEncodingInvalid => "relative content anchor input is invalid",
            Self::InvalidToken => "round-trip token is invalid",
            Self::InvalidEnvelope => "private artifact envelope is invalid",
            Self::InvalidSchema => "private artifact schema is invalid",
            Self::InvalidState => "private session state is invalid",
            Self::DpapiFailed => "CurrentUser private-data protection failed",
            Self::FilesystemFailure => "private state filesystem operation failed",
            Self::LockContention => "private session mutation is already in progress",
            Self::PrivateOrphansPresent => "private orphan artifacts are present",
            Self::CreateIncomplete => "private session creation is incomplete",
            Self::UnsupportedAliasNamespace => "private namespace is unsupported",
            Self::AliasNamespaceAmbiguous => "private namespace is ambiguous",
            Self::AliasIdentityMismatch => "private namespace identity does not match",
            Self::CaseSensitiveDirectoryUnsupported => {
                "case-sensitive private directories are unsupported"
            }
            Self::PersistentVolumeQueryFailed => "persistent volume state could not be established",
            Self::PersistentVolumeStateAmbiguous => "persistent volume state is ambiguous",
            Self::StateCommitUncertain => "private state commit result is uncertain",
            Self::CorruptState => "private session state is corrupt",
            Self::CreateConflict => "round-trip create target conflicts with existing state",
            Self::OriginalWorkspaceRejected => "original workspace is unsupported or unstable",
            Self::WorkspaceVerificationFailed => "AI workspace verification failed",
            Self::WorkspaceUnstable => "edited AI workspace is unstable",
            Self::OriginalBaselineMismatch => {
                "original workspace no longer matches the authenticated baseline"
            }
            Self::UnsafeWorkspaceOverlap => "round-trip workspace overlap is unsafe",
            Self::ApprovalStale => "round-trip approval review authority is stale",
            Self::ApprovalEventInvalid => "round-trip approval event is invalid or stale",
            Self::ApprovalEventIneligible => "round-trip event is not approval eligible",
            Self::ApprovalReasonMismatch => "round-trip approval reason does not match the event",
            Self::ApprovalConflict => "round-trip approval conflicts with the authenticated record",
            Self::ReconstructionRejected => "round-trip reconstruction authority was rejected",
            Self::ProjectedRetokenizationMismatch => {
                "round-trip projected retokenization did not match the edited snapshot"
            }
            Self::OccurrenceGraphMismatch => {
                "round-trip reconstructed occurrence graph did not match authority"
            }
            Self::CandidateNamespaceCollision => {
                "round-trip candidate namespace has a deterministic collision"
            }
            Self::CandidateVolumeIdentityMismatch => {
                "round-trip candidate volume identity does not match"
            }
            Self::CandidateRootIdentityMismatch => {
                "round-trip candidate root identity does not match"
            }
            Self::CandidateMarkerAuthenticationFailed => {
                "round-trip candidate marker authentication failed"
            }
            Self::CandidateVerificationFailed => "round-trip candidate verification failed",
            Self::CandidateIncomplete => "round-trip candidate requires manual inspection",
        })
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
