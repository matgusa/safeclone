use hmac::{Hmac, KeyInit, Mac};
use safeclone::roundtrip::schema::{CAPSULE_SCHEMA_VERSION, MANIFEST_SCHEMA_VERSION};
use safeclone::roundtrip::token::{ENGINE_VERSION, POLICY_ID, TOKEN_SUITE_ID};
use sha2::{Digest, Sha256};

const USAGE: &str = include_str!("../docs/usage.md");
const THIRD_PARTY: &str = include_str!("../THIRD_PARTY.md");
const SIMILAR_LICENSE: &[u8] = include_bytes!("../third_party/licenses/similar-Apache-2.0.txt");
const EVENTS_SOURCE: &str = include_str!("../src/roundtrip/events.rs");
const CLASSIFY_SOURCE: &str = include_str!("../src/roundtrip/classify.rs");
const ANCHOR_SOURCE: &str = include_str!("../src/roundtrip/anchor.rs");
const ROUNDTRIP_WORKSPACE_SOURCE: &str = include_str!("../src/roundtrip/workspace.rs");
const ROUNDTRIP_BASELINE_SOURCE: &str = include_str!("../src/roundtrip/baseline.rs");
const REPORT_DIFF_SOURCE: &str = include_str!("../src/roundtrip/report_diff.rs");
const MANIFEST_PROJECTION_SOURCE: &str = include_str!("../src/roundtrip/manifest_projection.rs");
const REVIEW_SOURCE: &str = include_str!("../src/roundtrip/review.rs");
const REVIEW_IDENTITY_SOURCE: &str = include_str!("../src/roundtrip/review_identity.rs");
const APPROVAL_SOURCE: &str = include_str!("../src/roundtrip/approval.rs");
const APPROVE_SOURCE: &str = include_str!("../src/roundtrip/approve.rs");
const RECONSTRUCT_SOURCE: &str = include_str!("../src/roundtrip/reconstruct.rs");
const RECONSTRUCTION_REFERENCE_SOURCE: &str =
    include_str!("../src/roundtrip/reconstruction_reference.rs");
const CANDIDATE_MODEL_SOURCE: &str = include_str!("../src/roundtrip/candidate_model.rs");
const APPLY_SOURCE: &str = include_str!("../src/roundtrip/apply.rs");
const CANDIDATE_SOURCE: &str = include_str!("../src/roundtrip/candidate.rs");
const CANDIDATE_IDENTITY_SOURCE: &str = include_str!("../src/roundtrip/candidate_identity.rs");
const CANDIDATE_MARKER_SOURCE: &str = include_str!("../src/roundtrip/candidate_marker.rs");
const STATUS_SOURCE: &str = include_str!("../src/roundtrip/status.rs");
const CLOSE_SOURCE: &str = include_str!("../src/roundtrip/close.rs");
const CLI_SOURCE: &str = include_str!("../src/cli.rs");
const ONE_WAY_PIPELINE_SOURCE: &str = include_str!("../src/pipeline.rs");

fn normalized_source(source: &str) -> String {
    source.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn named_function_body<'a>(source: &'a str, signature: &str) -> &'a str {
    let function_start = source
        .find(signature)
        .unwrap_or_else(|| panic!("missing source function: {signature}"));
    let body_start = source[function_start..]
        .find('{')
        .map(|offset| function_start + offset)
        .unwrap_or_else(|| panic!("missing source function body: {signature}"));
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[body_start..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth
                    .checked_sub(1)
                    .unwrap_or_else(|| panic!("unbalanced source function: {signature}"));
                if depth == 0 {
                    return &source[function_start..=body_start + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated source function: {signature}")
}

const PROJECT_TOKEN: u8 = 1;
const PROJECT_FILE: u8 = 2;
const PROJECT_DIRECTORY: u8 = 4;
const PROJECT_PRESERVED_SUPPRESSION: u8 = 8;

const EVENT_PROJECTION: &[(&str, u16, u8)] = &[
    (
        "PreservedSameAnchor",
        1,
        PROJECT_TOKEN | PROJECT_PRESERVED_SUPPRESSION,
    ),
    ("TokenDeleted", 2, PROJECT_TOKEN),
    ("ProtectedContextChanged", 3, PROJECT_TOKEN),
    ("ProtectedCoreChanged", 4, PROJECT_TOKEN),
    ("AnchorAmbiguous", 5, PROJECT_TOKEN),
    ("MovedToOtherFile", 6, PROJECT_TOKEN),
    ("PathMoved", 7, PROJECT_TOKEN),
    ("TokenDuplicated", 8, PROJECT_TOKEN),
    ("TokenModified", 9, PROJECT_TOKEN),
    ("TokenUnknown", 10, PROJECT_TOKEN),
    ("CategoryMismatch", 11, PROJECT_TOKEN),
    ("TokenOrderChanged", 12, PROJECT_TOKEN),
    ("FileModified", 32, PROJECT_FILE),
    ("FileDeleted", 33, PROJECT_FILE),
    ("FileRenamed", 34, PROJECT_FILE),
    ("FileMoved", 35, PROJECT_FILE),
    ("NewTextFile", 36, PROJECT_FILE),
    ("DirectoryAdded", 48, PROJECT_DIRECTORY),
    ("DirectoryDeleted", 49, PROJECT_DIRECTORY),
    ("DirectoryRenamed", 50, PROJECT_DIRECTORY),
    ("DirectoryMoved", 51, PROJECT_DIRECTORY),
    ("StrictTokenFileModified", 52, PROJECT_FILE),
    (
        "NewUntokenizedSensitiveFinding",
        64,
        PROJECT_FILE | PROJECT_DIRECTORY,
    ),
    ("UnsupportedAddition", 65, PROJECT_FILE),
    ("LinkLikeAddition", 66, PROJECT_FILE),
    ("HardLink", 67, PROJECT_FILE),
    ("AlternateDataStream", 68, PROJECT_FILE),
    ("ProtectedNamespace", 69, PROJECT_FILE | PROJECT_DIRECTORY),
    ("OmittedPathCollision", 70, PROJECT_FILE | PROJECT_DIRECTORY),
    ("InvalidUtf8", 71, PROJECT_FILE),
];

fn current_event_kind_registry() -> Vec<(&'static str, u16)> {
    let marker = "pub(crate) enum EventKind {";
    let start = EVENTS_SOURCE
        .find(marker)
        .expect("current classification EventKind registry");
    let remainder = &EVENTS_SOURCE[start + marker.len()..];
    let end = remainder
        .find("\n}")
        .expect("current classification EventKind registry end");

    remainder[..end]
        .lines()
        .filter_map(|line| {
            let (name, value) = line.trim().strip_suffix(',')?.split_once(" = ")?;
            Some((name, value.parse::<u16>().expect("numeric EventKind value")))
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelTokenEventKind {
    PreservedSameAnchor,
    TokenDeleted,
    ProtectedContextChanged,
    ProtectedCoreChanged,
    AnchorAmbiguous,
    MovedToOtherFile,
    PathMoved,
    TokenDuplicated,
    TokenModified,
    TokenUnknown,
    CategoryMismatch,
    TokenOrderChanged,
}

const BASELINE_MODEL_TOKEN_EVENTS: &[ModelTokenEventKind] = &[
    ModelTokenEventKind::PreservedSameAnchor,
    ModelTokenEventKind::TokenDeleted,
    ModelTokenEventKind::ProtectedContextChanged,
    ModelTokenEventKind::ProtectedCoreChanged,
    ModelTokenEventKind::AnchorAmbiguous,
    ModelTokenEventKind::MovedToOtherFile,
    ModelTokenEventKind::PathMoved,
    ModelTokenEventKind::TokenDuplicated,
    ModelTokenEventKind::TokenModified,
    ModelTokenEventKind::CategoryMismatch,
    ModelTokenEventKind::TokenOrderChanged,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelTokenEventDiscriminant {
    Known(ModelTokenEventKind),
    Unknown(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelApprovalState {
    NotEligible,
    Required,
    Approved,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelDecision {
    Automatic,
    ApprovalRequired,
    Approved,
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ModelManifestTokenEvent {
    event_id: [u8; 16],
    token_id: Option<[u8; 16]>,
    category_expected: Option<u8>,
    category_observed: Option<u8>,
    event: ModelTokenEventDiscriminant,
    approval_state: ModelApprovalState,
    decision: ModelDecision,
}

fn valid_model_manifest_token_event(event: &ModelManifestTokenEvent) -> bool {
    let ModelTokenEventDiscriminant::Known(kind) = event.event else {
        return false;
    };
    if event.token_id.is_none() != event.category_expected.is_none() {
        return false;
    }
    if kind == ModelTokenEventKind::TokenUnknown {
        event.token_id.is_none()
            && event.category_expected.is_none()
            && event.approval_state == ModelApprovalState::NotEligible
            && event.decision == ModelDecision::Reject
    } else {
        event.token_id.is_some() && event.category_expected.is_some()
    }
}

struct ModelTransientUnknown {
    event_id: [u8; 16],
    observed_unknown_oid: Option<[u8; 16]>,
    observed_category: Option<u8>,
}

fn project_model_unknown(value: ModelTransientUnknown) -> ModelManifestTokenEvent {
    let ModelTransientUnknown {
        event_id,
        observed_unknown_oid,
        observed_category,
    } = value;
    let _observed_unknown_oid = observed_unknown_oid;
    ModelManifestTokenEvent {
        event_id,
        token_id: None,
        category_expected: None,
        category_observed: observed_category,
        event: ModelTokenEventDiscriminant::Known(ModelTokenEventKind::TokenUnknown),
        approval_state: ModelApprovalState::NotEligible,
        decision: ModelDecision::Reject,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModelCanonicalEvent {
    group: u8,
    class: u8,
    kind: u16,
    decision: u8,
    baseline_oid: Option<[u8; 16]>,
    expected_category: Option<u8>,
    observed_category: Option<u8>,
    before_entry: Option<[u8; 32]>,
    after_entry: Option<[u8; 32]>,
    before_anchor: Option<[u8; 32]>,
    after_anchor: Option<[u8; 32]>,
    observed_count: u32,
    reason: u16,
    before_path: Option<Vec<u8>>,
    after_path: Option<Vec<u8>>,
    position: u64,
}

fn append_model_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .expect("bounded schema-model bytes")
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
}

fn append_model_optional_bytes(output: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            output.push(1);
            append_model_bytes(output, value);
        }
        None => output.push(0),
    }
}

fn append_model_optional_category(output: &mut Vec<u8>, value: Option<u8>) {
    match value {
        Some(value) => {
            output.push(1);
            output.push(value);
        }
        None => output.push(0),
    }
}

fn encode_model_event_body(event: &ModelCanonicalEvent) -> Vec<u8> {
    let mut output = Vec::new();
    output.push(event.group);
    output.push(event.class);
    output.extend_from_slice(&event.kind.to_be_bytes());
    output.push(event.decision);
    append_model_optional_bytes(
        &mut output,
        event.baseline_oid.as_ref().map(|value| value.as_slice()),
    );
    append_model_optional_category(&mut output, event.expected_category);
    append_model_optional_category(&mut output, event.observed_category);
    append_model_optional_bytes(
        &mut output,
        event.before_entry.as_ref().map(|value| value.as_slice()),
    );
    append_model_optional_bytes(
        &mut output,
        event.after_entry.as_ref().map(|value| value.as_slice()),
    );
    append_model_optional_bytes(
        &mut output,
        event.before_anchor.as_ref().map(|value| value.as_slice()),
    );
    append_model_optional_bytes(
        &mut output,
        event.after_anchor.as_ref().map(|value| value.as_slice()),
    );
    output.extend_from_slice(&event.observed_count.to_be_bytes());
    output.extend_from_slice(&event.reason.to_be_bytes());
    append_model_optional_bytes(&mut output, event.before_path.as_deref());
    append_model_optional_bytes(&mut output, event.after_path.as_deref());
    output.extend_from_slice(&event.position.to_be_bytes());
    output
}

fn encode_versioned_model_event(event: &ModelCanonicalEvent) -> Vec<u8> {
    let mut output = vec![1];
    output.extend_from_slice(&encode_model_event_body(event));
    output
}

fn model_hmac_128(key: &[u8; 32], input: &[u8]) -> [u8; 16] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("fixed HMAC key");
    mac.update(input);
    let tag = mac.finalize().into_bytes();
    let mut output = [0u8; 16];
    output.copy_from_slice(&tag[..16]);
    output
}

fn model_event_id(
    key: &[u8; 32],
    review_id: &[u8; 16],
    owning_entry_id: &[u8; 16],
    event: &ModelCanonicalEvent,
) -> [u8; 16] {
    let mut canonical = Vec::new();
    append_model_bytes(&mut canonical, b"safeclone/rt1/event-id");
    append_model_bytes(&mut canonical, review_id);
    append_model_bytes(&mut canonical, owning_entry_id);
    append_model_bytes(&mut canonical, &encode_versioned_model_event(event));
    model_hmac_128(key, &canonical)
}

fn encode_model_event_set(events: &[ModelCanonicalEvent]) -> Vec<u8> {
    let mut ordered = events.to_vec();
    ordered.sort_by(|left, right| {
        left.group
            .cmp(&right.group)
            .then_with(|| left.baseline_oid.cmp(&right.baseline_oid))
            .then_with(|| left.after_path.cmp(&right.after_path))
            .then_with(|| left.before_path.cmp(&right.before_path))
            .then_with(|| left.position.cmp(&right.position))
            .then_with(|| left.kind.cmp(&right.kind))
    });
    let mut output = vec![1];
    output.extend_from_slice(
        &u32::try_from(ordered.len())
            .expect("bounded schema-model events")
            .to_be_bytes(),
    );
    for event in &ordered {
        output.extend_from_slice(&encode_model_event_body(event));
    }
    output
}

fn model_review_id(key: &[u8; 32], events: &[ModelCanonicalEvent]) -> [u8; 16] {
    // This is a property model for the already accepted review-ID rule. It
    // deliberately models the complete canonical classification set input, not a new
    // production encoder or golden vector.
    let mut canonical = Vec::new();
    append_model_bytes(&mut canonical, b"safeclone/rt4c/review-id-property-model");
    append_model_bytes(&mut canonical, &[0xA1; 32]);
    append_model_bytes(&mut canonical, &[0xB2; 32]);
    append_model_bytes(&mut canonical, &encode_model_event_set(events));
    model_hmac_128(key, &canonical)
}

fn model_unknown_event(path: &[u8], position: u64) -> ModelCanonicalEvent {
    ModelCanonicalEvent {
        group: 2,
        class: 1,
        kind: 10,
        decision: 3,
        baseline_oid: None,
        expected_category: None,
        observed_category: Some(1),
        before_entry: None,
        after_entry: None,
        before_anchor: None,
        after_anchor: None,
        observed_count: 1,
        reason: 2,
        before_path: None,
        after_path: Some(path.to_vec()),
        position,
    }
}

#[test]
fn current_event_projection_matrix_is_complete() {
    let current = current_event_kind_registry();
    assert_eq!(
        current.len(),
        EVENT_PROJECTION.len(),
        "every current classification EventKind must have one projection rule"
    );

    for ((current_name, current_value), (model_name, model_value, targets)) in
        current.iter().zip(EVENT_PROJECTION)
    {
        assert_eq!(current_name, model_name, "projection registry name drift");
        assert_eq!(
            current_value, model_value,
            "projection registry value drift"
        );
        assert_ne!(*targets, 0, "unrepresentable EventKind: {model_name}");
        assert_eq!(
            targets
                & !(PROJECT_TOKEN
                    | PROJECT_FILE
                    | PROJECT_DIRECTORY
                    | PROJECT_PRESERVED_SUPPRESSION),
            0,
            "projection escapes the closed A/B/C/D model: {model_name}"
        );
    }

    assert_eq!(
        EVENT_PROJECTION
            .iter()
            .filter(|(_, _, targets)| *targets & PROJECT_PRESERVED_SUPPRESSION != 0)
            .map(|(name, _, _)| *name)
            .collect::<Vec<_>>(),
        vec!["PreservedSameAnchor"]
    );
}

#[test]
fn token_event_nullability_model_rejects_every_invalid_pair() {
    let pairs = [
        (None, None),
        (Some([0x11; 16]), None),
        (None, Some(1)),
        (Some([0x11; 16]), Some(1)),
    ];

    for (index, (token_id, category_expected)) in pairs.into_iter().enumerate() {
        let unknown = ModelManifestTokenEvent {
            event_id: [0x22; 16],
            token_id,
            category_expected,
            category_observed: None,
            event: ModelTokenEventDiscriminant::Known(ModelTokenEventKind::TokenUnknown),
            approval_state: ModelApprovalState::NotEligible,
            decision: ModelDecision::Reject,
        };
        assert_eq!(
            valid_model_manifest_token_event(&unknown),
            index == 0,
            "TOKEN_UNKNOWN null-pair combination {index}"
        );

        for kind in BASELINE_MODEL_TOKEN_EVENTS {
            let baseline = ModelManifestTokenEvent {
                event: ModelTokenEventDiscriminant::Known(*kind),
                decision: ModelDecision::Automatic,
                ..unknown
            };
            assert_eq!(
                valid_model_manifest_token_event(&baseline),
                index == 3,
                "baseline event {kind:?} null-pair combination {index}"
            );
        }
    }

    for observed in [None, Some(1)] {
        let unknown = ModelManifestTokenEvent {
            event_id: [0x33; 16],
            token_id: None,
            category_expected: None,
            category_observed: observed,
            event: ModelTokenEventDiscriminant::Known(ModelTokenEventKind::TokenUnknown),
            approval_state: ModelApprovalState::NotEligible,
            decision: ModelDecision::Reject,
        };
        assert!(
            valid_model_manifest_token_event(&unknown),
            "observed category must remain independently nullable"
        );
    }

    for approval_state in [
        ModelApprovalState::Required,
        ModelApprovalState::Approved,
        ModelApprovalState::Stale,
    ] {
        let unknown = ModelManifestTokenEvent {
            event_id: [0x44; 16],
            token_id: None,
            category_expected: None,
            category_observed: Some(1),
            event: ModelTokenEventDiscriminant::Known(ModelTokenEventKind::TokenUnknown),
            approval_state,
            decision: ModelDecision::Reject,
        };
        assert!(!valid_model_manifest_token_event(&unknown));
    }

    for decision in [
        ModelDecision::Automatic,
        ModelDecision::ApprovalRequired,
        ModelDecision::Approved,
    ] {
        let unknown = ModelManifestTokenEvent {
            event_id: [0x55; 16],
            token_id: None,
            category_expected: None,
            category_observed: None,
            event: ModelTokenEventDiscriminant::Known(ModelTokenEventKind::TokenUnknown),
            approval_state: ModelApprovalState::NotEligible,
            decision,
        };
        assert!(!valid_model_manifest_token_event(&unknown));
    }

    let unknown_discriminant = ModelManifestTokenEvent {
        event_id: [0x66; 16],
        token_id: Some([0x77; 16]),
        category_expected: Some(1),
        category_observed: Some(1),
        event: ModelTokenEventDiscriminant::Unknown(u16::MAX),
        approval_state: ModelApprovalState::NotEligible,
        decision: ModelDecision::Reject,
    };
    assert!(!valid_model_manifest_token_event(&unknown_discriminant));

    let category_mismatch_without_expected = ModelManifestTokenEvent {
        event_id: [0x88; 16],
        token_id: None,
        category_expected: None,
        category_observed: Some(2),
        event: ModelTokenEventDiscriminant::Known(ModelTokenEventKind::CategoryMismatch),
        approval_state: ModelApprovalState::NotEligible,
        decision: ModelDecision::Reject,
    };
    assert!(!valid_model_manifest_token_event(
        &category_mismatch_without_expected
    ));
}

#[test]
fn unknown_projection_never_persists_an_observed_unknown_oid() {
    let first = project_model_unknown(ModelTransientUnknown {
        event_id: [0xE1; 16],
        observed_unknown_oid: Some([0x91; 16]),
        observed_category: Some(2),
    });
    let second = project_model_unknown(ModelTransientUnknown {
        event_id: [0xE1; 16],
        observed_unknown_oid: Some([0xA2; 16]),
        observed_category: Some(2),
    });
    let malformed = project_model_unknown(ModelTransientUnknown {
        event_id: [0xE2; 16],
        observed_unknown_oid: None,
        observed_category: None,
    });

    assert_eq!(first, second);
    assert_eq!(first.token_id, None);
    assert_eq!(first.category_expected, None);
    assert_eq!(malformed.token_id, None);
    assert_eq!(malformed.category_observed, None);
    assert!(valid_model_manifest_token_event(&first));
    assert!(valid_model_manifest_token_event(&malformed));
}

#[test]
fn canonical_event_ids_distinguish_unknown_positions_and_replay_exactly() {
    let first_key = [0x31; 32];
    let second_key = [0x32; 32];
    let owning_entry_id = [0x41; 16];
    let first = model_unknown_event(b"safe/file.txt", 17);
    let second = model_unknown_event(b"safe/file.txt", 81);
    let authority = vec![first.clone(), second.clone()];
    let review_id = model_review_id(&first_key, &authority);

    let first_id = model_event_id(&first_key, &review_id, &owning_entry_id, &first);
    let second_id = model_event_id(&first_key, &review_id, &owning_entry_id, &second);
    assert_ne!(
        first_id, second_id,
        "positions must distinguish unknown events"
    );
    let projected = [
        project_model_unknown(ModelTransientUnknown {
            event_id: first_id,
            observed_unknown_oid: Some([0xA1; 16]),
            observed_category: first.observed_category,
        }),
        project_model_unknown(ModelTransientUnknown {
            event_id: second_id,
            observed_unknown_oid: Some([0xA2; 16]),
            observed_category: second.observed_category,
        }),
    ];
    assert_eq!(projected.len(), 2);
    assert!(projected.iter().all(valid_model_manifest_token_event));
    assert_ne!(projected[0].event_id, projected[1].event_id);
    assert!(projected
        .iter()
        .all(|event| event.token_id.is_none() && event.category_expected.is_none()));
    assert_eq!(
        first_id,
        model_event_id(&first_key, &review_id, &owning_entry_id, &first),
        "exact replay must reproduce event ID"
    );
    assert_eq!(
        review_id,
        model_review_id(&first_key, &authority),
        "exact replay must reproduce review ID"
    );

    let moved = model_unknown_event(b"safe/file.txt", 82);
    let moved_authority = vec![first.clone(), moved.clone()];
    let moved_review_id = model_review_id(&first_key, &moved_authority);
    assert_ne!(review_id, moved_review_id);
    assert_ne!(
        second_id,
        model_event_id(&first_key, &moved_review_id, &owning_entry_id, &moved)
    );

    let cross_session_review = model_review_id(&second_key, &authority);
    assert_ne!(review_id, cross_session_review);
    assert_ne!(
        first_id,
        model_event_id(&second_key, &cross_session_review, &owning_entry_id, &first)
    );

    assert_eq!(first.baseline_oid, None);
    assert_eq!(first.expected_category, None);
    assert_eq!(first.before_anchor, None);
    assert_eq!(first.after_anchor, None);
}

#[test]
fn schema_and_compatibility_versions_remain_unchanged() {
    assert_eq!(CAPSULE_SCHEMA_VERSION, 1);
    assert_eq!(MANIFEST_SCHEMA_VERSION, 1);
    assert_eq!(ENGINE_VERSION, "safeclone-roundtrip-engine-v3");
    assert_eq!(POLICY_ID, "roundtrip-v3");
    assert_eq!(TOKEN_SUITE_ID, 1);
}

#[test]
fn manifest_projection_cannot_supply_authority() {
    for authority_source in [CLASSIFY_SOURCE, ANCHOR_SOURCE, EVENTS_SOURCE] {
        assert!(!authority_source.contains("use super::report_diff"));
        assert!(!authority_source.contains("use super::manifest_projection"));
    }
    for forbidden_authority in [
        "use super::classify",
        "use super::anchor",
        "use super::events",
    ] {
        assert!(!REPORT_DIFF_SOURCE.contains(forbidden_authority));
    }
    for required_consumer in [
        "use super::classify",
        "use super::events",
        "use super::manifest",
        "use super::report_diff",
    ] {
        assert!(MANIFEST_PROJECTION_SOURCE.contains(required_consumer));
    }
    assert!(REVIEW_SOURCE.contains("ReviewIdentityIndex::derive"));
    assert!(REVIEW_SOURCE.contains("project_review(&authority, &identities"));
    assert!(CLI_SOURCE.contains("review_session"));
    assert!(CLI_SOURCE.contains("approve_review_event"));
    assert!(!ONE_WAY_PIPELINE_SOURCE.contains("review_session"));
    assert!(!ONE_WAY_PIPELINE_SOURCE.contains("approve_review_event"));
    assert!(USAGE.contains("safeclone session review"));
    assert!(USAGE.contains("safeclone session approve"));
}

#[test]
fn approval_workflow_is_fresh_typed_authenticated_and_manifest_independent() {
    for source in [APPROVAL_SOURCE, APPROVE_SOURCE] {
        assert!(!source.contains("use super::manifest"));
        assert!(!source.contains("use crate::roundtrip::manifest"));
        assert!(!source.contains("use super::report_diff"));
        assert!(!source.contains("use crate::roundtrip::report_diff"));
        assert!(!source.contains("manifest_projection::project_review"));
    }
    assert!(APPROVE_SOURCE.contains("prepare_approval_authority"));
    assert!(APPROVE_SOURCE.contains("append_capsule_generation"));
    assert!(APPROVAL_SOURCE.contains("ApprovalEventType::Deleted"));
    assert!(APPROVAL_SOURCE.contains("ApprovalEventType::FileDeleted"));
    assert!(APPROVAL_SOURCE.contains("ApprovalEventType::StrictTokenFileModified"));
    assert!(MANIFEST_PROJECTION_SOURCE.contains("ReviewIdentityIndex"));
    assert!(APPROVE_SOURCE.contains("ReviewIdentityIndex"));
    assert!(REVIEW_IDENTITY_SOURCE.contains("event.event_id"));
}

#[test]
fn reconstruction_is_fresh_nonforgeable_file_local_and_publication_free() {
    for anchor in [
        "prepare_reconstruction_authority",
        "authenticate_complete_approval_set",
        "build_reserved_form_index",
        "project_retokenized_component",
        "read_planned_original_file",
        "CandidateCommitmentWriter",
    ] {
        assert!(
            RECONSTRUCT_SOURCE.contains(anchor),
            "reconstruction reconstruction source missing boundary: {anchor}"
        );
    }
    assert!(RECONSTRUCTION_REFERENCE_SOURCE.contains("OccurrenceGraphMismatch"));
    assert!(RECONSTRUCTION_REFERENCE_SOURCE.contains("ProjectedRetokenizationMismatch"));
    assert!(CANDIDATE_MODEL_SOURCE.contains("CandidateNamespacePlan"));
    assert!(CANDIDATE_MODEL_SOURCE.contains("CANDIDATE_ROLE"));
    assert!(!RECONSTRUCT_SOURCE.contains("use super::manifest"));
    assert!(!RECONSTRUCT_SOURCE.contains("use super::report_diff"));
    assert!(!RECONSTRUCT_SOURCE.contains("ContentChangeRegion"));
    assert!(!CLI_SOURCE.contains("reconstruct_session_model"));
    assert!(!ONE_WAY_PIPELINE_SOURCE.contains("reconstruct_session_model"));
    assert!(USAGE.contains("safeclone session apply"));
}

#[test]
fn candidate_runtime_is_plaintext_gated() {
    for anchor in [
        "BeforeApplyArmedCommit",
        "BeforeCandidateRootCreate",
        "BeforeApplyIncompleteCommit",
        "FirstSensitiveWrite",
        "ApplyResultManifestCommit",
        "BeforeAppliedCompleteCommit",
        "FinalVerification",
        "prepare_apply_reconstruction_model",
        "persist_next_apply_manifest",
        "append_apply_capsule_generation",
    ] {
        assert!(
            APPLY_SOURCE.contains(anchor),
            "candidate apply source missing lifecycle boundary: {anchor}"
        );
    }
    for anchor in [
        "CandidateRoot<PopulationAuthorized>",
        "stream_planned_original_file",
        "verify_six",
        "verify_existing_complete",
        "ApplyIncompleteAuthorization",
        "ApplyResultAuthorization",
    ] {
        assert!(
            CANDIDATE_SOURCE.contains(anchor),
            "candidate candidate source missing boundary: {anchor}"
        );
    }
    assert!(CANDIDATE_IDENTITY_SOURCE.contains("safeclone/rt1/candidate-volume-identity-v1"));
    assert!(CANDIDATE_IDENTITY_SOURCE.contains("safeclone/rt1/candidate-root-file-id-v1"));
    assert!(CANDIDATE_IDENTITY_SOURCE.contains("KeyPurpose::TreeCommit"));
    assert!(CANDIDATE_MARKER_SOURCE.contains("KeyPurpose::CandidateMarker"));
    assert!(CLI_SOURCE.contains("session apply"));
    assert!(USAGE.contains("safeclone session apply"));
    assert!(!ONE_WAY_PIPELINE_SOURCE.contains("apply_session"));
}

#[test]
fn cli_lifecycle_is_dispatch_only_and_raw_free() {
    for command in [
        "safeclone session create",
        "safeclone session status",
        "safeclone session review",
        "safeclone session approve",
        "safeclone session apply",
        "safeclone session close",
    ] {
        assert!(USAGE.contains(command));
        assert!(CLI_SOURCE.contains(command));
    }
    for dispatch in [
        "create_session(",
        "status_session(",
        "review_session(",
        "approve_review_event(",
        "apply_session(",
        "close_session(",
    ] {
        assert!(CLI_SOURCE.contains(dispatch));
    }
    for forbidden in [
        "GenerationStore",
        "ClosedTombstoneV1",
        "protect_closed_tombstone",
        "GetFileInformationByHandleEx",
        "FileIdInfo",
    ] {
        assert!(
            !CLI_SOURCE.contains(forbidden),
            "CLI must not own round-trip policy primitive: {forbidden}"
        );
    }

    for anchor in [
        "pub fn status_session",
        "GenerationStore::from_qualified_root",
        "store.read()",
        "StatusState::CreateIncomplete",
        "StatusState::PrivateOrphansPresent",
        "StatusState::Closed",
    ] {
        assert!(STATUS_SOURCE.contains(anchor));
    }
    for anchor in [
        "pub fn close_session",
        "acquire_mutation_lock",
        "read_while_locked",
        "constant_time_equal",
        "protect_closed_tombstone",
        "append_capsule_generation",
        "SensitiveCandidateState::ArmedUnknown",
    ] {
        assert!(CLOSE_SOURCE.contains(anchor));
    }

    for anchor in [
        "session_report_format=1",
        "SESSION_OUTPUT_WARNING",
        "CONFIDENTIAL_REVIEW_WARNING",
        "SENSITIVE_CANDIDATE_WARNING",
        "decode_base32_128",
        "INTENTIONAL_TOKEN_REMOVAL",
        "INTENTIONAL_FILE_DELETE",
        "STRICT_TOKEN_FILE_EDIT_REVIEWED",
    ] {
        assert!(CLI_SOURCE.contains(anchor));
    }
    assert!(!ONE_WAY_PIPELINE_SOURCE.contains("status_session"));
    assert!(!ONE_WAY_PIPELINE_SOURCE.contains("close_session"));
    assert!(!ONE_WAY_PIPELINE_SOURCE.contains("apply_session"));
}

#[test]
fn fresh_authority_boundaries_have_no_ordinary_equality_fallback() {
    let apply_normalized = normalized_source(APPLY_SOURCE);
    let approval_normalized = normalized_source(APPROVAL_SOURCE);
    let reconstruct_normalized = normalized_source(RECONSTRUCT_SOURCE);
    let review_normalized = normalized_source(REVIEW_SOURCE);

    for (source_name, source, signature, primitive) in [
        (
            "apply review",
            APPLY_SOURCE,
            "fn require_review_manifest_commitments(",
            "constant_time_equal(",
        ),
        (
            "apply completed",
            APPLY_SOURCE,
            "fn require_completed_apply_commitments(",
            "constant_time_equal_option_fixed(",
        ),
        (
            "approval",
            APPROVAL_SOURCE,
            "fn require_fresh_approval_commitments(",
            "constant_time_equal(",
        ),
        (
            "reconstruct final capsule",
            RECONSTRUCT_SOURCE,
            "fn require_final_capsule_tag(",
            "constant_time_equal(",
        ),
        (
            "review",
            REVIEW_SOURCE,
            "fn require_fresh_review_commitments(",
            "constant_time_equal(",
        ),
    ] {
        let body = named_function_body(source, signature);
        assert!(
            body.contains(primitive),
            "{source_name} authority guard no longer performs its constant-time verification"
        );
    }

    for (source_name, source, forbidden) in [
        (
            "apply",
            apply_normalized.as_str(),
            "manifest.edited_tree_commitment != model.authority.report.edited_tree_commitment",
        ),
        (
            "apply",
            apply_normalized.as_str(),
            "manifest.event_set_commitment != model.authority.event_set_commitment",
        ),
        (
            "apply",
            apply_normalized.as_str(),
            "apply.candidate_tree_commitment != Some(candidate_commitment)",
        ),
        (
            "apply",
            apply_normalized.as_str(),
            "apply.final_manifest_commitment !=",
        ),
        (
            "approval",
            approval_normalized.as_str(),
            "review.edited_tree_commitment != authority.report.edited_tree_commitment",
        ),
        (
            "approval",
            approval_normalized.as_str(),
            "review.event_set_commitment != authority.event_set_commitment",
        ),
        (
            "approval",
            approval_normalized.as_str(),
            "capsule.original_tree_commitment != authority.original_tree_commitment",
        ),
        (
            "reconstruct",
            reconstruct_normalized.as_str(),
            "final_live.tag() != authority.owner.tag()",
        ),
        (
            "review",
            review_normalized.as_str(),
            "current.edited_tree_commitment != authority.report.edited_tree_commitment",
        ),
        (
            "review",
            review_normalized.as_str(),
            "current.event_set_commitment != authority.event_set_commitment",
        ),
    ] {
        assert!(
            !source.contains(forbidden),
            "{source_name} reintroduced ordinary equality at fresh authority boundary: {forbidden}"
        );
    }

    let workspace_verifier =
        named_function_body(ROUNDTRIP_WORKSPACE_SOURCE, "fn verify_workspace_summary(");
    assert_eq!(
        workspace_verifier.matches("constant_time_equal(").count(),
        2
    );
    for structural_field in [
        "observed.entries == expected.entries",
        "observed.directories == expected.directories",
        "observed.regular_files == expected.regular_files",
        "observed.total_file_bytes == expected.total_file_bytes",
        "observed.token_occurrences == expected.token_occurrences",
    ] {
        assert!(
            workspace_verifier.contains(structural_field),
            "workspace verifier lost explicit structural check: {structural_field}"
        );
    }
    assert!(!workspace_verifier.contains("observed == expected"));
    assert!(!workspace_verifier.contains("observed != expected"));

    let anchor_verifier =
        named_function_body(ROUNDTRIP_BASELINE_SOURCE, "fn verify_content_anchor_facts(");
    assert_eq!(anchor_verifier.matches("constant_time_equal(").count(), 2);
    for structural_field in [
        "observed.anchor_version == expected.anchor_version",
        "observed.context_version == expected.context_version",
        "observed.selected_radius == expected.selected_radius",
    ] {
        assert!(
            anchor_verifier.contains(structural_field),
            "content-anchor verifier lost explicit structural check: {structural_field}"
        );
    }
    assert!(!anchor_verifier.contains("observed == expected"));
    assert!(!anchor_verifier.contains("observed != expected"));

    let occurrence_verifier = named_function_body(
        RECONSTRUCT_SOURCE,
        "fn verify_protected_occurrence_authority(",
    );
    assert!(occurrence_verifier.contains("constant_time_equal("));
    for signature in [
        "fn account_deleted_spans(",
        "fn authorize_occurrences<'path>(",
    ] {
        assert!(
            named_function_body(RECONSTRUCT_SOURCE, signature)
                .contains("verify_protected_occurrence_authority("),
            "reconstruction path lost protected-occurrence verification: {signature}"
        );
    }

    let indexed_verifier =
        named_function_body(CLASSIFY_SOURCE, "fn unique_constant_time_confirmed_path(");
    for required in [
        "constant_time_equal(query, &candidate.commitment)",
        "confirmed_count",
        "confirmed_count == 1",
    ] {
        assert!(
            indexed_verifier.contains(required),
            "indexed correspondence verifier lost confirmed-match logic: {required}"
        );
    }
    let pair_verifier = named_function_body(
        CLASSIFY_SOURCE,
        "fn unique_constant_time_confirmed_pair<'a>(",
    );
    assert_eq!(
        pair_verifier
            .matches("unique_constant_time_confirmed_path(")
            .count(),
        2,
        "pair uniqueness must come from confirmed cardinality on both sides"
    );
    for signature in [
        "fn pair_unique_token_free_directories(",
        "fn pair_unique_token_free_files(",
    ] {
        let body = named_function_body(CLASSIFY_SOURCE, signature);
        assert!(body.contains("CommitmentCandidateIndex::default()"));
        assert!(body.contains("unique_constant_time_confirmed_pair("));
        assert!(!body.contains("BTreeMap::<[u8; 32]"));
        assert!(!body.contains("after_groups.get("));
    }
}

#[test]
fn exact_diff_port_provenance_and_scope_are_fixed() {
    for anchor in [
        "src/algorithms/myers.rs",
        "0C10102279AD0946946DB9BD116A5BC0BD28C50C3C5BDF1ADCCED2F96B713177",
        "src/roundtrip/report_diff.rs",
        "third_party/licenses/similar-Apache-2.0.txt",
        "no `similar` Cargo dependency",
    ] {
        assert!(
            THIRD_PARTY.contains(anchor),
            "third-party record missing exact diff anchor: {anchor}"
        );
    }

    let license_hash: [u8; 32] = Sha256::digest(SIMILAR_LICENSE).into();
    assert_eq!(
        license_hash,
        [
            0xA6, 0x0E, 0xEA, 0x81, 0x75, 0x14, 0x53, 0x16, 0x68, 0xD7, 0xE0, 0x07, 0x65, 0x73,
            0x14, 0x49, 0xFE, 0x14, 0xD0, 0x59, 0xD3, 0x24, 0x9E, 0x0B, 0xC9, 0x3B, 0x36, 0xDE,
            0x45, 0xF7, 0x59, 0xF2,
        ]
    );
}
