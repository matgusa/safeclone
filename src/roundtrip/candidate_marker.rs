//! Exact authenticated sensitive-candidate root markers.

use data_encoding::BASE32_NOPAD;

use super::crypto::{constant_time_equal, hmac_tag, KeyPurpose, KeySchedule};
use super::observe::{CANDIDATE_COMPLETE_LEAF, CANDIDATE_INCOMPLETE_LEAF};
use super::token::{valid_ruleset_id, ENGINE_VERSION, POLICY_ID, TOKEN_SUITE_ID};
use super::{Error, Result};

const FORMAT: &str = "safeclone-sensitive-output-v1";
const MAX_MARKER_BYTES: usize = 1_024;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum CandidateMarkerState {
    Incomplete,
    Complete { candidate_commitment: [u8; 32] },
}

impl CandidateMarkerState {
    pub(super) const fn leaf(self) -> &'static str {
        match self {
            Self::Incomplete => CANDIDATE_INCOMPLETE_LEAF,
            Self::Complete { .. } => CANDIDATE_COMPLETE_LEAF,
        }
    }
}

pub(super) fn encode(
    schedule: &KeySchedule<'_>,
    apply_id: [u8; 16],
    ruleset_id: &str,
    state: CandidateMarkerState,
) -> Result<Vec<u8>> {
    if !valid_ruleset_id(ruleset_id) {
        return Err(Error::InvalidState);
    }
    let session_id = BASE32_NOPAD.encode(schedule.session_id().as_bytes());
    let apply_id = BASE32_NOPAD.encode(&apply_id);
    let mut body = String::new();
    body.try_reserve(MAX_MARKER_BYTES)
        .map_err(|_| Error::BoundExceeded)?;
    body.push_str("format=");
    body.push_str(FORMAT);
    body.push('\n');
    match state {
        CandidateMarkerState::Incomplete => body.push_str("state=INCOMPLETE\n"),
        CandidateMarkerState::Complete { .. } => body.push_str("state=COMPLETE\n"),
    }
    body.push_str("session_id=");
    body.push_str(&session_id);
    body.push('\n');
    body.push_str("apply_id=");
    body.push_str(&apply_id);
    body.push('\n');
    body.push_str("engine_version=");
    body.push_str(ENGINE_VERSION);
    body.push('\n');
    body.push_str("policy_id=");
    body.push_str(POLICY_ID);
    body.push('\n');
    body.push_str("ruleset_id=");
    body.push_str(ruleset_id);
    body.push('\n');
    body.push_str("token_suite_id=");
    body.push_str(&TOKEN_SUITE_ID.to_string());
    body.push('\n');
    if let CandidateMarkerState::Complete {
        candidate_commitment,
    } = state
    {
        body.push_str("candidate_commitment=");
        body.push_str(&BASE32_NOPAD.encode(&candidate_commitment));
        body.push('\n');
    }
    body.push_str(match state {
        CandidateMarkerState::Incomplete => "reconstruction_status=INCOMPLETE\n",
        CandidateMarkerState::Complete { .. } => "reconstruction_status=PASS\n",
    });
    body.push_str("semantic_safety_assessed=false\n");
    let key = schedule.derive(KeyPurpose::CandidateMarker)?;
    let auth = hmac_tag(&key, &[body.as_bytes()])?;
    body.push_str("auth=");
    body.push_str(&BASE32_NOPAD.encode(&auth));
    body.push('\n');
    if body.len() > MAX_MARKER_BYTES || !body.is_ascii() {
        return Err(Error::BoundExceeded);
    }
    Ok(body.into_bytes())
}

pub(super) fn authenticate_exact(
    actual: &[u8],
    schedule: &KeySchedule<'_>,
    apply_id: [u8; 16],
    ruleset_id: &str,
    state: CandidateMarkerState,
) -> Result<()> {
    if actual.len() > MAX_MARKER_BYTES {
        return Err(Error::CandidateMarkerAuthenticationFailed);
    }
    let expected = encode(schedule, apply_id, ruleset_id, state)
        .map_err(|_| Error::CandidateMarkerAuthenticationFailed)?;
    if constant_time_equal(actual, &expected) {
        Ok(())
    } else {
        Err(Error::CandidateMarkerAuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip::crypto::{SessionId, SessionMasterSecret};

    #[test]
    fn exact_markers_are_canonical_domain_separated_and_authenticated() {
        let master = SessionMasterSecret::from_bytes([0x51; 32]);
        let schedule = KeySchedule::new(&master, SessionId::from_bytes([0x52; 16]));
        let ruleset = crate::roundtrip::ruleset::ruleset_id();
        let incomplete = encode(
            &schedule,
            [0x53; 16],
            ruleset,
            CandidateMarkerState::Incomplete,
        )
        .expect("incomplete marker");
        let complete = encode(
            &schedule,
            [0x53; 16],
            ruleset,
            CandidateMarkerState::Complete {
                candidate_commitment: [0x54; 32],
            },
        )
        .expect("complete marker");
        assert_ne!(incomplete, complete);
        assert!(incomplete.ends_with(b"\n"));
        assert!(complete.ends_with(b"\n"));
        authenticate_exact(
            &incomplete,
            &schedule,
            [0x53; 16],
            ruleset,
            CandidateMarkerState::Incomplete,
        )
        .expect("authenticate incomplete");
        let mut corrupted = complete.clone();
        corrupted[0] ^= 1;
        assert_eq!(
            authenticate_exact(
                &corrupted,
                &schedule,
                [0x53; 16],
                ruleset,
                CandidateMarkerState::Complete {
                    candidate_commitment: [0x54; 32]
                }
            ),
            Err(Error::CandidateMarkerAuthenticationFailed)
        );
    }
}
