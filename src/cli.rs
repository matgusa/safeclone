//! Command-line parsing and dispatch. Core decisions live in other modules.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::pipeline::{
    self, CloneError, CloneFailureClass, CloneReport, CloneRequest, InspectReport, InspectRequest,
};
use crate::roundtrip::apply::{ApplyFailureState, ApplyPublicationState, ApplyReport};
use crate::roundtrip::approve::ApprovalOutcome;
use crate::roundtrip::close::{CloseDisposalGuidance, CloseFailure, CloseReport};
use crate::roundtrip::create::{AiPublicationState, CreateReport};
use crate::roundtrip::review::{ReviewOutcome, CONFIDENTIAL_REVIEW_WARNING};
use crate::roundtrip::schema::{ApplyState, ApprovalReason, SensitiveCandidateState, SessionState};
use crate::roundtrip::status::{SessionStatusReport, StatusManualAction, StatusState};
use crate::roundtrip::token::{
    decode_base32_128, encode_base32_128, encode_base32_256, ReviewProfile,
};
use crate::roundtrip::Error as RoundTripError;

const HELP: &str = "safeclone - local-only policy-relative workspace boundary\n\nUSAGE:\n    safeclone status\n    safeclone inspect <SOURCE_DIRECTORY>\n    safeclone clone <SOURCE_DIRECTORY> <OUTPUT_DIRECTORY>\n    safeclone session create <ORIGINAL> <AI_WORKSPACE> --state <PRIVATE_SESSION_DIRECTORY> [--profile standard-v2|strict-token-files-v2]\n    safeclone session status --state <PRIVATE_SESSION_DIRECTORY>\n    safeclone session review <ORIGINAL> <AI_WORKSPACE> --state <PRIVATE_SESSION_DIRECTORY> [--show-private-paths]\n    safeclone session approve <ORIGINAL> <AI_WORKSPACE> --state <PRIVATE_SESSION_DIRECTORY> --review-id <REVIEW_ID> --event-id <EVENT_ID> --reason-code <REASON_CODE>\n    safeclone session apply <ORIGINAL> <AI_WORKSPACE> <SENSITIVE_CANDIDATE> --state <PRIVATE_SESSION_DIRECTORY>\n    safeclone session close --state <PRIVATE_SESSION_DIRECTORY> [--acknowledge-incomplete <APPLY_ID>]\n\nCOMMANDS:\n    status     Show product capabilities and safety limits\n    inspect    Inventory, plan, validate content, and detect aggregate evidence\n    clone      Build, independently verify, and publish a policy-relative sanitized clone\n    session    Run the authenticated six-command Windows round-trip lifecycle\n\nROUND-TRIP SAFETY:\n    Session filesystem operations require qualifying local NTFS on Windows.\n    Review output is path-free by default; --show-private-paths is confidential.\n    Apply writes a sensitive plaintext candidate and never assesses semantic safety.\n    Close is logical retirement, not secure erase, and deletes no artifact.\n    Exit 3 means manual state; do not retry automatically.\n\nRELEASE FILESYSTEM SCOPE:\n    inspect and clone are currently supported only on qualifying local NTFS\n    volumes on Windows. On other platforms they reject before path access.\n    A boundary path containing an exact case-insensitive .git component is\n    rejected before locality queries or filesystem access.\n\nWINDOWS FAILURE RECOVERY:\n    After staging creation, a clone failure leaves unpublished staging for\n    manual inspection and exits 3. Do not retry automatically.\n\nOPTIONS:\n    -h, --help       Print help\n    -V, --version    Print version\n";

const SESSION_OUTPUT_WARNING: &str =
    "warning=session result is authoritative but its report could not be written";
const SENSITIVE_CANDIDATE_WARNING: &str =
    "warning=sensitive candidate contains reconstructed plaintext; semantic safety was not assessed";

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Help,
    Version,
    Status,
    Inspect(InspectRequest),
    Clone(CloneRequest),
    SessionCreate(SessionCreateRequest),
    SessionStatus(SessionStateRequest),
    SessionReview(SessionReviewRequest),
    SessionApprove(SessionApproveRequest),
    SessionApply(SessionApplyRequest),
    SessionClose(SessionCloseRequest),
}

#[derive(Debug, Eq, PartialEq)]
struct SessionCreateRequest {
    original: PathBuf,
    ai_workspace: PathBuf,
    private_state: PathBuf,
    profile: ReviewProfile,
}

#[derive(Debug, Eq, PartialEq)]
struct SessionStateRequest {
    private_state: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
struct SessionReviewRequest {
    original: PathBuf,
    ai_workspace: PathBuf,
    private_state: PathBuf,
    show_private_paths: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct SessionApproveRequest {
    original: PathBuf,
    ai_workspace: PathBuf,
    private_state: PathBuf,
    review_id: [u8; 16],
    event_id: [u8; 16],
    reason: ApprovalReason,
}

#[derive(Debug, Eq, PartialEq)]
struct SessionApplyRequest {
    original: PathBuf,
    ai_workspace: PathBuf,
    candidate: PathBuf,
    private_state: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
struct SessionCloseRequest {
    private_state: PathBuf,
    acknowledgement: Option<[u8; 16]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionUsageError {
    MissingCommand,
    UnknownCommand,
    MissingPositional,
    ExtraArgument,
    MissingState,
    DuplicateOption,
    UnknownOption,
    MissingOptionValue,
    InvalidOptionValue,
}

impl SessionUsageError {
    const fn code(self) -> &'static str {
        match self {
            Self::MissingCommand => "SESSION_COMMAND_MISSING",
            Self::UnknownCommand => "SESSION_COMMAND_UNKNOWN",
            Self::MissingPositional => "SESSION_POSITIONAL_MISSING",
            Self::ExtraArgument => "SESSION_ARGUMENT_UNEXPECTED",
            Self::MissingState => "SESSION_STATE_OPTION_MISSING",
            Self::DuplicateOption => "SESSION_OPTION_DUPLICATE",
            Self::UnknownOption => "SESSION_OPTION_UNKNOWN",
            Self::MissingOptionValue => "SESSION_OPTION_VALUE_MISSING",
            Self::InvalidOptionValue => "SESSION_OPTION_VALUE_INVALID",
        }
    }
}

enum ParseFailure {
    OneWay(String),
    Session(SessionUsageError),
}

pub fn run<I, S, O, E>(args: I, mut stdout: O, mut stderr: E) -> ExitCode
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
    O: Write,
    E: Write,
{
    match parse(args) {
        Ok(Command::Help) => write_success(&mut stdout, HELP),
        Ok(Command::Version) => write_success(
            &mut stdout,
            concat!("safeclone ", env!("CARGO_PKG_VERSION"), "\n"),
        ),
        Ok(Command::Status) => write_success(
            &mut stdout,
            &format!(
                "status_format=1\ninspect_enabled=true\nclone_enabled=true\nsanitization_enabled=true\npromotion_support=runtime-checked\nrelease_filesystem_scope=windows-local-ntfs\nfilesystem_commands_supported_on_this_platform={}\nnetwork=false\ntelemetry=false\nmaturity=experimental-mvp\n",
                cfg!(windows),
            ),
        ),
        Ok(Command::Inspect(request)) => match pipeline::execute_inspect(request) {
            Ok(report) => write_inspect_report(&mut stdout, report),
            Err(error) => write_error(&mut stderr, &error.to_string()),
        },
        Ok(Command::Clone(request)) => match pipeline::execute_clone(request) {
            Ok(report) => write_clone_success(&mut stdout, &mut stderr, report),
            Err(error) => write_clone_error(&mut stderr, &error),
        },
        Ok(Command::SessionCreate(request)) => {
            run_session_create(request, &mut stdout, &mut stderr)
        }
        Ok(Command::SessionStatus(request)) => {
            run_session_status(request, &mut stdout, &mut stderr)
        }
        Ok(Command::SessionReview(request)) => {
            run_session_review(request, &mut stdout, &mut stderr)
        }
        Ok(Command::SessionApprove(request)) => {
            run_session_approve(request, &mut stdout, &mut stderr)
        }
        Ok(Command::SessionApply(request)) => {
            run_session_apply(request, &mut stdout, &mut stderr)
        }
        Ok(Command::SessionClose(request)) => {
            run_session_close(request, &mut stdout, &mut stderr)
        }
        Err(ParseFailure::OneWay(message)) => write_error(&mut stderr, &message),
        Err(ParseFailure::Session(error)) => {
            write_session_diagnostic(&mut stderr, error.code(), None, ExitCode::from(2))
        }
    }
}

fn parse<I, S>(args: I) -> Result<Command, ParseFailure>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut args = args.into_iter().map(Into::into);
    let Some(first) = args.next() else {
        return Ok(Command::Help);
    };

    match first.to_str() {
        Some("-h" | "--help" | "help") => no_extra_args(args, Command::Help),
        Some("-V" | "--version") => no_extra_args(args, Command::Version),
        Some("status") => no_extra_args(args, Command::Status),
        Some("inspect") => {
            let source =
                required_path(args.next(), "SOURCE_DIRECTORY").map_err(ParseFailure::OneWay)?;
            if args.next().is_some() {
                return Err(ParseFailure::OneWay(
                    "inspect accepts exactly one path".to_owned(),
                ));
            }
            Ok(Command::Inspect(InspectRequest { source }))
        }
        Some("clone") => {
            let source =
                required_path(args.next(), "SOURCE_DIRECTORY").map_err(ParseFailure::OneWay)?;
            let output =
                required_path(args.next(), "OUTPUT_DIRECTORY").map_err(ParseFailure::OneWay)?;
            if args.next().is_some() {
                return Err(ParseFailure::OneWay(
                    "clone accepts exactly two paths".to_owned(),
                ));
            }
            Ok(Command::Clone(CloneRequest { source, output }))
        }
        Some("session") => parse_session(args.collect()),
        Some(command) => Err(ParseFailure::OneWay(format!("unknown command: {command}"))),
        None => Err(ParseFailure::OneWay(
            "command must be valid Unicode".to_owned(),
        )),
    }
}

fn no_extra_args(
    mut args: impl Iterator<Item = OsString>,
    command: Command,
) -> Result<Command, ParseFailure> {
    if args.next().is_some() {
        Err(ParseFailure::OneWay("unexpected argument".to_owned()))
    } else {
        Ok(command)
    }
}

fn required_path(value: Option<OsString>, name: &str) -> Result<PathBuf, String> {
    value
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing required argument: {name}"))
}

fn parse_session(args: Vec<OsString>) -> Result<Command, ParseFailure> {
    let subcommand = args
        .first()
        .and_then(|value| value.to_str())
        .ok_or(ParseFailure::Session(SessionUsageError::MissingCommand))?;
    let result = match subcommand {
        "create" => parse_session_create(&args),
        "status" => parse_session_status(&args),
        "review" => parse_session_review(&args),
        "approve" => parse_session_approve(&args),
        "apply" => parse_session_apply(&args),
        "close" => parse_session_close(&args),
        _ => Err(SessionUsageError::UnknownCommand),
    };
    result.map_err(ParseFailure::Session)
}

fn parse_session_create(args: &[OsString]) -> Result<Command, SessionUsageError> {
    let original = positional_path(args, 1)?;
    let ai_workspace = positional_path(args, 2)?;
    let mut private_state = None;
    let mut profile = None;
    let mut index = 3;
    while index < args.len() {
        if option_is(&args[index], "--state") {
            set_once_path(&mut private_state, option_value(args, &mut index)?)?;
        } else if option_is(&args[index], "--profile") {
            let value = option_text(args, &mut index)?;
            let parsed = match value {
                "standard-v2" => ReviewProfile::StandardV2,
                "strict-token-files-v2" => ReviewProfile::StrictTokenFilesV2,
                _ => return Err(SessionUsageError::InvalidOptionValue),
            };
            if profile.replace(parsed).is_some() {
                return Err(SessionUsageError::DuplicateOption);
            }
        } else {
            return Err(classify_trailing(&args[index]));
        }
        index += 1;
    }
    Ok(Command::SessionCreate(SessionCreateRequest {
        original,
        ai_workspace,
        private_state: private_state.ok_or(SessionUsageError::MissingState)?,
        profile: profile.unwrap_or(ReviewProfile::StandardV2),
    }))
}

fn parse_session_status(args: &[OsString]) -> Result<Command, SessionUsageError> {
    let mut private_state = None;
    let mut index = 1;
    while index < args.len() {
        if option_is(&args[index], "--state") {
            set_once_path(&mut private_state, option_value(args, &mut index)?)?;
        } else {
            return Err(classify_trailing(&args[index]));
        }
        index += 1;
    }
    Ok(Command::SessionStatus(SessionStateRequest {
        private_state: private_state.ok_or(SessionUsageError::MissingState)?,
    }))
}

fn parse_session_review(args: &[OsString]) -> Result<Command, SessionUsageError> {
    let original = positional_path(args, 1)?;
    let ai_workspace = positional_path(args, 2)?;
    let mut private_state = None;
    let mut show_private_paths = false;
    let mut index = 3;
    while index < args.len() {
        if option_is(&args[index], "--state") {
            set_once_path(&mut private_state, option_value(args, &mut index)?)?;
        } else if option_is(&args[index], "--show-private-paths") {
            if show_private_paths {
                return Err(SessionUsageError::DuplicateOption);
            }
            show_private_paths = true;
        } else {
            return Err(classify_trailing(&args[index]));
        }
        index += 1;
    }
    Ok(Command::SessionReview(SessionReviewRequest {
        original,
        ai_workspace,
        private_state: private_state.ok_or(SessionUsageError::MissingState)?,
        show_private_paths,
    }))
}

fn parse_session_approve(args: &[OsString]) -> Result<Command, SessionUsageError> {
    let original = positional_path(args, 1)?;
    let ai_workspace = positional_path(args, 2)?;
    let mut private_state = None;
    let mut review_id = None;
    let mut event_id = None;
    let mut reason = None;
    let mut index = 3;
    while index < args.len() {
        if option_is(&args[index], "--state") {
            set_once_path(&mut private_state, option_value(args, &mut index)?)?;
        } else if option_is(&args[index], "--review-id") {
            set_once_id(&mut review_id, parse_id(option_text(args, &mut index)?)?)?;
        } else if option_is(&args[index], "--event-id") {
            set_once_id(&mut event_id, parse_id(option_text(args, &mut index)?)?)?;
        } else if option_is(&args[index], "--reason-code") {
            let parsed = parse_reason(option_text(args, &mut index)?)?;
            if reason.replace(parsed).is_some() {
                return Err(SessionUsageError::DuplicateOption);
            }
        } else {
            return Err(classify_trailing(&args[index]));
        }
        index += 1;
    }
    Ok(Command::SessionApprove(SessionApproveRequest {
        original,
        ai_workspace,
        private_state: private_state.ok_or(SessionUsageError::MissingState)?,
        review_id: review_id.ok_or(SessionUsageError::InvalidOptionValue)?,
        event_id: event_id.ok_or(SessionUsageError::InvalidOptionValue)?,
        reason: reason.ok_or(SessionUsageError::InvalidOptionValue)?,
    }))
}

fn parse_session_apply(args: &[OsString]) -> Result<Command, SessionUsageError> {
    let original = positional_path(args, 1)?;
    let ai_workspace = positional_path(args, 2)?;
    let candidate = positional_path(args, 3)?;
    let mut private_state = None;
    let mut index = 4;
    while index < args.len() {
        if option_is(&args[index], "--state") {
            set_once_path(&mut private_state, option_value(args, &mut index)?)?;
        } else {
            return Err(classify_trailing(&args[index]));
        }
        index += 1;
    }
    Ok(Command::SessionApply(SessionApplyRequest {
        original,
        ai_workspace,
        candidate,
        private_state: private_state.ok_or(SessionUsageError::MissingState)?,
    }))
}

fn parse_session_close(args: &[OsString]) -> Result<Command, SessionUsageError> {
    let mut private_state = None;
    let mut acknowledgement = None;
    let mut index = 1;
    while index < args.len() {
        if option_is(&args[index], "--state") {
            set_once_path(&mut private_state, option_value(args, &mut index)?)?;
        } else if option_is(&args[index], "--acknowledge-incomplete") {
            set_once_id(
                &mut acknowledgement,
                parse_id(option_text(args, &mut index)?)?,
            )?;
        } else {
            return Err(classify_trailing(&args[index]));
        }
        index += 1;
    }
    Ok(Command::SessionClose(SessionCloseRequest {
        private_state: private_state.ok_or(SessionUsageError::MissingState)?,
        acknowledgement,
    }))
}

fn positional_path(args: &[OsString], index: usize) -> Result<PathBuf, SessionUsageError> {
    args.get(index)
        .cloned()
        .map(PathBuf::from)
        .ok_or(SessionUsageError::MissingPositional)
}

fn option_is(value: &OsStr, expected: &str) -> bool {
    value == OsStr::new(expected)
}

fn option_value<'a>(
    args: &'a [OsString],
    index: &mut usize,
) -> Result<&'a OsString, SessionUsageError> {
    *index = index
        .checked_add(1)
        .ok_or(SessionUsageError::MissingOptionValue)?;
    let value = args
        .get(*index)
        .ok_or(SessionUsageError::MissingOptionValue)?;
    if value.to_str().is_some_and(|text| text.starts_with("--")) {
        return Err(SessionUsageError::MissingOptionValue);
    }
    Ok(value)
}

fn option_text<'a>(args: &'a [OsString], index: &mut usize) -> Result<&'a str, SessionUsageError> {
    option_value(args, index)?
        .to_str()
        .ok_or(SessionUsageError::InvalidOptionValue)
}

fn set_once_path(slot: &mut Option<PathBuf>, value: &OsStr) -> Result<(), SessionUsageError> {
    if slot.replace(PathBuf::from(value)).is_some() {
        Err(SessionUsageError::DuplicateOption)
    } else {
        Ok(())
    }
}

fn set_once_id(slot: &mut Option<[u8; 16]>, value: [u8; 16]) -> Result<(), SessionUsageError> {
    if slot.replace(value).is_some() {
        Err(SessionUsageError::DuplicateOption)
    } else {
        Ok(())
    }
}

fn parse_id(value: &str) -> Result<[u8; 16], SessionUsageError> {
    decode_base32_128(value).map_err(|_| SessionUsageError::InvalidOptionValue)
}

fn parse_reason(value: &str) -> Result<ApprovalReason, SessionUsageError> {
    match value {
        "INTENTIONAL_TOKEN_REMOVAL" => Ok(ApprovalReason::IntentionalTokenRemoval),
        "INTENTIONAL_FILE_DELETE" => Ok(ApprovalReason::IntentionalFileDelete),
        "STRICT_TOKEN_FILE_EDIT_REVIEWED" => Ok(ApprovalReason::StrictTokenFileEditReviewed),
        _ => Err(SessionUsageError::InvalidOptionValue),
    }
}

fn classify_trailing(value: &OsStr) -> SessionUsageError {
    if value.to_str().is_some_and(|text| text.starts_with("--")) {
        SessionUsageError::UnknownOption
    } else {
        SessionUsageError::ExtraArgument
    }
}

fn run_session_create(
    request: SessionCreateRequest,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> ExitCode {
    match crate::roundtrip::create::create_session(
        &request.original,
        &request.ai_workspace,
        &request.private_state,
        request.profile,
    ) {
        Ok(report) => {
            write_session_report(stdout, stderr, &render_create(&report), ExitCode::SUCCESS)
        }
        Err(crate::roundtrip::create::CreateFailure::DefiniteFailure(error)) => {
            write_roundtrip_error(stderr, error, None, ExitCode::from(2))
        }
        Err(crate::roundtrip::create::CreateFailure::ManualInspectionRequired(error)) => {
            write_roundtrip_error(
                stderr,
                error,
                Some(manual_action_for_error(error)),
                ExitCode::from(3),
            )
        }
    }
}

fn run_session_status(
    request: SessionStateRequest,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> ExitCode {
    match crate::roundtrip::status::status_session(&request.private_state) {
        Ok(report) => {
            let semantic = status_manual_action_exit(report.manual_action);
            write_session_report(stdout, stderr, &render_status(&report), semantic)
        }
        Err(error) => write_roundtrip_error(stderr, error.error(), None, ExitCode::from(2)),
    }
}

fn run_session_review(
    request: SessionReviewRequest,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> ExitCode {
    let outcome = match crate::roundtrip::review::review_session(
        &request.original,
        &request.ai_workspace,
        &request.private_state,
    ) {
        Ok(outcome) => outcome,
        Err(crate::roundtrip::review::ReviewFailure::DefiniteFailure(error)) => {
            return write_roundtrip_error(stderr, error, None, ExitCode::from(2));
        }
        Err(crate::roundtrip::review::ReviewFailure::ManualInspectionRequired(error)) => {
            return write_roundtrip_error(
                stderr,
                error,
                Some(manual_action_for_error(error)),
                ExitCode::from(3),
            );
        }
    };
    let semantic = review_semantic_exit(&outcome);
    if request.show_private_paths {
        return write_private_review(outcome, stdout, stderr, semantic);
    }
    let rendered = format!(
        "session_report_format=1\ncommand=REVIEW\n{}",
        outcome.render_default()
    );
    write_session_report(stdout, stderr, &rendered, semantic)
}

fn run_session_approve(
    request: SessionApproveRequest,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> ExitCode {
    match crate::roundtrip::approve::approve_review_event(
        &request.original,
        &request.ai_workspace,
        &request.private_state,
        request.review_id,
        request.event_id,
        request.reason,
    ) {
        Ok(report) => {
            write_session_report(stdout, stderr, &render_approval(&report), ExitCode::SUCCESS)
        }
        Err(crate::roundtrip::approve::ApprovalFailure::DefiniteFailure(error)) => {
            write_roundtrip_error(stderr, error, None, ExitCode::from(2))
        }
        Err(crate::roundtrip::approve::ApprovalFailure::ManualInspectionRequired(error)) => {
            write_roundtrip_error(
                stderr,
                error,
                Some(manual_action_for_error(error)),
                ExitCode::from(3),
            )
        }
    }
}

fn run_session_apply(
    request: SessionApplyRequest,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> ExitCode {
    match crate::roundtrip::apply::apply_session(
        &request.original,
        &request.ai_workspace,
        &request.private_state,
        &request.candidate,
    ) {
        Ok(report) => {
            let _ = write_fixed_line(stderr, SENSITIVE_CANDIDATE_WARNING);
            write_session_report(stdout, stderr, &render_apply(&report), ExitCode::SUCCESS)
        }
        Err(failure) => {
            let (exit, manual) = apply_failure_state_exit(failure.state());
            write_roundtrip_error(stderr, failure.error(), manual, exit)
        }
    }
}

fn run_session_close(
    request: SessionCloseRequest,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> ExitCode {
    match crate::roundtrip::close::close_session(&request.private_state, request.acknowledgement) {
        Ok(report) => {
            write_session_report(stdout, stderr, &render_close(&report), ExitCode::SUCCESS)
        }
        Err(failure @ CloseFailure::DefiniteFailure(error)) => {
            write_roundtrip_error(stderr, error, None, close_failure_exit(failure))
        }
        Err(failure @ CloseFailure::AcknowledgementRequired) => write_session_diagnostic(
            stderr,
            "CLOSE_ACKNOWLEDGEMENT_REQUIRED",
            Some("ACKNOWLEDGE_INCOMPLETE_APPLY"),
            close_failure_exit(failure),
        ),
        Err(failure @ CloseFailure::AcknowledgementMismatch) => write_session_diagnostic(
            stderr,
            "CLOSE_ACKNOWLEDGEMENT_MISMATCH",
            None,
            close_failure_exit(failure),
        ),
        Err(failure @ CloseFailure::AcknowledgementNotAllowed) => write_session_diagnostic(
            stderr,
            "CLOSE_ACKNOWLEDGEMENT_NOT_ALLOWED",
            None,
            close_failure_exit(failure),
        ),
        Err(failure @ CloseFailure::ManualInspectionRequired(error)) => write_roundtrip_error(
            stderr,
            error,
            Some(manual_action_for_error(error)),
            close_failure_exit(failure),
        ),
    }
}

fn status_manual_action_exit(action: StatusManualAction) -> ExitCode {
    match action {
        StatusManualAction::None => ExitCode::SUCCESS,
        StatusManualAction::CreateIncomplete
        | StatusManualAction::PrivateOrphansPresent
        | StatusManualAction::ApplyArmed
        | StatusManualAction::ApplyIncomplete => ExitCode::from(3),
    }
}

fn apply_failure_state_exit(state: ApplyFailureState) -> (ExitCode, Option<&'static str>) {
    match state {
        ApplyFailureState::DefinitePreCandidate | ApplyFailureState::DisarmedReadyToApply => {
            (ExitCode::from(2), None)
        }
        ApplyFailureState::ManualIncomplete => {
            (ExitCode::from(3), Some("CANDIDATE_MANUAL_INCOMPLETE"))
        }
        ApplyFailureState::StateCommitUncertain => {
            (ExitCode::from(3), Some("STATE_COMMIT_UNCERTAIN"))
        }
    }
}

fn close_failure_exit(failure: CloseFailure) -> ExitCode {
    match failure {
        CloseFailure::DefiniteFailure(_)
        | CloseFailure::AcknowledgementMismatch
        | CloseFailure::AcknowledgementNotAllowed => ExitCode::from(2),
        CloseFailure::AcknowledgementRequired | CloseFailure::ManualInspectionRequired(_) => {
            ExitCode::from(3)
        }
    }
}

fn review_semantic_exit(outcome: &ReviewOutcome) -> ExitCode {
    review_state_semantic_exit(outcome.report().session_state)
}

fn review_state_semantic_exit(state: SessionState) -> ExitCode {
    match state {
        SessionState::ReviewedRejected => ExitCode::from(2),
        SessionState::Reviewed | SessionState::ApprovedPartial | SessionState::ReadyToApply => {
            ExitCode::SUCCESS
        }
        SessionState::ActiveUnreviewed
        | SessionState::ApplyArmed
        | SessionState::ApplyIncomplete
        | SessionState::AppliedComplete => ExitCode::from(2),
    }
}

fn write_private_review(
    outcome: ReviewOutcome,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    semantic: ExitCode,
) -> ExitCode {
    let gate = outcome.prepare_private_review();
    if write_fixed_line(stderr, gate.warning()).is_err() {
        return semantic;
    }
    let permit = match gate.acknowledge_warning(CONFIDENTIAL_REVIEW_WARNING) {
        Ok(permit) => permit,
        Err(_) => return semantic,
    };
    let rendered = format!(
        "session_report_format=1\ncommand=REVIEW\n{}",
        permit.render_private_paths()
    );
    write_session_report(stdout, stderr, &rendered, semantic)
}

fn render_create(report: &CreateReport) -> String {
    let counts = &report.baseline_counts;
    format!(
        "session_report_format=1\ncommand=CREATE\nsession_id={}\nprofile={}\nengine_version={}\npolicy_id={}\nruleset_id={}\ntoken_suite_id={}\ncapsule_generation={}\nsession_state={}\nai_publication={}\nentries={}\ndirectories={}\nregular_files={}\nbytes={}\nai_visible_files={}\nomitted_files={}\ntoken_occurrences={}\ntoken_bearing_files={}\nsemantic_safety_assessed=false\nreplayed={}\n",
        report.session_id,
        report.profile.external_label(),
        report.engine_version,
        report.policy_id,
        report.ruleset_id,
        report.token_suite_id,
        report.capsule_generation,
        session_state_label(report.session_state),
        match report.ai_publication {
            AiPublicationState::Published => "PUBLISHED",
        },
        counts.entries,
        counts.directories,
        counts.regular_files,
        counts.total_file_bytes,
        counts.ai_visible_files,
        counts.omitted_files,
        counts.token_occurrences,
        counts.token_bearing_files,
        report.replayed,
    )
}

fn render_status(report: &SessionStatusReport) -> String {
    format!(
        "session_report_format=1\ncommand=STATUS\nsession_id={}\nsession_state={}\nauthenticated_live_state={}\nprofile={}\ncapsule_generation={}\nengine_version={}\npolicy_id={}\nruleset_id={}\ntoken_suite_id={}\nreview_id={}\napproved_event_count={}\napproval_required_count={}\nprivate_orphan_count={}\nmanifest_count={}\napply_id={}\napply_state={}\nlast_nonclosed_state={}\nretained_capsule_generations={}\nretained_manifests={}\nretained_private_orphans={}\nsensitive_candidate_state={}\nincomplete_apply_acknowledged={}\nsemantic_safety_assessed=false\nmanual_action={}\n",
        report.session_id.as_deref().unwrap_or("none"),
        status_state_label(report.session_state),
        report.authenticated_live_state.map(session_state_label).unwrap_or("none"),
        report.review_profile.map(ReviewProfile::external_label).unwrap_or("none"),
        optional_u64(report.capsule_generation),
        report.engine_version.unwrap_or("none"),
        report.policy_id.unwrap_or("none"),
        report.ruleset_id.as_deref().unwrap_or("none"),
        optional_u16(report.token_suite_id),
        report.current_review_id.as_deref().unwrap_or("none"),
        report.approved_event_count,
        report.approval_required_count,
        report.private_orphan_count,
        report.manifest_count,
        report.apply_id.as_deref().unwrap_or("none"),
        report.apply_state.map(apply_state_label).unwrap_or("none"),
        report.last_nonclosed_state.map(session_state_label).unwrap_or("none"),
        optional_u32(report.retained_capsule_generation_count),
        optional_u32(report.retained_manifest_count),
        optional_u32(report.retained_private_orphan_count),
        report.sensitive_candidate_state.map(sensitive_candidate_state_label).unwrap_or("none"),
        optional_bool(report.incomplete_apply_acknowledged),
        status_manual_action_label(report.manual_action),
    )
}

fn render_approval(report: &ApprovalOutcome) -> String {
    format!(
        "session_report_format=1\ncommand=APPROVE\nsession_id={}\nreview_id={}\nevent_id={}\nreason_code={}\ncapsule_generation={}\nsession_state={}\napproved_count={}\nremaining_required_count={}\nduplicate={}\nsemantic_safety_assessed=false\n",
        report.session_id,
        report.review_id,
        report.event_id,
        approval_reason_label(report.reason),
        report.capsule_generation,
        session_state_label(report.session_state),
        report.approved_count,
        report.remaining_required_count,
        report.duplicate,
    )
}

fn render_apply(report: &ApplyReport) -> String {
    format!(
        "session_report_format=1\ncommand=APPLY\napply_id={}\npublication_state={}\ncandidate_commitment={}\ncandidate_entries={}\npreserved_original_only_files={}\npreserved_original_only_bytes={}\nsemantic_safety_assessed=false\n",
        encode_base32_128(&report.apply_id),
        match report.state {
            ApplyPublicationState::AppliedComplete => "APPLIED_COMPLETE",
            ApplyPublicationState::CompletedReplay => "COMPLETED_REPLAY",
            ApplyPublicationState::SplitCommitRecovered => "SPLIT_COMMIT_RECOVERED",
        },
        encode_base32_256(&report.candidate_tree_commitment),
        report.candidate_entries,
        report.preserved_original_only_files,
        report.preserved_original_only_bytes,
    )
}

fn render_close(report: &CloseReport) -> String {
    format!(
        "session_report_format=1\ncommand=CLOSE\nsession_id={}\nstate=CLOSED\ngeneration={}\nlast_nonclosed_state={}\nretained_capsule_generations={}\nretained_manifests={}\nretained_private_orphans={}\nsensitive_candidate_state={}\nincomplete_apply_acknowledged={}\nsemantic_safety_assessed=false\nsecure_erase_performed=false\nartifacts_deleted=false\ndisposal_guidance={}\nreplayed={}\n",
        report.session_id,
        report.generation,
        session_state_label(report.last_nonclosed_state),
        report.retained_capsule_generations,
        report.retained_manifests,
        report.retained_private_orphans,
        sensitive_candidate_state_label(report.sensitive_candidate_state),
        report.incomplete_apply_acknowledged,
        match report.disposal_guidance {
            CloseDisposalGuidance::RetainedArtifactsRequireUserDisposition => {
                "RETAINED_ARTIFACTS_REQUIRE_USER_DISPOSITION"
            }
        },
        report.replayed,
    )
}

fn write_session_report(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    report: &str,
    semantic: ExitCode,
) -> ExitCode {
    if stdout
        .write_all(report.as_bytes())
        .and_then(|()| stdout.flush())
        .is_err()
    {
        let _ = write_fixed_line(stderr, SESSION_OUTPUT_WARNING);
    }
    semantic
}

fn write_fixed_line(output: &mut impl Write, line: &str) -> std::io::Result<()> {
    output.write_all(line.as_bytes())?;
    output.write_all(b"\n")?;
    output.flush()
}

fn write_roundtrip_error(
    output: &mut impl Write,
    error: RoundTripError,
    manual_action: Option<&'static str>,
    semantic: ExitCode,
) -> ExitCode {
    write_session_diagnostic(output, roundtrip_error_code(error), manual_action, semantic)
}

fn write_session_diagnostic(
    output: &mut impl Write,
    error_code: &'static str,
    manual_action: Option<&'static str>,
    semantic: ExitCode,
) -> ExitCode {
    let mut diagnostic = format!("error_code={error_code}\n");
    if let Some(action) = manual_action {
        diagnostic.push_str("manual_action=");
        diagnostic.push_str(action);
        diagnostic.push('\n');
    }
    let _ = output
        .write_all(diagnostic.as_bytes())
        .and_then(|()| output.flush());
    semantic
}

const fn roundtrip_error_code(error: RoundTripError) -> &'static str {
    match error {
        RoundTripError::UnsupportedPlatform => "UNSUPPORTED_PLATFORM",
        RoundTripError::RandomGenerationFailed => "RANDOM_GENERATION_FAILED",
        RoundTripError::KeyDerivationFailed => "KEY_DERIVATION_FAILED",
        RoundTripError::AuthenticationFailed => "AUTHENTICATION_FAILED",
        RoundTripError::InvalidCanonicalInput => "INVALID_CANONICAL_INPUT",
        RoundTripError::BoundExceeded => "BOUND_EXCEEDED",
        RoundTripError::ChangeReportBoundExceeded => "CHANGE_REPORT_BOUND_EXCEEDED",
        RoundTripError::AnchorAmbiguous => "ANCHOR_AMBIGUOUS",
        RoundTripError::AnchorResourceLimitExceeded => "ANCHOR_RESOURCE_LIMIT_EXCEEDED",
        RoundTripError::AnchorEncodingInvalid => "ANCHOR_ENCODING_INVALID",
        RoundTripError::InvalidToken => "INVALID_TOKEN",
        RoundTripError::InvalidEnvelope => "INVALID_ENVELOPE",
        RoundTripError::InvalidSchema => "INVALID_SCHEMA",
        RoundTripError::InvalidState => "INVALID_STATE",
        RoundTripError::DpapiFailed => "DPAPI_FAILED",
        RoundTripError::FilesystemFailure => "FILESYSTEM_FAILURE",
        RoundTripError::LockContention => "LOCK_CONTENTION",
        RoundTripError::PrivateOrphansPresent => "PRIVATE_ORPHANS_PRESENT",
        RoundTripError::CreateIncomplete => "CREATE_INCOMPLETE",
        RoundTripError::UnsupportedAliasNamespace => "UNSUPPORTED_ALIAS_NAMESPACE",
        RoundTripError::AliasNamespaceAmbiguous => "ALIAS_NAMESPACE_AMBIGUOUS",
        RoundTripError::AliasIdentityMismatch => "ALIAS_IDENTITY_MISMATCH",
        RoundTripError::CaseSensitiveDirectoryUnsupported => "CASE_SENSITIVE_DIRECTORY_UNSUPPORTED",
        RoundTripError::PersistentVolumeQueryFailed => "PERSISTENT_VOLUME_QUERY_FAILED",
        RoundTripError::PersistentVolumeStateAmbiguous => "PERSISTENT_VOLUME_STATE_AMBIGUOUS",
        RoundTripError::StateCommitUncertain => "STATE_COMMIT_UNCERTAIN",
        RoundTripError::CorruptState => "CORRUPT_STATE",
        RoundTripError::CreateConflict => "CREATE_CONFLICT",
        RoundTripError::OriginalWorkspaceRejected => "ORIGINAL_WORKSPACE_REJECTED",
        RoundTripError::WorkspaceVerificationFailed => "WORKSPACE_VERIFICATION_FAILED",
        RoundTripError::WorkspaceUnstable => "WORKSPACE_UNSTABLE",
        RoundTripError::OriginalBaselineMismatch => "ORIGINAL_BASELINE_MISMATCH",
        RoundTripError::UnsafeWorkspaceOverlap => "UNSAFE_WORKSPACE_OVERLAP",
        RoundTripError::ApprovalStale => "APPROVAL_STALE",
        RoundTripError::ApprovalEventInvalid => "APPROVAL_EVENT_INVALID",
        RoundTripError::ApprovalEventIneligible => "APPROVAL_EVENT_INELIGIBLE",
        RoundTripError::ApprovalReasonMismatch => "APPROVAL_REASON_MISMATCH",
        RoundTripError::ApprovalConflict => "APPROVAL_CONFLICT",
        RoundTripError::ReconstructionRejected => "RECONSTRUCTION_REJECTED",
        RoundTripError::ProjectedRetokenizationMismatch => "PROJECTED_RETOKENIZATION_MISMATCH",
        RoundTripError::OccurrenceGraphMismatch => "OCCURRENCE_GRAPH_MISMATCH",
        RoundTripError::CandidateNamespaceCollision => "CANDIDATE_NAMESPACE_COLLISION",
        RoundTripError::CandidateVolumeIdentityMismatch => "CANDIDATE_VOLUME_IDENTITY_MISMATCH",
        RoundTripError::CandidateRootIdentityMismatch => "CANDIDATE_ROOT_IDENTITY_MISMATCH",
        RoundTripError::CandidateMarkerAuthenticationFailed => {
            "CANDIDATE_MARKER_AUTHENTICATION_FAILED"
        }
        RoundTripError::CandidateVerificationFailed => "CANDIDATE_VERIFICATION_FAILED",
        RoundTripError::CandidateIncomplete => "CANDIDATE_INCOMPLETE",
    }
}

const fn manual_action_for_error(error: RoundTripError) -> &'static str {
    match error {
        RoundTripError::CreateIncomplete => "CREATE_INCOMPLETE",
        RoundTripError::PrivateOrphansPresent => "PRIVATE_ORPHANS_PRESENT",
        RoundTripError::StateCommitUncertain => "STATE_COMMIT_UNCERTAIN",
        RoundTripError::CandidateIncomplete => "CANDIDATE_MANUAL_INCOMPLETE",
        _ => "DO_NOT_RETRY_AUTOMATICALLY",
    }
}

const fn session_state_label(state: SessionState) -> &'static str {
    match state {
        SessionState::ActiveUnreviewed => "ACTIVE_UNREVIEWED",
        SessionState::ReviewedRejected => "REVIEWED_REJECTED",
        SessionState::Reviewed => "REVIEWED",
        SessionState::ApprovedPartial => "APPROVED_PARTIAL",
        SessionState::ReadyToApply => "READY_TO_APPLY",
        SessionState::ApplyArmed => "APPLY_ARMED",
        SessionState::ApplyIncomplete => "APPLY_INCOMPLETE",
        SessionState::AppliedComplete => "APPLIED_COMPLETE",
    }
}

const fn status_state_label(state: StatusState) -> &'static str {
    match state {
        StatusState::CreateIncomplete => "CREATE_INCOMPLETE",
        StatusState::ActiveUnreviewed => "ACTIVE_UNREVIEWED",
        StatusState::ReviewedRejected => "REVIEWED_REJECTED",
        StatusState::Reviewed => "REVIEWED",
        StatusState::ApprovedPartial => "APPROVED_PARTIAL",
        StatusState::ReadyToApply => "READY_TO_APPLY",
        StatusState::ApplyArmed => "APPLY_ARMED",
        StatusState::ApplyIncomplete => "APPLY_INCOMPLETE",
        StatusState::AppliedComplete => "APPLIED_COMPLETE",
        StatusState::PrivateOrphansPresent => "PRIVATE_ORPHANS_PRESENT",
        StatusState::Closed => "CLOSED",
    }
}

const fn status_manual_action_label(action: StatusManualAction) -> &'static str {
    match action {
        StatusManualAction::None => "NONE",
        StatusManualAction::CreateIncomplete => "CREATE_INCOMPLETE",
        StatusManualAction::PrivateOrphansPresent => "PRIVATE_ORPHANS_PRESENT",
        StatusManualAction::ApplyArmed => "APPLY_ARMED",
        StatusManualAction::ApplyIncomplete => "APPLY_INCOMPLETE",
    }
}

const fn apply_state_label(state: ApplyState) -> &'static str {
    match state {
        ApplyState::Armed => "ARMED",
        ApplyState::Incomplete => "INCOMPLETE",
        ApplyState::Complete => "COMPLETE",
    }
}

const fn sensitive_candidate_state_label(state: SensitiveCandidateState) -> &'static str {
    match state {
        SensitiveCandidateState::None => "NONE",
        SensitiveCandidateState::ArmedUnknown => "ARMED_UNKNOWN",
        SensitiveCandidateState::Incomplete => "INCOMPLETE",
        SensitiveCandidateState::Complete => "COMPLETE",
    }
}

const fn approval_reason_label(reason: ApprovalReason) -> &'static str {
    match reason {
        ApprovalReason::IntentionalTokenRemoval => "INTENTIONAL_TOKEN_REMOVAL",
        ApprovalReason::IntentionalFileDelete => "INTENTIONAL_FILE_DELETE",
        ApprovalReason::StrictTokenFileEditReviewed => "STRICT_TOKEN_FILE_EDIT_REVIEWED",
    }
}

fn optional_u16(value: Option<u16>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

fn optional_u32(value: Option<u32>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

fn optional_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "none",
    }
}

fn write_success(output: &mut impl Write, message: &str) -> ExitCode {
    if output.write_all(message.as_bytes()).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn write_inspect_report(output: &mut impl Write, report: InspectReport) -> ExitCode {
    let inventory = report.inventory;
    let filename = report.filename;
    let policy = report.regular_file_policy;
    let decisions = policy.decisions;
    let structural = report.structural_exclusions;
    let content = report.content;
    let secrets = report.secrets;
    let sensitive = report.sensitive;
    let effective_policy = report.effective_policy;
    let report = format!(
        "inventory_status=PASS\npolicy_id={}\ninspection_only={}\nsanitization_performed={}\ntotal_entries={}\nregular_files={}\ndirectories={}\nlink_like_entries={}\ngit_metadata_entries={}\nspecial_entries={}\ntext_or_code_candidates={}\nunsupported_files={}\nunknown_files={}\npath_component_scan_candidates={}\npath_component_uninspectable={}\npath_component_components_with_findings={}\npath_component_secret_findings={}\npath_component_sensitive_findings={}\npath_component_directory_components_with_findings={}\npath_component_file_components_with_findings={}\nfilename_scan_candidates={}\nfilename_findings={}\nfilename_files_with_findings={}\nfilename_uninspectable={}\nfilename_environment_findings={}\nfilename_private_key_findings={}\nfilename_credential_findings={}\nfilename_auth_config_findings={}\npolicy_regular_files={}\ndecision_allow={}\ndecision_transform={}\ndecision_structure_only={}\ndecision_omit={}\ndecision_block={}\nstructural_excluded_link_like={}\nstructural_excluded_git={}\nstructural_excluded_special={}\ncontent_candidates={}\ncontent_readable_text={}\ncontent_binary_like={}\ncontent_invalid_utf8={}\ncontent_oversized={}\ncontent_hard_linked={}\ncontent_bytes_inspected={}\nsecret_scan_candidates={}\nsecret_findings={}\nsecret_files_with_findings={}\nsensitive_scan_candidates={}\nsensitive_findings={}\nsensitive_files_with_findings={}\nsensitive_email_findings={}\nsensitive_phone_findings={}\nsensitive_jp_phone_findings={}\nsensitive_ip_findings={}\nsensitive_jp_postal_findings={}\nsensitive_my_number_candidate_findings={}\nsensitive_corporate_number_candidate_findings={}\n",
        policy.policy_id,
        report.inspection_only,
        report.sanitization_performed,
        inventory.total_entries,
        inventory.regular_files,
        inventory.directories,
        inventory.link_like_entries,
        inventory.git_metadata_entries,
        inventory.special_entries,
        inventory.text_or_code_candidates,
        inventory.unsupported_files,
        inventory.unknown_files,
        report.path_evidence.scan_candidates,
        report.path_evidence.uninspectable,
        report.path_evidence.components_with_findings,
        report.path_evidence.secret_findings,
        report.path_evidence.sensitive_findings,
        report.path_evidence.directory_components_with_findings,
        report.path_evidence.file_components_with_findings,
        filename.scan_candidates,
        filename.findings,
        filename.files_with_findings,
        filename.uninspectable,
        filename.environment_findings,
        filename.private_key_findings,
        filename.credential_findings,
        filename.auth_config_findings,
        policy.policy_regular_files,
        decisions.allow,
        decisions.transform,
        decisions.structure_only,
        decisions.omit,
        decisions.block,
        structural.link_like,
        structural.git_metadata,
        structural.special,
        content.candidates,
        content.readable_text,
        content.binary_like,
        content.invalid_utf8,
        content.oversized,
        content.hard_linked,
        content.bytes_inspected,
        secrets.scan_candidates,
        secrets.findings,
        secrets.files_with_findings,
        sensitive.scan_candidates,
        sensitive.findings,
        sensitive.files_with_findings,
        sensitive.email_findings,
        sensitive.phone_findings,
        sensitive.jp_phone_findings,
        sensitive.ip_findings,
        sensitive.jp_postal_findings,
        sensitive.my_number_candidate_findings,
        sensitive.corporate_number_candidate_findings,
    );
    let report = format!(
        "{report}effective_policy_plan={}\neffective_policy_id={}\neffective_policy_regular_files={}\neffective_transform={}\neffective_omit={}\neffective_block={}\neffective_unresolved={}\n",
        effective_policy.policy_id,
        effective_policy.policy_id,
        effective_policy.regular_files,
        effective_policy.effective_transform,
        effective_policy.effective_omit,
        effective_policy.effective_block,
        effective_policy.effective_unresolved,
    );
    write_success(output, &report)
}

fn write_error(output: &mut impl Write, message: &str) -> ExitCode {
    let _ = writeln!(output, "error: {message}");
    ExitCode::from(2)
}

fn write_clone_success(
    output: &mut impl Write,
    warning_output: &mut impl Write,
    report: CloneReport,
) -> ExitCode {
    let verification = report.publication.verification;
    let message = format!(
        "report_format=1\npublication_status=PASS\npublication_state=policy-relative-published\npolicy_id={}\nsanitization_performed=true\nverification_status=PASS\npublished_files={}\npublished_directories={}\npublished_bytes={}\nomitted_source_files={}\npromotion_platform={}\ndurability_guaranteed=false\n",
        report.policy_id,
        verification.files_verified,
        verification.directories_verified,
        verification.bytes_verified,
        report.build.files_omitted,
        report.publication.platform.as_str(),
    );
    if output
        .write_all(message.as_bytes())
        .and_then(|()| output.flush())
        .is_err()
    {
        let _ = writeln!(
            warning_output,
            "warning: clone was published but the success report could not be written"
        );
    }
    ExitCode::SUCCESS
}

fn write_clone_error(output: &mut impl Write, error: &CloneError) -> ExitCode {
    let exit_code = match error.classification() {
        CloneFailureClass::DefiniteFailure => ExitCode::from(2),
        CloneFailureClass::ManualInspectionRequired => ExitCode::from(3),
    };
    if matches!(
        error.classification(),
        CloneFailureClass::ManualInspectionRequired
    ) {
        let _ = writeln!(
            output,
            "error: clone filesystem state requires manual inspection; do not retry automatically"
        );
    }
    let _ = writeln!(output, "error: {error}");
    exit_code
}

#[cfg(test)]
mod tests {
    use super::{run, write_clone_error};
    use crate::pipeline::CloneError;
    use crate::promotion::PromotionError;
    use crate::staging::UNVERIFIED_STAGING_LEAF;
    use crate::staging_tree::StagingTreeError;
    use std::ffi::OsString;
    use std::fs;
    #[cfg(windows)]
    use std::io::{self, Write};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    #[cfg(windows)]
    use std::sync::Mutex;

    #[cfg(windows)]
    static SESSION_CLI_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("safeclone-cli-1g-{}-{id}", std::process::id()));
            fs::create_dir(&path).expect("create isolated CLI fixture");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn run_clone(
        source: &std::path::Path,
        output: &std::path::Path,
    ) -> (std::process::ExitCode, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            [
                OsString::from("clone"),
                source.as_os_str().to_owned(),
                output.as_os_str().to_owned(),
            ],
            &mut stdout,
            &mut stderr,
        );
        (
            code,
            String::from_utf8(stdout).expect("CLI stdout is UTF-8"),
            String::from_utf8(stderr).expect("CLI stderr is UTF-8"),
        )
    }

    fn run_inspect(source: &std::path::Path) -> (std::process::ExitCode, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            [OsString::from("inspect"), source.as_os_str().to_owned()],
            &mut stdout,
            &mut stderr,
        );
        (
            code,
            String::from_utf8(stdout).expect("CLI stdout is UTF-8"),
            String::from_utf8(stderr).expect("CLI stderr is UTF-8"),
        )
    }

    #[cfg(windows)]
    fn run_session_cli(args: Vec<OsString>) -> (std::process::ExitCode, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(args, &mut stdout, &mut stderr);
        (
            code,
            String::from_utf8(stdout).expect("session CLI stdout is UTF-8"),
            String::from_utf8(stderr).expect("session CLI stderr is UTF-8"),
        )
    }

    #[cfg(windows)]
    fn session_args(command: &str, paths: &[&std::path::Path]) -> Vec<OsString> {
        let mut args = vec![OsString::from("session"), OsString::from(command)];
        args.extend(paths.iter().map(|path| path.as_os_str().to_owned()));
        args
    }

    #[cfg(windows)]
    fn kv<'a>(output: &'a str, key: &str) -> &'a str {
        output
            .lines()
            .find_map(|line| {
                line.strip_prefix(key)
                    .and_then(|value| value.strip_prefix('='))
            })
            .expect("required CLI key")
    }

    #[cfg(windows)]
    fn review_word<'a>(output: &'a str, line_prefix: &str, key: &str) -> &'a str {
        let line = output
            .lines()
            .find(|line| line.starts_with(line_prefix))
            .expect("review output line");
        line.split_ascii_whitespace()
            .find_map(|part| {
                part.strip_prefix(key)
                    .and_then(|value| value.strip_prefix('='))
            })
            .expect("review output field")
    }

    #[cfg(windows)]
    fn sample_token_file(value: &str) -> Vec<u8> {
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

    #[cfg(windows)]
    fn synthetic_github_token() -> String {
        const ALPHABET: &[u8] = b"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0";
        let body = (0..36)
            .map(|index| ALPHABET[index % ALPHABET.len()])
            .collect::<Vec<_>>();
        format!(
            "gho_{}",
            String::from_utf8(body).expect("synthetic token body is ASCII")
        )
    }

    #[cfg(windows)]
    #[test]
    fn clone_cli_publishes_policy_relative_report_on_windows_ntfs() {
        let fixture = TestDirectory::new();
        let source = fixture.0.join("synthetic-private-source");
        let destination_parent = fixture.0.join("destination");
        let output = destination_parent.join("published");
        let email = "fixture.user@example.invalid";
        let phone = "090-1234-5678";
        let token = synthetic_github_token();
        let source_file = source.join(email).join(format!("report_{phone}.rs"));
        let source_text = format!("token={token}\nemail={email}\nphone={phone}\n");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&destination_parent).expect("create destination parent");
        fs::create_dir(source.join(email)).expect("create source directory");
        fs::write(&source_file, &source_text).expect("write source text");
        fs::write(source.join(".env"), b"synthetic omitted environment value")
            .expect("write omitted environment file");
        let source_before = fs::read(&source_file).expect("read source before clone");

        let (code, stdout, stderr) = run_clone(&source, &output);

        assert_eq!(code, std::process::ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        for expected in [
            "report_format=1",
            "publication_status=PASS",
            "publication_state=policy-relative-published",
            "policy_id=default-strict-v1",
            "sanitization_performed=true",
            "verification_status=PASS",
            "published_files=1",
            "published_directories=1",
            "omitted_source_files=1",
            "promotion_platform=windows-ntfs",
            "durability_guaranteed=false",
        ] {
            assert!(stdout.contains(expected), "missing {expected}");
        }
        for raw in [
            source.to_string_lossy().to_string(),
            output.to_string_lossy().to_string(),
            token.clone(),
            email.to_owned(),
            phone.to_owned(),
        ] {
            assert!(!stdout.contains(&raw));
            assert!(!stderr.contains(&raw));
        }
        let published_file = output
            .join("__REDACTED_EMAIL__")
            .join("report___REDACTED_PHONE__.rs");
        let published_text = fs::read_to_string(published_file).expect("read published text");
        assert!(!published_text.contains(email));
        assert!(!published_text.contains(phone));
        assert!(!published_text.contains(&token));
        assert!(fs::symlink_metadata(destination_parent.join(UNVERIFIED_STAGING_LEAF)).is_err());
        assert!(fs::symlink_metadata(output.join(".env")).is_err());
        assert_eq!(
            fs::read(&source_file).expect("read source after clone"),
            source_before
        );
    }

    #[cfg(windows)]
    #[test]
    fn existing_output_is_unchanged_and_has_no_stdout() {
        let fixture = TestDirectory::new();
        let source = fixture.0.join("source");
        let destination_parent = fixture.0.join("destination");
        let output = destination_parent.join("published");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&destination_parent).expect("create destination parent");
        fs::write(source.join("main.rs"), b"fn main() {}\n").expect("write source");
        fs::write(&output, b"existing destination").expect("write existing output");

        let (code, stdout, stderr) = run_clone(&source, &output);

        assert_eq!(code, std::process::ExitCode::from(2));
        assert!(stdout.is_empty());
        assert!(stderr.contains("final output already exists"));
        assert_eq!(
            fs::read(&output).expect("read existing output"),
            b"existing destination"
        );
        assert!(fs::symlink_metadata(destination_parent.join(UNVERIFIED_STAGING_LEAF)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn post_creation_collision_is_manual_and_retains_staging_without_output() {
        let fixture = TestDirectory::new();
        let source = fixture.0.join("source");
        let destination_parent = fixture.0.join("destination");
        let output = destination_parent.join("published");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&destination_parent).expect("create destination parent");
        fs::write(source.join("alice@example.invalid.txt"), b"first").expect("write first");
        fs::write(source.join("bob@example.invalid.txt"), b"second").expect("write second");

        let (code, stdout, stderr) = run_clone(&source, &output);

        assert_eq!(code, std::process::ExitCode::from(3));
        assert!(stdout.is_empty());
        assert!(stderr.contains("manual inspection; do not retry automatically"));
        assert!(stderr.contains("no automatic cleanup was attempted"));
        assert!(fs::symlink_metadata(&output).is_err());
        assert!(destination_parent.join(UNVERIFIED_STAGING_LEAF).is_dir());
        assert!(destination_parent
            .join(UNVERIFIED_STAGING_LEAF)
            .join("__REDACTED_EMAIL__.txt")
            .is_file());
    }

    #[cfg(windows)]
    #[test]
    fn git_metadata_source_and_output_boundaries_reject_raw_free_before_creation() {
        let fixture = TestDirectory::new();
        let git_root = fixture.0.join("synthetic-private-.GiT").join(".GiT");
        let below_git = git_root.join("objects");
        fs::create_dir_all(&below_git).expect("create synthetic git boundary");
        fs::write(git_root.join("sentinel.txt"), b"source remains unchanged")
            .expect("write source sentinel");

        let (inspect_code, inspect_stdout, inspect_stderr) = run_inspect(&git_root);
        assert_eq!(inspect_code, std::process::ExitCode::from(2));
        assert!(inspect_stdout.is_empty());
        assert!(inspect_stderr.contains("git metadata is forbidden"));
        assert!(!inspect_stderr.contains("synthetic-private"));

        let destination_parent = fixture.0.join("source-boundary-output");
        fs::create_dir(&destination_parent).expect("create destination parent");
        for source in [&git_root, &below_git] {
            let output = destination_parent.join(if source == &git_root {
                "root-result"
            } else {
                "ancestor-result"
            });
            let (code, stdout, stderr) = run_clone(source, &output);
            assert_eq!(code, std::process::ExitCode::from(2));
            assert!(stdout.is_empty());
            assert!(stderr.contains("git metadata is forbidden"));
            assert!(!stderr.contains("synthetic-private"));
            assert!(fs::symlink_metadata(output).is_err());
        }
        assert_eq!(
            fs::read(git_root.join("sentinel.txt")).expect("source sentinel remains"),
            b"source remains unchanged"
        );
        assert!(fs::symlink_metadata(destination_parent.join(UNVERIFIED_STAGING_LEAF)).is_err());

        let ordinary_source = fixture.0.join("ordinary-source");
        fs::create_dir(&ordinary_source).expect("create ordinary source");
        fs::write(ordinary_source.join("main.rs"), b"fn main() {}\n")
            .expect("write ordinary source");

        let output_parent = fixture.0.join("output-leaf-parent");
        fs::create_dir(&output_parent).expect("create output leaf parent");
        let git_output = output_parent.join(".gIt");
        let (code, stdout, stderr) = run_clone(&ordinary_source, &git_output);
        assert_eq!(code, std::process::ExitCode::from(2));
        assert!(stdout.is_empty());
        assert!(stderr.contains("git metadata is forbidden"));
        assert!(fs::symlink_metadata(&git_output).is_err());
        assert!(fs::symlink_metadata(output_parent.join(UNVERIFIED_STAGING_LEAF)).is_err());

        let git_output_parent = fixture.0.join("output-chain").join(".GIT");
        fs::create_dir_all(&git_output_parent).expect("create git output parent");
        fs::write(
            git_output_parent.join("sentinel.txt"),
            b"output parent remains unchanged",
        )
        .expect("write output sentinel");
        let nested_output = git_output_parent.join("published");
        let (code, stdout, stderr) = run_clone(&ordinary_source, &nested_output);
        assert_eq!(code, std::process::ExitCode::from(2));
        assert!(stdout.is_empty());
        assert!(stderr.contains("git metadata is forbidden"));
        assert!(fs::symlink_metadata(&nested_output).is_err());
        assert!(fs::symlink_metadata(git_output_parent.join(UNVERIFIED_STAGING_LEAF)).is_err());
        assert_eq!(
            fs::read(git_output_parent.join("sentinel.txt")).expect("output sentinel remains"),
            b"output parent remains unchanged"
        );
    }

    #[cfg(windows)]
    #[test]
    fn internal_git_child_remains_excluded_without_rejecting_the_boundary() {
        let fixture = TestDirectory::new();
        let source = fixture.0.join("ordinary-source");
        let git_child = source.join(".GiT");
        let destination_parent = fixture.0.join("destination");
        let output = destination_parent.join("published");
        fs::create_dir_all(&git_child).expect("create internal git child");
        fs::create_dir(&destination_parent).expect("create destination parent");
        fs::write(source.join("main.rs"), b"fn main() {}\n").expect("write ordinary source");
        fs::write(
            git_child.join("secret.rs"),
            b"must never be inspected or published",
        )
        .expect("write internal git metadata");

        let (inspect_code, inspect_stdout, inspect_stderr) = run_inspect(&source);
        assert_eq!(
            inspect_code,
            std::process::ExitCode::SUCCESS,
            "inspect stderr: {inspect_stderr}"
        );
        assert!(inspect_stdout.contains("git_metadata_entries=1"));
        assert!(inspect_stderr.is_empty());

        let (clone_code, clone_stdout, clone_stderr) = run_clone(&source, &output);
        assert_eq!(
            clone_code,
            std::process::ExitCode::SUCCESS,
            "clone stderr: {clone_stderr}"
        );
        assert!(clone_stdout.contains("publication_status=PASS"));
        assert!(clone_stderr.is_empty());
        assert!(output.join("main.rs").is_file());
        assert!(fs::symlink_metadata(output.join(".git")).is_err());
        assert!(fs::symlink_metadata(output.join(".GiT")).is_err());
        assert!(fs::symlink_metadata(destination_parent.join(UNVERIFIED_STAGING_LEAF)).is_err());
    }

    #[test]
    fn manual_failure_uses_exit_three_and_raw_free_message() {
        for error in [
            CloneError::Promotion(PromotionError::PromotionStateIndeterminate),
            CloneError::Build(StagingTreeError::ManualInspectionRequired),
        ] {
            let mut stderr = Vec::new();

            let code = write_clone_error(&mut stderr, &error);

            assert_eq!(code, std::process::ExitCode::from(3));
            let stderr = String::from_utf8(stderr).expect("CLI output is UTF-8");
            assert!(stderr.contains("manual inspection; do not retry automatically"));
            assert!(stderr.contains(&error.to_string()));
        }
    }

    #[cfg(windows)]
    struct FailingWriter;

    #[cfg(windows)]
    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "synthetic stdout failure",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "synthetic stdout failure",
            ))
        }
    }

    #[cfg(windows)]
    #[test]
    fn stdout_failure_after_publication_keeps_success_and_final_output() {
        let fixture = TestDirectory::new();
        let source = fixture.0.join("source");
        let destination_parent = fixture.0.join("destination");
        let output = destination_parent.join("published");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&destination_parent).expect("create destination parent");
        fs::write(source.join("main.rs"), b"fn main() {}\n").expect("write source");
        let mut stdout = FailingWriter;
        let mut stderr = Vec::new();

        let code = run(
            [
                OsString::from("clone"),
                source.clone().into_os_string(),
                output.clone().into_os_string(),
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, std::process::ExitCode::SUCCESS);
        let stderr = String::from_utf8(stderr).expect("CLI output is UTF-8");
        assert!(stderr.contains("clone was published but the success report could not be written"));
        assert!(output.is_dir());
        assert!(fs::symlink_metadata(destination_parent.join(UNVERIFIED_STAGING_LEAF)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn inspect_is_explicitly_read_only_and_has_no_clone_eligibility_field() {
        let fixture = TestDirectory::new();
        let source = fixture.0.join("source");
        fs::create_dir(&source).expect("create source");
        fs::write(source.join("main.rs"), b"fn main() {}\n").expect("write source");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(
            [OsString::from("inspect"), source.clone().into_os_string()],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, std::process::ExitCode::SUCCESS);
        let stdout = String::from_utf8(stdout).expect("CLI output is UTF-8");
        assert!(stdout.contains("inspection_only=true"));
        assert!(stdout.contains("sanitization_performed=false"));
        assert!(!stdout.contains("clone_eligible"));
        assert!(stderr.is_empty());
        assert!(fs::symlink_metadata(source.join(UNVERIFIED_STAGING_LEAF)).is_err());
    }

    #[test]
    fn status_and_help_report_product_capabilities() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(["status"], &mut stdout, &mut stderr);

        assert_eq!(code, std::process::ExitCode::SUCCESS);
        let status = String::from_utf8(std::mem::take(&mut stdout)).expect("CLI output is UTF-8");
        assert!(status.contains("status_format=1"));
        assert!(status.contains("clone_enabled=true"));
        assert!(status.contains("inspect_enabled=true"));
        assert!(status.contains("sanitization_enabled=true"));
        assert!(status.contains("promotion_support=runtime-checked"));
        assert!(status.contains("release_filesystem_scope=windows-local-ntfs"));
        assert!(status.contains(&format!(
            "filesystem_commands_supported_on_this_platform={}",
            cfg!(windows)
        )));
        assert!(status.contains("maturity=experimental-mvp"));
        assert!(!status.lines().any(|line| line.starts_with("release_gate=")));
        assert!(status.contains("network=false"));
        assert!(status.contains("telemetry=false"));
        assert!(stderr.is_empty());

        stdout.clear();
        stderr.clear();
        let code = run(["help"], &mut stdout, &mut stderr);
        assert_eq!(code, std::process::ExitCode::SUCCESS);
        let help = String::from_utf8(stdout).expect("CLI output is UTF-8");
        assert!(help.contains(
            "Build, independently verify, and publish a policy-relative sanitized clone"
        ));
        assert!(help.contains("qualifying local NTFS"));
        assert!(help.contains("reject before path access"));
        assert!(help.contains("case-insensitive .git component"));
        assert!(help.contains("leaves unpublished staging"));
        assert!(help.contains("Do not retry automatically"));
        for command in [
            "session create",
            "session status",
            "session review",
            "session approve",
            "session apply",
            "session close",
        ] {
            assert!(help.contains(command));
        }
        assert!(help.contains("--show-private-paths is confidential"));
        assert!(help.contains("Close is logical retirement, not secure erase"));
        assert!(stderr.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn standard_v2_cli_lifecycle_replay_and_close_are_end_to_end() {
        let _serial = SESSION_CLI_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = TestDirectory::new();
        let original = fixture.0.join("OriginalWorkspaceLongName");
        let ai = fixture.0.join("AiWorkspaceLongName");
        let state = fixture.0.join("PrivateSessionLongName");
        let candidate = fixture.0.join("SensitiveCandidateWorkspaceLongName");
        fs::create_dir(&original).expect("create CLI Original");
        fs::write(
            original.join("main.txt"),
            sample_token_file("rt8.standard@example.invalid"),
        )
        .expect("write token Original");
        fs::write(original.join("opaque.bin"), b"opaque\0original-only")
            .expect("write original-only file");

        let mut create = session_args("create", &[&original, &ai]);
        create.extend([OsString::from("--state"), state.as_os_str().to_owned()]);
        let (code, create_out, create_err) = run_session_cli(create);
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{create_err}");
        assert!(create_err.is_empty());
        assert_eq!(kv(&create_out, "command"), "CREATE");
        assert_eq!(kv(&create_out, "profile"), "standard-v2");
        let session_id = kv(&create_out, "session_id").to_owned();

        let (code, status_out, status_err) = run_session_cli(vec![
            OsString::from("session"),
            OsString::from("status"),
            OsString::from("--state"),
            state.as_os_str().to_owned(),
        ]);
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{status_err}");
        assert_eq!(kv(&status_out, "session_id"), session_id);
        assert_eq!(kv(&status_out, "session_state"), "ACTIVE_UNREVIEWED");

        let mut review = session_args("review", &[&original, &ai]);
        review.extend([OsString::from("--state"), state.as_os_str().to_owned()]);
        let (code, review_out, review_err) = run_session_cli(review);
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{review_err}");
        assert!(review_err.is_empty());
        assert_eq!(kv(&review_out, "command"), "REVIEW");
        assert!(review_out.contains("state=READY_TO_APPLY"));

        let mut apply = session_args("apply", &[&original, &ai, &candidate]);
        apply.extend([OsString::from("--state"), state.as_os_str().to_owned()]);
        let (code, applied_out, applied_err) = run_session_cli(apply.clone());
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{applied_err}");
        assert_eq!(kv(&applied_out, "publication_state"), "APPLIED_COMPLETE");
        assert_eq!(
            applied_err,
            format!("{}\n", super::SENSITIVE_CANDIDATE_WARNING)
        );
        assert_eq!(
            fs::read(candidate.join("main.txt")).expect("read reconstructed candidate"),
            sample_token_file("rt8.standard@example.invalid")
        );
        assert_eq!(
            fs::read(candidate.join("opaque.bin")).expect("read original-only candidate"),
            b"opaque\0original-only"
        );
        let private_count = fs::read_dir(&state).expect("read state").count();
        let (code, replay_out, replay_err) = run_session_cli(apply);
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{replay_err}");
        assert_eq!(kv(&replay_out, "publication_state"), "COMPLETED_REPLAY");
        assert_eq!(kv(&replay_out, "apply_id"), kv(&applied_out, "apply_id"));
        assert_eq!(
            fs::read_dir(&state).expect("read replay state").count(),
            private_count
        );

        let close = vec![
            OsString::from("session"),
            OsString::from("close"),
            OsString::from("--state"),
            state.as_os_str().to_owned(),
        ];
        let (code, close_out, close_err) = run_session_cli(close.clone());
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{close_err}");
        assert_eq!(kv(&close_out, "state"), "CLOSED");
        assert_eq!(kv(&close_out, "sensitive_candidate_state"), "COMPLETE");
        assert_eq!(kv(&close_out, "secure_erase_performed"), "false");
        let closed_count = fs::read_dir(&state).expect("read closed state").count();
        let (code, replay_close, replay_close_err) = run_session_cli(close);
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{replay_close_err}");
        assert_eq!(kv(&replay_close, "replayed"), "true");
        assert_eq!(
            fs::read_dir(&state).expect("read close replay").count(),
            closed_count
        );
        let (code, final_status, final_status_err) = run_session_cli(vec![
            OsString::from("session"),
            OsString::from("status"),
            OsString::from("--state"),
            state.as_os_str().to_owned(),
        ]);
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{final_status_err}");
        assert_eq!(kv(&final_status, "session_state"), "CLOSED");
    }

    #[cfg(windows)]
    #[test]
    fn strict_cli_uses_rendered_ids_for_one_event_approval() {
        let _serial = SESSION_CLI_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = TestDirectory::new();
        let original = fixture.0.join("StrictOriginalWorkspaceLongName");
        let ai = fixture.0.join("StrictAiWorkspaceLongName");
        let state = fixture.0.join("StrictPrivateSessionLongName");
        let candidate = fixture.0.join("StrictSensitiveCandidateLongName");
        fs::create_dir(&original).expect("create Strict Original");
        fs::write(
            original.join("strict.txt"),
            sample_token_file("rt8.strict@example.invalid"),
        )
        .expect("write Strict Original");

        let mut create = session_args("create", &[&original, &ai]);
        create.extend([
            OsString::from("--state"),
            state.as_os_str().to_owned(),
            OsString::from("--profile"),
            OsString::from("strict-token-files-v2"),
        ]);
        let (code, create_out, create_err) = run_session_cli(create);
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{create_err}");
        assert_eq!(kv(&create_out, "profile"), "strict-token-files-v2");

        let strict_file = ai.join("strict.txt");
        let mut edited = b"safe insertion\n".to_vec();
        edited.extend_from_slice(&fs::read(&strict_file).expect("read tokenized Strict AI"));
        fs::write(&strict_file, edited).expect("edit Strict AI");
        let mut review = session_args("review", &[&original, &ai]);
        review.extend([OsString::from("--state"), state.as_os_str().to_owned()]);
        let (code, review_out, review_err) = run_session_cli(review.clone());
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{review_err}");
        let review_id = review_word(&review_out, "review ", "id").to_owned();
        let event_id = review_word(&review_out, "approval-event ", "id").to_owned();
        let reason = review_word(&review_out, "approval-event ", "reason").to_owned();
        assert_eq!(reason, "STRICT_TOKEN_FILE_EDIT_REVIEWED");

        let approve = vec![
            OsString::from("session"),
            OsString::from("approve"),
            original.as_os_str().to_owned(),
            ai.as_os_str().to_owned(),
            OsString::from("--state"),
            state.as_os_str().to_owned(),
            OsString::from("--review-id"),
            OsString::from(&review_id),
            OsString::from("--event-id"),
            OsString::from(&event_id),
            OsString::from("--reason-code"),
            OsString::from(&reason),
        ];
        let (code, approved_out, approved_err) = run_session_cli(approve.clone());
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{approved_err}");
        assert_eq!(kv(&approved_out, "review_id"), review_id);
        assert_eq!(kv(&approved_out, "event_id"), event_id);
        assert_eq!(kv(&approved_out, "duplicate"), "false");
        let generation_count = fs::read_dir(&state).expect("read approval state").count();
        let (code, duplicate_out, duplicate_err) = run_session_cli(approve);
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{duplicate_err}");
        assert_eq!(kv(&duplicate_out, "duplicate"), "true");
        assert_eq!(
            fs::read_dir(&state).expect("read duplicate state").count(),
            generation_count
        );
        let (code, ready_out, ready_err) = run_session_cli(review);
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{ready_err}");
        assert!(ready_out.contains("state=READY_TO_APPLY"));

        let mut apply = session_args("apply", &[&original, &ai, &candidate]);
        apply.extend([OsString::from("--state"), state.as_os_str().to_owned()]);
        let (code, _, apply_err) = run_session_cli(apply);
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{apply_err}");
        let (code, _, close_err) = run_session_cli(vec![
            OsString::from("session"),
            OsString::from("close"),
            OsString::from("--state"),
            state.as_os_str().to_owned(),
        ]);
        assert_eq!(code, std::process::ExitCode::SUCCESS, "{close_err}");
    }

    #[cfg(windows)]
    #[test]
    fn confidential_review_warning_precedes_private_allowlist() {
        let _serial = SESSION_CLI_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = TestDirectory::new();
        let original = fixture.0.join("PrivateOriginalWorkspaceLongName");
        let ai = fixture.0.join("PrivateAiWorkspaceLongName");
        let state = fixture.0.join("PrivateSessionLongName");
        let path_canary = "ConfidentialPathCanary.txt";
        let content_canary = "confidential-content-canary";
        fs::create_dir(&original).expect("create private-view Original");
        fs::write(original.join(path_canary), content_canary).expect("write private-view file");
        let mut create = session_args("create", &[&original, &ai]);
        create.extend([OsString::from("--state"), state.as_os_str().to_owned()]);
        assert_eq!(run_session_cli(create).0, std::process::ExitCode::SUCCESS);
        fs::write(
            ai.join(path_canary),
            format!("{content_canary}\nsafe edit\n"),
        )
        .expect("edit private-view AI");
        let mut review = session_args("review", &[&original, &ai]);
        review.extend([OsString::from("--state"), state.as_os_str().to_owned()]);
        let (default_code, default_out, default_err) = run_session_cli(review.clone());
        assert_eq!(
            default_code,
            std::process::ExitCode::SUCCESS,
            "{default_err}"
        );
        assert!(!default_out.contains(path_canary));
        assert!(!default_out.contains(content_canary));

        review.push(OsString::from("--show-private-paths"));
        let (private_code, private_out, private_err) = run_session_cli(review);
        assert_eq!(private_code, std::process::ExitCode::SUCCESS);
        assert_eq!(
            private_err,
            format!(
                "{}\n",
                crate::roundtrip::review::CONFIDENTIAL_REVIEW_WARNING
            )
        );
        assert!(private_out.contains(path_canary));
        assert!(!private_out.contains(content_canary));
        assert!(!private_out.contains(&fixture.0.to_string_lossy().to_string()));
        assert!(!private_out.contains("\\\\?\\Volume"));
    }

    #[cfg(windows)]
    #[test]
    fn session_writer_failures_preserve_committed_authority_and_semantic_exit() {
        let _serial = SESSION_CLI_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        struct BrokenWriter;
        impl Write for BrokenWriter {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "synthetic failure",
                ))
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "synthetic failure",
                ))
            }
        }

        let rejected_fixture = TestDirectory::new();
        let rejected_original = rejected_fixture.0.join("RejectedOriginalLongName");
        let rejected_ai = rejected_fixture.0.join("RejectedAiLongName");
        let rejected_state = rejected_fixture.0.join("RejectedStateLongName");
        fs::create_dir(&rejected_original).expect("create rejected Original");
        fs::write(
            rejected_original.join("ConfidentialRejectedPath.txt"),
            sample_token_file("rt8.writer.rejected@example.invalid"),
        )
        .expect("write rejected Original");
        let mut create = session_args("create", &[&rejected_original, &rejected_ai]);
        create.extend([
            OsString::from("--state"),
            rejected_state.as_os_str().to_owned(),
        ]);
        let mut broken_stdout = BrokenWriter;
        let mut create_stderr = Vec::new();
        assert_eq!(
            run(create, &mut broken_stdout, &mut create_stderr),
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(
            crate::roundtrip::status::status_session(&rejected_state)
                .expect("create remains committed")
                .session_state,
            crate::roundtrip::status::StatusState::ActiveUnreviewed
        );
        fs::write(
            rejected_ai.join("NewSensitiveFindingLongName.txt"),
            b"rt8.writer.new-sensitive@example.invalid\n",
        )
        .expect("write rejected new sensitive finding");
        let mut review = session_args("review", &[&rejected_original, &rejected_ai]);
        review.extend([
            OsString::from("--state"),
            rejected_state.as_os_str().to_owned(),
        ]);
        let mut broken_stdout = BrokenWriter;
        let mut review_stderr = Vec::new();
        assert_eq!(
            run(review.clone(), &mut broken_stdout, &mut review_stderr),
            std::process::ExitCode::from(2)
        );
        let rejected_status = crate::roundtrip::status::status_session(&rejected_state)
            .expect("rejected review remains committed");
        assert_eq!(
            rejected_status.authenticated_live_state,
            Some(crate::roundtrip::schema::SessionState::ReviewedRejected)
        );
        let generation = rejected_status.capsule_generation;
        review.push(OsString::from("--show-private-paths"));
        let mut private_stdout = Vec::new();
        let mut broken_stderr = BrokenWriter;
        assert_eq!(
            run(review, &mut private_stdout, &mut broken_stderr),
            std::process::ExitCode::from(2)
        );
        assert!(private_stdout.is_empty());
        assert_eq!(
            crate::roundtrip::status::status_session(&rejected_state)
                .expect("warning failure leaves review unchanged")
                .capsule_generation,
            generation
        );

        let fixture = TestDirectory::new();
        let original = fixture.0.join("WriterOriginalLongName");
        let ai = fixture.0.join("WriterAiLongName");
        let state = fixture.0.join("WriterStateLongName");
        let candidate = fixture.0.join("WriterCandidateLongName");
        fs::create_dir(&original).expect("create writer Original");
        fs::write(
            original.join("strict.txt"),
            sample_token_file("rt8.writer.strict@example.invalid"),
        )
        .expect("write writer Original");
        crate::roundtrip::create::create_session(
            &original,
            &ai,
            &state,
            crate::roundtrip::token::ReviewProfile::StrictTokenFilesV2,
        )
        .expect("create writer session");
        let strict_file = ai.join("strict.txt");
        let mut edited = b"safe insertion\n".to_vec();
        edited.extend_from_slice(&fs::read(&strict_file).expect("read strict AI"));
        fs::write(&strict_file, edited).expect("edit strict AI");
        let review = crate::roundtrip::review::review_session(&original, &ai, &state)
            .expect("review writer fixture");
        assert_eq!(review.report().approval_events.len(), 1);
        let event = &review.report().approval_events[0];
        let approve = vec![
            OsString::from("session"),
            OsString::from("approve"),
            original.as_os_str().to_owned(),
            ai.as_os_str().to_owned(),
            OsString::from("--state"),
            state.as_os_str().to_owned(),
            OsString::from("--review-id"),
            OsString::from(&review.report().review_id),
            OsString::from("--event-id"),
            OsString::from(&event.event_id),
            OsString::from("--reason-code"),
            OsString::from("STRICT_TOKEN_FILE_EDIT_REVIEWED"),
        ];
        let mut broken_stdout = BrokenWriter;
        let mut approve_stderr = Vec::new();
        assert_eq!(
            run(approve, &mut broken_stdout, &mut approve_stderr),
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(
            crate::roundtrip::status::status_session(&state)
                .expect("approval remains committed")
                .authenticated_live_state,
            Some(crate::roundtrip::schema::SessionState::ReadyToApply)
        );
        let mut apply = session_args("apply", &[&original, &ai, &candidate]);
        apply.extend([OsString::from("--state"), state.as_os_str().to_owned()]);
        let mut broken_stdout = BrokenWriter;
        let mut broken_stderr = BrokenWriter;
        assert_eq!(
            run(apply, &mut broken_stdout, &mut broken_stderr),
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(
            crate::roundtrip::status::status_session(&state)
                .expect("apply remains committed")
                .session_state,
            crate::roundtrip::status::StatusState::AppliedComplete
        );
        let close = vec![
            OsString::from("session"),
            OsString::from("close"),
            OsString::from("--state"),
            state.as_os_str().to_owned(),
        ];
        let mut broken_stdout = BrokenWriter;
        let mut close_stderr = Vec::new();
        assert_eq!(
            run(close, &mut broken_stdout, &mut close_stderr),
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(
            crate::roundtrip::status::status_session(&state)
                .expect("close remains committed")
                .session_state,
            crate::roundtrip::status::StatusState::Closed
        );
    }

    #[test]
    fn session_parser_accepts_exact_syntax_and_closed_enum_values() {
        let id = crate::roundtrip::token::encode_base32_128(&[0x42; 16]);
        let create = super::parse(["session", "create", "original", "ai", "--state", "state"]);
        assert!(matches!(
            create,
            Ok(super::Command::SessionCreate(super::SessionCreateRequest {
                profile: crate::roundtrip::token::ReviewProfile::StandardV2,
                ..
            }))
        ));
        let strict = super::parse([
            "session",
            "create",
            "original",
            "ai",
            "--profile",
            "strict-token-files-v2",
            "--state",
            "state",
        ]);
        assert!(matches!(
            strict,
            Ok(super::Command::SessionCreate(super::SessionCreateRequest {
                profile: crate::roundtrip::token::ReviewProfile::StrictTokenFilesV2,
                ..
            }))
        ));
        assert!(matches!(
            super::parse(["session", "status", "--state", "state"]),
            Ok(super::Command::SessionStatus(_))
        ));
        assert!(matches!(
            super::parse([
                "session",
                "review",
                "original",
                "ai",
                "--state",
                "state",
                "--show-private-paths",
            ]),
            Ok(super::Command::SessionReview(super::SessionReviewRequest {
                show_private_paths: true,
                ..
            }))
        ));
        for reason in [
            "INTENTIONAL_TOKEN_REMOVAL",
            "INTENTIONAL_FILE_DELETE",
            "STRICT_TOKEN_FILE_EDIT_REVIEWED",
        ] {
            let parsed = super::parse([
                "session",
                "approve",
                "original",
                "ai",
                "--state",
                "state",
                "--review-id",
                &id,
                "--event-id",
                &id,
                "--reason-code",
                reason,
            ]);
            assert!(matches!(parsed, Ok(super::Command::SessionApprove(_))));
        }
        let close = super::parse([
            "session",
            "close",
            "--state",
            "state",
            "--acknowledge-incomplete",
            &id,
        ]);
        assert!(matches!(close, Ok(super::Command::SessionClose(_))));
        assert!(matches!(
            super::parse([
                "session",
                "apply",
                "original",
                "ai",
                "candidate",
                "--state",
                "state",
            ]),
            Ok(super::Command::SessionApply(_))
        ));
    }

    #[test]
    fn session_parser_rejects_noncanonical_and_duplicate_options_raw_free() {
        let canonical = crate::roundtrip::token::encode_base32_128(&[0x31; 16]);
        let cases = vec![
            vec!["session", "status"],
            vec!["session", "status", "--state"],
            vec!["session", "status", "--state", "a", "--state", "b"],
            vec!["session", "status", "--unknown"],
            vec!["session", "review", "o", "a", "--state", "s", "extra"],
            vec![
                "session",
                "create",
                "o",
                "a",
                "--state",
                "s",
                "--profile",
                "standard-v1",
            ],
            vec![
                "session",
                "approve",
                "o",
                "a",
                "--state",
                "s",
                "--review-id",
                "lowercaseinvalidbase32xx",
                "--event-id",
                &canonical,
                "--reason-code",
                "INTENTIONAL_TOKEN_REMOVAL",
            ],
            vec![
                "session",
                "approve",
                "o",
                "a",
                "--state",
                "s",
                "--review-id",
                &canonical,
                "--event-id",
                &canonical,
                "--reason-code",
                "intentional_token_removal",
            ],
        ];
        for args in cases {
            assert!(matches!(
                super::parse(args),
                Err(super::ParseFailure::Session(_))
            ));
        }

        let raw = "raw-private-argument-canary";
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            ["session", "status", "--state", "state", raw],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, std::process::ExitCode::from(2));
        assert!(stdout.is_empty());
        let stderr = String::from_utf8(stderr).expect("session diagnostic UTF-8");
        assert!(stderr.starts_with("error_code=SESSION_"));
        assert!(!stderr.contains(raw));
        assert!(!stderr.contains("state"));
    }

    #[test]
    fn every_session_subcommand_rejects_missing_extra_duplicate_unknown_and_illegal_input() {
        let id = crate::roundtrip::token::encode_base32_128(&[0x21; 16]);
        let lowercase = id.to_ascii_lowercase();
        let padded = format!("{id}=");
        let cases = vec![
            vec!["session", "create"],
            vec!["session", "create", "o"],
            vec!["session", "create", "o", "a"],
            vec!["session", "create", "o", "a", "--state"],
            vec!["session", "create", "o", "a", "--state", "s", "extra"],
            vec![
                "session", "create", "o", "a", "--state", "s", "--state", "t",
            ],
            vec!["session", "create", "o", "a", "--state", "s", "--unknown"],
            vec![
                "session",
                "create",
                "o",
                "a",
                "--state",
                "s",
                "--show-private-paths",
            ],
            vec!["session", "create", "o", "a", "--state", "s", "--profile"],
            vec!["session", "status"],
            vec!["session", "status", "--state"],
            vec!["session", "status", "--state", "s", "extra"],
            vec!["session", "status", "--state", "s", "--state", "t"],
            vec!["session", "status", "--state", "s", "--unknown"],
            vec![
                "session",
                "status",
                "--state",
                "s",
                "--profile",
                "standard-v2",
            ],
            vec!["session", "review"],
            vec!["session", "review", "o"],
            vec!["session", "review", "o", "a"],
            vec!["session", "review", "o", "a", "--state"],
            vec!["session", "review", "o", "a", "--state", "s", "extra"],
            vec![
                "session", "review", "o", "a", "--state", "s", "--state", "t",
            ],
            vec!["session", "review", "o", "a", "--state", "s", "--unknown"],
            vec![
                "session",
                "review",
                "o",
                "a",
                "--state",
                "s",
                "--profile",
                "standard-v2",
            ],
            vec![
                "session",
                "review",
                "o",
                "a",
                "--state",
                "s",
                "--show-private-paths",
                "--show-private-paths",
            ],
            vec!["session", "approve"],
            vec!["session", "approve", "o"],
            vec!["session", "approve", "o", "a"],
            vec![
                "session",
                "approve",
                "o",
                "a",
                "--state",
                "s",
                "--review-id",
                &id,
                "--event-id",
                &id,
            ],
            vec![
                "session",
                "approve",
                "o",
                "a",
                "--state",
                "s",
                "--review-id",
                &id,
                "--event-id",
                &id,
                "--reason-code",
                "INTENTIONAL_TOKEN_REMOVAL",
                "extra",
            ],
            vec![
                "session",
                "approve",
                "o",
                "a",
                "--state",
                "s",
                "--state",
                "t",
                "--review-id",
                &id,
                "--event-id",
                &id,
                "--reason-code",
                "INTENTIONAL_TOKEN_REMOVAL",
            ],
            vec!["session", "approve", "o", "a", "--state", "s", "--unknown"],
            vec![
                "session",
                "approve",
                "o",
                "a",
                "--state",
                "s",
                "--profile",
                "standard-v2",
            ],
            vec![
                "session",
                "approve",
                "o",
                "a",
                "--state",
                "s",
                "--review-id",
            ],
            vec![
                "session",
                "approve",
                "o",
                "a",
                "--state",
                "s",
                "--review-id",
                &id,
                "--review-id",
                &id,
                "--event-id",
                &id,
                "--reason-code",
                "INTENTIONAL_TOKEN_REMOVAL",
            ],
            vec!["session", "apply"],
            vec!["session", "apply", "o"],
            vec!["session", "apply", "o", "a"],
            vec!["session", "apply", "o", "a", "c"],
            vec!["session", "apply", "o", "a", "c", "--state"],
            vec!["session", "apply", "o", "a", "c", "--state", "s", "extra"],
            vec![
                "session", "apply", "o", "a", "c", "--state", "s", "--state", "t",
            ],
            vec![
                "session",
                "apply",
                "o",
                "a",
                "c",
                "--state",
                "s",
                "--unknown",
            ],
            vec![
                "session",
                "apply",
                "o",
                "a",
                "c",
                "--state",
                "s",
                "--profile",
                "standard-v2",
            ],
            vec!["session", "close"],
            vec!["session", "close", "--state"],
            vec!["session", "close", "--state", "s", "extra"],
            vec!["session", "close", "--state", "s", "--state", "t"],
            vec!["session", "close", "--state", "s", "--unknown"],
            vec![
                "session",
                "close",
                "--state",
                "s",
                "--profile",
                "standard-v2",
            ],
            vec![
                "session",
                "close",
                "--state",
                "s",
                "--acknowledge-incomplete",
            ],
            vec![
                "session",
                "close",
                "--state",
                "s",
                "--acknowledge-incomplete",
                &id,
                "--acknowledge-incomplete",
                &id,
            ],
            vec![
                "session",
                "close",
                "--state",
                "s",
                "--acknowledge-incomplete",
                &lowercase,
            ],
            vec![
                "session",
                "close",
                "--state",
                "s",
                "--acknowledge-incomplete",
                &padded,
            ],
            vec![
                "session",
                "close",
                "--state",
                "s",
                "--acknowledge-incomplete",
                "A",
            ],
        ];
        for args in cases {
            assert!(
                matches!(super::parse(args), Err(super::ParseFailure::Session(_))),
                "session parser unexpectedly accepted invalid syntax"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn encoding_boundary_keeps_every_cli_path_exact_including_ill_formed_wide() {
        use super::Command;
        use std::os::windows::ffi::{OsStrExt, OsStringExt};

        let id = crate::roundtrip::token::encode_base32_128(&[1; 16]);
        let mut inputs: Vec<Vec<u16>> = [
            "日本語資料",
            "Ā-€-한글-Ж",
            "非BMP-🚀-𐐷",
            "space & apostrophe's-漢🚀",
        ]
        .into_iter()
        .map(|s| s.encode_utf16().collect())
        .collect();
        inputs.extend([vec![0xd800], vec![0xdc00], vec![0xd800, 0x61, 0xdc00]]);
        for wide in inputs {
            let path = OsString::from_wide(&wide);
            let cases = [
                vec!["inspect", "P"],
                vec!["clone", "P", "P"],
                vec!["session", "create", "P", "P", "--state", "P"],
                vec!["session", "status", "--state", "P"],
                vec!["session", "review", "P", "P", "--state", "P"],
                vec![
                    "session",
                    "approve",
                    "P",
                    "P",
                    "--state",
                    "P",
                    "--review-id",
                    &id,
                    "--event-id",
                    &id,
                    "--reason-code",
                    "INTENTIONAL_FILE_DELETE",
                ],
                vec!["session", "apply", "P", "P", "P", "--state", "P"],
                vec!["session", "close", "--state", "P"],
            ];
            for args in cases {
                let expected_count = args.iter().filter(|arg| **arg == "P").count();
                let args: Vec<OsString> = args
                    .into_iter()
                    .map(|arg| if arg == "P" { path.clone() } else { arg.into() })
                    .collect();
                let Ok(parsed) = super::parse(args) else {
                    panic!("native path was coerced or rejected by CLI parsing");
                };
                let paths = match parsed {
                    Command::Inspect(r) => vec![r.source],
                    Command::Clone(r) => vec![r.source, r.output],
                    Command::SessionCreate(r) => vec![r.original, r.ai_workspace, r.private_state],
                    Command::SessionStatus(r) => vec![r.private_state],
                    Command::SessionReview(r) => vec![r.original, r.ai_workspace, r.private_state],
                    Command::SessionApprove(r) => vec![r.original, r.ai_workspace, r.private_state],
                    Command::SessionApply(r) => {
                        vec![r.original, r.ai_workspace, r.candidate, r.private_state]
                    }
                    Command::SessionClose(r) => vec![r.private_state],
                    _ => panic!("expected path command"),
                };
                assert_eq!(paths.len(), expected_count);
                for parsed in paths {
                    assert_eq!(parsed.as_os_str().encode_wide().collect::<Vec<_>>(), wide);
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn session_paths_remain_os_string_capable() {
        use std::os::windows::ffi::OsStringExt;

        let non_unicode = OsString::from_wide(&[0xD800]);
        let parsed = super::parse(vec![
            OsString::from("session"),
            OsString::from("status"),
            OsString::from("--state"),
            non_unicode.clone(),
        ]);
        match parsed {
            Ok(super::Command::SessionStatus(request)) => {
                assert_eq!(request.private_state.as_os_str(), non_unicode)
            }
            _ => panic!("non-Unicode state path must remain a path"),
        }

        for args in [
            vec![
                OsString::from("session"),
                OsString::from("create"),
                OsString::from("o"),
                OsString::from("a"),
                OsString::from("--state"),
                OsString::from("s"),
                OsString::from("--profile"),
                non_unicode.clone(),
            ],
            vec![
                OsString::from("session"),
                OsString::from("close"),
                OsString::from("--state"),
                OsString::from("s"),
                OsString::from("--acknowledge-incomplete"),
                non_unicode.clone(),
            ],
            vec![
                OsString::from("session"),
                OsString::from("approve"),
                OsString::from("o"),
                OsString::from("a"),
                OsString::from("--state"),
                OsString::from("s"),
                OsString::from("--review-id"),
                non_unicode.clone(),
            ],
        ] {
            assert!(matches!(
                super::parse(args),
                Err(super::ParseFailure::Session(
                    super::SessionUsageError::InvalidOptionValue
                ))
            ));
        }
    }

    #[test]
    fn session_semantic_exit_never_becomes_one_on_writer_failure() {
        struct Failing;
        impl std::io::Write for Failing {
            fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "synthetic failure",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "synthetic failure",
                ))
            }
        }

        for expected in [
            std::process::ExitCode::SUCCESS,
            std::process::ExitCode::from(2),
            std::process::ExitCode::from(3),
        ] {
            let mut stdout = Failing;
            let mut stderr = Failing;
            assert_eq!(
                super::write_session_report(&mut stdout, &mut stderr, "report\n", expected),
                expected
            );
            assert_eq!(
                super::write_session_diagnostic(&mut stderr, "SYNTHETIC", Some("MANUAL"), expected,),
                expected
            );
        }
    }

    #[test]
    fn session_library_failure_and_manual_exit_mapping_is_closed() {
        assert_eq!(
            super::review_state_semantic_exit(
                crate::roundtrip::schema::SessionState::ReviewedRejected
            ),
            std::process::ExitCode::from(2)
        );
        for state in [
            crate::roundtrip::schema::SessionState::Reviewed,
            crate::roundtrip::schema::SessionState::ApprovedPartial,
            crate::roundtrip::schema::SessionState::ReadyToApply,
        ] {
            assert_eq!(
                super::review_state_semantic_exit(state),
                std::process::ExitCode::SUCCESS
            );
        }
        for state in [
            crate::roundtrip::schema::SessionState::ActiveUnreviewed,
            crate::roundtrip::schema::SessionState::ApplyArmed,
            crate::roundtrip::schema::SessionState::ApplyIncomplete,
            crate::roundtrip::schema::SessionState::AppliedComplete,
        ] {
            assert_eq!(
                super::review_state_semantic_exit(state),
                std::process::ExitCode::from(2)
            );
        }

        for action in [
            crate::roundtrip::status::StatusManualAction::CreateIncomplete,
            crate::roundtrip::status::StatusManualAction::PrivateOrphansPresent,
            crate::roundtrip::status::StatusManualAction::ApplyArmed,
            crate::roundtrip::status::StatusManualAction::ApplyIncomplete,
        ] {
            assert_eq!(
                super::status_manual_action_exit(action),
                std::process::ExitCode::from(3)
            );
        }
        assert_eq!(
            super::status_manual_action_exit(crate::roundtrip::status::StatusManualAction::None),
            std::process::ExitCode::SUCCESS
        );

        let apply_cases = [
            (
                crate::roundtrip::apply::ApplyFailureState::DefinitePreCandidate,
                std::process::ExitCode::from(2),
                None,
            ),
            (
                crate::roundtrip::apply::ApplyFailureState::DisarmedReadyToApply,
                std::process::ExitCode::from(2),
                None,
            ),
            (
                crate::roundtrip::apply::ApplyFailureState::ManualIncomplete,
                std::process::ExitCode::from(3),
                Some("CANDIDATE_MANUAL_INCOMPLETE"),
            ),
            (
                crate::roundtrip::apply::ApplyFailureState::StateCommitUncertain,
                std::process::ExitCode::from(3),
                Some("STATE_COMMIT_UNCERTAIN"),
            ),
        ];
        for (state, exit, manual) in apply_cases {
            assert_eq!(super::apply_failure_state_exit(state), (exit, manual));
        }

        for failure in [
            crate::roundtrip::close::CloseFailure::DefiniteFailure(
                crate::roundtrip::Error::InvalidState,
            ),
            crate::roundtrip::close::CloseFailure::AcknowledgementMismatch,
            crate::roundtrip::close::CloseFailure::AcknowledgementNotAllowed,
        ] {
            assert_eq!(
                super::close_failure_exit(failure),
                std::process::ExitCode::from(2)
            );
        }
        for failure in [
            crate::roundtrip::close::CloseFailure::AcknowledgementRequired,
            crate::roundtrip::close::CloseFailure::ManualInspectionRequired(
                crate::roundtrip::Error::StateCommitUncertain,
            ),
        ] {
            assert_eq!(
                super::close_failure_exit(failure),
                std::process::ExitCode::from(3)
            );
        }
    }

    #[test]
    fn roundtrip_error_mapping_is_explicit_and_raw_free() {
        let errors = [
            crate::roundtrip::Error::UnsupportedPlatform,
            crate::roundtrip::Error::RandomGenerationFailed,
            crate::roundtrip::Error::KeyDerivationFailed,
            crate::roundtrip::Error::AuthenticationFailed,
            crate::roundtrip::Error::InvalidCanonicalInput,
            crate::roundtrip::Error::BoundExceeded,
            crate::roundtrip::Error::ChangeReportBoundExceeded,
            crate::roundtrip::Error::AnchorAmbiguous,
            crate::roundtrip::Error::AnchorResourceLimitExceeded,
            crate::roundtrip::Error::AnchorEncodingInvalid,
            crate::roundtrip::Error::InvalidToken,
            crate::roundtrip::Error::InvalidEnvelope,
            crate::roundtrip::Error::InvalidSchema,
            crate::roundtrip::Error::InvalidState,
            crate::roundtrip::Error::DpapiFailed,
            crate::roundtrip::Error::FilesystemFailure,
            crate::roundtrip::Error::LockContention,
            crate::roundtrip::Error::PrivateOrphansPresent,
            crate::roundtrip::Error::CreateIncomplete,
            crate::roundtrip::Error::UnsupportedAliasNamespace,
            crate::roundtrip::Error::AliasNamespaceAmbiguous,
            crate::roundtrip::Error::AliasIdentityMismatch,
            crate::roundtrip::Error::CaseSensitiveDirectoryUnsupported,
            crate::roundtrip::Error::PersistentVolumeQueryFailed,
            crate::roundtrip::Error::PersistentVolumeStateAmbiguous,
            crate::roundtrip::Error::StateCommitUncertain,
            crate::roundtrip::Error::CorruptState,
            crate::roundtrip::Error::CreateConflict,
            crate::roundtrip::Error::OriginalWorkspaceRejected,
            crate::roundtrip::Error::WorkspaceVerificationFailed,
            crate::roundtrip::Error::WorkspaceUnstable,
            crate::roundtrip::Error::OriginalBaselineMismatch,
            crate::roundtrip::Error::UnsafeWorkspaceOverlap,
            crate::roundtrip::Error::ApprovalStale,
            crate::roundtrip::Error::ApprovalEventInvalid,
            crate::roundtrip::Error::ApprovalEventIneligible,
            crate::roundtrip::Error::ApprovalReasonMismatch,
            crate::roundtrip::Error::ApprovalConflict,
            crate::roundtrip::Error::ReconstructionRejected,
            crate::roundtrip::Error::ProjectedRetokenizationMismatch,
            crate::roundtrip::Error::OccurrenceGraphMismatch,
            crate::roundtrip::Error::CandidateNamespaceCollision,
            crate::roundtrip::Error::CandidateVolumeIdentityMismatch,
            crate::roundtrip::Error::CandidateRootIdentityMismatch,
            crate::roundtrip::Error::CandidateMarkerAuthenticationFailed,
            crate::roundtrip::Error::CandidateVerificationFailed,
            crate::roundtrip::Error::CandidateIncomplete,
        ];
        for error in errors {
            let code = super::roundtrip_error_code(error);
            assert!(code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_'));
            assert!(!code.contains("OTHER"));
        }
    }
}
