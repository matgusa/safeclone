//! Raw-free lexical evidence for transient source path components.
//!
//! This stage reuses the compiled secret and sensitive-identifier detectors. It
//! never performs filesystem access and retains only checked numeric aggregates.

use std::ffi::OsStr;
use std::fmt;

use crate::{detection::ComponentInspectability, secrets, sensitive};

pub const DEFAULT_MAX_FINDINGS_PER_RUN: usize =
    secrets::DEFAULT_MAX_FINDINGS_PER_RUN + sensitive::DEFAULT_MAX_FINDINGS_PER_RUN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentKind {
    Directory,
    File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_findings_per_run: usize,
    pub secrets: secrets::Limits,
    pub sensitive: sensitive::Limits,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_findings_per_run: DEFAULT_MAX_FINDINGS_PER_RUN,
            secrets: secrets::Limits::default(),
            sensitive: sensitive::Limits::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    pub scan_candidates: usize,
    pub uninspectable: usize,
    pub components_with_findings: usize,
    pub secret_findings: usize,
    pub sensitive_findings: usize,
    pub directory_components_with_findings: usize,
    pub file_components_with_findings: usize,
}

impl Report {
    fn detector_total(self) -> Result<usize, PathEvidenceError> {
        self.secret_findings
            .checked_add(self.sensitive_findings)
            .ok_or(PathEvidenceError::CountOverflow)
    }

    fn kind_total(self) -> Result<usize, PathEvidenceError> {
        self.directory_components_with_findings
            .checked_add(self.file_components_with_findings)
            .ok_or(PathEvidenceError::CountOverflow)
    }

    pub(crate) fn observed_component_total(self) -> Result<usize, PathEvidenceError> {
        self.scan_candidates
            .checked_add(self.uninspectable)
            .ok_or(PathEvidenceError::CountOverflow)
    }

    pub(crate) fn validate(self) -> Result<(), PathEvidenceError> {
        let detector_total = self.detector_total()?;
        let kind_total = self.kind_total()?;
        if self.components_with_findings > self.scan_candidates
            || self.components_with_findings > detector_total
            || self.directory_components_with_findings > self.components_with_findings
            || self.file_components_with_findings > self.components_with_findings
            || kind_total != self.components_with_findings
            || (detector_total == 0) != (self.components_with_findings == 0)
        {
            return Err(PathEvidenceError::InconsistentCounts);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathEvidenceError {
    Secret(secrets::SecretError),
    Sensitive(sensitive::SensitiveError),
    RunFindingLimitExceeded,
    CountOverflow,
    InconsistentCounts,
}

impl fmt::Display for PathEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secret(error) => error.fmt(formatter),
            Self::Sensitive(error) => error.fmt(formatter),
            Self::RunFindingLimitExceeded => {
                formatter.write_str("path-component finding run limit exceeded")
            }
            Self::CountOverflow => formatter.write_str("path-component evidence count overflowed"),
            Self::InconsistentCounts => {
                formatter.write_str("path-component evidence counts are inconsistent")
            }
        }
    }
}

pub(crate) struct Session {
    limits: Limits,
    secret_rules: secrets::RuleSet,
    sensitive_rules: sensitive::RuleSet,
    report: Report,
}

impl Session {
    pub(crate) fn new(limits: Limits) -> Result<Self, PathEvidenceError> {
        Ok(Self {
            limits,
            secret_rules: secrets::RuleSet::compile().map_err(PathEvidenceError::Secret)?,
            sensitive_rules: sensitive::RuleSet::compile().map_err(PathEvidenceError::Sensitive)?,
            report: Report::default(),
        })
    }

    pub(crate) fn scan_component(
        &mut self,
        component: &OsStr,
        kind: ComponentKind,
    ) -> Result<ComponentInspectability, PathEvidenceError> {
        self.scan_component_with_findings(component, kind, |_, _| {})
    }

    pub(crate) fn scan_component_with_findings(
        &mut self,
        component: &OsStr,
        kind: ComponentKind,
        mut consume_findings: impl FnMut(&[secrets::SecretFinding], &[sensitive::SensitiveFinding]),
    ) -> Result<ComponentInspectability, PathEvidenceError> {
        let Some(text) = component.to_str() else {
            self.record_uninspectable()?;
            return Ok(ComponentInspectability::Uninspectable);
        };

        let secret_findings = self
            .secret_rules
            .find(text, self.limits.secrets)
            .map_err(PathEvidenceError::Secret)?;
        let sensitive_findings = self
            .sensitive_rules
            .find(text, self.limits.sensitive)
            .map_err(PathEvidenceError::Sensitive)?;
        let secret_count = secret_findings.len();
        let sensitive_count = sensitive_findings.len();
        let finding_count = secret_count
            .checked_add(sensitive_count)
            .ok_or(PathEvidenceError::CountOverflow)?;
        let next_findings = self
            .report
            .detector_total()?
            .checked_add(finding_count)
            .ok_or(PathEvidenceError::CountOverflow)?;
        if next_findings > self.limits.max_findings_per_run {
            return Err(PathEvidenceError::RunFindingLimitExceeded);
        }

        let has_findings = finding_count != 0;
        let next_report = Report {
            scan_candidates: self
                .report
                .scan_candidates
                .checked_add(1)
                .ok_or(PathEvidenceError::CountOverflow)?,
            uninspectable: self.report.uninspectable,
            components_with_findings: if has_findings {
                self.report
                    .components_with_findings
                    .checked_add(1)
                    .ok_or(PathEvidenceError::CountOverflow)?
            } else {
                self.report.components_with_findings
            },
            secret_findings: self
                .report
                .secret_findings
                .checked_add(secret_count)
                .ok_or(PathEvidenceError::CountOverflow)?,
            sensitive_findings: self
                .report
                .sensitive_findings
                .checked_add(sensitive_count)
                .ok_or(PathEvidenceError::CountOverflow)?,
            directory_components_with_findings: if has_findings && kind == ComponentKind::Directory
            {
                self.report
                    .directory_components_with_findings
                    .checked_add(1)
                    .ok_or(PathEvidenceError::CountOverflow)?
            } else {
                self.report.directory_components_with_findings
            },
            file_components_with_findings: if has_findings && kind == ComponentKind::File {
                self.report
                    .file_components_with_findings
                    .checked_add(1)
                    .ok_or(PathEvidenceError::CountOverflow)?
            } else {
                self.report.file_components_with_findings
            },
        };
        next_report.validate()?;
        self.report = next_report;
        consume_findings(&secret_findings, &sensitive_findings);
        Ok(ComponentInspectability::Inspectable)
    }

    pub(crate) fn finish(self) -> Result<Report, PathEvidenceError> {
        self.report.validate()?;
        self.report.observed_component_total()?;
        Ok(self.report)
    }

    fn record_uninspectable(&mut self) -> Result<(), PathEvidenceError> {
        let next_report = Report {
            uninspectable: self
                .report
                .uninspectable
                .checked_add(1)
                .ok_or(PathEvidenceError::CountOverflow)?,
            ..self.report
        };
        next_report.validate()?;
        next_report.observed_component_total()?;
        self.report = next_report;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC_GITHUB_PAT: &str = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";

    fn scan(component: &str, kind: ComponentKind) -> Report {
        let mut session = Session::new(Limits::default()).expect("compile trusted rules");
        session
            .scan_component(OsStr::new(component), kind)
            .expect("component scan succeeds");
        session.finish().expect("report is consistent")
    }

    fn synthetic_my_number(base: &str) -> String {
        assert_eq!(base.len(), 11);
        assert!(base.bytes().all(|byte| byte.is_ascii_digit()));
        let sum = base
            .bytes()
            .rev()
            .enumerate()
            .map(|(index, byte)| {
                let position = index as u32 + 1;
                let weight = if position <= 6 {
                    position + 1
                } else {
                    position - 5
                };
                u32::from(byte - b'0') * weight
            })
            .sum::<u32>();
        let remainder = sum % 11;
        let check = if remainder <= 1 { 0 } else { 11 - remainder };
        format!("{base}{check}")
    }

    #[test]
    fn reuses_sensitive_and_secret_rules_for_file_and_directory_components() {
        let my_number = synthetic_my_number("12345678901");
        let email = scan("fixture.user@example.invalid.txt", ComponentKind::File);
        assert_eq!(email.scan_candidates, 1);
        assert_eq!(email.sensitive_findings, 1);
        assert_eq!(email.file_components_with_findings, 1);

        let phone = scan("report_090-1234-5678.md", ComponentKind::File);
        assert!(phone.sensitive_findings >= 1);
        assert_eq!(phone.file_components_with_findings, 1);

        let directory_phone = scan("090-1234-5678", ComponentKind::Directory);
        assert!(directory_phone.sensitive_findings >= 1);
        assert_eq!(directory_phone.directory_components_with_findings, 1);

        let identifier = scan(&format!("{my_number}.txt"), ComponentKind::File);
        assert_eq!(identifier.sensitive_findings, 1);
        assert_eq!(identifier.file_components_with_findings, 1);

        let token = scan(SYNTHETIC_GITHUB_PAT, ComponentKind::Directory);
        assert_eq!(token.secret_findings, 1);
        assert_eq!(token.directory_components_with_findings, 1);
    }

    #[test]
    fn ordinary_and_nested_components_have_only_local_evidence() {
        let ordinary = scan("ordinary", ComponentKind::Directory);
        assert_eq!(
            ordinary,
            Report {
                scan_candidates: 1,
                ..Report::default()
            }
        );

        let nested = scan("fixture.user@example.invalid", ComponentKind::Directory);
        assert_eq!(nested.components_with_findings, 1);
        assert_eq!(nested.directory_components_with_findings, 1);
        assert_eq!(nested.file_components_with_findings, 0);
    }

    #[test]
    fn detector_findings_are_independent_and_checked() {
        let mut session = Session::new(Limits::default()).expect("compile trusted rules");
        let combined = format!("{SYNTHETIC_GITHUB_PAT},fixture@example.invalid");
        session
            .scan_component(OsStr::new(&combined), ComponentKind::File)
            .expect("combined scan succeeds");
        assert_eq!(
            session.finish(),
            Ok(Report {
                scan_candidates: 1,
                components_with_findings: 1,
                secret_findings: 1,
                sensitive_findings: 1,
                file_components_with_findings: 1,
                ..Report::default()
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_components_are_uninspectable_without_lossy_scanning() {
        use std::os::unix::ffi::OsStrExt;

        for kind in [ComponentKind::Directory, ComponentKind::File] {
            let raw = OsStr::from_bytes(b"fixture-\xff@example.invalid");
            let mut session = Session::new(Limits::default()).expect("compile trusted rules");
            session
                .scan_component(raw, kind)
                .expect("invalid component is counted");
            assert_eq!(
                session.finish(),
                Ok(Report {
                    uninspectable: 1,
                    ..Report::default()
                })
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn invalid_unicode_component_is_uninspectable_without_lossy_scanning() {
        use std::os::windows::ffi::OsStringExt;

        let raw = std::ffi::OsString::from_wide(&[0xd800]);
        let mut session = Session::new(Limits::default()).expect("compile trusted rules");
        session
            .scan_component(&raw, ComponentKind::Directory)
            .expect("invalid component is counted");
        assert_eq!(
            session.finish(),
            Ok(Report {
                uninspectable: 1,
                ..Report::default()
            })
        );
    }

    #[test]
    fn path_run_and_detector_limits_fail_closed() {
        let mut run_limited = Session::new(Limits {
            max_findings_per_run: 0,
            ..Limits::default()
        })
        .expect("compile trusted rules");
        assert_eq!(
            run_limited.scan_component(OsStr::new(SYNTHETIC_GITHUB_PAT), ComponentKind::File),
            Err(PathEvidenceError::RunFindingLimitExceeded)
        );
        assert_eq!(run_limited.finish(), Ok(Report::default()));

        let mut secret_limited = Session::new(Limits {
            secrets: secrets::Limits {
                max_findings_per_file: 0,
                ..secrets::Limits::default()
            },
            ..Limits::default()
        })
        .expect("compile trusted rules");
        assert_eq!(
            secret_limited.scan_component(OsStr::new(SYNTHETIC_GITHUB_PAT), ComponentKind::File),
            Err(PathEvidenceError::Secret(
                secrets::SecretError::FileFindingLimitExceeded
            ))
        );

        let mut secret_candidate_limited = Session::new(Limits {
            secrets: secrets::Limits {
                max_matches_per_rule_per_file: 0,
                ..secrets::Limits::default()
            },
            ..Limits::default()
        })
        .expect("compile trusted rules");
        assert_eq!(
            secret_candidate_limited
                .scan_component(OsStr::new(SYNTHETIC_GITHUB_PAT), ComponentKind::File),
            Err(PathEvidenceError::Secret(
                secrets::SecretError::MatchLimitExceeded
            ))
        );

        let mut sensitive_limited = Session::new(Limits {
            sensitive: sensitive::Limits {
                max_findings_per_file: 0,
                ..sensitive::Limits::default()
            },
            ..Limits::default()
        })
        .expect("compile trusted rules");
        assert_eq!(
            sensitive_limited
                .scan_component(OsStr::new("fixture@example.invalid"), ComponentKind::File),
            Err(PathEvidenceError::Sensitive(
                sensitive::SensitiveError::FileFindingLimitExceeded
            ))
        );

        let mut sensitive_candidate_limited = Session::new(Limits {
            sensitive: sensitive::Limits {
                max_candidates_per_rule_per_file: 0,
                ..sensitive::Limits::default()
            },
            ..Limits::default()
        })
        .expect("compile trusted rules");
        assert_eq!(
            sensitive_candidate_limited
                .scan_component(OsStr::new("fixture@example.invalid"), ComponentKind::File),
            Err(PathEvidenceError::Sensitive(
                sensitive::SensitiveError::CandidateLimitExceeded
            ))
        );
    }

    #[test]
    fn report_and_errors_never_format_raw_components() {
        let raw = "fixture.user@example.invalid";
        let report = scan(raw, ComponentKind::Directory);
        let debug = format!("{report:?}");
        assert!(!debug.contains(raw));

        for error in [
            PathEvidenceError::RunFindingLimitExceeded,
            PathEvidenceError::CountOverflow,
            PathEvidenceError::InconsistentCounts,
        ] {
            assert!(!error.to_string().contains(raw));
            assert!(!format!("{error:?}").contains(raw));
        }
    }

    #[test]
    fn report_validation_is_checked() {
        assert_eq!(
            Report {
                scan_candidates: usize::MAX,
                uninspectable: 1,
                ..Report::default()
            }
            .observed_component_total(),
            Err(PathEvidenceError::CountOverflow)
        );
        assert_eq!(
            Report {
                scan_candidates: 1,
                components_with_findings: 1,
                secret_findings: 1,
                ..Report::default()
            }
            .validate(),
            Err(PathEvidenceError::InconsistentCounts)
        );
    }
}
