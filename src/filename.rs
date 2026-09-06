//! Deterministic, bounded sensitive-filename evidence for transient basenames.
//!
//! Selected predicates are adapted from Context Armor `src/rules.js` at
//! e31f60715c102cf92d3efbef304202da1284d5fe under Apache-2.0. They are modified
//! for basename-only, raw-free evidence; see `THIRD_PARTY.md`.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;

use crate::rule_metadata::{DetectorRuleSpec, Parameter, SCOPE_FILENAME, SCOPE_PATH};

pub const RULE_COUNT: usize = 4;
pub const DEFAULT_MAX_FINDINGS_PER_RUN: usize = 400_000;

const ENVIRONMENT_KEYWORDS: [&str; 2] = [".env", ".env."];
const PRIVATE_KEY_ROOTS: [&str; 4] = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"];
const PRIVATE_KEY_EXTENSIONS: [&str; 4] = [".pem", ".key", ".p12", ".pfx"];
const CREDENTIAL_ROOTS: [&str; 7] = [
    "credential",
    "credentials",
    "secret",
    "secrets",
    "service-account",
    "service_account",
    "service account",
];
const AUTH_CONFIG_NAMES: [&str; 3] = [".npmrc", ".pypirc", ".netrc"];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FilenameRuleId {
    FileEnv,
    FilePrivateKey,
    FileCredentials,
    FileAuthConfig,
}

impl FilenameRuleId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileEnv => "FILE_ENV",
            Self::FilePrivateKey => "FILE_PRIVATE_KEY",
            Self::FileCredentials => "FILE_CREDENTIALS",
            Self::FileAuthConfig => "FILE_AUTH_CONFIG",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FilenameCategory {
    EnvironmentFile,
    PrivateKeyFilename,
    CredentialFilename,
    AuthConfigFilename,
}

impl FilenameCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::EnvironmentFile => "environment_file",
            Self::PrivateKeyFilename => "private_key_filename",
            Self::CredentialFilename => "credential_filename",
            Self::AuthConfigFilename => "auth_config_filename",
        }
    }
}

/// File-local classification evidence. It intentionally contains no basename or path.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FilenameFinding {
    pub rule_id: FilenameRuleId,
    pub category: FilenameCategory,
}

impl fmt::Display for FilenameFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}",
            self.rule_id.as_str(),
            self.category.as_str()
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_findings_per_run: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_findings_per_run: DEFAULT_MAX_FINDINGS_PER_RUN,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    pub scan_candidates: usize,
    pub findings: usize,
    pub files_with_findings: usize,
    pub uninspectable: usize,
    pub environment_findings: usize,
    pub private_key_findings: usize,
    pub credential_findings: usize,
    pub auth_config_findings: usize,
}

impl Report {
    fn category_total(self) -> Result<usize, FilenameError> {
        [
            self.environment_findings,
            self.private_key_findings,
            self.credential_findings,
            self.auth_config_findings,
        ]
        .into_iter()
        .try_fold(0_usize, |total, count| {
            total.checked_add(count).ok_or(FilenameError::CountOverflow)
        })
    }

    pub(crate) fn observed_basename_total(self) -> Result<usize, FilenameError> {
        self.scan_candidates
            .checked_add(self.uninspectable)
            .ok_or(FilenameError::CountOverflow)
    }

    pub(crate) fn validate(self) -> Result<(), FilenameError> {
        let maximum_findings = self
            .scan_candidates
            .checked_mul(RULE_COUNT)
            .ok_or(FilenameError::CountOverflow)?;
        if self.category_total()? != self.findings
            || self.findings > maximum_findings
            || self.files_with_findings > self.scan_candidates
            || self.files_with_findings > self.findings
            || self.environment_findings > self.scan_candidates
            || self.private_key_findings > self.scan_candidates
            || self.credential_findings > self.scan_candidates
            || self.auth_config_findings > self.scan_candidates
            || (self.findings == 0) != (self.files_with_findings == 0)
        {
            return Err(FilenameError::InconsistentCounts);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilenameError {
    RunFindingLimitExceeded,
    CountOverflow,
    InconsistentCounts,
}

impl fmt::Display for FilenameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RunFindingLimitExceeded => "filename evidence finding run limit exceeded",
            Self::CountOverflow => "filename evidence count overflowed",
            Self::InconsistentCounts => "filename evidence counts are inconsistent",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CategoryCounts {
    environment: usize,
    private_key: usize,
    credential: usize,
    auth_config: usize,
}

impl CategoryCounts {
    fn from_findings(findings: &[FilenameFinding]) -> Result<Self, FilenameError> {
        let mut counts = Self::default();
        for finding in findings {
            let count = match finding.category {
                FilenameCategory::EnvironmentFile => &mut counts.environment,
                FilenameCategory::PrivateKeyFilename => &mut counts.private_key,
                FilenameCategory::CredentialFilename => &mut counts.credential,
                FilenameCategory::AuthConfigFilename => &mut counts.auth_config,
            };
            *count = count.checked_add(1).ok_or(FilenameError::CountOverflow)?;
        }
        Ok(counts)
    }
}

pub(crate) struct Session {
    limits: Limits,
    report: Report,
}

impl Session {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            limits,
            report: Report::default(),
        }
    }

    pub(crate) fn scan_basename(
        &mut self,
        basename: &OsStr,
        mut consume_findings: impl FnMut(&[FilenameFinding]),
    ) -> Result<usize, FilenameError> {
        let Some(name) = basename.to_str() else {
            self.record_uninspectable()?;
            return Ok(0);
        };

        let findings = findings_for(name);
        let file_counts = CategoryCounts::from_findings(&findings)?;
        let finding_count = findings.len();
        let next_findings = self
            .report
            .findings
            .checked_add(finding_count)
            .ok_or(FilenameError::CountOverflow)?;
        if next_findings > self.limits.max_findings_per_run {
            return Err(FilenameError::RunFindingLimitExceeded);
        }

        let next_report = Report {
            scan_candidates: self
                .report
                .scan_candidates
                .checked_add(1)
                .ok_or(FilenameError::CountOverflow)?,
            findings: next_findings,
            files_with_findings: if findings.is_empty() {
                self.report.files_with_findings
            } else {
                self.report
                    .files_with_findings
                    .checked_add(1)
                    .ok_or(FilenameError::CountOverflow)?
            },
            uninspectable: self.report.uninspectable,
            environment_findings: self
                .report
                .environment_findings
                .checked_add(file_counts.environment)
                .ok_or(FilenameError::CountOverflow)?,
            private_key_findings: self
                .report
                .private_key_findings
                .checked_add(file_counts.private_key)
                .ok_or(FilenameError::CountOverflow)?,
            credential_findings: self
                .report
                .credential_findings
                .checked_add(file_counts.credential)
                .ok_or(FilenameError::CountOverflow)?,
            auth_config_findings: self
                .report
                .auth_config_findings
                .checked_add(file_counts.auth_config)
                .ok_or(FilenameError::CountOverflow)?,
        };
        next_report.validate()?;
        self.report = next_report;
        consume_findings(&findings);
        Ok(finding_count)
    }

    pub(crate) fn finish(self) -> Result<Report, FilenameError> {
        self.report.validate()?;
        self.report.observed_basename_total()?;
        Ok(self.report)
    }

    fn record_uninspectable(&mut self) -> Result<(), FilenameError> {
        let next_report = Report {
            uninspectable: self
                .report
                .uninspectable
                .checked_add(1)
                .ok_or(FilenameError::CountOverflow)?,
            ..self.report
        };
        next_report.validate()?;
        next_report.observed_basename_total()?;
        self.report = next_report;
        Ok(())
    }
}

fn findings_for(name: &str) -> Vec<FilenameFinding> {
    let mut findings = BTreeSet::new();
    if is_environment_filename(name) {
        findings.insert(FilenameFinding {
            rule_id: FilenameRuleId::FileEnv,
            category: FilenameCategory::EnvironmentFile,
        });
    }
    if is_private_key_filename(name) {
        findings.insert(FilenameFinding {
            rule_id: FilenameRuleId::FilePrivateKey,
            category: FilenameCategory::PrivateKeyFilename,
        });
    }
    if is_credential_filename(name) {
        findings.insert(FilenameFinding {
            rule_id: FilenameRuleId::FileCredentials,
            category: FilenameCategory::CredentialFilename,
        });
    }
    if is_auth_config_filename(name) {
        findings.insert(FilenameFinding {
            rule_id: FilenameRuleId::FileAuthConfig,
            category: FilenameCategory::AuthConfigFilename,
        });
    }
    findings.into_iter().collect()
}

fn is_environment_filename(name: &str) -> bool {
    name.eq_ignore_ascii_case(ENVIRONMENT_KEYWORDS[0])
        || starts_with_ignore_ascii_case(name, ENVIRONMENT_KEYWORDS[1])
}

fn is_private_key_filename(name: &str) -> bool {
    PRIVATE_KEY_ROOTS
        .into_iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
        || PRIVATE_KEY_EXTENSIONS.into_iter().any(|extension| {
            name.len() > extension.len() && ends_with_ignore_ascii_case(name, extension)
        })
}

fn is_credential_filename(name: &str) -> bool {
    CREDENTIAL_ROOTS
        .into_iter()
        .any(|root| has_optional_extension(name, root))
}

fn is_auth_config_filename(name: &str) -> bool {
    AUTH_CONFIG_NAMES
        .into_iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

pub(crate) fn descriptor_rule_specs() -> Vec<DetectorRuleSpec> {
    let spec = |rule_id, category, validator_id, patterns: &[&str]| DetectorRuleSpec {
        rule_id,
        scope_flags: SCOPE_PATH | SCOPE_FILENAME,
        patterns: patterns
            .iter()
            .map(|pattern| pattern.as_bytes().to_vec())
            .collect(),
        validator_id,
        category,
        token_category: "SECRET",
        parameters: vec![Parameter {
            id: "max-findings-per-run",
            value: DEFAULT_MAX_FINDINGS_PER_RUN as u64,
        }],
    };
    let mut private_patterns = Vec::new();
    private_patterns.extend(PRIVATE_KEY_ROOTS);
    private_patterns.extend(PRIVATE_KEY_EXTENSIONS);
    vec![
        spec(
            FilenameRuleId::FileEnv.as_str(),
            "environment_file",
            "ascii-ci-env-exact-or-prefix-v1",
            &ENVIRONMENT_KEYWORDS,
        ),
        spec(
            FilenameRuleId::FilePrivateKey.as_str(),
            "private_key_filename",
            "ascii-ci-private-key-root-or-extension-v1",
            &private_patterns,
        ),
        spec(
            FilenameRuleId::FileCredentials.as_str(),
            "credential_filename",
            "ascii-ci-root-with-optional-extension-v1",
            &CREDENTIAL_ROOTS,
        ),
        spec(
            FilenameRuleId::FileAuthConfig.as_str(),
            "auth_config_filename",
            "ascii-ci-exact-auth-config-v1",
            &AUTH_CONFIG_NAMES,
        ),
    ]
}

fn has_optional_extension(name: &str, root: &str) -> bool {
    name.eq_ignore_ascii_case(root)
        || (name.as_bytes().get(root.len()) == Some(&b'.')
            && name
                .as_bytes()
                .get(..root.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(root.as_bytes())))
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn ends_with_ignore_ascii_case(value: &str, suffix: &str) -> bool {
    value
        .as_bytes()
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(suffix.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(name: &str) -> Vec<FilenameFinding> {
        let mut session = Session::new(Limits::default());
        let mut findings = Vec::new();
        session
            .scan_basename(OsStr::new(name), |file_findings| {
                findings.extend_from_slice(file_findings);
            })
            .expect("scan succeeds");
        session.finish().expect("report is consistent");
        findings
    }

    fn finding(rule_id: FilenameRuleId, category: FilenameCategory) -> FilenameFinding {
        FilenameFinding { rule_id, category }
    }

    #[test]
    fn environment_semantics_match_only_dot_env_or_dot_env_prefix() {
        for name in [
            ".env",
            ".env.local",
            ".env.production",
            ".env.test.local",
            ".ENV.production",
        ] {
            assert_eq!(
                scan(name),
                vec![finding(
                    FilenameRuleId::FileEnv,
                    FilenameCategory::EnvironmentFile
                )],
                "expected environment evidence for {name}"
            );
        }
        for name in [".envrc", "my.env", "environment.env", "nested/.env"] {
            assert!(scan(name).is_empty(), "unexpected evidence for {name}");
        }
    }

    #[test]
    fn private_key_semantics_are_exact_names_or_selected_extensions() {
        for name in [
            "id_rsa",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            "server.pem",
            "server.KEY",
            "archive.p12",
            "cert.pfx",
            "CLIENT.P12",
        ] {
            assert_eq!(
                scan(name),
                vec![finding(
                    FilenameRuleId::FilePrivateKey,
                    FilenameCategory::PrivateKeyFilename
                )],
                "expected private-key filename evidence for {name}"
            );
        }
        for name in ["id_rsa.pub", ".key", "server.pem.txt", "id_ed25519-old"] {
            assert!(scan(name).is_empty(), "unexpected evidence for {name}");
        }
    }

    #[test]
    fn credential_semantics_use_exact_roots_with_only_an_optional_dot_suffix() {
        for name in [
            "credential",
            "credentials",
            "credentials.json",
            "secret.yaml",
            "secrets",
            "service-account.json",
            "service_account.toml",
            "service account.env",
            "CREDENTIALS.JSON",
        ] {
            assert_eq!(
                scan(name),
                vec![finding(
                    FilenameRuleId::FileCredentials,
                    FilenameCategory::CredentialFilename
                )],
                "expected credential filename evidence for {name}"
            );
        }
        for name in [
            "secret_service.rs",
            "mycredentials.json",
            "credentials-old.json",
            "service-account-backup.json",
            "serviceaccount.json",
        ] {
            assert!(scan(name).is_empty(), "unexpected evidence for {name}");
        }
    }

    #[test]
    fn authentication_config_semantics_are_exact_and_ascii_case_insensitive() {
        for name in [".npmrc", ".pypirc", ".netrc", ".NPMRC"] {
            assert_eq!(
                scan(name),
                vec![finding(
                    FilenameRuleId::FileAuthConfig,
                    FilenameCategory::AuthConfigFilename
                )],
                "expected authentication-config evidence for {name}"
            );
        }
        for name in ["project.npmrc", ".npmrc.local", "npmrc"] {
            assert!(scan(name).is_empty(), "unexpected evidence for {name}");
        }
    }

    #[test]
    fn database_dump_rule_is_explicitly_absent() {
        for name in [
            "migration.sql",
            "schema.sql",
            "database.sqlite",
            "database.sqlite3",
            "backup.dump",
            "backup.bak",
        ] {
            assert!(
                scan(name).is_empty(),
                "database rule must not be ported for {name}"
            );
        }
    }

    #[test]
    fn overlapping_evidence_is_deduplicated_and_deterministically_ordered() {
        let expected = vec![
            finding(
                FilenameRuleId::FilePrivateKey,
                FilenameCategory::PrivateKeyFilename,
            ),
            finding(
                FilenameRuleId::FileCredentials,
                FilenameCategory::CredentialFilename,
            ),
        ];
        assert_eq!(scan("secrets.key"), expected);
        assert_eq!(scan("SECRETS.KEY"), expected);

        let duplicate = expected[0];
        let deduplicated = BTreeSet::from([duplicate, duplicate]);
        assert_eq!(
            deduplicated.into_iter().collect::<Vec<_>>(),
            vec![duplicate]
        );
    }

    #[test]
    fn category_aggregates_count_each_file_local_finding_once() {
        let mut session = Session::new(Limits::default());
        for name in [
            ".env",
            "server.pem",
            "credentials",
            ".npmrc",
            "secrets.key",
            "ordinary.rs",
        ] {
            session
                .scan_basename(OsStr::new(name), |_| {})
                .expect("scan succeeds");
        }

        assert_eq!(
            session.finish(),
            Ok(Report {
                scan_candidates: 6,
                findings: 6,
                files_with_findings: 5,
                environment_findings: 1,
                private_key_findings: 2,
                credential_findings: 2,
                auth_config_findings: 1,
                ..Report::default()
            })
        );
    }

    #[test]
    fn aggregates_are_checked_bounded_and_consistent() {
        assert_eq!(DEFAULT_MAX_FINDINGS_PER_RUN, 100_000 * RULE_COUNT);

        let mut limited = Session::new(Limits {
            max_findings_per_run: 1,
        });
        assert_eq!(
            limited.scan_basename(OsStr::new("secrets.key"), |_| {}),
            Err(FilenameError::RunFindingLimitExceeded)
        );
        assert_eq!(limited.finish(), Ok(Report::default()));

        let mut candidate_overflow = Session::new(Limits::default());
        candidate_overflow.report.scan_candidates = usize::MAX;
        assert_eq!(
            candidate_overflow.scan_basename(OsStr::new("ordinary.rs"), |_| {}),
            Err(FilenameError::CountOverflow)
        );

        let mut finding_overflow = Session::new(Limits {
            max_findings_per_run: usize::MAX,
        });
        finding_overflow.report.findings = usize::MAX;
        assert_eq!(
            finding_overflow.scan_basename(OsStr::new(".env"), |_| {}),
            Err(FilenameError::CountOverflow)
        );

        let mut uninspectable_overflow = Session::new(Limits::default());
        uninspectable_overflow.report.uninspectable = usize::MAX;
        assert_eq!(
            uninspectable_overflow.record_uninspectable(),
            Err(FilenameError::CountOverflow)
        );

        let mut category_overflow = Session::new(Limits {
            max_findings_per_run: usize::MAX,
        });
        category_overflow.report.environment_findings = usize::MAX;
        assert_eq!(
            category_overflow.scan_basename(OsStr::new(".env"), |_| {}),
            Err(FilenameError::CountOverflow)
        );

        assert_eq!(
            Report {
                findings: usize::MAX,
                environment_findings: usize::MAX,
                private_key_findings: 1,
                ..Report::default()
            }
            .validate(),
            Err(FilenameError::CountOverflow)
        );
        assert_eq!(
            Report {
                scan_candidates: 1,
                findings: 1,
                files_with_findings: 1,
                ..Report::default()
            }
            .validate(),
            Err(FilenameError::InconsistentCounts)
        );
        assert_eq!(
            Report {
                findings: 1,
                files_with_findings: 1,
                environment_findings: 1,
                ..Report::default()
            }
            .validate(),
            Err(FilenameError::InconsistentCounts)
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_basename_is_counted_without_lossy_scanning() {
        use std::os::unix::ffi::OsStrExt;

        let raw = OsStr::from_bytes(b".env.\xff");
        let mut session = Session::new(Limits::default());
        assert_eq!(
            session.scan_basename(raw, |_| panic!("no finding callback")),
            Ok(0)
        );
        assert_eq!(
            session.finish(),
            Ok(Report {
                uninspectable: 1,
                ..Report::default()
            })
        );
    }

    #[cfg(windows)]
    #[test]
    fn invalid_unicode_basename_is_counted_without_lossy_scanning() {
        use std::os::windows::ffi::OsStringExt;

        let raw = std::ffi::OsString::from_wide(&[0xd800]);
        let mut session = Session::new(Limits::default());
        assert_eq!(
            session.scan_basename(&raw, |_| panic!("no finding callback")),
            Ok(0)
        );
        assert_eq!(
            session.finish(),
            Ok(Report {
                uninspectable: 1,
                ..Report::default()
            })
        );
    }

    #[test]
    fn findings_reports_and_errors_never_format_raw_names() {
        let raw = ".env.production";
        let finding = scan(raw)[0];
        let report = Report {
            scan_candidates: 1,
            findings: 1,
            files_with_findings: 1,
            environment_findings: 1,
            ..Report::default()
        };
        assert!(!format!("{finding:?}").contains(raw));
        assert!(!finding.to_string().contains(raw));
        assert!(!format!("{report:?}").contains(raw));
        for error in [
            FilenameError::RunFindingLimitExceeded,
            FilenameError::CountOverflow,
            FilenameError::InconsistentCounts,
        ] {
            assert!(!format!("{error:?}").contains(raw));
            assert!(!error.to_string().contains(raw));
        }
    }
}
