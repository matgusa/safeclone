//! Bounded, transient content access for already-classified file candidates.

use std::ffi::OsStr;
use std::fmt;
use std::io::Read;

use cap_fs_ext::{FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};

pub const DEFAULT_MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    pub candidates: usize,
    pub readable_text: usize,
    pub binary_like: usize,
    pub invalid_utf8: usize,
    pub oversized: usize,
    pub hard_linked: usize,
    pub bytes_inspected: usize,
}

impl Report {
    pub fn outcome_total(self) -> Result<usize, ContentError> {
        [
            self.readable_text,
            self.binary_like,
            self.invalid_utf8,
            self.oversized,
            self.hard_linked,
        ]
        .into_iter()
        .try_fold(0_usize, |total, count| {
            total.checked_add(count).ok_or(ContentError::CountOverflow)
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentOutcome {
    ReadableText,
    BinaryLike,
    InvalidUtf8,
    Oversized,
    HardLinked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentError {
    AccessFailed,
    NotRegularFile,
    ReadFailed,
    TotalLimitExceeded,
    CountOverflow,
    ByteCountOverflow,
    InconsistentCounts,
    UntrustedLinkCount,
}

impl fmt::Display for ContentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AccessFailed => "candidate content could not be opened safely",
            Self::NotRegularFile => "candidate changed before content access",
            Self::ReadFailed => "candidate content could not be read consistently",
            Self::TotalLimitExceeded => "content inspection total byte limit exceeded",
            Self::CountOverflow => "content outcome count overflowed",
            Self::ByteCountOverflow => "content byte count overflowed",
            Self::InconsistentCounts => "content outcome counts are inconsistent",
            Self::UntrustedLinkCount => "candidate link count could not be trusted",
        })
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

    pub(crate) fn inspect_candidate(
        &mut self,
        directory: &Dir,
        name: &OsStr,
        mut consume_text: impl FnMut(&str),
    ) -> Result<ContentOutcome, ContentError> {
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let mut file = directory
            .open_with(name, &options)
            .map_err(|_| ContentError::AccessFailed)?;
        let metadata = file.metadata().map_err(|_| ContentError::AccessFailed)?;
        if !metadata.file_type().is_file() {
            return Err(ContentError::NotRegularFile);
        }
        match metadata.nlink() {
            1 => {}
            2.. => {
                self.record_outcome(ContentOutcome::HardLinked)?;
                return Ok(ContentOutcome::HardLinked);
            }
            0 => return Err(ContentError::UntrustedLinkCount),
        }

        let max_file_bytes = u64::try_from(self.limits.max_file_bytes)
            .map_err(|_| ContentError::ByteCountOverflow)?;
        if metadata.len() > max_file_bytes {
            self.record_outcome(ContentOutcome::Oversized)?;
            return Ok(ContentOutcome::Oversized);
        }

        let remaining_total = self
            .limits
            .max_total_bytes
            .checked_sub(self.report.bytes_inspected)
            .ok_or(ContentError::TotalLimitExceeded)?;
        let file_probe = self
            .limits
            .max_file_bytes
            .checked_add(1)
            .ok_or(ContentError::ByteCountOverflow)?;
        let total_probe = remaining_total
            .checked_add(1)
            .ok_or(ContentError::ByteCountOverflow)?;
        let read_limit = file_probe.min(total_probe);
        let read_limit = u64::try_from(read_limit).map_err(|_| ContentError::ByteCountOverflow)?;

        let mut bytes = Vec::new();
        file.by_ref()
            .take(read_limit)
            .read_to_end(&mut bytes)
            .map_err(|_| ContentError::ReadFailed)?;
        self.record_bytes(bytes.len())?;

        if self.report.bytes_inspected > self.limits.max_total_bytes {
            return Err(ContentError::TotalLimitExceeded);
        }
        if bytes.len() > self.limits.max_file_bytes {
            self.record_outcome(ContentOutcome::Oversized)?;
            return Ok(ContentOutcome::Oversized);
        }
        if bytes.contains(&0) {
            self.record_outcome(ContentOutcome::BinaryLike)?;
            return Ok(ContentOutcome::BinaryLike);
        }

        match std::str::from_utf8(&bytes) {
            Ok(text) => {
                consume_text(text);
                self.record_outcome(ContentOutcome::ReadableText)?;
                Ok(ContentOutcome::ReadableText)
            }
            Err(_) => {
                self.record_outcome(ContentOutcome::InvalidUtf8)?;
                Ok(ContentOutcome::InvalidUtf8)
            }
        }
    }

    pub(crate) fn finish(self) -> Result<Report, ContentError> {
        if self.report.outcome_total()? != self.report.candidates {
            return Err(ContentError::InconsistentCounts);
        }
        Ok(self.report)
    }

    fn record_bytes(&mut self, bytes: usize) -> Result<(), ContentError> {
        self.report.bytes_inspected = self
            .report
            .bytes_inspected
            .checked_add(bytes)
            .ok_or(ContentError::ByteCountOverflow)?;
        Ok(())
    }

    fn record_outcome(&mut self, outcome: ContentOutcome) -> Result<(), ContentError> {
        self.report.candidates = self
            .report
            .candidates
            .checked_add(1)
            .ok_or(ContentError::CountOverflow)?;
        let count = match outcome {
            ContentOutcome::ReadableText => &mut self.report.readable_text,
            ContentOutcome::BinaryLike => &mut self.report.binary_like,
            ContentOutcome::InvalidUtf8 => &mut self.report.invalid_utf8,
            ContentOutcome::Oversized => &mut self.report.oversized,
            ContentOutcome::HardLinked => &mut self.report.hard_linked,
        };
        *count = count.checked_add(1).ok_or(ContentError::CountOverflow)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ContentError, ContentOutcome, Limits, Report, Session, DEFAULT_MAX_FILE_BYTES,
        DEFAULT_MAX_TOTAL_BYTES,
    };
    use cap_std::ambient_authority;
    use cap_std::fs::Dir;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "safeclone-content-{label}-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated test directory");
            Self(path)
        }

        fn capability(&self) -> Dir {
            Dir::open_ambient_dir(&self.0, ambient_authority()).expect("open test capability")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn default_limits_are_explicit() {
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 4 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_TOTAL_BYTES, 64 * 1024 * 1024);
        assert_eq!(
            Limits::default(),
            Limits {
                max_file_bytes: DEFAULT_MAX_FILE_BYTES,
                max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            }
        );
    }

    #[test]
    fn ordinary_utf8_is_scoped_to_the_consumer_and_not_persisted() {
        let fixture = TestDirectory::new("utf8");
        let original = b"fn main() { println!(\"transient marker\"); }";
        fs::write(fixture.0.join("main.rs"), original).expect("write fixture");
        let entries_before = fs::read_dir(&fixture.0).expect("list before").count();
        let mut session = Session::new(Limits {
            max_file_bytes: 1024,
            max_total_bytes: 1024,
        });
        let mut observed = false;

        let outcome = session
            .inspect_candidate(&fixture.capability(), "main.rs".as_ref(), |text| {
                assert_eq!(text.as_bytes(), original);
                observed = true;
            })
            .expect("bounded UTF-8 content is readable");
        let report = session.finish().expect("report is consistent");

        assert!(observed);
        assert_eq!(outcome, ContentOutcome::ReadableText);
        assert_eq!(report.readable_text, 1);
        assert_eq!(report.bytes_inspected, original.len());
        assert_eq!(
            fs::read(fixture.0.join("main.rs")).expect("read source after"),
            original
        );
        assert_eq!(
            fs::read_dir(&fixture.0).expect("list after").count(),
            entries_before,
            "content access must not persist a copy"
        );
    }

    #[test]
    fn nul_and_invalid_utf8_are_never_passed_as_text() {
        let fixture = TestDirectory::new("validation");
        fs::write(fixture.0.join("contains-nul.rs"), b"text\0payload").expect("write NUL fixture");
        fs::write(fixture.0.join("invalid.rs"), [0xff, 0xfe]).expect("write UTF-8 fixture");
        let capability = fixture.capability();
        let mut session = Session::new(Limits {
            max_file_bytes: 1024,
            max_total_bytes: 1024,
        });
        let mut consumer_calls = 0;

        let nul = session
            .inspect_candidate(&capability, "contains-nul.rs".as_ref(), |_| {
                consumer_calls += 1
            })
            .expect("NUL is a safe outcome");
        let invalid = session
            .inspect_candidate(&capability, "invalid.rs".as_ref(), |_| consumer_calls += 1)
            .expect("invalid UTF-8 is a safe outcome");
        let report = session.finish().expect("report is consistent");

        assert_eq!(nul, ContentOutcome::BinaryLike);
        assert_eq!(invalid, ContentOutcome::InvalidUtf8);
        assert_eq!(consumer_calls, 0);
        assert_eq!(report.binary_like, 1);
        assert_eq!(report.invalid_utf8, 1);
    }

    #[test]
    fn per_file_limit_returns_only_an_oversized_outcome() {
        let fixture = TestDirectory::new("oversized");
        fs::write(fixture.0.join("large.rs"), b"12345").expect("write fixture");
        let mut session = Session::new(Limits {
            max_file_bytes: 4,
            max_total_bytes: 16,
        });
        let mut consumed = false;

        let outcome = session
            .inspect_candidate(&fixture.capability(), "large.rs".as_ref(), |_| {
                consumed = true
            })
            .expect("oversized file is a safe outcome");
        let report = session.finish().expect("report is consistent");

        assert_eq!(outcome, ContentOutcome::Oversized);
        assert!(!consumed);
        assert_eq!(report.oversized, 1);
        assert_eq!(report.bytes_inspected, 0);
    }

    fn assert_external_hard_link_is_not_consumed(label: &str) {
        let fixture = TestDirectory::new(label);
        let source = fixture.0.join("source");
        let outside = fixture.0.join("outside");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&outside).expect("create outside");
        let marker = b"external hard-link marker must not be consumed";
        let external = outside.join("external.rs");
        fs::write(&external, marker).expect("write external fixture");
        fs::hard_link(&external, source.join("linked.rs")).expect("create hard link");
        let source_before = fs::read(source.join("linked.rs")).expect("read source before");
        let mut session = Session::new(Limits {
            max_file_bytes: 1,
            max_total_bytes: 1,
        });
        let mut consumed = false;

        let outcome = session
            .inspect_candidate(
                &Dir::open_ambient_dir(&source, ambient_authority())
                    .expect("open source capability"),
                "linked.rs".as_ref(),
                |_| consumed = true,
            )
            .expect("hard link is a safe content outcome");
        let report = session.finish().expect("report is consistent");

        assert_eq!(outcome, ContentOutcome::HardLinked);
        assert!(!consumed, "hard-linked bytes must not reach the consumer");
        assert_eq!(report.hard_linked, 1);
        assert_eq!(report.oversized, 0);
        assert_eq!(report.bytes_inspected, 0);
        assert_eq!(
            fs::read(source.join("linked.rs")).expect("read source after"),
            source_before,
            "content inspection must not modify the source"
        );
        assert_eq!(fs::read(&external).expect("read external after"), marker);
    }

    #[cfg(unix)]
    #[test]
    fn unix_external_hard_link_is_rejected_before_content_or_size_inspection() {
        assert_external_hard_link_is_not_consumed("unix-hard-link");
    }

    #[cfg(windows)]
    #[test]
    fn windows_external_hard_link_is_rejected_before_content_or_size_inspection() {
        assert_external_hard_link_is_not_consumed("windows-hard-link");
    }

    #[test]
    fn total_limit_aborts_instead_of_returning_partial_success() {
        let fixture = TestDirectory::new("total-limit");
        fs::write(fixture.0.join("one.rs"), b"1234").expect("write fixture");
        fs::write(fixture.0.join("two.rs"), b"5678").expect("write fixture");
        let capability = fixture.capability();
        let mut session = Session::new(Limits {
            max_file_bytes: 4,
            max_total_bytes: 6,
        });

        assert_eq!(
            session.inspect_candidate(&capability, "one.rs".as_ref(), |_| {}),
            Ok(ContentOutcome::ReadableText)
        );
        assert_eq!(
            session.inspect_candidate(&capability, "two.rs".as_ref(), |_| {}),
            Err(ContentError::TotalLimitExceeded)
        );
    }

    #[test]
    fn checked_count_and_byte_overflow_fail_closed() {
        let mut count_session = Session {
            limits: Limits::default(),
            report: Report {
                candidates: usize::MAX,
                ..Report::default()
            },
        };
        assert_eq!(
            count_session.record_outcome(ContentOutcome::ReadableText),
            Err(ContentError::CountOverflow)
        );

        let mut byte_session = Session {
            limits: Limits::default(),
            report: Report {
                bytes_inspected: usize::MAX,
                ..Report::default()
            },
        };
        assert_eq!(
            byte_session.record_bytes(1),
            Err(ContentError::ByteCountOverflow)
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_candidate_is_not_followed() {
        use std::os::unix::fs::symlink;

        let fixture = TestDirectory::new("symlink");
        fs::write(fixture.0.join("outside.rs"), b"must not be read").expect("write target");
        symlink(fixture.0.join("outside.rs"), fixture.0.join("linked.rs")).expect("create symlink");
        let mut session = Session::new(Limits::default());

        assert_eq!(
            session.inspect_candidate(&fixture.capability(), "linked.rs".as_ref(), |_| {}),
            Err(ContentError::AccessFailed)
        );
    }
}
