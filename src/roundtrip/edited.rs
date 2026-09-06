//! Stable, no-follow observation of the hostile edited AI workspace.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Read;

use cap_fs_ext::MetadataExt;

use super::anchor::{ContentTokenSpan, TokenFact};
use super::baseline::{
    canonical_path, require_ai_visible_file_policy, validate_relative_path, StreamEncoder,
    MAX_CANONICAL_PATH_BYTES, MAX_DEPTH, MAX_ENTRIES, MAX_FILE_BYTES, MAX_TOTAL_AI_FILE_BYTES,
};
use super::crypto::{constant_time_equal, KeyPurpose, KeySchedule, SecretVec};
use super::observe::{
    file_identity, EntryKind as ObservedEntryKind, FileIdentity, ObservedNamespaceEntry,
    QualifiedDirectory, ShortNameMode,
};
use super::ruleset::ruleset_id;
use super::token::{
    authenticate_token, decode_base32_128, parse_token, ReviewProfile, TokenCategory,
    BASE32_128_LENGTH, ENGINE_VERSION, POLICY_ID, TOKEN_PREFIX, TOKEN_SUITE_ID,
};
use super::tokenize::{
    DetectorSet, TokenInventory, MAX_OCCURRENCES_PER_COMPONENT, MAX_SESSION_OCCURRENCES,
};
use super::{Error, Result};

const DETECTOR_SENTINEL: &str = "SAFECLONE_TOKEN";
const MAX_RESERVED_FORM_BYTES: usize = 128;

#[cfg(test)]
type AfterFileReadTestHook = Box<dyn FnMut() -> Result<()>>;

#[cfg(test)]
std::thread_local! {
    static AFTER_FILE_READ_TEST_HOOK: std::cell::RefCell<Option<AfterFileReadTestHook>> =
        std::cell::RefCell::new(None);
    static TOGGLE_FINAL_SHORT_NAME_MODE_FOR_TEST: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) struct AfterFileReadTestHookGuard;

#[cfg(test)]
impl Drop for AfterFileReadTestHookGuard {
    fn drop(&mut self) {
        AFTER_FILE_READ_TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
pub(crate) fn install_after_file_read_test_hook(
    hook: impl FnMut() -> Result<()> + 'static,
) -> AfterFileReadTestHookGuard {
    AFTER_FILE_READ_TEST_HOOK.with(|slot| {
        let prior = slot.borrow_mut().replace(Box::new(hook));
        assert!(prior.is_none(), "nested edited-file read test hook");
    });
    AfterFileReadTestHookGuard
}

#[cfg(test)]
pub(crate) struct FinalShortNameModeTestHookGuard;

#[cfg(test)]
impl Drop for FinalShortNameModeTestHookGuard {
    fn drop(&mut self) {
        TOGGLE_FINAL_SHORT_NAME_MODE_FOR_TEST.with(|toggle| toggle.set(false));
    }
}

#[cfg(test)]
pub(crate) fn install_final_short_name_mode_toggle_test_hook() -> FinalShortNameModeTestHookGuard {
    TOGGLE_FINAL_SHORT_NAME_MODE_FOR_TEST.with(|toggle| {
        assert!(!toggle.replace(true), "nested short-name mode test hook");
    });
    FinalShortNameModeTestHookGuard
}

#[cfg(test)]
fn run_after_file_read_test_hook() -> Result<()> {
    AFTER_FILE_READ_TEST_HOOK.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| Error::InvalidState)?;
        match slot.as_mut() {
            Some(hook) => hook(),
            None => Ok(()),
        }
    })
}

#[cfg(test)]
fn final_short_name_mode_for_test(actual: ShortNameMode) -> ShortNameMode {
    TOGGLE_FINAL_SHORT_NAME_MODE_FOR_TEST.with(|toggle| {
        if toggle.get() {
            match actual {
                ShortNameMode::Enabled => ShortNameMode::Disabled,
                ShortNameMode::Disabled => ShortNameMode::Enabled,
            }
        } else {
            actual
        }
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ReservedFormState {
    Canonical = 1,
    Incomplete = 2,
    MalformedCategory = 3,
    MalformedSid = 4,
    MalformedOid = 5,
    MalformedAuth = 6,
    BadSeparatorsOrLength = 7,
    Noncanonical = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ReservedLocationKind {
    Path = 1,
    Content = 2,
}

/// Bounded reserved-form evidence. It intentionally retains no full token or
/// malformed source bytes and has no ordinary `Debug` implementation.
pub(crate) struct ReservedForm {
    pub(crate) path: Vec<u8>,
    pub(crate) location_kind: ReservedLocationKind,
    pub(crate) component_index: u32,
    pub(crate) position: u64,
    pub(crate) end_position: u64,
    pub(crate) state: ReservedFormState,
    pub(crate) session_id: Option<[u8; 16]>,
    pub(crate) occurrence_id: Option<[u8; 16]>,
    pub(crate) category: Option<TokenCategory>,
    pub(crate) authentication_valid: bool,
    pub(crate) authenticated_known: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EditedEntryKind {
    Directory,
    File,
    Unsupported,
}

/// One raw-free entry observation retained after a pass. Canonical safe paths
/// are private transient inputs and therefore this type has no `Debug`.
pub(crate) struct EditedEntry {
    pub(crate) path: Vec<u8>,
    pub(crate) components: Vec<String>,
    pub(crate) kind: EditedEntryKind,
    pub(crate) identity: Option<FileIdentity>,
    pub(crate) directory_file_id64: u64,
    pub(crate) observed_short_alias_utf16: Option<Vec<u16>>,
    pub(crate) byte_len: u64,
    pub(crate) exact_file_match: Option<[u8; 32]>,
    pub(crate) protected_name: bool,
    pub(crate) hard_link: bool,
    pub(crate) named_stream: bool,
    pub(crate) supported_utf8_text: bool,
    pub(crate) invalid_utf8: bool,
    pub(crate) new_sensitive_finding: bool,
    pub(crate) path_form_range: std::ops::Range<usize>,
    pub(crate) content_form_range: std::ops::Range<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EditedSummary {
    pub(crate) edited_tree_commitment: [u8; 32],
    pub(crate) reserved_form_commitment: [u8; 32],
    pub(crate) root_identity: FileIdentity,
    pub(crate) short_name_mode: ShortNameMode,
    pub(crate) entries: u32,
    pub(crate) directories: u32,
    pub(crate) regular_files: u32,
    pub(crate) total_file_bytes: u64,
    pub(crate) canonical_path_bytes: u64,
    pub(crate) reserved_forms: u32,
    pub(crate) parseable_known_oids: u32,
    pub(crate) authenticated_known_forms: u32,
}

pub(crate) struct EditedPass {
    pub(crate) summary: EditedSummary,
    pub(crate) entries: Vec<EditedEntry>,
    pub(crate) forms: Vec<ReservedForm>,
}

pub(crate) struct EditedFileInput<'a> {
    pub(crate) path: &'a [u8],
    pub(crate) bytes: &'a [u8],
    pub(crate) authenticated_tokens: &'a [ContentTokenSpan],
}

pub(super) fn observe_pass(
    root: &QualifiedDirectory,
    schedule: &KeySchedule<'_>,
    inventory: &TokenInventory,
    profile: ReviewProfile,
    mut inspect_file: impl FnMut(EditedFileInput<'_>) -> Result<()>,
) -> Result<EditedPass> {
    if !profile.is_current() {
        return Err(Error::InvalidState);
    }
    root.requery_policy()?;
    root.verify()?;
    let root_identity = root.identity();
    let short_name_mode = root.short_name_mode();
    let mut scanner =
        EditedScanner::new(schedule, inventory, profile, root_identity, short_name_mode)?;
    scanner.walk(root, &[], 0, &mut inspect_file)?;
    root.requery_policy()?;
    root.verify()?;
    let final_short_name_mode = root.short_name_mode();
    #[cfg(test)]
    let final_short_name_mode = final_short_name_mode_for_test(final_short_name_mode);
    if root.identity() != root_identity || final_short_name_mode != short_name_mode {
        return Err(Error::WorkspaceUnstable);
    }
    scanner.finish(root_identity, short_name_mode)
}

pub(super) fn exact_file_match_commitment(
    schedule: &KeySchedule<'_>,
    bytes: &[u8],
) -> Result<[u8; 32]> {
    let mut output = StreamEncoder::new(
        schedule,
        KeyPurpose::TreeCommit,
        b"safeclone/rt3/token-free-file-match-v1",
    )?;
    output.u8(1); // ordinary default-stream regular file
    output.bytes(bytes)?;
    Ok(output.finish())
}

/// Reopen exactly one accepted edited file through retained namespace
/// capabilities and prove that its bytes and identity still equal the stable
/// classification observation.  The returned raw bytes are zeroizing and file-local.
pub(crate) fn read_accepted_file(
    root: &QualifiedDirectory,
    accepted_by_path: &BTreeMap<&[u8], &EditedEntry>,
    accepted: &EditedEntry,
    schedule: &KeySchedule<'_>,
) -> Result<SecretVec> {
    if accepted.kind != EditedEntryKind::File
        || accepted.protected_name
        || accepted.hard_link
        || accepted.named_stream
        || accepted.identity.is_none()
        || accepted.exact_file_match.is_none()
        || accepted.components.is_empty()
    {
        return Err(Error::WorkspaceUnstable);
    }

    let mut retained_parent = None;
    for component_count in 1..accepted.components.len() {
        let parent = retained_parent.as_ref().unwrap_or(root);
        let component = accepted
            .components
            .get(component_count - 1)
            .ok_or(Error::InvalidState)?;
        let path = canonical_path(&accepted.components[..component_count])?;
        let expected_directory = accepted_by_path
            .get(path.as_slice())
            .copied()
            .ok_or(Error::WorkspaceUnstable)?;
        let observation = parent.observe()?;
        let observed = observation.find_exact_long(component)?;
        if !namespace_record_matches(observed, expected_directory)
            || expected_directory.kind != EditedEntryKind::Directory
            || expected_directory.protected_name
            || expected_directory.hard_link
            || expected_directory.named_stream
        {
            return Err(Error::WorkspaceUnstable);
        }
        let opened = parent.open_exact_child_directory(OsStr::new(component))?;
        if expected_directory.identity != Some(opened.identity()) {
            return Err(Error::WorkspaceUnstable);
        }
        retained_parent = Some(opened);
    }

    let parent = retained_parent.as_ref().unwrap_or(root);
    let leaf = accepted.components.last().ok_or(Error::InvalidState)?;
    let observation = parent.observe()?;
    let observed = observation.find_exact_long(leaf)?;
    if !namespace_record_matches(observed, accepted) {
        return Err(Error::WorkspaceUnstable);
    }
    let mut opened = parent.open_observed_regular_for_edited(observed)?;
    if opened.identity() != accepted.identity.ok_or(Error::WorkspaceUnstable)?
        || opened.link_count() != 1
        || !opened.default_stream_only()
    {
        return Err(Error::WorkspaceUnstable);
    }
    let before = opened
        .file()
        .metadata()
        .map_err(|_| Error::FilesystemFailure)?;
    let before_modified = before.modified().map_err(|_| Error::FilesystemFailure)?;
    let length = usize::try_from(before.len()).map_err(|_| Error::BoundExceeded)?;
    if length > MAX_FILE_BYTES || before.len() != accepted.byte_len {
        return Err(Error::WorkspaceUnstable);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::BoundExceeded)?;
    opened
        .file_mut()
        .take(u64::try_from(MAX_FILE_BYTES + 1).map_err(|_| Error::BoundExceeded)?)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::FilesystemFailure)?;
    let after = opened
        .file()
        .metadata()
        .map_err(|_| Error::FilesystemFailure)?;
    if bytes.len() != length
        || file_identity(opened.file())? != opened.identity()
        || after.len() != before.len()
        || after.nlink() != before.nlink()
        || after.modified().map_err(|_| Error::FilesystemFailure)? != before_modified
        || opened.recheck_default_stream_only()? != opened.default_stream_only()
    {
        return Err(Error::WorkspaceUnstable);
    }
    let actual = exact_file_match_commitment(schedule, &bytes)?;
    let expected = accepted.exact_file_match.ok_or(Error::WorkspaceUnstable)?;
    if !constant_time_equal(&actual, &expected) {
        return Err(Error::WorkspaceUnstable);
    }
    Ok(SecretVec::new(bytes))
}

fn namespace_record_matches(observed: &ObservedNamespaceEntry, accepted: &EditedEntry) -> bool {
    let expected_kind = match accepted.kind {
        EditedEntryKind::Directory => ObservedEntryKind::Directory,
        EditedEntryKind::File => ObservedEntryKind::File,
        EditedEntryKind::Unsupported => ObservedEntryKind::Unsupported,
    };
    observed.entry_kind() == expected_kind
        && observed.directory_file_id64() == accepted.directory_file_id64
        && observed.short_alias_utf16() == accepted.observed_short_alias_utf16.as_deref()
        && observed.protected_name() == accepted.protected_name
}

struct EditedScanner<'a> {
    schedule: &'a KeySchedule<'a>,
    inventory: &'a TokenInventory,
    detectors: DetectorSet,
    tree: StreamEncoder,
    entries: Vec<EditedEntry>,
    forms: Vec<ReservedForm>,
    entry_count: usize,
    directory_count: usize,
    file_count: usize,
    total_bytes: usize,
    canonical_path_bytes: usize,
}

impl<'a> EditedScanner<'a> {
    fn new(
        schedule: &'a KeySchedule<'a>,
        inventory: &'a TokenInventory,
        profile: ReviewProfile,
        root_identity: FileIdentity,
        short_name_mode: ShortNameMode,
    ) -> Result<Self> {
        let mut tree = StreamEncoder::new(
            schedule,
            KeyPurpose::TreeCommit,
            b"safeclone/rt3/edited-ai-tree-v1",
        )?;
        tree.bytes(b"EDITED_AI")?;
        tree.bytes(ENGINE_VERSION.as_bytes())?;
        tree.bytes(POLICY_ID.as_bytes())?;
        tree.bytes(ruleset_id().as_bytes())?;
        tree.u16(TOKEN_SUITE_ID);
        tree.u8(profile as u8);
        tree.u8(match short_name_mode {
            ShortNameMode::Enabled => 1,
            ShortNameMode::Disabled => 2,
        });
        encode_identity(&mut tree, root_identity)?;
        Ok(Self {
            schedule,
            inventory,
            detectors: DetectorSet::compile()?,
            tree,
            entries: Vec::new(),
            forms: Vec::new(),
            entry_count: 0,
            directory_count: 0,
            file_count: 0,
            total_bytes: 0,
            canonical_path_bytes: 0,
        })
    }

    fn walk(
        &mut self,
        directory: &QualifiedDirectory,
        parent: &[String],
        depth: usize,
        inspect_file: &mut impl FnMut(EditedFileInput<'_>) -> Result<()>,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::BoundExceeded);
        }
        let before = directory.observe()?;
        self.entry_count = checked_add(self.entry_count, before.entries().len())?;
        if self.entry_count > MAX_ENTRIES {
            return Err(Error::BoundExceeded);
        }
        for entry in before.entries() {
            let components = appended(parent, entry.canonical_long_name())?;
            validate_relative_path(&components)?;
            let path = canonical_path(&components)?;
            self.canonical_path_bytes = checked_add(self.canonical_path_bytes, path.len())?;
            if self.canonical_path_bytes > MAX_CANONICAL_PATH_BYTES {
                return Err(Error::BoundExceeded);
            }
            let component_index =
                u32::try_from(components.len() - 1).map_err(|_| Error::BoundExceeded)?;
            let path_scan = scan_reserved(
                entry.canonical_long_name().as_bytes(),
                &path,
                ReservedLocationKind::Path,
                component_index,
                self.schedule,
                self.inventory,
            )?;
            let path_sensitive = self.detectors.has_finding(
                path_scan
                    .masked_utf8
                    .as_deref()
                    .ok_or(Error::InvalidCanonicalInput)?,
            )?;
            let path_form_start = self.forms.len();
            self.extend_forms(path_scan.forms)?;
            let path_form_end = self.forms.len();
            self.encode_entry_prefix(&path, entry)?;

            match entry.entry_kind() {
                ObservedEntryKind::Unsupported => {
                    self.tree.u8(3);
                    self.tree.u8(1); // reparse/link-like directory record
                    self.push_entry(EditedEntry {
                        path,
                        components,
                        kind: EditedEntryKind::Unsupported,
                        identity: None,
                        directory_file_id64: entry.directory_file_id64(),
                        observed_short_alias_utf16: entry.short_alias_utf16().map(<[u16]>::to_vec),
                        byte_len: 0,
                        exact_file_match: None,
                        protected_name: entry.protected_name(),
                        hard_link: false,
                        named_stream: false,
                        supported_utf8_text: false,
                        invalid_utf8: false,
                        new_sensitive_finding: path_sensitive,
                        path_form_range: path_form_start..path_form_end,
                        content_form_range: self.forms.len()..self.forms.len(),
                    })?;
                }
                ObservedEntryKind::Directory => {
                    self.directory_count = checked_add(self.directory_count, 1)?;
                    self.tree.u8(1);
                    if entry.protected_name() {
                        self.tree.u8(1); // deliberately not followed
                        self.push_entry(EditedEntry {
                            path,
                            components,
                            kind: EditedEntryKind::Directory,
                            identity: None,
                            directory_file_id64: entry.directory_file_id64(),
                            observed_short_alias_utf16: entry
                                .short_alias_utf16()
                                .map(<[u16]>::to_vec),
                            byte_len: 0,
                            exact_file_match: None,
                            protected_name: true,
                            hard_link: false,
                            named_stream: false,
                            supported_utf8_text: false,
                            invalid_utf8: false,
                            new_sensitive_finding: path_sensitive,
                            path_form_range: path_form_start..path_form_end,
                            content_form_range: self.forms.len()..self.forms.len(),
                        })?;
                        continue;
                    }
                    let child = directory
                        .open_exact_child_directory(OsStr::new(entry.canonical_long_name()))?;
                    let identity = child.identity();
                    let link_count = child.link_count()?;
                    encode_identity(&mut self.tree, identity)?;
                    self.tree.u64(link_count);
                    self.tree.u8(0); // followed ordinary directory
                    self.push_entry(EditedEntry {
                        path,
                        components: components.clone(),
                        kind: EditedEntryKind::Directory,
                        identity: Some(identity),
                        directory_file_id64: entry.directory_file_id64(),
                        observed_short_alias_utf16: entry.short_alias_utf16().map(<[u16]>::to_vec),
                        byte_len: 0,
                        exact_file_match: None,
                        protected_name: false,
                        hard_link: link_count != 1,
                        named_stream: false,
                        supported_utf8_text: false,
                        invalid_utf8: false,
                        new_sensitive_finding: path_sensitive,
                        path_form_range: path_form_start..path_form_end,
                        content_form_range: self.forms.len()..self.forms.len(),
                    })?;
                    self.walk(&child, &components, depth + 1, inspect_file)?;
                }
                ObservedEntryKind::File => {
                    self.file_count = checked_add(self.file_count, 1)?;
                    self.observe_file(
                        directory,
                        entry,
                        components,
                        path,
                        path_sensitive,
                        path_form_start..path_form_end,
                        inspect_file,
                    )?;
                }
            }
        }
        let after = directory.observe()?;
        if before != after {
            return Err(Error::WorkspaceUnstable);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_file(
        &mut self,
        directory: &QualifiedDirectory,
        entry: &ObservedNamespaceEntry,
        components: Vec<String>,
        path: Vec<u8>,
        path_sensitive: bool,
        path_form_range: std::ops::Range<usize>,
        inspect_file: &mut impl FnMut(EditedFileInput<'_>) -> Result<()>,
    ) -> Result<()> {
        self.tree.u8(2);
        if entry.protected_name() {
            self.tree.u8(1); // protected record, deliberately not opened
            self.push_entry(EditedEntry {
                path,
                components,
                kind: EditedEntryKind::File,
                identity: None,
                directory_file_id64: entry.directory_file_id64(),
                observed_short_alias_utf16: entry.short_alias_utf16().map(<[u16]>::to_vec),
                byte_len: 0,
                exact_file_match: None,
                protected_name: true,
                hard_link: false,
                named_stream: false,
                supported_utf8_text: false,
                invalid_utf8: false,
                new_sensitive_finding: path_sensitive,
                path_form_range,
                content_form_range: self.forms.len()..self.forms.len(),
            })?;
            return Ok(());
        }
        let mut opened = directory.open_observed_regular_for_edited(entry)?;
        let identity = opened.identity();
        let link_count = opened.link_count();
        let default_stream_only = opened.default_stream_only();
        if link_count != 1 || !default_stream_only {
            let metadata = opened
                .file()
                .metadata()
                .map_err(|_| Error::FilesystemFailure)?;
            if file_identity(opened.file())? != identity
                || metadata.nlink() != link_count
                || opened.recheck_default_stream_only()? != default_stream_only
            {
                return Err(Error::WorkspaceUnstable);
            }
            let length = usize::try_from(metadata.len()).map_err(|_| Error::BoundExceeded)?;
            if length > MAX_FILE_BYTES {
                return Err(Error::BoundExceeded);
            }
            self.total_bytes = checked_add(self.total_bytes, length)?;
            if self.total_bytes > MAX_TOTAL_AI_FILE_BYTES {
                return Err(Error::BoundExceeded);
            }
            encode_identity(&mut self.tree, identity)?;
            self.tree.u64(link_count);
            self.tree.u8(u8::from(default_stream_only));
            self.tree.u64(metadata.len());
            self.tree.bytes(&[])?; // content deliberately not read for structural rejects
            self.tree.u8(0); // no reparse after no-follow open
            self.tree.u8(u8::from(!default_stream_only));
            self.tree.u8(u8::from(link_count != 1));
            self.tree.u8(1); // structural file, content not observed
            self.push_entry(EditedEntry {
                path,
                components,
                kind: EditedEntryKind::File,
                identity: Some(identity),
                directory_file_id64: entry.directory_file_id64(),
                observed_short_alias_utf16: entry.short_alias_utf16().map(<[u16]>::to_vec),
                byte_len: metadata.len(),
                exact_file_match: None,
                protected_name: false,
                hard_link: link_count != 1,
                named_stream: !default_stream_only,
                supported_utf8_text: false,
                invalid_utf8: false,
                new_sensitive_finding: path_sensitive,
                path_form_range,
                content_form_range: self.forms.len()..self.forms.len(),
            })?;
            return Ok(());
        }
        let before = opened
            .file()
            .metadata()
            .map_err(|_| Error::FilesystemFailure)?;
        let before_modified = before.modified().map_err(|_| Error::FilesystemFailure)?;
        let length = usize::try_from(before.len()).map_err(|_| Error::BoundExceeded)?;
        if length > MAX_FILE_BYTES {
            return Err(Error::BoundExceeded);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::BoundExceeded)?;
        opened
            .file_mut()
            .take(u64::try_from(MAX_FILE_BYTES + 1).map_err(|_| Error::BoundExceeded)?)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::FilesystemFailure)?;
        #[cfg(test)]
        run_after_file_read_test_hook().map_err(|_| Error::WorkspaceUnstable)?;
        let after = opened
            .file()
            .metadata()
            .map_err(|_| Error::FilesystemFailure)?;
        if bytes.len() != length
            || file_identity(opened.file())? != identity
            || after.len() != before.len()
            || after.nlink() != before.nlink()
            || after.modified().map_err(|_| Error::FilesystemFailure)? != before_modified
            || opened.recheck_default_stream_only()? != default_stream_only
        {
            return Err(Error::WorkspaceUnstable);
        }
        self.total_bytes = checked_add(self.total_bytes, bytes.len())?;
        if self.total_bytes > MAX_TOTAL_AI_FILE_BYTES {
            return Err(Error::BoundExceeded);
        }
        let content_scan = scan_reserved(
            &bytes,
            &path,
            ReservedLocationKind::Content,
            0,
            self.schedule,
            self.inventory,
        )?;
        let content_form_start = self.forms.len();
        let authenticated_tokens = authenticated_content_spans(&content_scan.forms)?;
        let utf8 = std::str::from_utf8(&bytes).ok();
        let invalid_utf8 = utf8.is_none();
        let supported_utf8_text = utf8.is_some_and(|_| {
            !bytes.contains(&0)
                && components
                    .last()
                    .is_some_and(|leaf| require_ai_visible_file_policy(leaf).is_ok())
        });
        let content_sensitive = match utf8 {
            Some(_) => self.detectors.has_finding(
                content_scan
                    .masked_utf8
                    .as_deref()
                    .ok_or(Error::InvalidCanonicalInput)?,
            )?,
            None => false,
        };
        self.extend_forms(content_scan.forms)?;
        let content_form_end = self.forms.len();
        inspect_file(EditedFileInput {
            path: &path,
            bytes: &bytes,
            authenticated_tokens: &authenticated_tokens,
        })?;
        let exact_file_match = exact_file_match_commitment(self.schedule, &bytes)?;

        encode_identity(&mut self.tree, identity)?;
        self.tree.u64(link_count);
        self.tree.u8(u8::from(default_stream_only));
        self.tree.bytes(&bytes)?;
        self.tree.u8(0); // no reparse after no-follow open
        self.tree.u8(u8::from(!default_stream_only));
        self.tree.u8(u8::from(link_count != 1));
        self.tree.u8(0); // ordinary file object
        self.push_entry(EditedEntry {
            path,
            components,
            kind: EditedEntryKind::File,
            identity: Some(identity),
            directory_file_id64: entry.directory_file_id64(),
            observed_short_alias_utf16: entry.short_alias_utf16().map(<[u16]>::to_vec),
            byte_len: u64::try_from(bytes.len()).map_err(|_| Error::BoundExceeded)?,
            exact_file_match: Some(exact_file_match),
            protected_name: false,
            hard_link: link_count != 1,
            named_stream: !default_stream_only,
            supported_utf8_text,
            invalid_utf8,
            new_sensitive_finding: path_sensitive || content_sensitive,
            path_form_range,
            content_form_range: content_form_start..content_form_end,
        })?;
        Ok(())
    }

    fn encode_entry_prefix(&mut self, path: &[u8], entry: &ObservedNamespaceEntry) -> Result<()> {
        self.tree.bytes(path)?;
        encode_utf16(&mut self.tree, entry.canonical_long_name_utf16())?;
        match entry.short_alias_utf16() {
            Some(alias) => {
                self.tree.u8(1);
                encode_utf16(&mut self.tree, alias)?;
            }
            None => self.tree.u8(0),
        }
        self.tree.u64(entry.directory_file_id64());
        self.tree.u8(u8::from(entry.protected_name()));
        Ok(())
    }

    fn extend_forms(&mut self, forms: Vec<ReservedForm>) -> Result<()> {
        let _ = checked_form_total(self.forms.len(), forms.len())?;
        self.forms
            .try_reserve_exact(forms.len())
            .map_err(|_| Error::BoundExceeded)?;
        self.forms.extend(forms);
        Ok(())
    }

    fn push_entry(&mut self, entry: EditedEntry) -> Result<()> {
        if self.entries.len() >= MAX_ENTRIES {
            return Err(Error::BoundExceeded);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| Error::BoundExceeded)?;
        self.entries.push(entry);
        Ok(())
    }

    fn finish(
        self,
        root_identity: FileIdentity,
        short_name_mode: ShortNameMode,
    ) -> Result<EditedPass> {
        let reserved_form_commitment = reserved_form_commitment(self.schedule, &self.forms)?;
        let parseable_known_oids = self
            .forms
            .iter()
            .filter(|form| {
                form.occurrence_id
                    .is_some_and(|oid| self.inventory.category_for(&oid).is_some())
            })
            .count();
        let authenticated_known_forms = self
            .forms
            .iter()
            .filter(|form| form.authenticated_known)
            .count();
        Ok(EditedPass {
            summary: EditedSummary {
                edited_tree_commitment: self.tree.finish(),
                reserved_form_commitment,
                root_identity,
                short_name_mode,
                entries: to_u32(self.entry_count)?,
                directories: to_u32(self.directory_count)?,
                regular_files: to_u32(self.file_count)?,
                total_file_bytes: u64::try_from(self.total_bytes)
                    .map_err(|_| Error::BoundExceeded)?,
                canonical_path_bytes: u64::try_from(self.canonical_path_bytes)
                    .map_err(|_| Error::BoundExceeded)?,
                reserved_forms: to_u32(self.forms.len())?,
                parseable_known_oids: to_u32(parseable_known_oids)?,
                authenticated_known_forms: to_u32(authenticated_known_forms)?,
            },
            entries: self.entries,
            forms: self.forms,
        })
    }
}

struct ScannedText {
    forms: Vec<ReservedForm>,
    masked_utf8: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn scan_reserved(
    bytes: &[u8],
    path: &[u8],
    location_kind: ReservedLocationKind,
    component_index: u32,
    schedule: &KeySchedule<'_>,
    inventory: &TokenInventory,
) -> Result<ScannedText> {
    let prefix = TOKEN_PREFIX.as_bytes();
    let mut starts = Vec::new();
    for (index, window) in bytes.windows(prefix.len()).enumerate() {
        if window.eq_ignore_ascii_case(prefix) {
            if starts.len() == MAX_OCCURRENCES_PER_COMPONENT {
                return Err(Error::BoundExceeded);
            }
            starts.try_reserve(1).map_err(|_| Error::BoundExceeded)?;
            starts.push(index);
        }
    }
    let mut forms = Vec::new();
    forms
        .try_reserve_exact(starts.len())
        .map_err(|_| Error::BoundExceeded)?;
    for start in starts {
        let maximum = start
            .checked_add(MAX_RESERVED_FORM_BYTES)
            .ok_or(Error::BoundExceeded)?
            .min(bytes.len());
        let body_start = start
            .checked_add(prefix.len())
            .ok_or(Error::BoundExceeded)?;
        let suffix = bytes
            .get(body_start..maximum)
            .and_then(|tail| tail.windows(2).position(|window| window == b"__"));
        let end = suffix
            .and_then(|relative| body_start.checked_add(relative)?.checked_add(2))
            .unwrap_or(maximum);
        let candidate = bytes.get(start..end).ok_or(Error::BoundExceeded)?;
        forms.push(parse_reserved_form(
            candidate,
            start,
            end,
            path,
            location_kind,
            component_index,
            schedule,
            inventory,
            suffix.is_some(),
        )?);
    }
    let masked_utf8 = match std::str::from_utf8(bytes) {
        Ok(_) => Some(mask_authenticated(bytes, &forms)?),
        Err(_) => None,
    };
    Ok(ScannedText { forms, masked_utf8 })
}

#[allow(clippy::too_many_arguments)]
fn parse_reserved_form(
    candidate: &[u8],
    start: usize,
    end: usize,
    path: &[u8],
    location_kind: ReservedLocationKind,
    component_index: u32,
    schedule: &KeySchedule<'_>,
    inventory: &TokenInventory,
    has_suffix: bool,
) -> Result<ReservedForm> {
    let prefix_len = TOKEN_PREFIX.len();
    let body_end = candidate.len().saturating_sub(usize::from(has_suffix) * 2);
    let body = candidate.get(prefix_len..body_end).unwrap_or_default();
    let fields = body.split(|byte| *byte == b'_').collect::<Vec<_>>();
    let category = fields.first().and_then(|field| relaxed_category(field));
    let session_id = fields.get(1).and_then(|field| relaxed_base32(field));
    let occurrence_id = fields.get(2).and_then(|field| relaxed_base32(field));
    let auth = fields.get(3).and_then(|field| relaxed_base32(field));
    let canonical_text = std::str::from_utf8(candidate).ok();
    let canonical_parsed = canonical_text.and_then(|text| parse_token(text).ok());
    let state = if !has_suffix {
        ReservedFormState::Incomplete
    } else if fields.len() != 4 {
        ReservedFormState::BadSeparatorsOrLength
    } else if category.is_none() {
        ReservedFormState::MalformedCategory
    } else if session_id.is_none() {
        ReservedFormState::MalformedSid
    } else if occurrence_id.is_none() {
        ReservedFormState::MalformedOid
    } else if auth.is_none() {
        ReservedFormState::MalformedAuth
    } else if canonical_parsed.is_none() {
        ReservedFormState::Noncanonical
    } else {
        ReservedFormState::Canonical
    };
    let authentication_valid = canonical_text.is_some_and(|text| {
        parse_token(text)
            .and_then(|parsed| authenticate_token(schedule, parsed))
            .is_ok()
    });
    let authenticated_known = authentication_valid
        && occurrence_id.is_some_and(|oid| {
            inventory.category_for(&oid) == category
                && session_id == Some(*schedule.session_id().as_bytes())
        });
    Ok(ReservedForm {
        path: path.to_vec(),
        location_kind,
        component_index,
        position: u64::try_from(start).map_err(|_| Error::BoundExceeded)?,
        end_position: u64::try_from(end).map_err(|_| Error::BoundExceeded)?,
        state,
        session_id,
        occurrence_id,
        category,
        authentication_valid,
        authenticated_known,
    })
}

fn relaxed_category(value: &[u8]) -> Option<TokenCategory> {
    TokenCategory::ALL
        .into_iter()
        .find(|category| value.eq_ignore_ascii_case(category.as_str().as_bytes()))
}

fn relaxed_base32(value: &[u8]) -> Option<[u8; 16]> {
    if value.len() != BASE32_128_LENGTH
        || !value
            .iter()
            .all(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'2'..=b'7'))
    {
        return None;
    }
    let upper = value.iter().map(u8::to_ascii_uppercase).collect::<Vec<_>>();
    let text = std::str::from_utf8(&upper).ok()?;
    decode_base32_128(text).ok()
}

fn mask_authenticated(bytes: &[u8], forms: &[ReservedForm]) -> Result<String> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidCanonicalInput)?;
    let mut spans = forms
        .iter()
        .filter(|form| form.authenticated_known)
        .map(|form| {
            Ok((
                usize::try_from(form.position).map_err(|_| Error::BoundExceeded)?,
                usize::try_from(form.end_position).map_err(|_| Error::BoundExceeded)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    spans.sort_unstable();
    spans.dedup();
    let mut output = String::new();
    output
        .try_reserve_exact(text.len())
        .map_err(|_| Error::BoundExceeded)?;
    let mut cursor = 0usize;
    for (start, end) in spans {
        if start < cursor || start >= end || end > text.len() {
            return Err(Error::InvalidToken);
        }
        output.push_str(text.get(cursor..start).ok_or(Error::InvalidToken)?);
        output.push_str(DETECTOR_SENTINEL);
        cursor = end;
    }
    output.push_str(text.get(cursor..).ok_or(Error::InvalidToken)?);
    Ok(output)
}

fn authenticated_content_spans(forms: &[ReservedForm]) -> Result<Vec<ContentTokenSpan>> {
    let mut spans = forms
        .iter()
        .filter(|form| form.authenticated_known)
        .map(|form| {
            Ok(ContentTokenSpan {
                start: usize::try_from(form.position).map_err(|_| Error::BoundExceeded)?,
                end: usize::try_from(form.end_position).map_err(|_| Error::BoundExceeded)?,
                fact: TokenFact {
                    category: form.category.ok_or(Error::InvalidToken)?,
                    occurrence_id: form.occurrence_id.ok_or(Error::InvalidToken)?,
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    spans.sort_unstable_by_key(|span| (span.start, span.end));
    Ok(spans)
}

fn reserved_form_commitment(
    schedule: &KeySchedule<'_>,
    forms: &[ReservedForm],
) -> Result<[u8; 32]> {
    let mut output = StreamEncoder::new(
        schedule,
        KeyPurpose::TreeCommit,
        b"safeclone/rt3/reserved-form-observation-v1",
    )?;
    output.u32(u32::try_from(forms.len()).map_err(|_| Error::BoundExceeded)?);
    for form in forms {
        output.bytes(&form.path)?;
        output.u8(form.location_kind as u8);
        output.u32(form.component_index);
        output.u64(form.position);
        output.u64(form.end_position);
        output.u8(form.state as u8);
        encode_optional_fixed(&mut output, form.session_id.as_ref())?;
        encode_optional_fixed(&mut output, form.occurrence_id.as_ref())?;
        output.u8(form.category.map_or(0, |category| category as u8));
        output.u8(u8::from(form.authentication_valid));
        output.u8(u8::from(form.authenticated_known));
    }
    Ok(output.finish())
}

fn encode_optional_fixed<const N: usize>(
    output: &mut StreamEncoder,
    value: Option<&[u8; N]>,
) -> Result<()> {
    match value {
        Some(value) => {
            output.u8(1);
            output.bytes(value)
        }
        None => {
            output.u8(0);
            Ok(())
        }
    }
}

fn encode_utf16(output: &mut StreamEncoder, units: &[u16]) -> Result<()> {
    output.u32(u32::try_from(units.len()).map_err(|_| Error::BoundExceeded)?);
    for unit in units {
        output.u16(*unit);
    }
    Ok(())
}

fn encode_identity(output: &mut StreamEncoder, identity: FileIdentity) -> Result<()> {
    output.u64(identity.volume_serial);
    output.bytes(&identity.file_id)
}

fn appended(parent: &[String], leaf: &str) -> Result<Vec<String>> {
    let mut output = parent.to_vec();
    output
        .try_reserve_exact(1)
        .map_err(|_| Error::BoundExceeded)?;
    output.push(leaf.to_owned());
    Ok(output)
}

fn checked_add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right).ok_or(Error::BoundExceeded)
}

fn checked_form_total(current: usize, additional: usize) -> Result<usize> {
    let total = checked_add(current, additional)?;
    if total > MAX_SESSION_OCCURRENCES {
        Err(Error::BoundExceeded)
    } else {
        Ok(total)
    }
}

fn to_u32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::BoundExceeded)
}

pub(super) fn forms_by_known_oid<'a>(
    forms: &'a [ReservedForm],
    inventory: &TokenInventory,
) -> Result<BTreeMap<[u8; 16], Vec<&'a ReservedForm>>> {
    let mut output = BTreeMap::<[u8; 16], Vec<&ReservedForm>>::new();
    for form in forms {
        if let Some(oid) = form.occurrence_id {
            if inventory.category_for(&oid).is_some() {
                let bucket = output.entry(oid).or_default();
                bucket.try_reserve(1).map_err(|_| Error::BoundExceeded)?;
                bucket.push(form);
            }
        }
    }
    Ok(output)
}

pub(super) fn require_same_summary(left: &EditedSummary, right: &EditedSummary) -> Result<()> {
    if !constant_time_equal(&left.edited_tree_commitment, &right.edited_tree_commitment)
        || !constant_time_equal(
            &left.reserved_form_commitment,
            &right.reserved_form_commitment,
        )
        || left.root_identity != right.root_identity
        || left.short_name_mode != right.short_name_mode
        || left.entries != right.entries
        || left.directories != right.directories
        || left.regular_files != right.regular_files
        || left.total_file_bytes != right.total_file_bytes
        || left.canonical_path_bytes != right.canonical_path_bytes
        || left.reserved_forms != right.reserved_forms
        || left.parseable_known_oids != right.parseable_known_oids
        || left.authenticated_known_forms != right.authenticated_known_forms
    {
        Err(Error::WorkspaceUnstable)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip::crypto::{SessionId, SessionMasterSecret};
    use crate::roundtrip::ruleset::ruleset_id;
    use crate::roundtrip::token::{generate_token, ComponentKind, EntryKind, OccurrenceDescriptor};

    fn token_fixture() -> (SessionMasterSecret, String, TokenFact, TokenInventory) {
        let master = SessionMasterSecret::from_bytes([0x73; 32]);
        let schedule = KeySchedule::new(&master, SessionId::from_bytes([0x29; 16]));
        let descriptor = OccurrenceDescriptor {
            session_id: schedule.session_id(),
            ruleset_id: ruleset_id(),
            review_profile: ReviewProfile::StandardV2,
            entry_kind: EntryKind::RegularFile,
            canonical_original_relative_path: b"synthetic/reserved.txt",
            component_index: 0,
            component_kind: ComponentKind::Content,
            byte_span_start: 7,
            byte_span_end: 19,
            category: TokenCategory::Email,
            occurrence_ordinal_within_component: 0,
            pre_token_anchor_commitment: [0x41; 32],
        };
        let token = generate_token(&schedule, &descriptor).expect("generate token");
        let parsed = parse_token(&token).expect("parse token");
        let fact = TokenFact {
            category: parsed.category(),
            occurrence_id: *parsed.occurrence_id(),
        };
        let mut inventory = TokenInventory::new();
        inventory
            .insert_test_token(&token, &fact)
            .expect("insert test inventory");
        (master, token, fact, inventory)
    }

    fn scan_one(
        text: &str,
        master: &SessionMasterSecret,
        inventory: &TokenInventory,
    ) -> ScannedText {
        let schedule = KeySchedule::new(master, SessionId::from_bytes([0x29; 16]));
        scan_reserved(
            text.as_bytes(),
            b"synthetic/reserved.txt",
            ReservedLocationKind::Content,
            0,
            &schedule,
            inventory,
        )
        .expect("scan reserved form")
    }

    #[test]
    fn canonical_reserved_form_is_authenticated_and_only_it_is_masked() {
        let (master, token, fact, inventory) = token_fixture();
        let scanned = scan_one(&format!("before {token} after"), &master, &inventory);
        assert_eq!(scanned.forms.len(), 1);
        let form = &scanned.forms[0];
        assert_eq!(form.state, ReservedFormState::Canonical);
        assert_eq!(form.occurrence_id, Some(fact.occurrence_id));
        assert!(form.authentication_valid);
        assert!(form.authenticated_known);
        let masked = scanned.masked_utf8.expect("UTF-8 masked text");
        assert!(!masked.contains(&token));
        assert!(masked.contains(DETECTOR_SENTINEL));
        let detectors = DetectorSet::compile().expect("compile detectors");
        assert!(!detectors
            .has_finding(DETECTOR_SENTINEL)
            .expect("scan detector sentinel"));

        let mut bad_auth = token.clone().into_bytes();
        let auth = bad_auth.len() - 4;
        bad_auth[auth] = if bad_auth[auth] == b'A' { b'B' } else { b'A' };
        let bad_auth = String::from_utf8(bad_auth).expect("ASCII token mutation");
        let unmasked = scan_one(&bad_auth, &master, &inventory);
        assert_eq!(unmasked.forms.len(), 1);
        assert!(!unmasked.forms[0].authenticated_known);
        assert_eq!(unmasked.masked_utf8.as_deref(), Some(bad_auth.as_str()));
    }

    #[test]
    fn reserved_scanner_classifies_every_malformed_and_overlapping_introducer() {
        let (master, token, _fact, inventory) = token_fixture();
        let fields = token
            .strip_prefix(TOKEN_PREFIX)
            .and_then(|value| value.strip_suffix("__"))
            .expect("canonical token body")
            .split('_')
            .collect::<Vec<_>>();
        assert_eq!(fields.len(), 4);
        let forms = [
            (
                format!(
                    "{TOKEN_PREFIX}BOGUS_{}_{}_{}__",
                    fields[1], fields[2], fields[3]
                ),
                ReservedFormState::MalformedCategory,
            ),
            (
                format!(
                    "{TOKEN_PREFIX}{}_0_{}_{}__",
                    fields[0], fields[2], fields[3]
                ),
                ReservedFormState::MalformedSid,
            ),
            (
                format!(
                    "{TOKEN_PREFIX}{}_{}_0_{}__",
                    fields[0], fields[1], fields[3]
                ),
                ReservedFormState::MalformedOid,
            ),
            (
                format!(
                    "{TOKEN_PREFIX}{}_{}_{}_0__",
                    fields[0], fields[1], fields[2]
                ),
                ReservedFormState::MalformedAuth,
            ),
            (
                format!("{TOKEN_PREFIX}{}_{}_{}__", fields[0], fields[1], fields[2]),
                ReservedFormState::BadSeparatorsOrLength,
            ),
            (
                format!(
                    "{TOKEN_PREFIX}{}_{}_{}_{}",
                    fields[0], fields[1], fields[2], fields[3]
                ),
                ReservedFormState::Incomplete,
            ),
            (
                token.replacen(TOKEN_PREFIX, &TOKEN_PREFIX.to_ascii_lowercase(), 1),
                ReservedFormState::Noncanonical,
            ),
            (
                token.replacen(fields[1], &fields[1].to_ascii_lowercase(), 1),
                ReservedFormState::Noncanonical,
            ),
            (
                format!(
                    "{TOKEN_PREFIX}{}_{}_0_{}__",
                    fields[0], fields[1], fields[3]
                ),
                ReservedFormState::MalformedOid,
            ),
            (
                format!(
                    "{TOKEN_PREFIX}{}_{}_{}_{}=__",
                    fields[0],
                    fields[1],
                    fields[2],
                    &fields[3][..fields[3].len() - 1]
                ),
                ReservedFormState::MalformedAuth,
            ),
            (
                format!(
                    "{TOKEN_PREFIX}{}_{}_{}_{}X__",
                    fields[0], fields[1], fields[2], fields[3]
                ),
                ReservedFormState::MalformedAuth,
            ),
            (
                format!(
                    "{TOKEN_PREFIX}{}-{}_{}_{}__",
                    fields[0], fields[1], fields[2], fields[3]
                ),
                ReservedFormState::BadSeparatorsOrLength,
            ),
        ];
        for (text, expected) in forms {
            let scanned = scan_one(&text, &master, &inventory);
            assert_eq!(scanned.forms.len(), 1, "{expected:?}");
            assert_eq!(scanned.forms[0].state, expected);
            assert!(!scanned.forms[0].authenticated_known);
        }

        let adjacent = scan_one(&format!("{token}{token}"), &master, &inventory);
        assert_eq!(adjacent.forms.len(), 2);
        assert!(adjacent.forms.iter().all(|form| form.authenticated_known));

        let overlapping = scan_one(&format!("{TOKEN_PREFIX}{token}"), &master, &inventory);
        assert_eq!(overlapping.forms.len(), 2);
        assert!(overlapping
            .forms
            .iter()
            .any(|form| form.authenticated_known));
        assert!(overlapping
            .forms
            .iter()
            .any(|form| form.state != ReservedFormState::Canonical));
    }

    #[test]
    fn reserved_form_per_component_and_session_bounds_are_exact() {
        let (master, _token, _fact, inventory) = token_fixture();
        let schedule = KeySchedule::new(&master, SessionId::from_bytes([0x29; 16]));
        let excessive = TOKEN_PREFIX.repeat(MAX_OCCURRENCES_PER_COMPONENT + 1);
        assert!(matches!(
            scan_reserved(
                excessive.as_bytes(),
                b"synthetic/excessive.txt",
                ReservedLocationKind::Content,
                0,
                &schedule,
                &inventory,
            ),
            Err(Error::BoundExceeded)
        ));
        assert_eq!(
            checked_form_total(MAX_SESSION_OCCURRENCES - 1, 1),
            Ok(MAX_SESSION_OCCURRENCES)
        );
        assert_eq!(
            checked_form_total(MAX_SESSION_OCCURRENCES, 1),
            Err(Error::BoundExceeded)
        );
    }

    #[test]
    fn edited_summary_requires_both_commitments_identity_mode_and_aggregates() {
        let summary = |tree, forms| EditedSummary {
            edited_tree_commitment: [tree; 32],
            reserved_form_commitment: [forms; 32],
            root_identity: FileIdentity {
                volume_serial: 7,
                file_id: [8; 16],
            },
            short_name_mode: ShortNameMode::Disabled,
            entries: 2,
            directories: 1,
            regular_files: 1,
            total_file_bytes: 9,
            canonical_path_bytes: 11,
            reserved_forms: 1,
            parseable_known_oids: 1,
            authenticated_known_forms: 1,
        };
        let accepted = summary(1, 2);
        assert_eq!(require_same_summary(&accepted, &summary(1, 2)), Ok(()));
        assert_eq!(
            require_same_summary(&accepted, &summary(3, 2)),
            Err(Error::WorkspaceUnstable)
        );
        assert_eq!(
            require_same_summary(&accepted, &summary(1, 4)),
            Err(Error::WorkspaceUnstable)
        );
        let mut changed_mode = summary(1, 2);
        changed_mode.short_name_mode = ShortNameMode::Enabled;
        assert_eq!(
            require_same_summary(&accepted, &changed_mode),
            Err(Error::WorkspaceUnstable)
        );
    }

    #[test]
    fn edited_tree_commitment_binds_short_name_mode() {
        let (master, _token, _fact, inventory) = token_fixture();
        let schedule = KeySchedule::new(&master, SessionId::from_bytes([0x29; 16]));
        let identity = FileIdentity {
            volume_serial: 7,
            file_id: [8; 16],
        };
        let commitment = |mode| {
            EditedScanner::new(
                &schedule,
                &inventory,
                ReviewProfile::StandardV2,
                identity,
                mode,
            )
            .expect("construct empty edited scanner")
            .finish(identity, mode)
            .expect("finish empty edited scanner")
            .summary
            .edited_tree_commitment
        };
        assert_ne!(
            commitment(ShortNameMode::Enabled),
            commitment(ShortNameMode::Disabled)
        );
    }
}
