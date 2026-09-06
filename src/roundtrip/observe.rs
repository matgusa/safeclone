//! Alias-aware retained-capability observation for private round-trip state.
//!
//! This module is the sole owner of the alias-aware Windows round-trip
//! namespace model.
//! It never opens an ambient path, predicts or mutates an 8.3 alias, or issues
//! a persistent-volume SET control.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::mem::{align_of, offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::rc::Rc;

use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, File, OpenOptions, OpenOptionsExt};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FileIsRemoteDeviceInformation, NtCreateFile, NtFsControlFile, NtQueryInformationFile,
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Wdk::System::SystemServices::FILE_IS_REMOTE_DEVICE_INFORMATION;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_HANDLE_EOF, ERROR_NO_MORE_FILES, HANDLE, OBJ_CASE_INSENSITIVE,
    STATUS_SUCCESS, TRUE, UNICODE_STRING,
};
use windows_sys::Win32::Globalization::{
    CompareStringOrdinal, NormalizationC, NormalizeString, CSTR_EQUAL, CSTR_GREATER_THAN,
    CSTR_LESS_THAN,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileAttributeTagInfo, FileCaseSensitiveInfo, FileIdBothDirectoryInfo,
    FileIdBothDirectoryRestartInfo, FileIdInfo, FileStreamInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, GetVolumeInformationByHandleW,
    BY_HANDLE_FILE_INFORMATION, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_CASE_SENSITIVE_INFO,
    FILE_ID_BOTH_DIR_INFO, FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_NAME_OPENED,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STREAM_INFO,
    FILE_TRAVERSE, SYNCHRONIZE, VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::Ioctl::{
    FILE_FS_PERSISTENT_VOLUME_INFORMATION, FSCTL_QUERY_PERSISTENT_VOLUME_STATE,
    PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED,
};
use windows_sys::Win32::System::SystemServices::FILE_CS_FLAG_CASE_SENSITIVE_DIR;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use crate::fs_boundary::TrustedVolumeAnchor;
use crate::locality::{ConfirmedLocalSource, ConfirmedLocalVolumePath};

use super::schema::ManifestPhase;
use super::token::decode_base32_128;
use super::{Error, Result};

pub(super) const LOCK_LEAF: &str = "session.lock";
pub(super) const FINAL_PREFIX: &str = "capsule-";
pub(super) const FINAL_SUFFIX: &str = ".scdp";
pub(super) const MANIFEST_PREFIX: &str = "manifest-";
pub(super) const MANIFEST_REVIEW_SUFFIX: &str = "-review.scdp";
pub(super) const MANIFEST_APPLY_SUFFIX: &str = "-apply.scdp";
pub(super) const PENDING_PREFIX: &str = ".pending-";
pub(super) const PENDING_SUFFIX: &str = ".scdp";
pub(super) const CANDIDATE_INCOMPLETE_LEAF: &str = ".safeclone-sensitive-output-v1.incomplete";
pub(super) const CANDIDATE_COMPLETE_LEAF: &str = ".safeclone-sensitive-output-v1.complete";

const PERSISTENT_STATE_VERSION: u32 = 1;
const CREATED_DIRECTORY_ACCESS: u32 = FILE_LIST_DIRECTORY
    | FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_TRAVERSE
    | FILE_READ_ATTRIBUTES
    | SYNCHRONIZE;
// NtCreateFile reports FILE_CREATED through IO_STATUS_BLOCK.Information. The
// generated WDK binding exposes the disposition constants but not this result
// name under the currently unified feature set.
const NT_FILE_CREATED: usize = 2;
const DIRECTORY_PAGE_BYTES: usize = 4_096;
const DIRECTORY_PAGE_WORDS: usize = DIRECTORY_PAGE_BYTES / size_of::<u64>();
pub(super) const MAX_DIRECTORY_ENTRIES: usize = 100_000;
// A successful fixed-page call may legally return only one maximum-size
// record. Permit the accepted entry bound plus the initial dot-only page,
// while retaining a strict finite continuation limit.
const MAX_DIRECTORY_PAGES: usize = MAX_DIRECTORY_ENTRIES + 1;
const MAX_ENTRIES_PER_PAGE: usize = 256;
const MAX_LONG_NAME_UNITS: usize = 255;
const MAX_SHORT_NAME_UNITS: usize = 12;
const MAX_NORMALIZED_NAME_UNITS: usize = 1_024;
const MAX_STREAM_QUERY_BYTES: usize = 64 * 1024;
const FINAL_PATH_BUFFER_UNITS: usize = 32_768;

const NEXT_ENTRY_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, NextEntryOffset);
const FILE_ATTRIBUTES_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, FileAttributes);
const FILE_NAME_LENGTH_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, FileNameLength);
const SHORT_NAME_LENGTH_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, ShortNameLength);
const SHORT_NAME_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, ShortName);
const FILE_ID_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, FileId);
const FILE_NAME_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);

const FORBIDDEN_FIXED_NAMES: [&str; 4] = [
    ".git",
    ".safeclone-staging-v1",
    CANDIDATE_INCOMPLETE_LEAF,
    CANDIDATE_COMPLETE_LEAF,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShortNameMode {
    Enabled,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NamespaceScope {
    PathSelection,
    PrivateState,
    Workspace,
    EditedWorkspace,
    CandidateRoot,
    CandidateWorkspace,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FileIdentity {
    pub volume_serial: u64,
    pub file_id: [u8; 16],
}

/// Same-handle Windows identity facts consumed only by candidate identity commitment
/// derivation. Raw GUID/serial/FileId values have no formatter or persistence
/// surface.
#[derive(Clone, Copy)]
pub(super) struct CandidatePhysicalSource {
    pub(super) volume_guid: [u8; 16],
    pub(super) volume_serial_number: u64,
    pub(super) root_file_id: [u8; 16],
}

impl fmt::Debug for FileIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileIdentity")
            .field("state", &"redacted")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EntryKind {
    File,
    Directory,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrivateLeafRole {
    Lock,
    Capsule(u64),
    Manifest {
        review_id: [u8; 16],
        phase: ManifestPhase,
    },
    Pending,
    Unrecognized,
}

#[derive(Clone, Copy)]
struct HandleIdentity {
    stable: FileIdentity,
    directory_file_id64: u64,
}

impl fmt::Debug for HandleIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandleIdentity")
            .field("state", &"redacted")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct ObservedNamespaceEntry {
    record_ordinal: usize,
    canonical_long_name_utf16: Vec<u16>,
    canonical_long_name: String,
    optional_short_alias_utf16: Option<Vec<u16>>,
    directory_file_id64: u64,
    entry_kind: EntryKind,
    role: PrivateLeafRole,
    protected_name: bool,
}

impl ObservedNamespaceEntry {
    pub(super) fn canonical_long_name(&self) -> &str {
        &self.canonical_long_name
    }

    /// Exact observed authority input retained for the classification tree
    /// commitment. It must never be normalized or persisted as a path alias.
    #[allow(dead_code)]
    pub(super) fn canonical_long_name_utf16(&self) -> &[u16] {
        &self.canonical_long_name_utf16
    }

    /// Transient alias evidence retained for the classification tree commitment.
    /// No formatter or persistence type receives this value.
    #[allow(dead_code)]
    pub(super) fn short_alias_utf16(&self) -> Option<&[u16]> {
        self.optional_short_alias_utf16.as_deref()
    }

    pub(super) const fn entry_kind(&self) -> EntryKind {
        self.entry_kind
    }

    pub(super) const fn role(&self) -> PrivateLeafRole {
        self.role
    }

    pub(super) fn alias_present(&self) -> bool {
        self.optional_short_alias_utf16.is_some()
    }

    pub(super) const fn directory_file_id64(&self) -> u64 {
        self.directory_file_id64
    }

    pub(super) const fn protected_name(&self) -> bool {
        self.protected_name
    }

    #[cfg(test)]
    pub(super) fn synthetic_file_for_commitment(
        canonical_long_name: &str,
        short_alias: Option<&str>,
        directory_file_id64: u64,
    ) -> Self {
        Self {
            record_ordinal: 0,
            canonical_long_name_utf16: canonical_long_name.encode_utf16().collect(),
            canonical_long_name: canonical_long_name.to_owned(),
            optional_short_alias_utf16: short_alias
                .map(|value| value.encode_utf16().collect::<Vec<_>>()),
            directory_file_id64,
            entry_kind: EntryKind::File,
            role: PrivateLeafRole::Unrecognized,
            protected_name: false,
        }
    }
}

impl fmt::Debug for ObservedNamespaceEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedNamespaceEntry")
            .field("record_ordinal", &self.record_ordinal)
            .field("alias_present", &self.alias_present())
            .field("entry_kind", &self.entry_kind)
            .field("identity", &"redacted")
            .finish_non_exhaustive()
    }
}

#[derive(Eq, PartialEq)]
pub(super) struct NamespaceObservation {
    entries: Vec<ObservedNamespaceEntry>,
}

impl NamespaceObservation {
    pub(super) fn entries(&self) -> &[ObservedNamespaceEntry] {
        &self.entries
    }

    pub(super) fn find_exact_long(&self, expected: &str) -> Result<&ObservedNamespaceEntry> {
        let expected_utf16 = expected.encode_utf16().collect::<Vec<_>>();
        let mut matches = self
            .entries
            .iter()
            .filter(|entry| entry.canonical_long_name_utf16 == expected_utf16);
        let found = matches.next().ok_or(Error::AliasIdentityMismatch)?;
        if matches.next().is_some() {
            return Err(Error::AliasNamespaceAmbiguous);
        }
        Ok(found)
    }

    fn find_by_file_id64(&self, expected: u64) -> Result<&ObservedNamespaceEntry> {
        let mut matches = self
            .entries
            .iter()
            .filter(|entry| entry.directory_file_id64 == expected);
        let found = matches.next().ok_or(Error::AliasIdentityMismatch)?;
        if matches.next().is_some() {
            return Err(Error::AliasNamespaceAmbiguous);
        }
        Ok(found)
    }

    pub(super) fn find_exact_long_utf16(
        &self,
        expected: &[u16],
    ) -> Result<&ObservedNamespaceEntry> {
        let mut matches = self
            .entries
            .iter()
            .filter(|entry| entry.canonical_long_name_utf16 == expected);
        let found = matches.next().ok_or(Error::AliasIdentityMismatch)?;
        if matches.next().is_some() {
            return Err(Error::AliasNamespaceAmbiguous);
        }
        Ok(found)
    }
}

impl fmt::Debug for NamespaceObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NamespaceObservation")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

struct RetainedVolumePolicy {
    authority: Dir,
    identity: FileIdentity,
    mode: ShortNameMode,
    anchor: TrustedVolumeAnchor,
}

impl RetainedVolumePolicy {
    fn requery(&self) -> Result<()> {
        let observed = query_stable_volume_mode(&self.authority, self.identity)?;
        require_same_mode(self.mode, observed)
    }
}

/// A volume-qualified path whose user components have not yet been opened.
/// It can only be constructed from the three-path locality boundary.
pub(super) struct RetainedVolumePath {
    volume: Rc<RetainedVolumePolicy>,
    root: Dir,
    root_identity: FileIdentity,
    components: Vec<OsString>,
}

impl fmt::Debug for RetainedVolumePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedVolumePath")
            .field("state", &"qualified-components-unopened")
            .field("component_count", &self.components.len())
            .finish_non_exhaustive()
    }
}

/// All three policy queries are complete before this type can expose a path
/// opening operation. This fixes the preflight/query ordering structurally.
pub(super) struct QualifiedCreateVolumePaths {
    pub(super) original: RetainedVolumePath,
    pub(super) ai_parent: RetainedVolumePath,
    pub(super) ai_leaf: OsString,
    pub(super) state_parent: RetainedVolumePath,
    pub(super) state_leaf: OsString,
}

pub(super) struct QualifiedApplyVolumePaths {
    pub(super) original: RetainedVolumePath,
    pub(super) ai_parent: RetainedVolumePath,
    pub(super) ai_leaf: OsString,
    pub(super) state_parent: RetainedVolumePath,
    pub(super) state_leaf: OsString,
    pub(super) candidate_parent: RetainedVolumePath,
    pub(super) candidate_leaf: OsString,
}

/// Convert three confirmed volume-root handles into stable alias-policy
/// authorities. Each retained handle is queried twice and no user component
/// is opened by this function.
pub(super) fn qualify_roundtrip_create_volumes(
    paths: crate::locality::ConfirmedRoundTripCreatePaths,
) -> Result<QualifiedCreateVolumePaths> {
    let original = qualify_volume_path(paths.original)?;
    let ai_parent = qualify_volume_path(paths.ai_parent)?;
    let state_parent = qualify_volume_path(paths.state_parent)?;
    Ok(QualifiedCreateVolumePaths {
        original,
        ai_parent,
        ai_leaf: paths.ai_leaf,
        state_parent,
        state_leaf: paths.state_leaf,
    })
}

pub(super) fn qualify_roundtrip_apply_volumes(
    paths: crate::locality::ConfirmedRoundTripApplyPaths,
) -> Result<QualifiedApplyVolumePaths> {
    let original = qualify_volume_path(paths.original)?;
    let ai_parent = qualify_volume_path(paths.ai_parent)?;
    let state_parent = qualify_volume_path(paths.state_parent)?;
    let candidate_parent = qualify_volume_path(paths.candidate_parent)?;
    Ok(QualifiedApplyVolumePaths {
        original,
        ai_parent,
        ai_leaf: paths.ai_leaf,
        state_parent,
        state_leaf: paths.state_leaf,
        candidate_parent,
        candidate_leaf: paths.candidate_leaf,
    })
}

pub(super) fn qualify_roundtrip_state_volume(
    confirmed: ConfirmedLocalVolumePath,
) -> Result<QualifiedPrivateStateRoot> {
    qualify_volume_path(confirmed)?
        .open_directory(NamespaceScope::Workspace)?
        .into_private_state_root()
}

fn qualify_volume_path(confirmed: ConfirmedLocalVolumePath) -> Result<RetainedVolumePath> {
    let (root, components, anchor) = confirmed.into_parts();
    require_local_ntfs(&root)?;
    require_not_reparse(&root)?;
    require_case_insensitive(&root)?;
    let root_identity = file_identity(&root)?;
    let authority = root
        .try_clone()
        .map_err(|_| Error::PersistentVolumeQueryFailed)?;
    let identity = file_identity(&authority).map_err(|_| Error::PersistentVolumeQueryFailed)?;
    if identity != root_identity {
        return Err(Error::PersistentVolumeStateAmbiguous);
    }
    let first = query_stable_volume_mode(&authority, identity)?;
    let second = query_stable_volume_mode(&authority, identity)?;
    require_same_mode(first, second)?;
    Ok(RetainedVolumePath {
        volume: Rc::new(RetainedVolumePolicy {
            authority,
            identity,
            mode: first,
            anchor,
        }),
        root,
        root_identity,
        components,
    })
}

pub(crate) struct ValidatedLeaf {
    name: String,
    utf16: Vec<u16>,
}

impl ValidatedLeaf {
    pub(super) fn utf16(&self) -> &[u16] {
        &self.utf16
    }
}

impl fmt::Debug for ValidatedLeaf {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedLeaf")
            .field("state", &"validated-redacted")
            .finish_non_exhaustive()
    }
}

/// Alias-aware retained directory authority used by original traversal and
/// output construction. No constructor accepts a raw path or caller identity.
pub(crate) struct QualifiedDirectory {
    volume: Rc<RetainedVolumePolicy>,
    directory: Dir,
    identity: FileIdentity,
    ancestor_identities: Vec<FileIdentity>,
    scope: NamespaceScope,
}

pub(super) struct CreatedFile {
    file: File,
    identity: FileIdentity,
}

/// Retained no-follow regular-file observation used only for hostile edited
/// workspace classification. Structural rejection facts are exposed without
/// weakening the stricter create-time opener.
pub(super) struct ObservedEditedRegularFile {
    file: File,
    identity: FileIdentity,
    link_count: u64,
    default_stream_only: bool,
}

impl ObservedEditedRegularFile {
    pub(super) fn file(&self) -> &File {
        &self.file
    }

    pub(super) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub(super) const fn identity(&self) -> FileIdentity {
        self.identity
    }

    pub(super) const fn link_count(&self) -> u64 {
        self.link_count
    }

    pub(super) const fn default_stream_only(&self) -> bool {
        self.default_stream_only
    }

    pub(super) fn recheck_default_stream_only(&self) -> Result<bool> {
        has_only_default_stream(&self.file, StreamKind::File)
    }
}

impl CreatedFile {
    pub(super) fn file(&self) -> &File {
        &self.file
    }

    pub(super) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub(super) const fn identity(&self) -> FileIdentity {
        self.identity
    }
}

impl fmt::Debug for CreatedFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedFile")
            .field("state", &"empty-post-observed")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for QualifiedDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedDirectory")
            .field("state", &"retained-alias-qualified")
            .field("ancestor_count", &self.ancestor_identities.len())
            .finish_non_exhaustive()
    }
}

impl RetainedVolumePath {
    /// Open every supplied component only after exact canonical-long
    /// selection from a complete retained-parent enumeration.
    pub(super) fn open_directory(self, final_scope: NamespaceScope) -> Result<QualifiedDirectory> {
        let mut current = QualifiedDirectory {
            volume: self.volume,
            directory: self.root,
            identity: self.root_identity,
            ancestor_identities: vec![self.root_identity],
            scope: NamespaceScope::PathSelection,
        };
        for component in self.components {
            current = current.open_exact_child_directory(&component)?;
        }
        current.scope = final_scope;
        Ok(current)
    }
}

impl QualifiedDirectory {
    pub(super) const fn identity(&self) -> FileIdentity {
        self.identity
    }

    pub(super) fn ancestor_identities(&self) -> &[FileIdentity] {
        &self.ancestor_identities
    }

    pub(super) fn verify(&self) -> Result<()> {
        validate_directory_one_link_stream_clean(&self.directory)?;
        require_case_insensitive(&self.directory)?;
        if file_identity(&self.directory)? != self.identity {
            return Err(Error::AliasIdentityMismatch);
        }
        if self.identity.volume_serial != self.volume.identity.volume_serial {
            return Err(Error::PersistentVolumeStateAmbiguous);
        }
        Ok(())
    }

    pub(super) fn requery_policy(&self) -> Result<()> {
        self.verify()?;
        self.volume.requery()
    }

    pub(super) fn short_name_mode(&self) -> ShortNameMode {
        self.volume.mode
    }

    pub(super) fn observe(&self) -> Result<NamespaceObservation> {
        self.requery_policy()?;
        let entries = enumerate_directory(&self.directory)?;
        self.verify()?;
        validate_namespace(entries, self.scope)
    }

    pub(super) fn open_exact_child_directory(&self, supplied: &OsStr) -> Result<Self> {
        let supplied_utf16 = supplied.encode_wide().collect::<Vec<_>>();
        validate_component(&supplied_utf16)?;
        let observation = self.observe()?;
        let entry = select_exact_canonical(
            &observation,
            &supplied_utf16,
            EntryKind::Directory,
            self.scope,
        )?;
        let opened = self
            .directory
            .open_dir_nofollow(OsStr::new(entry.canonical_long_name()))
            .map_err(|_| Error::FilesystemFailure)?;
        validate_directory_one_link_stream_clean(&opened)?;
        require_case_insensitive(&opened)?;
        verify_entry_handle(entry, &opened)?;
        self.verify()?;
        let identity = file_identity(&opened)?;
        let mut ancestors = self.ancestor_identities.clone();
        ancestors
            .try_reserve_exact(1)
            .map_err(|_| Error::BoundExceeded)?;
        ancestors.push(identity);
        Ok(Self {
            volume: Rc::clone(&self.volume),
            directory: opened,
            identity,
            ancestor_identities: ancestors,
            scope: if self.scope == NamespaceScope::CandidateRoot {
                NamespaceScope::CandidateWorkspace
            } else {
                self.scope
            },
        })
    }

    pub(super) fn validate_absent_leaf(&self, supplied: &OsStr) -> Result<ValidatedLeaf> {
        let utf16 = supplied.encode_wide().collect::<Vec<_>>();
        let name = validate_component(&utf16)?;
        validate_proposed_name(&utf16, self.scope)?;
        let observation = self.observe()?;
        reject_proposed_collision(&observation, &utf16)?;
        self.verify()?;
        Ok(ValidatedLeaf { name, utf16 })
    }

    /// Return an exact existing directory, or an absence proof. Alias-only,
    /// case-only, NFC, protected, and namespace-collision shapes reject.
    pub(super) fn classify_directory_leaf(
        &self,
        supplied: &OsStr,
        leaf_scope: NamespaceScope,
    ) -> Result<std::result::Result<Self, ValidatedLeaf>> {
        let utf16 = supplied.encode_wide().collect::<Vec<_>>();
        let name = validate_component(&utf16)?;
        validate_proposed_name(&utf16, leaf_scope)?;
        let observation = self.observe()?;
        if let Ok(entry) = observation.find_exact_long_utf16(&utf16) {
            if entry.entry_kind() != EntryKind::Directory {
                return Err(Error::UnsupportedAliasNamespace);
            }
            let opened = self.open_exact_child_directory(supplied)?;
            return Ok(Ok(opened));
        }
        reject_proposed_collision(&observation, &utf16)?;
        Ok(Err(ValidatedLeaf { name, utf16 }))
    }

    /// Closed native primitive: create exactly one absent directory leaf and
    /// retain the returned handle through its post-create namespace gate.
    pub(super) fn create_directory(&self, leaf: ValidatedLeaf) -> Result<Self> {
        let pre = self.observe()?;
        reject_proposed_collision(&pre, &leaf.utf16)?;
        self.requery_policy()?;
        let created = create_new_directory_handle(&self.directory, &leaf)?;
        validate_directory_one_link_stream_clean(&created)?;
        require_case_insensitive(&created)?;
        let created_identity = file_identity(&created)?;
        let post = self.observe()?;
        let entry = post.find_by_file_id64(handle_identity(&created)?.directory_file_id64)?;
        if entry.canonical_long_name_utf16 != leaf.utf16 || entry.entry_kind != EntryKind::Directory
        {
            return Err(Error::AliasIdentityMismatch);
        }
        // A newly created output root is made under a path-selection parent,
        // but its own long/short record is already part of the controlled
        // safeclone namespace. Validate that target with the full workspace
        // protected-name policy while leaving unrelated parent siblings out
        // of the output-root trust boundary.
        let created_scope = if self.scope == NamespaceScope::PathSelection {
            NamespaceScope::Workspace
        } else {
            self.scope
        };
        validate_protected_entry(entry, &ProtectedNames::new(), created_scope)?;
        verify_entry_handle(entry, &created)?;
        if self.volume.mode == ShortNameMode::Disabled && entry.alias_present() {
            self.volume.requery()?;
            return Err(Error::PersistentVolumeStateAmbiguous);
        }
        self.verify()?;
        self.volume.requery()?;
        let mut ancestors = self.ancestor_identities.clone();
        ancestors
            .try_reserve_exact(1)
            .map_err(|_| Error::BoundExceeded)?;
        ancestors.push(created_identity);
        let created = Self {
            volume: Rc::clone(&self.volume),
            directory: created,
            identity: created_identity,
            ancestor_identities: ancestors,
            scope: self.scope,
        };
        if !created.observe()?.entries().is_empty() {
            return Err(Error::AliasNamespaceAmbiguous);
        }
        Ok(created)
    }

    pub(super) fn create_workspace_root(&self, leaf: ValidatedLeaf) -> Result<Self> {
        let mut created = self.create_directory(leaf)?;
        created.scope = NamespaceScope::Workspace;
        created.observe()?;
        Ok(created)
    }

    pub(super) fn create_candidate_root(&self, leaf: ValidatedLeaf) -> Result<Self> {
        let mut created = self.create_directory(leaf)?;
        created.scope = NamespaceScope::CandidateRoot;
        created.observe()?;
        Ok(created)
    }

    pub(super) fn create_candidate_directory(&self, leaf: ValidatedLeaf) -> Result<Self> {
        let mut created = self.create_directory(leaf)?;
        created.scope = NamespaceScope::CandidateWorkspace;
        created.observe()?;
        Ok(created)
    }

    pub(super) fn into_workspace_root(mut self) -> Result<Self> {
        self.scope = NamespaceScope::Workspace;
        self.observe()?;
        Ok(self)
    }

    pub(super) fn into_edited_workspace_root(mut self) -> Result<Self> {
        self.scope = NamespaceScope::EditedWorkspace;
        self.observe()?;
        Ok(self)
    }

    pub(super) fn into_candidate_root(mut self) -> Result<Self> {
        self.scope = NamespaceScope::CandidateRoot;
        self.observe()?;
        Ok(self)
    }

    pub(super) fn observe_candidate_physical_source(&self) -> Result<CandidatePhysicalSource> {
        self.verify()?;
        self.volume.requery()?;
        require_local_ntfs(&self.directory)?;
        let mut buffer = vec![0u16; FINAL_PATH_BUFFER_UNITS];
        // SAFETY: the retained directory handle and writable fixed-capacity
        // UTF-16 buffer remain live for this non-mutating handle query.
        let written = unsafe {
            GetFinalPathNameByHandleW(
                self.directory.as_raw_handle() as HANDLE,
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).map_err(|_| Error::BoundExceeded)?,
                FILE_NAME_OPENED | VOLUME_NAME_GUID,
            )
        };
        let written = usize::try_from(written).map_err(|_| Error::FilesystemFailure)?;
        if written == 0 || written >= buffer.len() {
            return Err(Error::FilesystemFailure);
        }
        buffer.truncate(written);
        if !self.volume.anchor.matches_handle_path(&buffer) {
            return Err(Error::PersistentVolumeStateAmbiguous);
        }
        let before = file_identity(&self.directory)?;
        let after = file_identity(&self.directory)?;
        if before != after
            || before != self.identity
            || before.volume_serial != self.volume.identity.volume_serial
        {
            return Err(Error::PersistentVolumeStateAmbiguous);
        }
        self.verify()?;
        self.volume.requery()?;
        Ok(CandidatePhysicalSource {
            volume_guid: self.volume.anchor.canonical_guid_bytes(),
            volume_serial_number: before.volume_serial,
            root_file_id: before.file_id,
        })
    }

    pub(super) fn open_observed_regular(&self, entry: &ObservedNamespaceEntry) -> Result<File> {
        if entry.entry_kind != EntryKind::File {
            return Err(Error::UnsupportedAliasNamespace);
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .follow(FollowSymlinks::No)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        let file = self
            .directory
            .open_with(OsStr::new(entry.canonical_long_name()), &options)
            .map_err(|_| Error::FilesystemFailure)?;
        validate_regular_one_link_stream_clean(&file)?;
        verify_entry_handle(entry, &file)?;
        self.verify()?;
        Ok(file)
    }

    pub(super) fn open_observed_regular_for_edited(
        &self,
        entry: &ObservedNamespaceEntry,
    ) -> Result<ObservedEditedRegularFile> {
        if entry.entry_kind != EntryKind::File {
            return Err(Error::UnsupportedAliasNamespace);
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .follow(FollowSymlinks::No)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        let file = self
            .directory
            .open_with(OsStr::new(entry.canonical_long_name()), &options)
            .map_err(|_| Error::FilesystemFailure)?;
        require_not_reparse(&file)?;
        let metadata = file.metadata().map_err(|_| Error::FilesystemFailure)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(Error::UnsupportedAliasNamespace);
        }
        verify_entry_handle(entry, &file)?;
        self.verify()?;
        Ok(ObservedEditedRegularFile {
            identity: file_identity(&file)?,
            link_count: metadata.nlink(),
            default_stream_only: has_only_default_stream(&file, StreamKind::File)?,
            file,
        })
    }

    pub(super) fn link_count(&self) -> Result<u64> {
        self.verify()?;
        let metadata = self
            .directory
            .dir_metadata()
            .map_err(|_| Error::FilesystemFailure)?;
        Ok(metadata.nlink())
    }

    pub(super) fn open_exact_regular(&self, supplied: &OsStr) -> Result<File> {
        let supplied_utf16 = supplied.encode_wide().collect::<Vec<_>>();
        validate_component(&supplied_utf16)?;
        let observation = self.observe()?;
        let entry =
            select_exact_canonical(&observation, &supplied_utf16, EntryKind::File, self.scope)?;
        self.open_observed_regular(entry)
    }

    pub(super) fn create_empty_file(&self, leaf: ValidatedLeaf) -> Result<CreatedFile> {
        let pre = self.observe()?;
        reject_proposed_collision(&pre, &leaf.utf16)?;
        self.requery_policy()?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        let file = self
            .directory
            .open_with(OsStr::new(&leaf.name), &options)
            .map_err(|_| Error::FilesystemFailure)?;
        validate_regular_one_link_stream_clean(&file)?;
        if file.metadata().map_err(|_| Error::FilesystemFailure)?.len() != 0 {
            return Err(Error::AliasNamespaceAmbiguous);
        }
        let opened = handle_identity(&file)?;
        let post = self.observe()?;
        let entry = post.find_by_file_id64(opened.directory_file_id64)?;
        if entry.canonical_long_name_utf16 != leaf.utf16 || entry.entry_kind != EntryKind::File {
            return Err(Error::AliasIdentityMismatch);
        }
        verify_entry_handle(entry, &file)?;
        if file.metadata().map_err(|_| Error::FilesystemFailure)?.len() != 0 {
            return Err(Error::AliasNamespaceAmbiguous);
        }
        if self.volume.mode == ShortNameMode::Disabled && entry.alias_present() {
            self.volume.requery()?;
            return Err(Error::PersistentVolumeStateAmbiguous);
        }
        self.verify()?;
        self.volume.requery()?;
        Ok(CreatedFile {
            file,
            identity: opened.stable,
        })
    }

    /// Promote this exact retained directory handle to the alias-aware private
    /// generation-store authority without an ambient or path-based reopen.
    pub(super) fn into_private_state_root(self) -> Result<QualifiedPrivateStateRoot> {
        self.verify()?;
        self.volume.requery()?;
        let volume_authority = self
            .volume
            .authority
            .try_clone()
            .map_err(|_| Error::PersistentVolumeQueryFailed)?;
        Ok(QualifiedPrivateStateRoot {
            volume_authority,
            selected_volume_identity: self.volume.identity,
            selected_mode: self.volume.mode,
            state_root: self.directory,
            state_root_identity: self.identity,
        })
    }
}

pub(super) fn validate_regular_one_link_stream_clean(file: &File) -> Result<()> {
    require_not_reparse(file)?;
    let metadata = file.metadata().map_err(|_| Error::FilesystemFailure)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1 {
        return Err(Error::UnsupportedAliasNamespace);
    }
    validate_default_stream_only(file, StreamKind::File)
}

fn validate_directory_one_link_stream_clean(directory: &Dir) -> Result<()> {
    require_not_reparse(directory)?;
    let metadata = directory
        .dir_metadata()
        .map_err(|_| Error::FilesystemFailure)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.nlink() != 1 {
        return Err(Error::UnsupportedAliasNamespace);
    }
    validate_default_stream_only(directory, StreamKind::Directory)
}

#[derive(Clone, Copy)]
enum StreamKind {
    File,
    Directory,
}

fn validate_default_stream_only<T: AsRawHandle>(handle: &T, kind: StreamKind) -> Result<()> {
    if has_only_default_stream(handle, kind)? {
        Ok(())
    } else {
        Err(Error::UnsupportedAliasNamespace)
    }
}

fn has_only_default_stream<T: AsRawHandle>(handle: &T, kind: StreamKind) -> Result<bool> {
    let word_count = MAX_STREAM_QUERY_BYTES.div_ceil(size_of::<usize>());
    let mut storage = vec![0usize; word_count];
    // SAFETY: storage is aligned and writable for the advertised fixed size;
    // the retained file handle remains live for this synchronous query.
    let queried = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle() as HANDLE,
            FileStreamInfo,
            storage.as_mut_ptr().cast(),
            u32::try_from(MAX_STREAM_QUERY_BYTES).map_err(|_| Error::FilesystemFailure)?,
        )
    };
    if queried == 0 {
        // Microsoft defines ERROR_HANDLE_EOF for a successful FileStreamInfo
        // class with no returned streams. On exact NTFS this is the ordinary
        // ADS-free directory result; regular files must still expose their
        // unnamed default data stream.
        if matches!(kind, StreamKind::Directory) && unsafe { GetLastError() } == ERROR_HANDLE_EOF {
            return Ok(true);
        }
        return Err(Error::FilesystemFailure);
    }
    let info = storage.as_ptr().cast::<FILE_STREAM_INFO>();
    // SAFETY: a successful query initialized the fixed first record.
    let next = unsafe { (*info).NextEntryOffset };
    // SAFETY: same initialized record.
    let name_bytes = usize::try_from(unsafe { (*info).StreamNameLength })
        .map_err(|_| Error::UnsupportedAliasNamespace)?;
    let fixed = offset_of!(FILE_STREAM_INFO, StreamName);
    if !name_bytes.is_multiple_of(size_of::<u16>())
        || fixed
            .checked_add(name_bytes)
            .is_none_or(|end| end > MAX_STREAM_QUERY_BYTES)
    {
        return Err(Error::UnsupportedAliasNamespace);
    }
    // SAFETY: the checked record bounds cover this exact UTF-16 slice.
    let name = unsafe {
        std::slice::from_raw_parts((*info).StreamName.as_ptr(), name_bytes / size_of::<u16>())
    };
    let is_expected = match kind {
        StreamKind::File => name.iter().copied().eq(OsStr::new("::$DATA").encode_wide()),
        StreamKind::Directory => ["::$INDEX_ALLOCATION", ":$I30:$INDEX_ALLOCATION"]
            .iter()
            .any(|candidate| name.iter().copied().eq(OsStr::new(candidate).encode_wide())),
    };
    Ok(next == 0 && is_expected)
}

fn select_exact_canonical<'a>(
    observation: &'a NamespaceObservation,
    supplied: &[u16],
    expected_kind: EntryKind,
    scope: NamespaceScope,
) -> Result<&'a ObservedNamespaceEntry> {
    if let Ok(entry) = observation.find_exact_long_utf16(supplied) {
        if entry.entry_kind == expected_kind {
            // Path selection may ignore an unrelated protected-looking
            // sibling, but the selected component itself is subject to the
            // complete workspace protected-name policy. In particular, an
            // ordinary canonical long name with a protected short alias must
            // never become a path-boundary bypass.
            let selected_scope = if scope == NamespaceScope::PathSelection {
                NamespaceScope::Workspace
            } else {
                scope
            };
            validate_protected_entry(entry, &ProtectedNames::new(), selected_scope)?;
            return Ok(entry);
        }
        return Err(Error::UnsupportedAliasNamespace);
    }
    // CompareStringOrdinal is rejection policy only. It never supplies a
    // name to an open operation.
    for entry in observation.entries() {
        if compare_windows_ordinal_ignore_case(&entry.canonical_long_name_utf16, supplied)?
            == Ordering::Equal
        {
            return Err(Error::UnsupportedAliasNamespace);
        }
        if let Some(alias) = entry.optional_short_alias_utf16.as_deref() {
            if compare_windows_ordinal_ignore_case(alias, supplied)? == Ordering::Equal {
                return Err(Error::UnsupportedAliasNamespace);
            }
        }
    }
    Err(Error::AliasIdentityMismatch)
}

fn verify_entry_handle<T: AsRawHandle>(
    entry: &ObservedNamespaceEntry,
    handle: &T,
) -> Result<FileIdentity> {
    let opened = handle_identity(handle)?;
    if opened.directory_file_id64 != entry.directory_file_id64 {
        return Err(Error::AliasIdentityMismatch);
    }
    require_not_reparse(handle)?;
    Ok(opened.stable)
}

fn create_new_directory_handle(parent: &Dir, leaf: &ValidatedLeaf) -> Result<Dir> {
    let byte_length = leaf
        .utf16
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(Error::BoundExceeded)?;
    let byte_length = u16::try_from(byte_length).map_err(|_| Error::BoundExceeded)?;
    let name = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: leaf.utf16.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>()).map_err(|_| Error::BoundExceeded)?,
        RootDirectory: parent.as_raw_handle() as HANDLE,
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle: HANDLE = ptr::null_mut();
    let mut io_status = IO_STATUS_BLOCK::default();
    // SAFETY: the retained parent, checked single-component UTF-16 name,
    // output handle and IO status remain live. Disposition and options are
    // closed constants: create-new directory, synchronous, open reparse point.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            CREATED_DIRECTORY_ACCESS,
            &attributes,
            &mut io_status,
            ptr::null(),
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    // SAFETY: this synchronous call completed before the status union read.
    let completion = unsafe { io_status.Anonymous.Status };
    if status != STATUS_SUCCESS
        || completion != STATUS_SUCCESS
        || io_status.Information != NT_FILE_CREATED
        || handle.is_null()
    {
        return Err(Error::FilesystemFailure);
    }
    // SAFETY: NtCreateFile returned one owned, non-null handle on success.
    let owned = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
    Ok(Dir::from(owned))
}

/// Non-forgeable private-root authority produced only from the accepted
/// locality boundary. The duplicated retained root handle is the compatible
/// volume-query authority proven by retained-volume tests; no ambient volume reopen occurs.
pub(crate) struct QualifiedPrivateStateRoot {
    volume_authority: Dir,
    selected_volume_identity: FileIdentity,
    selected_mode: ShortNameMode,
    state_root: Dir,
    state_root_identity: FileIdentity,
}

impl fmt::Debug for QualifiedPrivateStateRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedPrivateStateRoot")
            .field("state", &"retained-local-ntfs")
            .field("selected_mode", &self.selected_mode)
            .finish_non_exhaustive()
    }
}

// The current product has no round-trip CLI. This seam remains for an already
// opened root; session creation new-root creation instead consumes the exact created
// handle through `QualifiedDirectory::into_private_state_root`.
#[allow(dead_code)]
pub(crate) fn qualify_private_state_root(
    confirmed: ConfirmedLocalSource,
) -> Result<QualifiedPrivateStateRoot> {
    qualify_retained_private_state_root(confirmed.into_directory())
}

#[cfg(test)]
pub(crate) fn qualify_synthetic_private_state_root(
    state_root: Dir,
) -> Result<QualifiedPrivateStateRoot> {
    qualify_retained_private_state_root(state_root)
}

fn qualify_retained_private_state_root(state_root: Dir) -> Result<QualifiedPrivateStateRoot> {
    let volume_authority = state_root
        .try_clone()
        .map_err(|_| Error::PersistentVolumeQueryFailed)?;
    require_local_ntfs(&volume_authority)?;
    require_local_ntfs(&state_root)?;
    require_not_reparse(&state_root)?;
    let selected_volume_identity = file_identity(&volume_authority)?;
    let state_root_identity = file_identity(&state_root)?;
    if selected_volume_identity.volume_serial != state_root_identity.volume_serial {
        return Err(Error::PersistentVolumeStateAmbiguous);
    }
    let selected_mode = query_stable_volume_mode(&volume_authority, selected_volume_identity)?;
    require_case_insensitive(&state_root)?;
    Ok(QualifiedPrivateStateRoot {
        volume_authority,
        selected_volume_identity,
        selected_mode,
        state_root,
        state_root_identity,
    })
}

impl QualifiedPrivateStateRoot {
    pub(super) fn root(&self) -> &Dir {
        &self.state_root
    }

    pub(super) const fn root_identity(&self) -> FileIdentity {
        self.state_root_identity
    }

    #[cfg(test)]
    pub(crate) const fn selected_mode(&self) -> ShortNameMode {
        self.selected_mode
    }

    pub(super) fn observe_root(&self) -> Result<NamespaceObservation> {
        self.requery_policy()?;
        self.verify_root()?;
        require_case_insensitive(&self.state_root)?;
        let entries = enumerate_directory(&self.state_root)?;
        self.verify_root()?;
        validate_namespace(entries, NamespaceScope::PrivateState)
    }

    pub(super) fn requery_before_mutation(&self) -> Result<()> {
        self.verify_root()?;
        require_case_insensitive(&self.state_root)?;
        self.requery_policy()
    }

    pub(super) fn requery_policy(&self) -> Result<()> {
        let observed =
            query_stable_volume_mode(&self.volume_authority, self.selected_volume_identity)?;
        require_same_mode(self.selected_mode, observed)
    }

    pub(super) fn verify_root(&self) -> Result<()> {
        require_not_reparse(&self.state_root)?;
        if file_identity(&self.state_root)? != self.state_root_identity {
            return Err(Error::AliasIdentityMismatch);
        }
        Ok(())
    }

    pub(super) fn bind_created<T: AsRawHandle>(
        &self,
        observation: &NamespaceObservation,
        expected_long_name: &str,
        expected_kind: EntryKind,
        handle: &T,
    ) -> Result<FileIdentity> {
        let opened = handle_identity(handle)?;
        let entry = observation.find_by_file_id64(opened.directory_file_id64)?;
        if entry.canonical_long_name_utf16 != expected_long_name.encode_utf16().collect::<Vec<_>>()
            || entry.entry_kind != expected_kind
        {
            return Err(Error::AliasIdentityMismatch);
        }
        self.verify_opened_entry(entry, handle)?;
        if self.selected_mode == ShortNameMode::Disabled && entry.alias_present() {
            self.verify_root()?;
            self.requery_policy()?;
            return Err(Error::UnsupportedAliasNamespace);
        }
        self.verify_root()?;
        // This is the last state transition before the caller may populate a
        // just-created empty leaf. A mode change therefore blocks the write.
        self.requery_policy()?;
        Ok(opened.stable)
    }

    pub(super) fn verify_opened_entry<T: AsRawHandle>(
        &self,
        entry: &ObservedNamespaceEntry,
        handle: &T,
    ) -> Result<FileIdentity> {
        let opened = handle_identity(handle)?;
        if opened.directory_file_id64 != entry.directory_file_id64 {
            return Err(Error::AliasIdentityMismatch);
        }
        require_not_reparse(handle)?;
        self.verify_root()?;
        Ok(opened.stable)
    }
}

fn query_stable_volume_mode(
    volume: &Dir,
    expected_identity: FileIdentity,
) -> Result<ShortNameMode> {
    let before = file_identity(volume).map_err(|_| Error::PersistentVolumeQueryFailed)?;
    if before != expected_identity {
        return Err(Error::PersistentVolumeStateAmbiguous);
    }
    let mode = query_short_name_mode(volume)?;
    let after = file_identity(volume).map_err(|_| Error::PersistentVolumeQueryFailed)?;
    if after != before || after != expected_identity {
        return Err(Error::PersistentVolumeStateAmbiguous);
    }
    Ok(mode)
}

fn query_short_name_mode(volume: &Dir) -> Result<ShortNameMode> {
    let input = FILE_FS_PERSISTENT_VOLUME_INFORMATION {
        VolumeFlags: 0,
        FlagMask: PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED,
        Version: PERSISTENT_STATE_VERSION,
        Reserved: 0,
    };
    let mut output = FILE_FS_PERSISTENT_VOLUME_INFORMATION::default();
    let mut io_status = IO_STATUS_BLOCK::default();
    let bytes = u32::try_from(size_of::<FILE_FS_PERSISTENT_VOLUME_INFORMATION>())
        .map_err(|_| Error::PersistentVolumeQueryFailed)?;
    // SAFETY: the retained synchronous authority and exact-size input, output,
    // and status blocks remain live for this closed read-only QUERY control.
    let status = unsafe {
        NtFsControlFile(
            volume.as_raw_handle() as HANDLE,
            ptr::null_mut(),
            None,
            ptr::null(),
            &mut io_status,
            FSCTL_QUERY_PERSISTENT_VOLUME_STATE,
            (&input as *const FILE_FS_PERSISTENT_VOLUME_INFORMATION).cast(),
            bytes,
            (&mut output as *mut FILE_FS_PERSISTENT_VOLUME_INFORMATION).cast(),
            bytes,
        )
    };
    // SAFETY: the synchronous call completed before the status union is read.
    let completion = unsafe { io_status.Anonymous.Status };
    classify_persistent_query(
        status,
        completion,
        io_status.Information,
        output.VolumeFlags,
    )
}

fn classify_persistent_query(
    immediate_status: i32,
    completion_status: i32,
    information_bytes: usize,
    volume_flags: u32,
) -> Result<ShortNameMode> {
    if immediate_status != STATUS_SUCCESS
        || completion_status != STATUS_SUCCESS
        || information_bytes != size_of::<FILE_FS_PERSISTENT_VOLUME_INFORMATION>()
    {
        return Err(Error::PersistentVolumeQueryFailed);
    }
    Ok(
        if volume_flags & PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED != 0 {
            ShortNameMode::Disabled
        } else {
            ShortNameMode::Enabled
        },
    )
}

fn require_same_mode(expected: ShortNameMode, observed: ShortNameMode) -> Result<()> {
    if expected == observed {
        Ok(())
    } else {
        Err(Error::PersistentVolumeStateAmbiguous)
    }
}

fn require_case_insensitive(directory: &Dir) -> Result<()> {
    let mut information = FILE_CASE_SENSITIVE_INFO::default();
    // SAFETY: the retained directory and exact-size writable structure remain
    // live for the synchronous query.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            directory.as_raw_handle() as HANDLE,
            FileCaseSensitiveInfo,
            (&mut information as *mut FILE_CASE_SENSITIVE_INFO).cast(),
            u32::try_from(size_of::<FILE_CASE_SENSITIVE_INFO>())
                .map_err(|_| Error::FilesystemFailure)?,
        )
    };
    if succeeded == 0 {
        return Err(Error::FilesystemFailure);
    }
    classify_case_flags(information.Flags)
}

fn classify_case_flags(flags: u32) -> Result<()> {
    let case_sensitive = flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0;
    let unknown_flags = flags & !FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0;
    if case_sensitive || unknown_flags {
        Err(Error::CaseSensitiveDirectoryUnsupported)
    } else {
        Ok(())
    }
}

pub(super) fn require_not_reparse<T: AsRawHandle>(handle: &T) -> Result<()> {
    let mut information = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: the retained handle and exact-size writable structure remain
    // live for this synchronous handle-relative query.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle() as HANDLE,
            FileAttributeTagInfo,
            (&mut information as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>())
                .map_err(|_| Error::FilesystemFailure)?,
        )
    };
    if succeeded == 0 {
        return Err(Error::FilesystemFailure);
    }
    if information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Error::CorruptState);
    }
    Ok(())
}

fn enumerate_directory(directory: &Dir) -> Result<Vec<ObservedNamespaceEntry>> {
    let mut entries = Vec::new();
    let mut restart = true;
    let mut next_ordinal = 0usize;
    for _ in 0..MAX_DIRECTORY_PAGES {
        let mut words = [0u64; DIRECTORY_PAGE_WORDS];
        let bytes = words_as_bytes_mut(&mut words);
        // SAFETY: the retained directory and fixed 8-byte-aligned writable
        // page remain live for this synchronous enumeration call.
        let succeeded = unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle() as HANDLE,
                if restart {
                    FileIdBothDirectoryRestartInfo
                } else {
                    FileIdBothDirectoryInfo
                },
                bytes.as_mut_ptr().cast(),
                u32::try_from(bytes.len()).map_err(|_| Error::BoundExceeded)?,
            )
        };
        if succeeded == 0 {
            // SAFETY: reads the immediately preceding enumeration failure.
            return if unsafe { GetLastError() } == ERROR_NO_MORE_FILES {
                Ok(entries)
            } else {
                Err(Error::FilesystemFailure)
            };
        }
        restart = false;
        let page = parse_directory_page(bytes, &mut next_ordinal)?;
        let total = entries
            .len()
            .checked_add(page.len())
            .ok_or(Error::BoundExceeded)?;
        if total > MAX_DIRECTORY_ENTRIES {
            return Err(Error::BoundExceeded);
        }
        entries
            .try_reserve_exact(page.len())
            .map_err(|_| Error::BoundExceeded)?;
        entries.extend(page);
    }
    Err(Error::BoundExceeded)
}

fn parse_directory_page(
    buffer: &[u8],
    next_ordinal: &mut usize,
) -> Result<Vec<ObservedNamespaceEntry>> {
    if !(buffer.as_ptr() as usize).is_multiple_of(align_of::<FILE_ID_BOTH_DIR_INFO>()) {
        return Err(Error::UnsupportedAliasNamespace);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(MAX_ENTRIES_PER_PAGE)
        .map_err(|_| Error::BoundExceeded)?;
    let mut cursor = 0usize;
    loop {
        if entries.len() >= MAX_ENTRIES_PER_PAGE {
            return Err(Error::BoundExceeded);
        }
        let header_end = cursor
            .checked_add(FILE_NAME_OFFSET)
            .ok_or(Error::UnsupportedAliasNamespace)?;
        if header_end > buffer.len() {
            return Err(Error::UnsupportedAliasNamespace);
        }
        let next = usize::try_from(read_u32(buffer, cursor + NEXT_ENTRY_OFFSET)?)
            .map_err(|_| Error::UnsupportedAliasNamespace)?;
        let file_name_bytes = usize::try_from(read_u32(buffer, cursor + FILE_NAME_LENGTH_OFFSET)?)
            .map_err(|_| Error::UnsupportedAliasNamespace)?;
        if file_name_bytes == 0
            || !file_name_bytes.is_multiple_of(size_of::<u16>())
            || file_name_bytes / size_of::<u16>() > MAX_LONG_NAME_UNITS
        {
            return Err(Error::UnsupportedAliasNamespace);
        }
        let short_name_signed = read_i8(buffer, cursor + SHORT_NAME_LENGTH_OFFSET)?;
        if short_name_signed < 0 {
            return Err(Error::UnsupportedAliasNamespace);
        }
        let short_name_bytes =
            usize::try_from(short_name_signed).map_err(|_| Error::UnsupportedAliasNamespace)?;
        if !short_name_bytes.is_multiple_of(size_of::<u16>())
            || short_name_bytes / size_of::<u16>() > MAX_SHORT_NAME_UNITS
        {
            return Err(Error::UnsupportedAliasNamespace);
        }

        let name_start = cursor
            .checked_add(FILE_NAME_OFFSET)
            .ok_or(Error::UnsupportedAliasNamespace)?;
        let name_end = name_start
            .checked_add(file_name_bytes)
            .ok_or(Error::UnsupportedAliasNamespace)?;
        let short_start = cursor
            .checked_add(SHORT_NAME_OFFSET)
            .ok_or(Error::UnsupportedAliasNamespace)?;
        let short_end = short_start
            .checked_add(short_name_bytes)
            .ok_or(Error::UnsupportedAliasNamespace)?;
        let record_end = if next == 0 {
            buffer.len()
        } else {
            if next < FILE_NAME_OFFSET || !next.is_multiple_of(align_of::<FILE_ID_BOTH_DIR_INFO>())
            {
                return Err(Error::UnsupportedAliasNamespace);
            }
            cursor
                .checked_add(next)
                .ok_or(Error::UnsupportedAliasNamespace)?
        };
        if record_end > buffer.len()
            || record_end <= cursor
            || name_end > record_end
            || short_end > record_end
        {
            return Err(Error::UnsupportedAliasNamespace);
        }

        let canonical_long_name_utf16 = read_utf16(buffer, name_start, file_name_bytes)?;
        if !is_dot_entry(&canonical_long_name_utf16) {
            let optional_short_alias_utf16 = if short_name_bytes == 0 {
                None
            } else {
                Some(read_utf16(buffer, short_start, short_name_bytes)?)
            };
            let canonical_long_name = validate_component(&canonical_long_name_utf16)?;
            if let Some(alias) = &optional_short_alias_utf16 {
                validate_component(alias)?;
            }
            let attributes = read_u32(buffer, cursor + FILE_ATTRIBUTES_OFFSET)?;
            let directory_file_id64 = read_i64(buffer, cursor + FILE_ID_OFFSET)? as u64;
            if directory_file_id64 == 0 {
                return Err(Error::UnsupportedAliasNamespace);
            }
            let role = classify_exact_private_role(&canonical_long_name);
            entries.push(ObservedNamespaceEntry {
                record_ordinal: *next_ordinal,
                canonical_long_name_utf16,
                canonical_long_name,
                optional_short_alias_utf16,
                directory_file_id64,
                entry_kind: if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    EntryKind::Unsupported
                } else if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    EntryKind::Directory
                } else {
                    EntryKind::File
                },
                role,
                protected_name: false,
            });
            *next_ordinal = next_ordinal.checked_add(1).ok_or(Error::BoundExceeded)?;
        }
        if next == 0 {
            return Ok(entries);
        }
        cursor = record_end;
    }
}

fn validate_namespace(
    mut entries: Vec<ObservedNamespaceEntry>,
    scope: NamespaceScope,
) -> Result<NamespaceObservation> {
    let mut identities = BTreeMap::new();
    let protected = ProtectedNames::new();
    for entry in &mut entries {
        if identities
            .insert(entry.directory_file_id64, entry.record_ordinal)
            .is_some()
            && scope != NamespaceScope::EditedWorkspace
        {
            return Err(Error::AliasNamespaceAmbiguous);
        }
        entry.protected_name = entry_has_protected_name(entry, &protected, scope)?;
        if entry.protected_name && scope != NamespaceScope::EditedWorkspace {
            return Err(Error::UnsupportedAliasNamespace);
        }
        if entry.entry_kind == EntryKind::Unsupported
            && !matches!(
                scope,
                NamespaceScope::PathSelection | NamespaceScope::EditedWorkspace
            )
        {
            return Err(Error::UnsupportedAliasNamespace);
        }
    }

    let tokens = comparison_tokens(&entries)?;
    reject_comparison_collisions(&tokens, compare_windows_ordinal_ignore_case)?;

    let mut normalized_units = Vec::new();
    normalized_units
        .try_reserve_exact(tokens.len())
        .map_err(|_| Error::BoundExceeded)?;
    for token in &tokens {
        normalized_units.push(normalize_nfc(token.units)?);
    }
    let mut normalized = Vec::new();
    normalized
        .try_reserve_exact(tokens.len())
        .map_err(|_| Error::BoundExceeded)?;
    for (units, token) in normalized_units.iter().zip(&tokens) {
        normalized.push(ComparisonToken {
            units,
            owner: token.owner,
        });
    }
    reject_comparison_collisions(&normalized, compare_windows_ordinal_ignore_case)?;

    let order = fallible_merge_sort_indices(entries.len(), |left, right| {
        let ordering = compare_windows_ordinal_ignore_case(
            &entries[left].canonical_long_name_utf16,
            &entries[right].canonical_long_name_utf16,
        )?;
        Ok(if ordering == Ordering::Equal {
            entries[left]
                .canonical_long_name_utf16
                .cmp(&entries[right].canonical_long_name_utf16)
        } else {
            ordering
        })
    })?;
    let mut slots = entries.into_iter().map(Some).collect::<Vec<_>>();
    entries = Vec::new();
    entries
        .try_reserve_exact(order.len())
        .map_err(|_| Error::BoundExceeded)?;
    for (ordinal, index) in order.into_iter().enumerate() {
        let mut entry = slots[index].take().ok_or(Error::AliasNamespaceAmbiguous)?;
        entry.record_ordinal = ordinal;
        entries.push(entry);
    }
    Ok(NamespaceObservation { entries })
}

#[derive(Clone, Copy)]
struct ComparisonToken<'a> {
    units: &'a [u16],
    owner: usize,
}

fn comparison_tokens(entries: &[ObservedNamespaceEntry]) -> Result<Vec<ComparisonToken<'_>>> {
    let capacity = entries.len().checked_mul(2).ok_or(Error::BoundExceeded)?;
    let mut tokens = Vec::new();
    tokens
        .try_reserve_exact(capacity)
        .map_err(|_| Error::BoundExceeded)?;
    for entry in entries {
        tokens.push(ComparisonToken {
            units: &entry.canonical_long_name_utf16,
            owner: entry.record_ordinal,
        });
        if let Some(alias) = &entry.optional_short_alias_utf16 {
            tokens.push(ComparisonToken {
                units: alias,
                owner: entry.record_ordinal,
            });
        }
    }
    Ok(tokens)
}

fn reject_comparison_collisions(
    tokens: &[ComparisonToken<'_>],
    mut compare: impl FnMut(&[u16], &[u16]) -> Result<Ordering>,
) -> Result<()> {
    let order = fallible_merge_sort_indices(tokens.len(), |left, right| {
        compare(tokens[left].units, tokens[right].units)
    })?;
    for pair in order.windows(2) {
        let left = tokens[pair[0]];
        let right = tokens[pair[1]];
        if compare(left.units, right.units)? == Ordering::Equal && left.owner != right.owner {
            return Err(Error::AliasNamespaceAmbiguous);
        }
    }
    Ok(())
}

fn fallible_merge_sort_indices(
    length: usize,
    mut compare: impl FnMut(usize, usize) -> Result<Ordering>,
) -> Result<Vec<usize>> {
    let mut source = Vec::new();
    source
        .try_reserve_exact(length)
        .map_err(|_| Error::BoundExceeded)?;
    source.extend(0..length);
    let mut destination = Vec::new();
    destination
        .try_reserve_exact(length)
        .map_err(|_| Error::BoundExceeded)?;
    destination.resize(length, 0usize);
    let mut width = 1usize;
    while width < length {
        let step = width.checked_mul(2).ok_or(Error::BoundExceeded)?;
        let mut start = 0usize;
        while start < length {
            let middle = start.saturating_add(width).min(length);
            let end = start.saturating_add(step).min(length);
            let (mut left, mut right, mut output) = (start, middle, start);
            while left < middle && right < end {
                if compare(source[left], source[right])? != Ordering::Greater {
                    destination[output] = source[left];
                    left += 1;
                } else {
                    destination[output] = source[right];
                    right += 1;
                }
                output += 1;
            }
            while left < middle {
                destination[output] = source[left];
                left += 1;
                output += 1;
            }
            while right < end {
                destination[output] = source[right];
                right += 1;
                output += 1;
            }
            start = end;
        }
        std::mem::swap(&mut source, &mut destination);
        width = step;
    }
    Ok(source)
}

fn compare_windows_ordinal_ignore_case(left: &[u16], right: &[u16]) -> Result<Ordering> {
    let left_len = i32::try_from(left.len()).map_err(|_| Error::BoundExceeded)?;
    let right_len = i32::try_from(right.len()).map_err(|_| Error::BoundExceeded)?;
    // SAFETY: both slices remain live for the explicit checked lengths. TRUE
    // is the sole accepted numeric true value for this API.
    let result =
        unsafe { CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, TRUE) };
    match result {
        CSTR_LESS_THAN => Ok(Ordering::Less),
        CSTR_EQUAL => Ok(Ordering::Equal),
        CSTR_GREATER_THAN => Ok(Ordering::Greater),
        _ => Err(Error::AliasNamespaceAmbiguous),
    }
}

fn normalize_nfc(input: &[u16]) -> Result<Vec<u16>> {
    let input_len = i32::try_from(input.len()).map_err(|_| Error::BoundExceeded)?;
    // SAFETY: `input` remains live for the checked explicit length; a null
    // destination with zero length requests one bounded size estimate.
    let estimated = unsafe {
        NormalizeString(
            NormalizationC,
            input.as_ptr(),
            input_len,
            ptr::null_mut(),
            0,
        )
    };
    let estimated = usize::try_from(estimated).map_err(|_| Error::UnsupportedAliasNamespace)?;
    if estimated == 0 || estimated > MAX_NORMALIZED_NAME_UNITS {
        return Err(Error::UnsupportedAliasNamespace);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(estimated)
        .map_err(|_| Error::BoundExceeded)?;
    output.resize(estimated, 0u16);
    // SAFETY: the source and exact estimated destination remain live for the
    // single normalization attempt; failure does not trigger buffer growth.
    let written = unsafe {
        NormalizeString(
            NormalizationC,
            input.as_ptr(),
            input_len,
            output.as_mut_ptr(),
            i32::try_from(output.len()).map_err(|_| Error::BoundExceeded)?,
        )
    };
    let written = usize::try_from(written).map_err(|_| Error::UnsupportedAliasNamespace)?;
    if written == 0 || written > output.len() {
        return Err(Error::UnsupportedAliasNamespace);
    }
    output.truncate(written);
    String::from_utf16(&output).map_err(|_| Error::UnsupportedAliasNamespace)?;
    Ok(output)
}

/// Exact Windows namespace collision relation shared with the hostile edited
/// observer. It is rejection-only evidence and never selects a path.
pub(super) fn namespace_components_collide(left: &[String], right: &[String]) -> Result<bool> {
    Ok(namespace_path_compare(left, right)? == Ordering::Equal)
}

fn namespace_path_compare(left: &[String], right: &[String]) -> Result<Ordering> {
    for (left, right) in left.iter().zip(right) {
        let left = checked_utf16(left)?;
        let right = checked_utf16(right)?;
        if compare_windows_ordinal_ignore_case(&left, &right)? == Ordering::Equal {
            continue;
        }
        let ordering =
            compare_windows_ordinal_ignore_case(&normalize_nfc(&left)?, &normalize_nfc(&right)?)?;
        if ordering != Ordering::Equal {
            return Ok(ordering);
        }
    }
    Ok(left.len().cmp(&right.len()))
}

fn checked_utf16(value: &str) -> Result<Vec<u16>> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(value.encode_utf16().count())
        .map_err(|_| Error::BoundExceeded)?;
    output.extend(value.encode_utf16());
    Ok(output)
}

pub(super) fn sort_namespace_paths(paths: &mut Vec<Vec<String>>) -> Result<()> {
    let order = fallible_merge_sort_indices(paths.len(), |left, right| {
        namespace_path_compare(&paths[left], &paths[right])
    })?;
    let unsorted = std::mem::take(paths);
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(unsorted.len())
        .map_err(|_| Error::BoundExceeded)?;
    slots.extend(unsorted.into_iter().map(Some));
    paths
        .try_reserve_exact(slots.len())
        .map_err(|_| Error::BoundExceeded)?;
    for index in order {
        paths.push(slots[index].take().ok_or(Error::InvalidState)?);
    }
    Ok(())
}

pub(super) fn namespace_path_has_topology_collision(
    sorted_paths: &[Vec<String>],
    candidate: &[String],
) -> Result<bool> {
    for prefix_len in 1..=candidate.len() {
        let prefix = &candidate[..prefix_len];
        let position = namespace_path_lower_bound(sorted_paths, prefix)?;
        if let Some(path) = sorted_paths.get(position) {
            if namespace_components_collide(path, prefix)? {
                return Ok(true);
            }
        }
    }
    let position = namespace_path_lower_bound(sorted_paths, candidate)?;
    let Some(path) = sorted_paths.get(position) else {
        return Ok(false);
    };
    if path.len() <= candidate.len() {
        return Ok(false);
    }
    namespace_components_collide(&path[..candidate.len()], candidate)
}

fn namespace_path_lower_bound(sorted_paths: &[Vec<String>], key: &[String]) -> Result<usize> {
    let mut left = 0usize;
    let mut right = sorted_paths.len();
    while left < right {
        let middle = left + (right - left) / 2;
        if namespace_path_compare(&sorted_paths[middle], key)? == Ordering::Less {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    Ok(left)
}

struct ProtectedNames {
    forbidden_fixed: Vec<Vec<u16>>,
    lock: Vec<u16>,
    final_prefix: Vec<u16>,
    final_suffix: Vec<u16>,
    manifest_prefix: Vec<u16>,
    manifest_review_suffix: Vec<u16>,
    manifest_apply_suffix: Vec<u16>,
    pending_prefix: Vec<u16>,
    pending_suffix: Vec<u16>,
}

impl ProtectedNames {
    fn new() -> Self {
        Self {
            forbidden_fixed: FORBIDDEN_FIXED_NAMES
                .iter()
                .map(|name| name.encode_utf16().collect())
                .collect(),
            lock: LOCK_LEAF.encode_utf16().collect(),
            final_prefix: FINAL_PREFIX.encode_utf16().collect(),
            final_suffix: FINAL_SUFFIX.encode_utf16().collect(),
            manifest_prefix: MANIFEST_PREFIX.encode_utf16().collect(),
            manifest_review_suffix: MANIFEST_REVIEW_SUFFIX.encode_utf16().collect(),
            manifest_apply_suffix: MANIFEST_APPLY_SUFFIX.encode_utf16().collect(),
            pending_prefix: PENDING_PREFIX.encode_utf16().collect(),
            pending_suffix: PENDING_SUFFIX.encode_utf16().collect(),
        }
    }
}

fn validate_protected_entry(
    entry: &ObservedNamespaceEntry,
    protected: &ProtectedNames,
    scope: NamespaceScope,
) -> Result<()> {
    if entry_has_protected_name(entry, protected, scope)? {
        Err(Error::UnsupportedAliasNamespace)
    } else {
        Ok(())
    }
}

fn entry_has_protected_name(
    entry: &ObservedNamespaceEntry,
    protected: &ProtectedNames,
    scope: NamespaceScope,
) -> Result<bool> {
    if scope == NamespaceScope::PathSelection {
        return Ok(false);
    }
    for fixed in &protected.forbidden_fixed {
        if compare_windows_ordinal_ignore_case(&entry.canonical_long_name_utf16, fixed)?
            == Ordering::Equal
            && (scope != NamespaceScope::CandidateRoot
                || !is_exact_candidate_marker(&entry.canonical_long_name_utf16)
                || entry.entry_kind != EntryKind::File)
        {
            return Ok(true);
        }
    }
    match scope {
        NamespaceScope::PathSelection => unreachable!("handled above"),
        NamespaceScope::PrivateState => {
            if entry.role == PrivateLeafRole::Unrecognized
                && matches_private_role_collision(&entry.canonical_long_name_utf16, protected)?
            {
                return Ok(true);
            }
        }
        NamespaceScope::Workspace
        | NamespaceScope::EditedWorkspace
        | NamespaceScope::CandidateRoot
        | NamespaceScope::CandidateWorkspace => {
            if matches_private_role_collision(&entry.canonical_long_name_utf16, protected)? {
                return Ok(true);
            }
        }
    }
    if let Some(alias) = &entry.optional_short_alias_utf16 {
        for fixed in &protected.forbidden_fixed {
            if compare_windows_ordinal_ignore_case(alias, fixed)? == Ordering::Equal {
                return Ok(true);
            }
        }
        if matches_private_role_collision(alias, protected)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_proposed_name(name: &[u16], scope: NamespaceScope) -> Result<()> {
    let protected = ProtectedNames::new();
    for fixed in &protected.forbidden_fixed {
        if compare_windows_ordinal_ignore_case(name, fixed)? == Ordering::Equal
            && (scope != NamespaceScope::CandidateRoot || !is_exact_candidate_marker(name))
        {
            return Err(Error::UnsupportedAliasNamespace);
        }
    }
    if matches!(
        scope,
        NamespaceScope::Workspace
            | NamespaceScope::EditedWorkspace
            | NamespaceScope::CandidateRoot
            | NamespaceScope::CandidateWorkspace
    ) && matches_private_role_collision(name, &protected)?
    {
        return Err(Error::UnsupportedAliasNamespace);
    }
    Ok(())
}

fn is_exact_candidate_marker(name: &[u16]) -> bool {
    [CANDIDATE_INCOMPLETE_LEAF, CANDIDATE_COMPLETE_LEAF]
        .iter()
        .any(|leaf| name.iter().copied().eq(leaf.encode_utf16()))
}

pub(super) fn validate_workspace_component(name: &str) -> Result<Vec<u16>> {
    let utf16 = name.encode_utf16().collect::<Vec<_>>();
    if utf16.len() > MAX_LONG_NAME_UNITS || name.len() > 8 * 1024 {
        return Err(Error::BoundExceeded);
    }
    validate_component(&utf16)?;
    validate_proposed_name(&utf16, NamespaceScope::Workspace)?;
    Ok(utf16)
}

pub(super) fn validate_virtual_sibling_names(names: &[(Vec<u16>, usize)]) -> Result<()> {
    let tokens = names
        .iter()
        .map(|(units, owner)| ComparisonToken {
            units: units.as_slice(),
            owner: *owner,
        })
        .collect::<Vec<_>>();
    reject_comparison_collisions(&tokens, compare_windows_ordinal_ignore_case)?;
    let normalized = names
        .iter()
        .map(|(units, owner)| Ok((normalize_nfc(units)?, *owner)))
        .collect::<Result<Vec<_>>>()?;
    let normalized_tokens = normalized
        .iter()
        .map(|(units, owner)| ComparisonToken {
            units: units.as_slice(),
            owner: *owner,
        })
        .collect::<Vec<_>>();
    reject_comparison_collisions(&normalized_tokens, compare_windows_ordinal_ignore_case)
}

pub(super) fn sort_utf16_indices(values: &[Vec<u16>]) -> Result<Vec<usize>> {
    fallible_merge_sort_indices(values.len(), |left, right| {
        let ordering = compare_windows_ordinal_ignore_case(&values[left], &values[right])?;
        Ok(if ordering == Ordering::Equal {
            values[left].cmp(&values[right])
        } else {
            ordering
        })
    })
}

fn reject_proposed_collision(observation: &NamespaceObservation, proposed: &[u16]) -> Result<()> {
    let normalized_proposed = normalize_nfc(proposed)?;
    for entry in observation.entries() {
        for existing in std::iter::once(entry.canonical_long_name_utf16.as_slice())
            .chain(entry.optional_short_alias_utf16.as_deref())
        {
            if compare_windows_ordinal_ignore_case(existing, proposed)? == Ordering::Equal
                || compare_windows_ordinal_ignore_case(
                    &normalize_nfc(existing)?,
                    &normalized_proposed,
                )? == Ordering::Equal
            {
                return Err(Error::AliasNamespaceAmbiguous);
            }
        }
    }
    Ok(())
}

fn classify_exact_private_role(name: &str) -> PrivateLeafRole {
    if name == LOCK_LEAF {
        return PrivateLeafRole::Lock;
    }
    if let Some(generation) = parse_final_leaf(name) {
        return PrivateLeafRole::Capsule(generation);
    }
    if let Some((review_id, phase)) = parse_manifest_leaf(name) {
        return PrivateLeafRole::Manifest { review_id, phase };
    }
    if is_pending_leaf(name) {
        return PrivateLeafRole::Pending;
    }
    PrivateLeafRole::Unrecognized
}

fn matches_private_role_collision(name: &[u16], protected: &ProtectedNames) -> Result<bool> {
    if compare_windows_ordinal_ignore_case(name, &protected.lock)? == Ordering::Equal {
        return Ok(true);
    }
    if matches_reserved_shape(name, &protected.final_prefix, 16, &protected.final_suffix)?
        || matches_reserved_shape(
            name,
            &protected.manifest_prefix,
            26,
            &protected.manifest_review_suffix,
        )?
        || matches_reserved_shape(
            name,
            &protected.manifest_prefix,
            26,
            &protected.manifest_apply_suffix,
        )?
        || matches_reserved_shape(
            name,
            &protected.pending_prefix,
            26,
            &protected.pending_suffix,
        )?
    {
        return Ok(true);
    }
    Ok(false)
}

fn matches_reserved_shape(
    name: &[u16],
    prefix: &[u16],
    body_units: usize,
    suffix: &[u16],
) -> Result<bool> {
    let suffix_start = prefix
        .len()
        .checked_add(body_units)
        .ok_or(Error::BoundExceeded)?;
    let expected = suffix_start
        .checked_add(suffix.len())
        .ok_or(Error::BoundExceeded)?;
    if name.len() != expected {
        return Ok(false);
    }
    Ok(
        compare_windows_ordinal_ignore_case(&name[..prefix.len()], prefix)? == Ordering::Equal
            && compare_windows_ordinal_ignore_case(&name[suffix_start..], suffix)?
                == Ordering::Equal,
    )
}

pub(super) fn final_leaf(generation: u64) -> String {
    format!("{FINAL_PREFIX}{generation:016X}{FINAL_SUFFIX}")
}

pub(super) fn manifest_leaf(review_id: &[u8; 16], phase: ManifestPhase) -> String {
    use super::token::encode_base32_128;

    let suffix = match phase {
        ManifestPhase::Review => MANIFEST_REVIEW_SUFFIX,
        ManifestPhase::ApplyResult => MANIFEST_APPLY_SUFFIX,
    };
    format!("{MANIFEST_PREFIX}{}{suffix}", encode_base32_128(review_id))
}

pub(super) fn is_pending_leaf(leaf: &str) -> bool {
    leaf.strip_prefix(PENDING_PREFIX)
        .and_then(|value| value.strip_suffix(PENDING_SUFFIX))
        .is_some_and(|encoded| decode_base32_128(encoded).is_ok())
}

fn parse_final_leaf(leaf: &str) -> Option<u64> {
    let body = leaf
        .strip_prefix(FINAL_PREFIX)?
        .strip_suffix(FINAL_SUFFIX)?;
    if body.len() != 16
        || !body
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
    {
        return None;
    }
    let generation = u64::from_str_radix(body, 16).ok()?;
    (generation != 0).then_some(generation)
}

fn parse_manifest_leaf(leaf: &str) -> Option<([u8; 16], ManifestPhase)> {
    let body = leaf.strip_prefix(MANIFEST_PREFIX)?;
    let (review, phase) = if let Some(review) = body.strip_suffix(MANIFEST_REVIEW_SUFFIX) {
        (review, ManifestPhase::Review)
    } else {
        (
            body.strip_suffix(MANIFEST_APPLY_SUFFIX)?,
            ManifestPhase::ApplyResult,
        )
    };
    Some((decode_base32_128(review).ok()?, phase))
}

fn validate_component(units: &[u16]) -> Result<String> {
    if units.is_empty() || units.len() > MAX_LONG_NAME_UNITS {
        return Err(Error::UnsupportedAliasNamespace);
    }
    let name = String::from_utf16(units).map_err(|_| Error::UnsupportedAliasNamespace)?;
    if name.encode_utf16().ne(units.iter().copied())
        || name == "."
        || name == ".."
        || name.ends_with(['.', ' '])
        || name.chars().any(|character| {
            character <= '\u{1f}'
                || matches!(
                    character,
                    '\0' | '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
                )
        })
        || is_dos_device_basename(&name)
    {
        return Err(Error::UnsupportedAliasNamespace);
    }
    Ok(name)
}

fn is_dos_device_basename(name: &str) -> bool {
    let basename = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim_end_matches(['.', ' ']);
    if basename.eq_ignore_ascii_case("CON")
        || basename.eq_ignore_ascii_case("PRN")
        || basename.eq_ignore_ascii_case("AUX")
        || basename.eq_ignore_ascii_case("NUL")
    {
        return true;
    }
    let bytes = basename.as_bytes();
    if bytes.len() >= 4
        && bytes[..3].is_ascii()
        && (bytes[..3].eq_ignore_ascii_case(b"COM") || bytes[..3].eq_ignore_ascii_case(b"LPT"))
    {
        let suffix = &basename[3..];
        return matches!(
            suffix,
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        );
    }
    false
}

fn read_u32(buffer: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_ne_bytes(read_array::<4>(buffer, offset)?))
}

fn read_i64(buffer: &[u8], offset: usize) -> Result<i64> {
    Ok(i64::from_ne_bytes(read_array::<8>(buffer, offset)?))
}

fn read_i8(buffer: &[u8], offset: usize) -> Result<i8> {
    buffer
        .get(offset)
        .copied()
        .map(|byte| byte as i8)
        .ok_or(Error::UnsupportedAliasNamespace)
}

fn read_array<const N: usize>(buffer: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or(Error::UnsupportedAliasNamespace)?;
    buffer
        .get(offset..end)
        .ok_or(Error::UnsupportedAliasNamespace)?
        .try_into()
        .map_err(|_| Error::UnsupportedAliasNamespace)
}

fn read_utf16(buffer: &[u8], offset: usize, byte_length: usize) -> Result<Vec<u16>> {
    let end = offset
        .checked_add(byte_length)
        .ok_or(Error::UnsupportedAliasNamespace)?;
    let bytes = buffer
        .get(offset..end)
        .ok_or(Error::UnsupportedAliasNamespace)?;
    Ok(bytes
        .chunks_exact(size_of::<u16>())
        .map(|unit| u16::from_ne_bytes([unit[0], unit[1]]))
        .collect())
}

fn is_dot_entry(name: &[u16]) -> bool {
    name == [u16::from(b'.')] || name == [u16::from(b'.'), u16::from(b'.')]
}

fn words_as_bytes_mut(words: &mut [u64]) -> &mut [u8] {
    let length = std::mem::size_of_val(words);
    // SAFETY: the mutable u64 slice is contiguous and is viewed over the same
    // exact allocation as initialized bytes.
    unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast(), length) }
}

pub(super) fn file_identity<T: AsRawHandle>(handle: &T) -> Result<FileIdentity> {
    Ok(handle_identity(handle)?.stable)
}

fn handle_identity<T: AsRawHandle>(handle: &T) -> Result<HandleIdentity> {
    let raw = handle.as_raw_handle() as HANDLE;
    let mut extended = FILE_ID_INFO::default();
    // SAFETY: the retained handle and exact writable identity structure remain
    // live for this synchronous query.
    if unsafe {
        GetFileInformationByHandleEx(
            raw,
            FileIdInfo,
            (&mut extended as *mut FILE_ID_INFO).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>()).map_err(|_| Error::FilesystemFailure)?,
        )
    } == 0
    {
        return Err(Error::FilesystemFailure);
    }
    let mut basic = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the retained handle and exact writable basic structure remain
    // live for this synchronous query.
    if unsafe { GetFileInformationByHandle(raw, &mut basic) } == 0 {
        return Err(Error::FilesystemFailure);
    }
    Ok(HandleIdentity {
        stable: FileIdentity {
            volume_serial: extended.VolumeSerialNumber,
            file_id: extended.FileId.Identifier,
        },
        directory_file_id64: (u64::from(basic.nFileIndexHigh) << 32)
            | u64::from(basic.nFileIndexLow),
    })
}

#[allow(dead_code)]
fn require_local_ntfs(root: &Dir) -> Result<()> {
    let handle = root.as_raw_handle() as HANDLE;
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut remote = FILE_IS_REMOTE_DEVICE_INFORMATION::default();
    // SAFETY: the retained handle and exact writable status/information blocks
    // remain live for this synchronous read-only query.
    let status = unsafe {
        NtQueryInformationFile(
            handle,
            &mut io_status,
            (&mut remote as *mut FILE_IS_REMOTE_DEVICE_INFORMATION).cast(),
            u32::try_from(size_of::<FILE_IS_REMOTE_DEVICE_INFORMATION>())
                .map_err(|_| Error::FilesystemFailure)?,
            FileIsRemoteDeviceInformation,
        )
    };
    if status < 0 || remote.IsRemote {
        return Err(Error::UnsupportedPlatform);
    }
    let mut filesystem_name = [0u16; 16];
    // SAFETY: the retained handle and fixed writable filesystem-name buffer
    // remain live; unused outputs are deliberately null.
    let queried = unsafe {
        GetVolumeInformationByHandleW(
            handle,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            filesystem_name.as_mut_ptr(),
            u32::try_from(filesystem_name.len()).map_err(|_| Error::FilesystemFailure)?,
        )
    };
    if queried == 0 {
        return Err(Error::FilesystemFailure);
    }
    let end = filesystem_name
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(Error::UnsupportedPlatform)?;
    if !utf16_ascii_eq_ignore_case(&filesystem_name[..end], b"NTFS") {
        return Err(Error::UnsupportedPlatform);
    }
    Ok(())
}

#[allow(dead_code)]
fn utf16_ascii_eq_ignore_case(actual: &[u16], expected: &[u8]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            u8::try_from(*actual).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
        })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::mem::size_of;

    use super::*;

    fn model_entry(
        ordinal: usize,
        long: &str,
        alias: Option<&str>,
        file_id: u64,
    ) -> ObservedNamespaceEntry {
        let canonical_long_name_utf16 = long.encode_utf16().collect::<Vec<_>>();
        ObservedNamespaceEntry {
            record_ordinal: ordinal,
            canonical_long_name_utf16,
            canonical_long_name: long.to_owned(),
            optional_short_alias_utf16: alias.map(|value| value.encode_utf16().collect()),
            directory_file_id64: file_id,
            entry_kind: EntryKind::File,
            role: classify_exact_private_role(long),
            protected_name: false,
        }
    }

    fn synthetic_record(long: &[u16], alias: &[u16], next: u32, file_id: i64) -> Vec<u64> {
        let long_bytes = std::mem::size_of_val(long);
        let record_bytes = FILE_NAME_OFFSET + long_bytes;
        let words = record_bytes.div_ceil(size_of::<u64>());
        let mut storage = vec![0u64; words];
        let bytes = words_as_bytes_mut(&mut storage);
        bytes[NEXT_ENTRY_OFFSET..NEXT_ENTRY_OFFSET + 4].copy_from_slice(&next.to_ne_bytes());
        bytes[FILE_NAME_LENGTH_OFFSET..FILE_NAME_LENGTH_OFFSET + 4].copy_from_slice(
            &u32::try_from(long_bytes)
                .expect("bounded name")
                .to_ne_bytes(),
        );
        bytes[SHORT_NAME_LENGTH_OFFSET] =
            u8::try_from(std::mem::size_of_val(alias)).expect("bounded alias");
        bytes[FILE_ID_OFFSET..FILE_ID_OFFSET + 8].copy_from_slice(&file_id.to_ne_bytes());
        for (index, unit) in alias.iter().enumerate() {
            let start = SHORT_NAME_OFFSET + index * 2;
            bytes[start..start + 2].copy_from_slice(&unit.to_ne_bytes());
        }
        for (index, unit) in long.iter().enumerate() {
            let start = FILE_NAME_OFFSET + index * 2;
            bytes[start..start + 2].copy_from_slice(&unit.to_ne_bytes());
        }
        storage
    }

    #[test]
    fn exact_windows_binding_layout_and_query_constants_are_fixed() {
        assert_eq!(FSCTL_QUERY_PERSISTENT_VOLUME_STATE, 0x0009_023C);
        assert_eq!(PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED, 1);
        assert_eq!(size_of::<FILE_FS_PERSISTENT_VOLUME_INFORMATION>(), 16);
        assert_eq!(size_of::<FILE_ID_BOTH_DIR_INFO>(), 112);
        assert_eq!(align_of::<FILE_ID_BOTH_DIR_INFO>(), 8);
        assert_eq!(FILE_NAME_OFFSET, 104);
        assert_eq!(size_of::<FILE_CASE_SENSITIVE_INFO>(), 4);
        assert_eq!(size_of::<FILE_ATTRIBUTE_TAG_INFO>(), 8);
        assert_eq!(size_of::<FILE_ID_INFO>(), 24);
        assert_eq!(size_of::<BY_HANDLE_FILE_INFORMATION>(), 52);
        assert_eq!(CREATED_DIRECTORY_ACCESS, 0x0010_00A7);
        assert_eq!(
            classify_persistent_query(0, 0, 16, 0),
            Ok(ShortNameMode::Enabled)
        );
        assert_eq!(
            classify_persistent_query(0, 0, 16, 1),
            Ok(ShortNameMode::Disabled)
        );
        for result in [
            classify_persistent_query(-1, 0, 16, 0),
            classify_persistent_query(0, -1, 16, 0),
            classify_persistent_query(0, 0, 15, 0),
        ] {
            assert_eq!(result, Err(Error::PersistentVolumeQueryFailed));
        }
        assert_eq!(
            require_same_mode(ShortNameMode::Enabled, ShortNameMode::Disabled),
            Err(Error::PersistentVolumeStateAmbiguous)
        );
    }

    #[test]
    fn parser_accepts_one_bounded_long_short_identity_record() {
        let mut ordinal = 0;
        let long = "CanonicalLongName.txt".encode_utf16().collect::<Vec<_>>();
        let alias = "CANONI~1.TXT".encode_utf16().collect::<Vec<_>>();
        let mut storage = synthetic_record(&long, &alias, 0, 42);
        let entries = parse_directory_page(words_as_bytes_mut(&mut storage), &mut ordinal)
            .expect("valid synthetic record");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].canonical_long_name(), "CanonicalLongName.txt");
        assert!(entries[0].alias_present());
        assert_eq!(entries[0].directory_file_id64, 42);
    }

    #[test]
    fn encoding_boundary_preserves_exact_names_and_rejects_each_unpaired_form() {
        for name in [
            "日本語資料.txt",
            "Ā-€-한글-Ж.txt",
            "非BMP-🚀-𐐷.txt",
            "space & apostrophe's-漢🚀.txt",
            "e\u{301}.txt",
            "İ-ı.txt",
        ] {
            let wide: Vec<u16> = name.encode_utf16().collect();
            let mut record = synthetic_record(&wide, &[], 0, 42);
            let entries = parse_directory_page(words_as_bytes_mut(&mut record), &mut 0)
                .expect("strict observed name decoding");
            assert_eq!(entries[0].canonical_long_name_utf16, wide);
            assert_eq!(entries[0].canonical_long_name().as_bytes(), name.as_bytes());
            assert_eq!(validate_workspace_component(name).unwrap(), wide);
            assert!(!entries[0].canonical_long_name().contains('\u{fffd}'));
        }
        for wide in [vec![0xd800], vec![0xdc00], vec![0xd800, 0x61, 0xdc00]] {
            let mut record = synthetic_record(&wide, &[], 0, 42);
            assert!(matches!(
                parse_directory_page(words_as_bytes_mut(&mut record), &mut 0),
                Err(Error::UnsupportedAliasNamespace)
            ));
        }
    }

    #[test]
    fn parser_rejects_malformed_lengths_offsets_and_unicode_without_overread() {
        let long = "ordinary.txt".encode_utf16().collect::<Vec<_>>();
        let mut cases = Vec::new();

        let mut odd_name = synthetic_record(&long, &[], 0, 1);
        words_as_bytes_mut(&mut odd_name)[FILE_NAME_LENGTH_OFFSET..FILE_NAME_LENGTH_OFFSET + 4]
            .copy_from_slice(&3u32.to_ne_bytes());
        cases.push(odd_name);

        let mut negative_short = synthetic_record(&long, &[], 0, 1);
        words_as_bytes_mut(&mut negative_short)[SHORT_NAME_LENGTH_OFFSET] = 0xFF;
        cases.push(negative_short);

        let mut oversized_short = synthetic_record(&long, &[], 0, 1);
        words_as_bytes_mut(&mut oversized_short)[SHORT_NAME_LENGTH_OFFSET] = 26;
        cases.push(oversized_short);

        let mut bad_next = synthetic_record(&long, &[], 0, 1);
        words_as_bytes_mut(&mut bad_next)[NEXT_ENTRY_OFFSET..NEXT_ENTRY_OFFSET + 4]
            .copy_from_slice(&7u32.to_ne_bytes());
        cases.push(bad_next);

        let invalid_surrogate = [0xD800u16];
        cases.push(synthetic_record(&invalid_surrogate, &[], 0, 1));

        cases.push(synthetic_record(&long, &[], 0, 0));

        for mut case in cases {
            assert!(parse_directory_page(words_as_bytes_mut(&mut case), &mut 0).is_err());
        }

        // The parser must preserve a reparse record so path selection can
        // safely ignore an unrelated ancestor sibling. Workspace/private
        // scopes still reject that record before traversal or mutation.
        let mut reparse = synthetic_record(&long, &[], 0, 1);
        words_as_bytes_mut(&mut reparse)[FILE_ATTRIBUTES_OFFSET..FILE_ATTRIBUTES_OFFSET + 4]
            .copy_from_slice(&FILE_ATTRIBUTE_REPARSE_POINT.to_ne_bytes());
        let parsed = parse_directory_page(words_as_bytes_mut(&mut reparse), &mut 0)
            .expect("bounded reparse record is retained for scope validation");
        assert_eq!(parsed[0].entry_kind(), EntryKind::Unsupported);
        validate_namespace(parsed.clone(), NamespaceScope::PathSelection)
            .expect("unrelated ancestor reparse sibling remains non-selectable");
        assert_eq!(
            validate_namespace(parsed.clone(), NamespaceScope::Workspace),
            Err(Error::UnsupportedAliasNamespace)
        );
        assert_eq!(
            validate_namespace(parsed, NamespaceScope::PrivateState),
            Err(Error::UnsupportedAliasNamespace)
        );
    }

    #[test]
    fn namespace_collision_matrix_and_hard_link_shape_fail_closed() {
        for entries in [
            vec![
                model_entry(0, "Alpha.txt", None, 1),
                model_entry(1, "alpha.TXT", None, 2),
            ],
            vec![
                model_entry(0, "ALPHA.TXT", None, 1),
                model_entry(1, "BetaLong.txt", Some("alpha.txt"), 2),
            ],
            vec![
                model_entry(0, "AlphaLong.txt", Some("beta.txt"), 1),
                model_entry(1, "BETA.TXT", None, 2),
            ],
            vec![
                model_entry(0, "AlphaLong.txt", Some("SAME.TXT"), 1),
                model_entry(1, "BetaLong.txt", Some("same.txt"), 2),
            ],
            vec![
                model_entry(0, "HardLinkA.txt", None, 7),
                model_entry(1, "HardLinkB.txt", None, 7),
            ],
        ] {
            assert_eq!(
                validate_namespace(entries, NamespaceScope::PrivateState).err(),
                Some(Error::AliasNamespaceAmbiguous)
            );
        }
        validate_namespace(
            vec![model_entry(0, "SAME.TXT", Some("same.txt"), 1)],
            NamespaceScope::PrivateState,
        )
        .expect("same-record long and alias have one owner");
        let edited_hard_links = validate_namespace(
            vec![
                model_entry(0, "HardLinkA.txt", None, 7),
                model_entry(1, "HardLinkB.txt", None, 7),
            ],
            NamespaceScope::EditedWorkspace,
        )
        .expect("edited observer retains hard-link records for structural rejection");
        assert_eq!(edited_hard_links.entries().len(), 2);
    }

    #[test]
    fn exact_long_selection_never_uses_case_or_alias_as_authority() {
        let mut canonical = model_entry(0, "CanonicalLongName.txt", Some("CANONI~1.TXT"), 1);
        canonical.entry_kind = EntryKind::File;
        let observation = validate_namespace(vec![canonical], NamespaceScope::Workspace)
            .expect("valid one-record namespace");
        assert_eq!(
            select_exact_canonical(
                &observation,
                &"CanonicalLongName.txt".encode_utf16().collect::<Vec<_>>(),
                EntryKind::File,
                NamespaceScope::Workspace,
            )
            .expect("exact canonical long selection")
            .directory_file_id64(),
            1
        );
        for rejected in ["canonicallongname.TXT", "CANONI~1.TXT"] {
            assert_eq!(
                select_exact_canonical(
                    &observation,
                    &rejected.encode_utf16().collect::<Vec<_>>(),
                    EntryKind::File,
                    NamespaceScope::Workspace,
                ),
                Err(Error::UnsupportedAliasNamespace)
            );
        }

        let mut protected = model_entry(0, "session.lock", None, 2);
        protected.entry_kind = EntryKind::Directory;
        let mut ordinary = model_entry(1, "ordinary-parent", None, 3);
        ordinary.entry_kind = EntryKind::Directory;
        let ancestor = validate_namespace(vec![protected, ordinary], NamespaceScope::PathSelection)
            .expect("path-selection namespace retains an unrelated protected spelling");
        select_exact_canonical(
            &ancestor,
            &"ordinary-parent".encode_utf16().collect::<Vec<_>>(),
            EntryKind::Directory,
            NamespaceScope::PathSelection,
        )
        .expect("an unrelated protected-looking sibling does not select an object");
        let supplied = "session.lock".encode_utf16().collect::<Vec<_>>();
        assert_eq!(
            select_exact_canonical(
                &ancestor,
                &supplied,
                EntryKind::Directory,
                NamespaceScope::PathSelection,
            ),
            Err(Error::UnsupportedAliasNamespace)
        );

        let mut protected_alias = model_entry(0, "ordinary-parent", Some(".git"), 4);
        protected_alias.entry_kind = EntryKind::Directory;
        let alias_observation =
            validate_namespace(vec![protected_alias], NamespaceScope::PathSelection)
                .expect("the selected record owns its canonical name and alias");
        assert_eq!(
            select_exact_canonical(
                &alias_observation,
                &"ordinary-parent".encode_utf16().collect::<Vec<_>>(),
                EntryKind::Directory,
                NamespaceScope::PathSelection,
            ),
            Err(Error::UnsupportedAliasNamespace)
        );
    }

    #[test]
    fn protected_alias_case_nfc_and_invalid_component_rules_reject() {
        for protected_alias in [
            ".GIT",
            "SESSION.LOCK",
            "CAPSULE-0000000000000001.SCDP",
            ".PENDING-CEIRCEIRCEIRCEIRCEIRCEIRCE.SCDP",
            "MANIFEST-CEIRCEIRCEIRCEIRCEIRCEIRCE-REVIEW.SCDP",
        ] {
            assert_eq!(
                validate_namespace(
                    vec![model_entry(
                        0,
                        "ordinary-long-name.txt",
                        Some(protected_alias),
                        1,
                    )],
                    NamespaceScope::PrivateState
                )
                .err(),
                Some(Error::UnsupportedAliasNamespace)
            );
        }
        assert_eq!(
            validate_namespace(
                vec![model_entry(0, ".git", None, 1)],
                NamespaceScope::PrivateState,
            )
            .err(),
            Some(Error::UnsupportedAliasNamespace)
        );
        assert_eq!(
            validate_namespace(
                vec![model_entry(0, "Session.Lock", None, 1)],
                NamespaceScope::PrivateState,
            )
            .err(),
            Some(Error::UnsupportedAliasNamespace)
        );
        assert_eq!(
            validate_namespace(
                vec![
                    model_entry(0, "\u{e9}.txt", None, 1),
                    model_entry(1, "e\u{301}.txt", None, 2),
                ],
                NamespaceScope::PrivateState
            )
            .err(),
            Some(Error::AliasNamespaceAmbiguous)
        );
        for invalid in ["CON.txt", "LPT¹.log", "trailing.", "trailing ", "bad:name"] {
            let units = invalid.encode_utf16().collect::<Vec<_>>();
            assert_eq!(
                validate_component(&units).err(),
                Some(Error::UnsupportedAliasNamespace)
            );
        }
        assert_eq!(
            normalize_nfc(&vec![u16::from(b'a'); MAX_NORMALIZED_NAME_UNITS + 1]).err(),
            Some(Error::UnsupportedAliasNamespace)
        );
        assert_eq!(
            normalize_nfc(&[0xD800]).err(),
            Some(Error::UnsupportedAliasNamespace)
        );
    }

    #[test]
    fn comparison_sort_is_fallible_and_n_log_n_bounded() {
        assert!(fallible_merge_sort_indices(0, |_, _| unreachable!()).is_ok());
        assert_eq!(
            fallible_merge_sort_indices(1, |_, _| unreachable!()).expect("one token"),
            [0]
        );

        let length = 4_096usize;
        let calls = Cell::new(0usize);
        let order = fallible_merge_sort_indices(length, |left, right| {
            calls.set(calls.get() + 1);
            Ok(right.cmp(&left))
        })
        .expect("bounded sort");
        assert_eq!(order.first(), Some(&(length - 1)));
        assert_eq!(order.last(), Some(&0));
        let levels = usize::BITS as usize - (length - 1).leading_zeros() as usize;
        assert!(calls.get() <= length * levels);

        assert_eq!(
            fallible_merge_sort_indices(2, |_, _| Err(Error::AliasNamespaceAmbiguous)).err(),
            Some(Error::AliasNamespaceAmbiguous)
        );

        let names = (0..length)
            .map(|index| {
                format!("N{index:07}.TXT")
                    .encode_utf16()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let tokens = names
            .iter()
            .enumerate()
            .map(|(owner, units)| ComparisonToken { units, owner })
            .collect::<Vec<_>>();
        calls.set(0);
        reject_comparison_collisions(&tokens, |left, right| {
            calls.set(calls.get() + 1);
            Ok(left.cmp(right))
        })
        .expect("collision scan remains bounded");
        assert!(calls.get() <= length * levels + length.saturating_sub(1));
        assert_eq!(
            reject_comparison_collisions(&tokens[..2], |_, _| {
                Err(Error::AliasNamespaceAmbiguous)
            })
            .err(),
            Some(Error::AliasNamespaceAmbiguous)
        );

        let long_short = vec![model_entry(0, "LongName.txt", Some("LONGNA~1.TXT"), 1)];
        let long_short_tokens = comparison_tokens(&long_short).expect("bounded long+short tokens");
        assert_eq!(long_short_tokens.len(), 2);
        assert_eq!(long_short_tokens[0].owner, long_short_tokens[1].owner);

        let maximum_token_count = MAX_DIRECTORY_ENTRIES * 2;
        let maximum_calls = Cell::new(0usize);
        let maximum_order = fallible_merge_sort_indices(maximum_token_count, |left, right| {
            maximum_calls.set(maximum_calls.get() + 1);
            Ok(left.cmp(&right))
        })
        .expect("maximum modeled namespace remains bounded");
        assert_eq!(maximum_order.len(), maximum_token_count);
        let maximum_levels =
            usize::BITS as usize - (maximum_token_count - 1).leading_zeros() as usize;
        assert!(maximum_calls.get() <= maximum_token_count * maximum_levels);
    }

    #[test]
    fn sorted_namespace_path_authority_detects_leaf_and_topology_collisions() {
        let mut omitted = vec![
            vec!["zeta".to_owned(), "child.bin".to_owned()],
            vec!["omitted.txt".to_owned()],
            vec!["caf\u{e9}".to_owned(), "payload.bin".to_owned()],
        ];
        sort_namespace_paths(&mut omitted).expect("sort omitted namespace paths");
        assert!(
            namespace_path_has_topology_collision(&omitted, &["OMITTED.TXT".to_owned()])
                .expect("case-insensitive leaf collision")
        );
        assert!(
            namespace_path_has_topology_collision(&omitted, &["zeta".to_owned()])
                .expect("candidate ancestor collision")
        );
        assert!(namespace_path_has_topology_collision(
            &omitted,
            &[
                "zeta".to_owned(),
                "child.bin".to_owned(),
                "descendant".to_owned(),
            ]
        )
        .expect("omitted ancestor collision"));
        assert!(namespace_path_has_topology_collision(
            &omitted,
            &["cafe\u{301}".to_owned(), "PAYLOAD.BIN".to_owned()]
        )
        .expect("NFC-equivalent collision"));
        assert!(
            !namespace_path_has_topology_collision(&omitted, &["unrelated.txt".to_owned()])
                .expect("unrelated namespace path")
        );
    }

    #[test]
    fn case_mode_and_raw_free_debug_fail_closed() {
        assert_eq!(
            classify_case_flags(FILE_CS_FLAG_CASE_SENSITIVE_DIR),
            Err(Error::CaseSensitiveDirectoryUnsupported)
        );
        assert_eq!(
            classify_case_flags(FILE_CS_FLAG_CASE_SENSITIVE_DIR << 1),
            Err(Error::CaseSensitiveDirectoryUnsupported)
        );
        let canary = "SHORTALIAS-CANARY";
        let entry = model_entry(0, "ordinary.txt", Some(canary), 1);
        assert!(!format!("{entry:?}").contains(canary));
        let namespace = NamespaceObservation {
            entries: vec![entry],
        };
        assert!(!format!("{namespace:?}").contains(canary));
        let canary_utf16 = canary
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        for authenticated_payload in [
            crate::roundtrip::schema::tests::active_capsule(1)
                .encode_canonical()
                .expect("canonical capsule"),
            crate::roundtrip::schema::tests::tombstone(2)
                .encode_canonical()
                .expect("canonical tombstone"),
        ] {
            assert!(!authenticated_payload
                .windows(canary.len())
                .any(|window| window == canary.as_bytes()));
            assert!(!authenticated_payload
                .windows(canary_utf16.len())
                .any(|window| window == canary_utf16));
        }
        for error in [
            Error::UnsupportedAliasNamespace,
            Error::AliasNamespaceAmbiguous,
            Error::AliasIdentityMismatch,
            Error::CaseSensitiveDirectoryUnsupported,
            Error::PersistentVolumeQueryFailed,
            Error::PersistentVolumeStateAmbiguous,
        ] {
            assert!(!error.to_string().contains(canary));
        }
    }
}
