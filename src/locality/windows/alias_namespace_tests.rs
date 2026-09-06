//! Alias-aware NTFS namespace regression tests.
//!
//! This module is test-only. It creates ordinary synthetic entries outside the
//! repository, observes them through one retained directory handle, and never
//! changes the volume's short-name policy.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::mem::{align_of, offset_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, File, OpenOptions};
use windows_sys::Wdk::Storage::FileSystem::NtFsControlFile;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_NO_MORE_FILES, HANDLE, STATUS_SUCCESS};
use windows_sys::Win32::Storage::FileSystem::{
    FileCaseSensitiveInfo, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo, FileIdInfo,
    GetFileInformationByHandle, GetFileInformationByHandleEx, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_DIRECTORY, FILE_CASE_SENSITIVE_INFO, FILE_ID_BOTH_DIR_INFO, FILE_ID_INFO,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const FSCTL_QUERY_PERSISTENT_VOLUME_STATE: u32 = 0x0009_023C;
const SHORT_NAME_CREATION_DISABLED: u32 = 0x0000_0001;
const PERSISTENT_STATE_VERSION: u32 = 1;
const FILE_CS_FLAG_CASE_SENSITIVE_DIR: u32 = 0x0000_0001;

const DIRECTORY_PAGE_BYTES: usize = 4_096;
const DIRECTORY_PAGE_WORDS: usize = DIRECTORY_PAGE_BYTES / size_of::<u64>();
const MAX_DIRECTORY_PAGES: usize = 256;
const MAX_DIRECTORY_ENTRIES: usize = 100_000;
const MAX_ENTRIES_PER_PAGE: usize = 256;
const MAX_SHORT_NAME_BYTES: usize = 12 * size_of::<u16>();
const FIXTURE_PREFIX: &str = "R2";

const NEXT_ENTRY_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, NextEntryOffset);
const FILE_ATTRIBUTES_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, FileAttributes);
const FILE_NAME_LENGTH_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, FileNameLength);
const SHORT_NAME_LENGTH_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, ShortNameLength);
const SHORT_NAME_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, ShortName);
const FILE_ID_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, FileId);
const FILE_NAME_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PersistentVolumeInformation {
    volume_flags: u32,
    flag_mask: u32,
    version: u32,
    reserved: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    File,
    Directory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct HandleIdentity {
    volume_serial: u64,
    file_id_128: [u8; 16],
    file_index_64: u64,
    number_of_links: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedNamespaceEntry {
    record_ordinal: usize,
    canonical_long_name: Vec<u16>,
    optional_short_alias: Option<Vec<u16>>,
    file_identity: u64,
    entry_kind: EntryKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryInfoError {
    ApiFailed,
    BufferMisaligned,
    TruncatedRecord,
    InvalidNextEntryOffset,
    InvalidFileNameLength,
    InvalidShortNameLength,
    EntryBoundExceeded,
    PageBoundExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamespaceError {
    NonAsciiLaboratoryKey,
    DifferentIdentityCollision,
    MultipleRecordsForIdentity,
    ProtectedNameCollision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamespaceOwner {
    record_ordinal: usize,
    file_identity: u64,
}

#[derive(Debug, Default)]
struct NamespaceIndex {
    owners: BTreeMap<Vec<u8>, NamespaceOwner>,
}

impl NamespaceIndex {
    fn insert(&mut self, entry: &ObservedNamespaceEntry) -> Result<(), NamespaceError> {
        self.insert_name(&entry.canonical_long_name, entry)?;
        if let Some(alias) = &entry.optional_short_alias {
            self.insert_name(alias, entry)?;
        }
        Ok(())
    }

    fn insert_name(
        &mut self,
        name: &[u16],
        entry: &ObservedNamespaceEntry,
    ) -> Result<(), NamespaceError> {
        let key = ascii_case_insensitive_key(name)?;
        let incoming = NamespaceOwner {
            record_ordinal: entry.record_ordinal,
            file_identity: entry.file_identity,
        };
        match self.owners.get(&key) {
            None => {
                self.owners.insert(key, incoming);
                Ok(())
            }
            Some(owner) if owner == &incoming => Ok(()),
            Some(owner) if owner.file_identity != incoming.file_identity => {
                Err(NamespaceError::DifferentIdentityCollision)
            }
            Some(_) => Err(NamespaceError::MultipleRecordsForIdentity),
        }
    }

    fn reject_protected(&self, protected: &[&str]) -> Result<(), NamespaceError> {
        for name in protected {
            let wide = OsStr::new(name).encode_wide().collect::<Vec<_>>();
            let key = ascii_case_insensitive_key(&wide)?;
            if self.owners.contains_key(&key) {
                return Err(NamespaceError::ProtectedNameCollision);
            }
        }
        Ok(())
    }
}

fn ascii_case_insensitive_key(name: &[u16]) -> Result<Vec<u8>, NamespaceError> {
    name.iter()
        .map(|unit| {
            let byte = u8::try_from(*unit).map_err(|_| NamespaceError::NonAsciiLaboratoryKey)?;
            if byte.is_ascii() {
                Ok(byte.to_ascii_lowercase())
            } else {
                Err(NamespaceError::NonAsciiLaboratoryKey)
            }
        })
        .collect()
}

fn query_short_name_creation_disabled(directory: &Dir) -> io::Result<bool> {
    let input = PersistentVolumeInformation {
        volume_flags: 0,
        flag_mask: SHORT_NAME_CREATION_DISABLED,
        version: PERSISTENT_STATE_VERSION,
        reserved: 0,
    };
    let mut output = PersistentVolumeInformation::default();
    let mut io_status = IO_STATUS_BLOCK::default();
    let bytes = u32::try_from(size_of::<PersistentVolumeInformation>())
        .map_err(|_| io::Error::other("persistent-state structure size"))?;
    // SAFETY: the retained synchronous directory handle and exact-size input,
    // output, and status blocks remain live for the closed read-only query.
    let status = unsafe {
        NtFsControlFile(
            directory.as_raw_handle() as HANDLE,
            ptr::null_mut(),
            None,
            ptr::null(),
            &mut io_status,
            FSCTL_QUERY_PERSISTENT_VOLUME_STATE,
            (&input as *const PersistentVolumeInformation).cast(),
            bytes,
            (&mut output as *mut PersistentVolumeInformation).cast(),
            bytes,
        )
    };
    // SAFETY: the synchronous call completed before the status union is read.
    let completion = unsafe { io_status.Anonymous.Status };
    if status != STATUS_SUCCESS
        || completion != STATUS_SUCCESS
        || io_status.Information != size_of::<PersistentVolumeInformation>()
    {
        return Err(io::Error::other("persistent-state query failed"));
    }
    Ok(output.volume_flags & SHORT_NAME_CREATION_DISABLED != 0)
}

fn query_case_sensitive(directory: &Dir) -> io::Result<bool> {
    let mut information = FILE_CASE_SENSITIVE_INFO::default();
    // SAFETY: the retained directory handle and exact-size writable output
    // structure remain live for the synchronous query.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            directory.as_raw_handle() as HANDLE,
            FileCaseSensitiveInfo,
            (&mut information as *mut FILE_CASE_SENSITIVE_INFO).cast(),
            u32::try_from(size_of::<FILE_CASE_SENSITIVE_INFO>())
                .map_err(|_| io::Error::other("case-info structure size"))?,
        )
    };
    if succeeded == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(information.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0)
    }
}

fn handle_identity(handle: &impl AsRawHandle) -> io::Result<HandleIdentity> {
    let raw = handle.as_raw_handle() as HANDLE;
    let mut basic = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the live handle and exact-size writable output structure remain
    // valid for the synchronous call.
    if unsafe { GetFileInformationByHandle(raw, &mut basic) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut extended = FILE_ID_INFO::default();
    // SAFETY: the live handle and exact-size writable FILE_ID_INFO remain
    // valid for the synchronous call.
    if unsafe {
        GetFileInformationByHandleEx(
            raw,
            FileIdInfo,
            (&mut extended as *mut FILE_ID_INFO).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>())
                .map_err(|_| io::Error::other("file-id structure size"))?,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(HandleIdentity {
        volume_serial: extended.VolumeSerialNumber,
        file_id_128: extended.FileId.Identifier,
        file_index_64: (u64::from(basic.nFileIndexHigh) << 32) | u64::from(basic.nFileIndexLow),
        number_of_links: basic.nNumberOfLinks,
    })
}

fn parse_directory_page(
    buffer: &[u8],
    next_ordinal: &mut usize,
) -> Result<Vec<ObservedNamespaceEntry>, DirectoryInfoError> {
    if !(buffer.as_ptr() as usize).is_multiple_of(align_of::<FILE_ID_BOTH_DIR_INFO>()) {
        return Err(DirectoryInfoError::BufferMisaligned);
    }
    let mut entries = Vec::new();
    let mut cursor = 0usize;
    loop {
        if entries.len() >= MAX_ENTRIES_PER_PAGE {
            return Err(DirectoryInfoError::EntryBoundExceeded);
        }
        let header_end = cursor
            .checked_add(FILE_NAME_OFFSET)
            .ok_or(DirectoryInfoError::TruncatedRecord)?;
        if header_end > buffer.len() {
            return Err(DirectoryInfoError::TruncatedRecord);
        }

        let next = read_u32(buffer, cursor + NEXT_ENTRY_OFFSET)? as usize;
        let file_name_bytes = read_u32(buffer, cursor + FILE_NAME_LENGTH_OFFSET)? as usize;
        if file_name_bytes == 0 || !file_name_bytes.is_multiple_of(size_of::<u16>()) {
            return Err(DirectoryInfoError::InvalidFileNameLength);
        }
        let short_name_signed = buffer[cursor + SHORT_NAME_LENGTH_OFFSET] as i8;
        if short_name_signed < 0 {
            return Err(DirectoryInfoError::InvalidShortNameLength);
        }
        let short_name_bytes = short_name_signed as usize;
        if short_name_bytes > MAX_SHORT_NAME_BYTES
            || !short_name_bytes.is_multiple_of(size_of::<u16>())
        {
            return Err(DirectoryInfoError::InvalidShortNameLength);
        }

        let name_start = cursor
            .checked_add(FILE_NAME_OFFSET)
            .ok_or(DirectoryInfoError::TruncatedRecord)?;
        let name_end = name_start
            .checked_add(file_name_bytes)
            .ok_or(DirectoryInfoError::TruncatedRecord)?;
        let short_start = cursor
            .checked_add(SHORT_NAME_OFFSET)
            .ok_or(DirectoryInfoError::TruncatedRecord)?;
        let short_end = short_start
            .checked_add(short_name_bytes)
            .ok_or(DirectoryInfoError::TruncatedRecord)?;

        let record_end = if next == 0 {
            buffer.len()
        } else {
            if next < FILE_NAME_OFFSET || !next.is_multiple_of(align_of::<FILE_ID_BOTH_DIR_INFO>())
            {
                return Err(DirectoryInfoError::InvalidNextEntryOffset);
            }
            cursor
                .checked_add(next)
                .ok_or(DirectoryInfoError::InvalidNextEntryOffset)?
        };
        if record_end > buffer.len()
            || record_end <= cursor
            || name_end > record_end
            || short_end > record_end
        {
            return Err(DirectoryInfoError::InvalidNextEntryOffset);
        }

        let long_name = read_utf16(buffer, name_start, file_name_bytes)?;
        if !is_dot_entry(&long_name) {
            let short_alias = if short_name_bytes == 0 {
                None
            } else {
                Some(read_utf16(buffer, short_start, short_name_bytes)?)
            };
            let attributes = read_u32(buffer, cursor + FILE_ATTRIBUTES_OFFSET)?;
            let file_identity = read_i64(buffer, cursor + FILE_ID_OFFSET)? as u64;
            entries.push(ObservedNamespaceEntry {
                record_ordinal: *next_ordinal,
                canonical_long_name: long_name,
                optional_short_alias: short_alias,
                file_identity,
                entry_kind: if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    EntryKind::Directory
                } else {
                    EntryKind::File
                },
            });
            *next_ordinal = next_ordinal
                .checked_add(1)
                .ok_or(DirectoryInfoError::EntryBoundExceeded)?;
        }
        if next == 0 {
            return Ok(entries);
        }
        cursor = record_end;
    }
}

fn enumerate_directory(directory: &Dir) -> Result<Vec<ObservedNamespaceEntry>, DirectoryInfoError> {
    let mut entries = Vec::new();
    let mut restart = true;
    let mut next_ordinal = 0usize;
    for _ in 0..MAX_DIRECTORY_PAGES {
        let mut words = [0u64; DIRECTORY_PAGE_WORDS];
        let bytes = words_as_bytes_mut(&mut words);
        // SAFETY: the retained directory handle and fixed, 8-byte-aligned
        // writable buffer remain live for the synchronous enumeration call.
        let succeeded = unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle() as HANDLE,
                if restart {
                    FileIdBothDirectoryRestartInfo
                } else {
                    FileIdBothDirectoryInfo
                },
                bytes.as_mut_ptr().cast(),
                u32::try_from(bytes.len()).map_err(|_| DirectoryInfoError::ApiFailed)?,
            )
        };
        if succeeded == 0 {
            // SAFETY: reads the thread-local error from the immediately
            // preceding failed enumeration call.
            return if unsafe { GetLastError() } == ERROR_NO_MORE_FILES {
                Ok(entries)
            } else {
                Err(DirectoryInfoError::ApiFailed)
            };
        }
        restart = false;
        entries.extend(parse_directory_page(bytes, &mut next_ordinal)?);
        if entries.len() > MAX_DIRECTORY_ENTRIES {
            return Err(DirectoryInfoError::EntryBoundExceeded);
        }
    }
    Err(DirectoryInfoError::PageBoundExceeded)
}

fn read_u32(buffer: &[u8], offset: usize) -> Result<u32, DirectoryInfoError> {
    let bytes = read_array::<4>(buffer, offset)?;
    Ok(u32::from_ne_bytes(bytes))
}

fn read_i64(buffer: &[u8], offset: usize) -> Result<i64, DirectoryInfoError> {
    let bytes = read_array::<8>(buffer, offset)?;
    Ok(i64::from_ne_bytes(bytes))
}

fn read_array<const N: usize>(buffer: &[u8], offset: usize) -> Result<[u8; N], DirectoryInfoError> {
    let end = offset
        .checked_add(N)
        .ok_or(DirectoryInfoError::TruncatedRecord)?;
    buffer
        .get(offset..end)
        .ok_or(DirectoryInfoError::TruncatedRecord)?
        .try_into()
        .map_err(|_| DirectoryInfoError::TruncatedRecord)
}

fn read_utf16(
    buffer: &[u8],
    offset: usize,
    byte_length: usize,
) -> Result<Vec<u16>, DirectoryInfoError> {
    let end = offset
        .checked_add(byte_length)
        .ok_or(DirectoryInfoError::TruncatedRecord)?;
    let bytes = buffer
        .get(offset..end)
        .ok_or(DirectoryInfoError::TruncatedRecord)?;
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
    // SAFETY: a mutable u64 slice is contiguous and can be viewed as the same
    // allocation's bytes for its exact initialized length.
    unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast(), length) }
}

fn wide(name: &str) -> Vec<u16> {
    OsStr::new(name).encode_wide().collect()
}

fn observed_by_long_name<'a>(
    entries: &'a [ObservedNamespaceEntry],
    name: &str,
) -> &'a ObservedNamespaceEntry {
    let expected = wide(name);
    let mut matches = entries
        .iter()
        .filter(|entry| entry.canonical_long_name == expected);
    let found = matches.next().expect("canonical fixture entry observed");
    assert!(matches.next().is_none(), "canonical entry is unique");
    found
}

fn observed_by_file_id(
    entries: &[ObservedNamespaceEntry],
    file_identity: u64,
) -> Vec<&ObservedNamespaceEntry> {
    entries
        .iter()
        .filter(|entry| entry.file_identity == file_identity)
        .collect()
}

fn create_empty_file(root: &Dir, name: &str) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    root.open_with(name, &options)
}

fn open_file_nofollow(root: &Dir, name: &OsString) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    root.open_with(Path::new(name), &options)
}

fn observe_created_handle(
    root: &Dir,
    name: &str,
    handle: &impl AsRawHandle,
    kind: EntryKind,
) -> (HandleIdentity, ObservedNamespaceEntry) {
    let identity = handle_identity(handle).expect("query created-handle identity");
    let entries = enumerate_directory(root).expect("enumerate retained fixture parent");
    let observed = observed_by_long_name(&entries, name).clone();
    assert_eq!(observed.file_identity, identity.file_index_64);
    assert_eq!(observed.entry_kind, kind);

    let canonical = OsString::from_wide(&observed.canonical_long_name);
    let reopened = match kind {
        EntryKind::File => open_file_nofollow(root, &canonical).expect("open canonical long file"),
        EntryKind::Directory => {
            let directory = root
                .open_dir_nofollow(Path::new(&canonical))
                .expect("open canonical long directory");
            let reopened_identity =
                handle_identity(&directory).expect("query canonical directory identity");
            assert_eq!(reopened_identity.file_index_64, observed.file_identity);
            return (identity, observed);
        }
    };
    let reopened_identity = handle_identity(&reopened).expect("query canonical file identity");
    assert_eq!(reopened_identity.file_index_64, observed.file_identity);
    (identity, observed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ComponentSelectionError {
    AliasOnly,
    Ambiguous,
    NotCanonical,
}

fn select_exact_canonical_component<'a>(
    supplied: &[u16],
    entries: &'a [ObservedNamespaceEntry],
) -> Result<&'a ObservedNamespaceEntry, ComponentSelectionError> {
    let long_matches = entries
        .iter()
        .filter(|entry| entry.canonical_long_name == supplied)
        .collect::<Vec<_>>();
    let alias_matches = entries
        .iter()
        .filter(|entry| entry.optional_short_alias.as_deref() == Some(supplied))
        .collect::<Vec<_>>();
    match (long_matches.as_slice(), alias_matches.as_slice()) {
        ([entry], []) => Ok(entry),
        ([], [_]) => Err(ComponentSelectionError::AliasOnly),
        ([], []) => Err(ComponentSelectionError::NotCanonical),
        _ => Err(ComponentSelectionError::Ambiguous),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SensitiveEvent {
    CreateEmpty,
    EnumerateParent,
    ValidateNamespace,
    VerifyIdentity,
    WriteSensitive,
}

fn gate_sensitive_write(
    namespace_valid: bool,
    identity_valid: bool,
    events: &mut Vec<SensitiveEvent>,
) -> Result<(), ()> {
    events.push(SensitiveEvent::CreateEmpty);
    events.push(SensitiveEvent::EnumerateParent);
    events.push(SensitiveEvent::ValidateNamespace);
    if !namespace_valid {
        return Err(());
    }
    events.push(SensitiveEvent::VerifyIdentity);
    if !identity_valid {
        return Err(());
    }
    events.push(SensitiveEvent::WriteSensitive);
    Ok(())
}

struct Fixture {
    root: PathBuf,
    temp_parent: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);

        let temp_parent = std::env::temp_dir();
        let workspace = std::env::current_dir().expect("read current directory");
        assert!(
            !temp_parent.starts_with(&workspace) && !workspace.starts_with(&temp_parent),
            "laboratory fixture must be outside the repository"
        );
        let initial = u64::from(std::process::id()) + NEXT.fetch_add(1, Ordering::Relaxed);
        let root = (0..1_024u64)
            .find_map(|attempt| {
                let value = initial.wrapping_add(attempt) & 0x00FF_FFFF;
                let candidate = temp_parent.join(format!("{FIXTURE_PREFIX}{value:06X}"));
                match fs::create_dir(&candidate) {
                    Ok(()) => Some(candidate),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                    Err(_) => panic!("create synthetic alias fixture"),
                }
            })
            .expect("bounded synthetic fixture-name space");
        Self { root, temp_parent }
    }

    fn open(&self) -> Dir {
        Dir::open_ambient_dir(&self.root, cap_std::ambient_authority())
            .expect("open retained synthetic alias fixture")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let safe_name = self
            .root
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| {
                name.len() == 8
                    && name.starts_with(FIXTURE_PREFIX)
                    && name[FIXTURE_PREFIX.len()..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
            });
        if self.root.parent() == Some(self.temp_parent.as_path()) && safe_name {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn model_entry(
    record_ordinal: usize,
    long: &str,
    short: Option<&str>,
    file_identity: u64,
) -> ObservedNamespaceEntry {
    ObservedNamespaceEntry {
        record_ordinal,
        canonical_long_name: wide(long),
        optional_short_alias: short.map(wide),
        file_identity,
        entry_kind: EntryKind::File,
    }
}

#[test]
fn alias_namespace_exact_binding_layout_is_fixed() {
    assert_eq!(size_of::<FILE_ID_BOTH_DIR_INFO>(), 112);
    assert_eq!(align_of::<FILE_ID_BOTH_DIR_INFO>(), 8);
    assert_eq!(FILE_ATTRIBUTES_OFFSET, 56);
    assert_eq!(FILE_NAME_LENGTH_OFFSET, 60);
    assert_eq!(SHORT_NAME_LENGTH_OFFSET, 68);
    assert_eq!(SHORT_NAME_OFFSET, 70);
    assert_eq!(FILE_ID_OFFSET, 96);
    assert_eq!(FILE_NAME_OFFSET, 104);
    assert_eq!(size_of::<FILE_CASE_SENSITIVE_INFO>(), 4);
    assert_eq!(size_of::<FILE_ID_INFO>(), 24);
    assert_eq!(size_of::<BY_HANDLE_FILE_INFORMATION>(), 52);
    assert_eq!(size_of::<PersistentVolumeInformation>(), 16);
}

#[test]
fn alias_namespace_collision_matrix_distinguishes_aliases_and_hard_links() {
    let cases = [
        (
            model_entry(0, "ALPHA.TXT", None, 10),
            model_entry(1, "alpha.txt", None, 11),
        ),
        (
            model_entry(0, "ALPHA.TXT", None, 10),
            model_entry(1, "BETA-LONG.TXT", Some("alpha.txt"), 11),
        ),
        (
            model_entry(0, "ALPHA-LONG.TXT", Some("beta.txt"), 10),
            model_entry(1, "BETA.TXT", None, 11),
        ),
        (
            model_entry(0, "ALPHA-LONG.TXT", Some("same.txt"), 10),
            model_entry(1, "BETA-LONG.TXT", Some("SAME.TXT"), 11),
        ),
    ];
    for (first, second) in cases {
        let mut index = NamespaceIndex::default();
        index.insert(&first).expect("first namespace owner");
        assert_eq!(
            index.insert(&second),
            Err(NamespaceError::DifferentIdentityCollision)
        );
    }

    let mut one_record = NamespaceIndex::default();
    one_record
        .insert(&model_entry(0, "SAME.TXT", Some("same.txt"), 10))
        .expect("same-record alias equivalence is one logical entry");

    let mut hard_link_shape = NamespaceIndex::default();
    hard_link_shape
        .insert(&model_entry(0, "LINK-A.TXT", Some("shared.txt"), 10))
        .expect("first hard-link record");
    assert_eq!(
        hard_link_shape.insert(&model_entry(1, "LINK-B.TXT", Some("SHARED.TXT"), 10)),
        Err(NamespaceError::MultipleRecordsForIdentity)
    );
}

#[test]
fn alias_namespace_component_selection_and_protected_names_fail_closed() {
    let entries = [model_entry(
        0,
        "CanonicalLongName.txt",
        Some("CANONI~1.TXT"),
        10,
    )];
    assert!(select_exact_canonical_component(&wide("CanonicalLongName.txt"), &entries).is_ok());
    assert_eq!(
        select_exact_canonical_component(&wide("CANONI~1.TXT"), &entries),
        Err(ComponentSelectionError::AliasOnly)
    );
    assert_eq!(
        select_exact_canonical_component(&wide("canonicallongname.TXT"), &entries),
        Err(ComponentSelectionError::NotCanonical)
    );

    let protected = [".git", ".safeclone-staging-v1", "session.lock"];
    let mut clean = NamespaceIndex::default();
    clean
        .insert(&model_entry(
            0,
            "ordinary-long-name.txt",
            Some("ORDINA~1.TXT"),
            10,
        ))
        .expect("clean namespace entry");
    assert!(clean.reject_protected(&protected).is_ok());

    let mut alias_collision = NamespaceIndex::default();
    alias_collision
        .insert(&model_entry(
            0,
            "ordinary-long-name.txt",
            Some("SESSION.LOCK"),
            10,
        ))
        .expect("one namespace owner");
    assert_eq!(
        alias_collision.reject_protected(&protected),
        Err(NamespaceError::ProtectedNameCollision)
    );
}

#[test]
fn alias_namespace_sensitive_write_gate_has_no_prevalidation_write() {
    let mut success = Vec::new();
    assert!(gate_sensitive_write(true, true, &mut success).is_ok());
    assert_eq!(
        success,
        [
            SensitiveEvent::CreateEmpty,
            SensitiveEvent::EnumerateParent,
            SensitiveEvent::ValidateNamespace,
            SensitiveEvent::VerifyIdentity,
            SensitiveEvent::WriteSensitive,
        ]
    );

    for (namespace_valid, identity_valid) in [(false, true), (true, false)] {
        let mut rejected = Vec::new();
        assert!(gate_sensitive_write(namespace_valid, identity_valid, &mut rejected).is_err());
        assert!(!rejected.contains(&SensitiveEvent::WriteSensitive));
    }
}

#[test]
fn alias_namespace_actual_enabled_ntfs_alias_lifecycle_is_identity_bound() {
    let fixture = Fixture::new();
    let root = fixture.open();
    let first_state = query_short_name_creation_disabled(&root)
        .expect("query first retained persistent-volume state");
    let second_state = query_short_name_creation_disabled(&root)
        .expect("query second retained persistent-volume state");
    assert_eq!(first_state, second_state);
    let case_sensitive = query_case_sensitive(&root).expect("query retained directory case mode");
    assert!(
        !case_sensitive,
        "laboratory requires default case-insensitive NTFS"
    );

    let compatible_name = "A83.TXT";
    let compatible = create_empty_file(&root, compatible_name).expect("create compatible file");
    let (compatible_identity, compatible_entry) =
        observe_created_handle(&root, compatible_name, &compatible, EntryKind::File);

    let long_name = "AliasLifecycleLongFileName.txt";
    let long = create_empty_file(&root, long_name).expect("create long file");
    let (long_identity, long_entry) =
        observe_created_handle(&root, long_name, &long, EntryKind::File);

    let similar_names = [
        "AliasCollisionPrefixAlphaLongName.txt",
        "AliasCollisionPrefixBetaLongName.txt",
        "AliasCollisionPrefixGammaLongName.txt",
    ];
    let mut similar_aliases = 0usize;
    for name in similar_names {
        let handle = create_empty_file(&root, name).expect("create similar-prefix file");
        let (_, entry) = observe_created_handle(&root, name, &handle, EntryKind::File);
        similar_aliases += usize::from(entry.optional_short_alias.is_some());
    }

    let directory_name = "AliasLifecycleLongDirectoryName";
    root.create_dir(directory_name)
        .expect("create long directory");
    let directory = root
        .open_dir_nofollow(directory_name)
        .expect("retain long directory");
    let (_, directory_entry) =
        observe_created_handle(&root, directory_name, &directory, EntryKind::Directory);
    let nested_name = "NestedLongFileNameForAlias.txt";
    let nested = create_empty_file(&directory, nested_name).expect("create nested long file");
    let (_, nested_entry) =
        observe_created_handle(&directory, nested_name, &nested, EntryKind::File);

    let compatible_rename_source = "R8A.TXT";
    let compatible_rename_target = "RenamedFromCompatibleLongFileName.txt";
    let compatible_rename =
        create_empty_file(&root, compatible_rename_source).expect("create compatible rename file");
    let rename_compatible_before = observe_created_handle(
        &root,
        compatible_rename_source,
        &compatible_rename,
        EntryKind::File,
    );
    root.rename(compatible_rename_source, &root, compatible_rename_target)
        .expect("rename compatible file to long name");
    let compatible_rename_after_identity =
        handle_identity(&compatible_rename).expect("identity after compatible-to-long rename");
    let compatible_rename_entries =
        enumerate_directory(&root).expect("enumerate compatible-to-long rename result");
    let compatible_rename_after =
        observed_by_long_name(&compatible_rename_entries, compatible_rename_target);
    assert_eq!(
        rename_compatible_before.0.file_id_128,
        compatible_rename_after_identity.file_id_128
    );
    assert_eq!(
        compatible_rename_after.file_identity,
        compatible_rename_after_identity.file_index_64
    );

    let long_rename_source = "RenameLongSourceFileName.txt";
    let long_rename_target = "RenameLongDestinationFileName.txt";
    let long_rename =
        create_empty_file(&root, long_rename_source).expect("create long rename file");
    let long_rename_before =
        observe_created_handle(&root, long_rename_source, &long_rename, EntryKind::File);
    root.rename(long_rename_source, &root, long_rename_target)
        .expect("rename long file to another long name");
    let long_rename_after_identity =
        handle_identity(&long_rename).expect("identity after long-to-long rename");
    let long_rename_entries =
        enumerate_directory(&root).expect("enumerate long-to-long rename result");
    let long_rename_after = observed_by_long_name(&long_rename_entries, long_rename_target);
    assert_eq!(
        long_rename_before.0.file_id_128,
        long_rename_after_identity.file_id_128
    );
    assert_eq!(
        long_rename_after.file_identity,
        long_rename_after_identity.file_index_64
    );
    let long_rename_alias_changed =
        long_rename_before.1.optional_short_alias != long_rename_after.optional_short_alias;

    let recreate_name = "DeleteAndRecreateLongFileName.txt";
    let first_recreate =
        create_empty_file(&root, recreate_name).expect("create first lifecycle file");
    let first_recreate_identity =
        observe_created_handle(&root, recreate_name, &first_recreate, EntryKind::File).0;
    drop(first_recreate);
    root.remove_file(recreate_name)
        .expect("delete first lifecycle file");
    let second_recreate = create_empty_file(&root, recreate_name).expect("recreate lifecycle file");
    let second_recreate_identity =
        observe_created_handle(&root, recreate_name, &second_recreate, EntryKind::File).0;
    let recreate_identity_changed =
        first_recreate_identity.file_id_128 != second_recreate_identity.file_id_128;

    let case_name = "CaseVariantLongFileName.txt";
    let case_file = create_empty_file(&root, case_name).expect("create case fixture");
    let (_, case_entry) = observe_created_handle(&root, case_name, &case_file, EntryKind::File);
    let case_variant_rejected = create_empty_file(&root, "casevariantlongfilename.TXT").is_err();
    assert!(case_variant_rejected);

    let hard_link_source_name = "HardLinkSourceLongFileName.txt";
    let hard_link_name = "HardLinkSecondLongFileName.txt";
    let hard_link_source =
        create_empty_file(&root, hard_link_source_name).expect("create hard-link source");
    let hard_link_before = observe_created_handle(
        &root,
        hard_link_source_name,
        &hard_link_source,
        EntryKind::File,
    );
    assert_eq!(hard_link_before.0.number_of_links, 1);
    root.hard_link(hard_link_source_name, &root, hard_link_name)
        .expect("create distinct hard link");
    let hard_link_after_identity =
        handle_identity(&hard_link_source).expect("identity after hard-link creation");
    let hard_link_entries = enumerate_directory(&root).expect("enumerate hard-link records");
    let same_id_records =
        observed_by_file_id(&hard_link_entries, hard_link_after_identity.file_index_64);
    assert_eq!(hard_link_after_identity.number_of_links, 2);
    assert_eq!(same_id_records.len(), 2);
    assert!(same_id_records
        .iter()
        .any(|entry| entry.canonical_long_name == wide(hard_link_source_name)));
    assert!(same_id_records
        .iter()
        .any(|entry| entry.canonical_long_name == wide(hard_link_name)));

    let final_entries = enumerate_directory(&root).expect("final retained-parent enumeration");
    let alias_records = final_entries
        .iter()
        .filter(|entry| entry.optional_short_alias.is_some())
        .count();
    let unique_aliases = final_entries
        .iter()
        .filter_map(|entry| entry.optional_short_alias.as_ref())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    assert_eq!(alias_records, unique_aliases);
    assert_eq!(compatible_identity.number_of_links, 1);
    assert_eq!(long_identity.number_of_links, 1);

    println!(
        "ALIAS_NAMESPACE_VOLUME query_1={} query_2={} case_sensitive={case_sensitive}",
        if first_state { "DISABLED" } else { "ENABLED" },
        if second_state { "DISABLED" } else { "ENABLED" },
    );
    println!(
        "ALIAS_NAMESPACE_CREATE compatible_alias={} long_alias={} similar_aliases={similar_aliases} directory_alias={} nested_alias={} total_alias_records={alias_records}",
        compatible_entry.optional_short_alias.is_some(),
        long_entry.optional_short_alias.is_some(),
        directory_entry.optional_short_alias.is_some(),
        nested_entry.optional_short_alias.is_some(),
    );
    println!(
        "ALIAS_NAMESPACE_RENAME compatible_before_alias={} compatible_after_alias={} compatible_identity_stable={} long_before_alias={} long_after_alias={} long_alias_changed={long_rename_alias_changed} long_identity_stable=true",
        rename_compatible_before.1.optional_short_alias.is_some(),
        compatible_rename_after.optional_short_alias.is_some(),
        rename_compatible_before.0.file_id_128 == compatible_rename_after_identity.file_id_128,
        long_rename_before.1.optional_short_alias.is_some(),
        long_rename_after.optional_short_alias.is_some(),
    );
    println!(
        "ALIAS_NAMESPACE_IDENTITY delete_recreate_changed={recreate_identity_changed} case_variant_rejected={case_variant_rejected} case_canonical_preserved={} alias_records_unique={} alias_nlink={} hard_link_nlink={} hard_link_records={}",
        case_entry.canonical_long_name == wide(case_name),
        alias_records == unique_aliases,
        long_identity.number_of_links,
        hard_link_after_identity.number_of_links,
        same_id_records.len(),
    );
}
