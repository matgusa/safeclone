//! Read-only Windows short-name policy regression tests.
//!
//! This module is compiled only for crate tests. It deliberately exposes no
//! production runtime surface and contains no generic control-code adapter.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::fs;
use std::mem::{align_of, offset_of, size_of};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use cap_fs_ext::DirExt;
use cap_std::fs::Dir;
use windows_sys::Wdk::Storage::FileSystem::{
    FileAccessInformation, NtFsControlFile, NtQueryInformationFile, FILE_ACCESS_INFORMATION,
};
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_NO_MORE_FILES, HANDLE, NTSTATUS, STATUS_ACCESS_DENIED,
    STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_PENDING, STATUS_SUCCESS,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo, GetFileInformationByHandleEx, DELETE,
    FILE_APPEND_DATA, FILE_ID_BOTH_DIR_INFO, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
    WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::{
    classify_source_path, select_local_volume, StandardAbsoluteResolver, WindowsNamespace,
};
use crate::fs_boundary::{self, FilesystemIdentity, TrustedVolumePath};

// Exact windows-sys 0.61.2 Win32_System_Ioctl values. That one feature is not
// enabled by the current manifest, so this test module mirrors only the missing generated
// ABI values under cfg(test). NtFsControlFile itself remains the generated WDK
// binding from the current feature set.
const FSCTL_QUERY_PERSISTENT_VOLUME_STATE: u32 = 590_396;
const PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED: u32 = 0x0000_0001;
const PERSISTENT_VOLUME_INFORMATION_VERSION: u32 = 1;

const DIRECTORY_PAGE_BYTES: usize = 4_096;
const DIRECTORY_PAGE_WORDS: usize = DIRECTORY_PAGE_BYTES / size_of::<u64>();
const MAX_DIRECTORY_PAGES: usize = 256;
const MAX_DIRECTORY_ENTRIES: usize = 100_000;
const MAX_ENTRIES_PER_PAGE: usize = 256;
const MAX_SHORT_NAME_BYTES: usize = 12 * size_of::<u16>();
const FIXTURE_PREFIX: &str = "S2";

const NEXT_ENTRY_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, NextEntryOffset);
const FILE_NAME_LENGTH_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, FileNameLength);
const SHORT_NAME_LENGTH_OFFSET: usize = offset_of!(FILE_ID_BOTH_DIR_INFO, ShortNameLength);
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
enum QueryCallError {
    AccessDenied,
    Unsupported,
    InvalidVolumeAuthority,
    IncompleteCompletion,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QualificationError {
    UnsupportedShortNameState,
    PersistentVolumeQueryFailed,
    PersistentVolumeStateAmbiguous,
}

impl fmt::Display for QualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedShortNameState => "short-name state is unsupported",
            Self::PersistentVolumeQueryFailed => "persistent-volume query failed",
            Self::PersistentVolumeStateAmbiguous => "persistent-volume state is ambiguous",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QueryObservation {
    request: PersistentVolumeInformation,
    output: PersistentVolumeInformation,
    information_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QualifiedPersistentState {
    version: u32,
    required_mask: u32,
    short_name_creation_disabled: bool,
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ParsedDirectoryPage {
    entries: usize,
    dot_entries: usize,
    short_name_aliases: usize,
    logical_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DirectoryEnumeration {
    pages: usize,
    entries: usize,
    dot_entries: usize,
    short_name_aliases: usize,
    logical_bytes: usize,
}

impl DirectoryEnumeration {
    fn user_entries(self) -> usize {
        self.entries - self.dot_entries
    }
}

trait QualificationIo {
    type Identity: Copy + Eq;

    fn identity(&mut self) -> Result<Self::Identity, QualificationError>;
    fn query(&mut self) -> Result<QueryObservation, QueryCallError>;
}

fn persistent_volume_query_input() -> PersistentVolumeInformation {
    PersistentVolumeInformation {
        volume_flags: 0,
        flag_mask: PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED,
        version: PERSISTENT_VOLUME_INFORMATION_VERSION,
        reserved: 0,
    }
}

fn classify_query_observation(
    observation: QueryObservation,
) -> Result<QualifiedPersistentState, QualificationError> {
    let qualified = decode_query_observation(observation)?;
    if qualified.short_name_creation_disabled {
        Ok(qualified)
    } else {
        Err(QualificationError::UnsupportedShortNameState)
    }
}

fn decode_query_observation(
    observation: QueryObservation,
) -> Result<QualifiedPersistentState, QualificationError> {
    let request = observation.request;
    if observation.information_bytes != size_of::<PersistentVolumeInformation>()
        || request.volume_flags != 0
        || request.version != PERSISTENT_VOLUME_INFORMATION_VERSION
        || request.reserved != 0
        || request.flag_mask != PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED
    {
        return Err(QualificationError::PersistentVolumeStateAmbiguous);
    }
    Ok(QualifiedPersistentState {
        version: request.version,
        required_mask: request.flag_mask,
        short_name_creation_disabled: observation.output.volume_flags
            & PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED
            == PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED,
    })
}

fn map_query_error(error: QueryCallError) -> QualificationError {
    match error {
        QueryCallError::IncompleteCompletion => QualificationError::PersistentVolumeStateAmbiguous,
        QueryCallError::AccessDenied
        | QueryCallError::Unsupported
        | QueryCallError::InvalidVolumeAuthority
        | QueryCallError::Failed => QualificationError::PersistentVolumeQueryFailed,
    }
}

fn qualify_twice_before_component_open<I, P, O>(
    io: &mut I,
    expected_identity: I::Identity,
    prepare_namespace: P,
    open_first_component: O,
) -> Result<QualifiedPersistentState, QualificationError>
where
    I: QualificationIo,
    P: FnOnce() -> Result<(), QualificationError>,
    O: FnOnce() -> Result<(), QualificationError>,
{
    require_identity(io, expected_identity)?;
    let first = decode_query_observation(io.query().map_err(map_query_error)?)?;
    if !first.short_name_creation_disabled {
        return Err(QualificationError::UnsupportedShortNameState);
    }
    require_identity(io, expected_identity)?;

    prepare_namespace()?;

    require_identity(io, expected_identity)?;
    let second = decode_query_observation(io.query().map_err(map_query_error)?)?;
    require_identity(io, expected_identity)?;
    if first != second {
        return Err(QualificationError::PersistentVolumeStateAmbiguous);
    }
    if !second.short_name_creation_disabled {
        return Err(QualificationError::UnsupportedShortNameState);
    }

    open_first_component()?;
    Ok(second)
}

fn require_identity<I: QualificationIo>(
    io: &mut I,
    expected: I::Identity,
) -> Result<(), QualificationError> {
    if io.identity()? == expected {
        Ok(())
    } else {
        Err(QualificationError::PersistentVolumeStateAmbiguous)
    }
}

fn query_short_name_creation_state(directory: &Dir) -> Result<QueryObservation, QueryCallError> {
    let input = persistent_volume_query_input();
    let mut output = PersistentVolumeInformation::default();
    let mut io_status = IO_STATUS_BLOCK::default();
    let structure_bytes = u32::try_from(size_of::<PersistentVolumeInformation>())
        .map_err(|_| QueryCallError::Failed)?;

    // SAFETY: `directory` is a live retained synchronous handle. The closed
    // query supplies no event, APC, or context. Input/output and IO status are
    // exact-size writable ABI values for the one read-only control code.
    let status = unsafe {
        NtFsControlFile(
            directory.as_raw_handle() as HANDLE,
            ptr::null_mut(),
            None,
            ptr::null(),
            &mut io_status,
            FSCTL_QUERY_PERSISTENT_VOLUME_STATE,
            (&input as *const PersistentVolumeInformation).cast(),
            structure_bytes,
            (&mut output as *mut PersistentVolumeInformation).cast(),
            structure_bytes,
        )
    };
    require_success_status(status)?;
    // SAFETY: IO_STATUS_BLOCK was initialized and the synchronous call
    // returned success, so the status union contains its completion status.
    require_success_status(unsafe { io_status.Anonymous.Status })?;
    if io_status.Information != size_of::<PersistentVolumeInformation>() {
        return Err(QueryCallError::IncompleteCompletion);
    }
    Ok(QueryObservation {
        request: input,
        output,
        information_bytes: io_status.Information,
    })
}

fn require_success_status(status: NTSTATUS) -> Result<(), QueryCallError> {
    match status {
        STATUS_SUCCESS => Ok(()),
        STATUS_ACCESS_DENIED => Err(QueryCallError::AccessDenied),
        STATUS_NOT_SUPPORTED => Err(QueryCallError::Unsupported),
        STATUS_INVALID_PARAMETER => Err(QueryCallError::InvalidVolumeAuthority),
        STATUS_PENDING => Err(QueryCallError::IncompleteCompletion),
        _ => Err(QueryCallError::Failed),
    }
}

fn query_granted_access(directory: &Dir) -> Result<u32, QueryCallError> {
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut access = FILE_ACCESS_INFORMATION::default();
    // SAFETY: the retained directory handle is live and both output values are
    // correctly sized for FileAccessInformation.
    let status = unsafe {
        NtQueryInformationFile(
            directory.as_raw_handle() as HANDLE,
            &mut io_status,
            (&mut access as *mut FILE_ACCESS_INFORMATION).cast(),
            u32::try_from(size_of::<FILE_ACCESS_INFORMATION>())
                .map_err(|_| QueryCallError::Failed)?,
            FileAccessInformation,
        )
    };
    require_success_status(status)?;
    // SAFETY: the synchronous query completed, so the status union contains
    // the final completion status.
    require_success_status(unsafe { io_status.Anonymous.Status })?;
    if io_status.Information != size_of::<FILE_ACCESS_INFORMATION>() {
        return Err(QueryCallError::IncompleteCompletion);
    }
    Ok(access.AccessFlags)
}

fn parse_directory_page(buffer: &[u8]) -> Result<ParsedDirectoryPage, DirectoryInfoError> {
    if !(buffer.as_ptr() as usize).is_multiple_of(align_of::<FILE_ID_BOTH_DIR_INFO>()) {
        return Err(DirectoryInfoError::BufferMisaligned);
    }

    let mut parsed = ParsedDirectoryPage::default();
    let mut cursor = 0usize;
    loop {
        if parsed.entries >= MAX_ENTRIES_PER_PAGE {
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
        if name_end > buffer.len() {
            return Err(DirectoryInfoError::TruncatedRecord);
        }

        let record_end = if next == 0 {
            buffer.len()
        } else {
            if !next.is_multiple_of(align_of::<FILE_ID_BOTH_DIR_INFO>()) || next < FILE_NAME_OFFSET
            {
                return Err(DirectoryInfoError::InvalidNextEntryOffset);
            }
            cursor
                .checked_add(next)
                .ok_or(DirectoryInfoError::InvalidNextEntryOffset)?
        };
        if record_end > buffer.len() || name_end > record_end || record_end <= cursor {
            return Err(DirectoryInfoError::InvalidNextEntryOffset);
        }

        parsed.entries += 1;
        parsed.dot_entries += usize::from(is_dot_entry(&buffer[name_start..name_end]));
        parsed.short_name_aliases += usize::from(short_name_bytes != 0);
        if next == 0 {
            parsed.logical_bytes = name_end;
            return Ok(parsed);
        }
        cursor = record_end;
    }
}

fn read_u32(buffer: &[u8], offset: usize) -> Result<u32, DirectoryInfoError> {
    let end = offset
        .checked_add(size_of::<u32>())
        .ok_or(DirectoryInfoError::TruncatedRecord)?;
    let bytes: [u8; size_of::<u32>()] = buffer
        .get(offset..end)
        .ok_or(DirectoryInfoError::TruncatedRecord)?
        .try_into()
        .map_err(|_| DirectoryInfoError::TruncatedRecord)?;
    Ok(u32::from_ne_bytes(bytes))
}

fn is_dot_entry(name: &[u8]) -> bool {
    let dot = u16::from(b'.').to_ne_bytes();
    name == dot || name == [dot, dot].concat()
}

fn enumerate_directory_short_names(
    directory: &Dir,
) -> Result<DirectoryEnumeration, DirectoryInfoError> {
    let mut result = DirectoryEnumeration::default();
    let mut restart = true;
    for _ in 0..MAX_DIRECTORY_PAGES {
        let mut words = [0u64; DIRECTORY_PAGE_WORDS];
        let bytes = words_as_bytes_mut(&mut words);
        let information_class = if restart {
            FileIdBothDirectoryRestartInfo
        } else {
            FileIdBothDirectoryInfo
        };
        // SAFETY: the retained directory handle is live and `bytes` is a
        // fixed, 8-byte-aligned writable buffer of the exact supplied size.
        let succeeded = unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle() as HANDLE,
                information_class,
                bytes.as_mut_ptr().cast(),
                u32::try_from(bytes.len()).map_err(|_| DirectoryInfoError::ApiFailed)?,
            )
        };
        if succeeded == 0 {
            // SAFETY: this reads the thread-local status of the immediately
            // preceding failed enumeration call.
            return if unsafe { GetLastError() } == ERROR_NO_MORE_FILES {
                Ok(result)
            } else {
                Err(DirectoryInfoError::ApiFailed)
            };
        }

        restart = false;
        let page = parse_directory_page(bytes)?;
        result.pages = result
            .pages
            .checked_add(1)
            .ok_or(DirectoryInfoError::PageBoundExceeded)?;
        result.entries = result
            .entries
            .checked_add(page.entries)
            .ok_or(DirectoryInfoError::EntryBoundExceeded)?;
        result.dot_entries = result
            .dot_entries
            .checked_add(page.dot_entries)
            .ok_or(DirectoryInfoError::EntryBoundExceeded)?;
        result.short_name_aliases = result
            .short_name_aliases
            .checked_add(page.short_name_aliases)
            .ok_or(DirectoryInfoError::EntryBoundExceeded)?;
        result.logical_bytes = result
            .logical_bytes
            .checked_add(page.logical_bytes)
            .ok_or(DirectoryInfoError::EntryBoundExceeded)?;
        if result.entries > MAX_DIRECTORY_ENTRIES {
            return Err(DirectoryInfoError::EntryBoundExceeded);
        }
    }
    Err(DirectoryInfoError::PageBoundExceeded)
}

fn words_as_bytes_mut(words: &mut [u64]) -> &mut [u8] {
    let length = std::mem::size_of_val(words);
    // SAFETY: a mutable u64 slice is contiguous and may be viewed as the same
    // initialized allocation's bytes for its exact byte length.
    unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast(), length) }
}

fn words_as_bytes(words: &[u64], length: usize) -> &[u8] {
    assert!(length <= std::mem::size_of_val(words));
    // SAFETY: an immutable u64 slice is contiguous and the requested prefix is
    // within its initialized allocation.
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), length) }
}

struct SyntheticDirectoryPage {
    words: Vec<u64>,
    logical_length: usize,
}

impl SyntheticDirectoryPage {
    fn bytes(&self) -> &[u8] {
        words_as_bytes(&self.words, self.logical_length)
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        let length = self.logical_length;
        &mut words_as_bytes_mut(&mut self.words)[..length]
    }
}

fn synthetic_directory_page(names: &[&[u16]], short_name_bytes: &[u8]) -> SyntheticDirectoryPage {
    assert_eq!(names.len(), short_name_bytes.len());
    let mut offsets = Vec::with_capacity(names.len());
    let mut cursor = 0usize;
    for (index, name) in names.iter().enumerate() {
        let raw_end = cursor + FILE_NAME_OFFSET + std::mem::size_of_val(*name);
        let end = if index + 1 == names.len() {
            raw_end
        } else {
            align_up(raw_end, align_of::<FILE_ID_BOTH_DIR_INFO>())
        };
        offsets.push((cursor, raw_end, end));
        cursor = end;
    }
    let word_count = cursor.div_ceil(size_of::<u64>());
    let mut page = SyntheticDirectoryPage {
        words: vec![0u64; word_count],
        logical_length: cursor,
    };
    for (index, name) in names.iter().enumerate() {
        let (offset, raw_end, end) = offsets[index];
        let next = if index + 1 == names.len() {
            0
        } else {
            end - offset
        };
        write_u32(page.bytes_mut(), offset + NEXT_ENTRY_OFFSET, next as u32);
        write_u32(
            page.bytes_mut(),
            offset + FILE_NAME_LENGTH_OFFSET,
            u32::try_from(std::mem::size_of_val(*name)).expect("bounded synthetic name"),
        );
        page.bytes_mut()[offset + SHORT_NAME_LENGTH_OFFSET] = short_name_bytes[index];
        let name_start = offset + FILE_NAME_OFFSET;
        let name_bytes = unsafe {
            std::slice::from_raw_parts(name.as_ptr().cast::<u8>(), std::mem::size_of_val(*name))
        };
        page.bytes_mut()[name_start..raw_end].copy_from_slice(name_bytes);
    }
    page
}

fn align_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

fn write_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_ne_bytes());
}

struct Fixture {
    root: PathBuf,
    temp_parent: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);

        assert!(label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'));
        let temp_parent = std::env::temp_dir();
        let workspace = std::env::current_dir().expect("read current directory");
        assert!(
            !temp_parent.starts_with(&workspace) && !workspace.starts_with(&temp_parent),
            "native fixture must be outside the repository"
        );
        let initial = u64::from(std::process::id()) + NEXT.fetch_add(1, Ordering::Relaxed);
        let root = (0..1_024u64)
            .find_map(|attempt| {
                let value = initial.wrapping_add(attempt) & 0x00FF_FFFF;
                let candidate = temp_parent.join(format!("{FIXTURE_PREFIX}{value:06X}"));
                match fs::create_dir(&candidate) {
                    Ok(()) => Some(candidate),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(_) => panic!("create synthetic native fixture"),
                }
            })
            .expect("bounded synthetic fixture-name space");
        Self { root, temp_parent }
    }

    fn open(&self) -> Dir {
        Dir::open_ambient_dir(&self.root, cap_std::ambient_authority())
            .expect("open retained synthetic fixture")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let safe_name = self
            .root
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
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

struct RetainedVolumeIo<'a> {
    directory: &'a Dir,
}

impl QualificationIo for RetainedVolumeIo<'_> {
    type Identity = FilesystemIdentity;

    fn identity(&mut self) -> Result<Self::Identity, QualificationError> {
        fs_boundary::directory_identity(self.directory)
            .map_err(|_| QualificationError::PersistentVolumeStateAmbiguous)
    }

    fn query(&mut self) -> Result<QueryObservation, QueryCallError> {
        query_short_name_creation_state(self.directory)
    }
}

fn open_retained_fixture_volume(
    fixture_path: &Path,
) -> (Dir, Vec<std::ffi::OsString>, FilesystemIdentity) {
    let classified = classify_source_path(fixture_path, &StandardAbsoluteResolver)
        .expect("classify synthetic local fixture");
    let anchor =
        select_local_volume(classified.drive, &WindowsNamespace).expect("select local volume");
    let volume_root = TrustedVolumePath::new(anchor, Vec::new()).expect("build trusted root path");
    let opened = fs_boundary::open_trusted_volume_dir_nofollow(&volume_root)
        .expect("open retained trusted volume root");
    let identity = fs_boundary::directory_identity(&opened.directory)
        .expect("query retained volume-root identity");
    (opened.directory, classified.components, identity)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LabEvent {
    Identity,
    Query,
    NamespacePreparation,
    ComponentOpen,
}

struct MockQualificationIo {
    identities: RefCell<Vec<usize>>,
    queries: RefCell<Vec<Result<QueryObservation, QueryCallError>>>,
    events: Rc<RefCell<Vec<LabEvent>>>,
}

impl MockQualificationIo {
    fn new(
        identities: impl IntoIterator<Item = usize>,
        queries: impl IntoIterator<Item = Result<QueryObservation, QueryCallError>>,
    ) -> Self {
        Self {
            identities: RefCell::new(identities.into_iter().collect()),
            queries: RefCell::new(queries.into_iter().collect()),
            events: Rc::new(RefCell::new(Vec::new())),
        }
    }
}

impl QualificationIo for MockQualificationIo {
    type Identity = usize;

    fn identity(&mut self) -> Result<Self::Identity, QualificationError> {
        self.events.borrow_mut().push(LabEvent::Identity);
        if self.identities.borrow().is_empty() {
            return Err(QualificationError::PersistentVolumeStateAmbiguous);
        }
        Ok(self.identities.borrow_mut().remove(0))
    }

    fn query(&mut self) -> Result<QueryObservation, QueryCallError> {
        self.events.borrow_mut().push(LabEvent::Query);
        if self.queries.borrow().is_empty() {
            return Err(QueryCallError::Failed);
        }
        self.queries.borrow_mut().remove(0)
    }
}

fn observation(volume_flags: u32, flag_mask: u32, version: u32, reserved: u32) -> QueryObservation {
    QueryObservation {
        request: PersistentVolumeInformation {
            volume_flags: 0,
            flag_mask,
            version,
            reserved,
        },
        output: PersistentVolumeInformation {
            volume_flags,
            ..PersistentVolumeInformation::default()
        },
        information_bytes: size_of::<PersistentVolumeInformation>(),
    }
}

fn disabled_observation() -> QueryObservation {
    observation(
        PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED,
        PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED,
        PERSISTENT_VOLUME_INFORMATION_VERSION,
        0,
    )
}

fn query_label(result: &Result<QueryObservation, QueryCallError>) -> &'static str {
    match result {
        Ok(observation) => match classify_query_observation(*observation) {
            Ok(_) => "DISABLED",
            Err(QualificationError::UnsupportedShortNameState) => "ENABLED",
            Err(QualificationError::PersistentVolumeStateAmbiguous) => "AMBIGUOUS",
            Err(QualificationError::PersistentVolumeQueryFailed) => "FAILED",
        },
        Err(QueryCallError::AccessDenied) => "ACCESS_DENIED",
        Err(QueryCallError::Unsupported) => "UNSUPPORTED",
        Err(QueryCallError::InvalidVolumeAuthority) => "INVALID_VOLUME_AUTHORITY",
        Err(QueryCallError::IncompleteCompletion) => "INCOMPLETE_COMPLETION",
        Err(QueryCallError::Failed) => "FAILED",
    }
}

#[test]
fn volume_policy_binding_layout_and_closed_query_input_are_exact() {
    assert_eq!(FSCTL_QUERY_PERSISTENT_VOLUME_STATE, 0x0009_023C);
    assert_eq!(size_of::<PersistentVolumeInformation>(), 16);
    assert_eq!(align_of::<PersistentVolumeInformation>(), 4);
    assert_eq!(offset_of!(PersistentVolumeInformation, volume_flags), 0);
    assert_eq!(offset_of!(PersistentVolumeInformation, flag_mask), 4);
    assert_eq!(offset_of!(PersistentVolumeInformation, version), 8);
    assert_eq!(offset_of!(PersistentVolumeInformation, reserved), 12);
    assert_eq!(
        persistent_volume_query_input(),
        observation(0, 1, 1, 0).request
    );

    assert_eq!(size_of::<IO_STATUS_BLOCK>(), 16);
    assert_eq!(align_of::<IO_STATUS_BLOCK>(), 8);
    assert_eq!(size_of::<FILE_ID_BOTH_DIR_INFO>(), 112);
    assert_eq!(align_of::<FILE_ID_BOTH_DIR_INFO>(), 8);
    assert_eq!(FILE_NAME_LENGTH_OFFSET, 60);
    assert_eq!(SHORT_NAME_LENGTH_OFFSET, 68);
    assert_eq!(FILE_NAME_OFFSET, 104);
}

#[test]
fn volume_policy_persistent_state_matrix_fails_closed() {
    assert!(classify_query_observation(disabled_observation()).is_ok());
    assert_eq!(
        classify_query_observation(observation(0, 1, 1, 0)),
        Err(QualificationError::UnsupportedShortNameState)
    );
    for malformed in [
        observation(1, 1, 2, 0),
        observation(1, 1, 1, 1),
        observation(1, 0, 1, 0),
        observation(1, 3, 1, 0),
    ] {
        assert_eq!(
            classify_query_observation(malformed),
            Err(QualificationError::PersistentVolumeStateAmbiguous)
        );
    }
    let mut truncated = disabled_observation();
    truncated.information_bytes -= 1;
    assert_eq!(
        classify_query_observation(truncated),
        Err(QualificationError::PersistentVolumeStateAmbiguous)
    );
    let mut nonzero_input_flags = disabled_observation();
    nonzero_input_flags.request.volume_flags = 1;
    assert_eq!(
        classify_query_observation(nonzero_input_flags),
        Err(QualificationError::PersistentVolumeStateAmbiguous)
    );

    let output_with_additional_documented_bits = observation(0x0000_0003, 1, 1, 0);
    assert!(classify_query_observation(output_with_additional_documented_bits).is_ok());
}

#[test]
fn volume_policy_double_query_order_and_failure_suppression_are_fixed() {
    let mut io = MockQualificationIo::new(
        [7, 7, 7, 7],
        [Ok(disabled_observation()), Ok(disabled_observation())],
    );
    let events = Rc::clone(&io.events);
    let prepare_events = Rc::clone(&events);
    let open_events = Rc::clone(&events);
    let result = qualify_twice_before_component_open(
        &mut io,
        7,
        || {
            prepare_events
                .borrow_mut()
                .push(LabEvent::NamespacePreparation);
            Ok(())
        },
        || {
            open_events.borrow_mut().push(LabEvent::ComponentOpen);
            Ok(())
        },
    );
    assert!(result.is_ok());
    assert_eq!(
        *events.borrow(),
        [
            LabEvent::Identity,
            LabEvent::Query,
            LabEvent::Identity,
            LabEvent::NamespacePreparation,
            LabEvent::Identity,
            LabEvent::Query,
            LabEvent::Identity,
            LabEvent::ComponentOpen,
        ]
    );

    let mut changed_state = MockQualificationIo::new(
        [7, 7, 7, 7],
        [Ok(disabled_observation()), Ok(observation(0, 1, 1, 0))],
    );
    assert_eq!(
        qualify_twice_before_component_open(&mut changed_state, 7, || Ok(()), || Ok(())),
        Err(QualificationError::PersistentVolumeStateAmbiguous)
    );

    let mut initially_enabled = MockQualificationIo::new([7], [Ok(observation(0, 1, 1, 0))]);
    let prepare_count = Cell::new(0usize);
    let open_count = Cell::new(0usize);
    assert_eq!(
        qualify_twice_before_component_open(
            &mut initially_enabled,
            7,
            || {
                prepare_count.set(prepare_count.get() + 1);
                Ok(())
            },
            || {
                open_count.set(open_count.get() + 1);
                Ok(())
            },
        ),
        Err(QualificationError::UnsupportedShortNameState)
    );
    assert_eq!(prepare_count.get(), 0);
    assert_eq!(open_count.get(), 0);

    let cases = [
        (
            vec![7, 7, 8, 8],
            vec![Ok(disabled_observation()), Ok(disabled_observation())],
        ),
        (
            vec![7, 7, 7, 7],
            vec![
                Ok(disabled_observation()),
                Err(QueryCallError::AccessDenied),
            ],
        ),
        (
            vec![7, 7, 7, 7],
            vec![Ok(disabled_observation()), Err(QueryCallError::Unsupported)],
        ),
    ];
    for (identities, queries) in cases {
        let mut io = MockQualificationIo::new(identities, queries);
        let open_count = Cell::new(0usize);
        assert!(qualify_twice_before_component_open(
            &mut io,
            7,
            || Ok(()),
            || {
                open_count.set(open_count.get() + 1);
                Ok(())
            },
        )
        .is_err());
        assert_eq!(open_count.get(), 0);
    }

    for first_failure in [
        Err(QueryCallError::Failed),
        Err(QueryCallError::AccessDenied),
        Err(QueryCallError::Unsupported),
        Err(QueryCallError::InvalidVolumeAuthority),
        Err(QueryCallError::IncompleteCompletion),
    ] {
        let mut io = MockQualificationIo::new([7], [first_failure]);
        let prepare_count = Cell::new(0usize);
        let open_count = Cell::new(0usize);
        assert!(qualify_twice_before_component_open(
            &mut io,
            7,
            || {
                prepare_count.set(prepare_count.get() + 1);
                Ok(())
            },
            || {
                open_count.set(open_count.get() + 1);
                Ok(())
            },
        )
        .is_err());
        assert_eq!(prepare_count.get(), 0);
        assert_eq!(open_count.get(), 0);
    }
}

#[test]
fn volume_policy_raw_free_error_model_is_closed() {
    let raw_canaries = ["C:", "Volume{", "8DOT3~1", "synthetic-private-path"];
    for error in [
        QualificationError::UnsupportedShortNameState,
        QualificationError::PersistentVolumeQueryFailed,
        QualificationError::PersistentVolumeStateAmbiguous,
    ] {
        for rendered in [format!("{error:?}"), error.to_string()] {
            for canary in raw_canaries {
                assert!(!rendered.contains(canary));
            }
        }
    }
}

#[test]
fn volume_policy_source_contains_no_set_or_alternate_control_route() {
    let source = include_str!("short_name_tests.rs");
    let forbidden = [
        ["FSCTL_", "SET_", "PERSISTENT_VOLUME_STATE"].concat(),
        ["Device", "IoControl"].concat(),
        ["fs", "util"].concat(),
    ];
    for value in forbidden {
        assert!(!source.contains(&value));
    }
}

#[test]
fn volume_policy_directory_parser_accepts_zero_alias_records_and_rejects_aliases() {
    let one = synthetic_directory_page(&[&[u16::from(b'A')]], &[0]);
    assert_eq!(
        parse_directory_page(one.bytes()),
        Ok(ParsedDirectoryPage {
            entries: 1,
            dot_entries: 0,
            short_name_aliases: 0,
            logical_bytes: FILE_NAME_OFFSET + size_of::<u16>(),
        })
    );

    let multiple = synthetic_directory_page(
        &[&[u16::from(b'A')], &[u16::from(b'B'), u16::from(b'C')]],
        &[0, 0],
    );
    let parsed = parse_directory_page(multiple.bytes()).expect("parse two valid records");
    assert_eq!(parsed.entries, 2);
    assert_eq!(parsed.short_name_aliases, 0);

    let alias = synthetic_directory_page(&[&[u16::from(b'A')]], &[2]);
    assert_eq!(
        parse_directory_page(alias.bytes())
            .expect("well-formed alias observation")
            .short_name_aliases,
        1
    );
}

#[test]
fn volume_policy_directory_parser_rejects_malformed_offsets_and_lengths_without_overread() {
    let valid = synthetic_directory_page(&[&[u16::from(b'A')]], &[0]);
    for length in 0..valid.logical_length {
        assert!(parse_directory_page(words_as_bytes(&valid.words, length)).is_err());
    }
    assert!(parse_directory_page(valid.bytes()).is_ok());

    let mut odd_name = synthetic_directory_page(&[&[u16::from(b'A')]], &[0]);
    write_u32(
        odd_name.bytes_mut(),
        FILE_NAME_LENGTH_OFFSET,
        u32::try_from(size_of::<u16>() - 1).expect("small constant"),
    );
    assert_eq!(
        parse_directory_page(odd_name.bytes()),
        Err(DirectoryInfoError::InvalidFileNameLength)
    );

    for invalid_short in [1, 25, u8::MAX] {
        let malformed = synthetic_directory_page(&[&[u16::from(b'A')]], &[invalid_short]);
        assert_eq!(
            parse_directory_page(malformed.bytes()),
            Err(DirectoryInfoError::InvalidShortNameLength)
        );
    }

    let mut misaligned_next =
        synthetic_directory_page(&[&[u16::from(b'A')], &[u16::from(b'B')]], &[0, 0]);
    write_u32(misaligned_next.bytes_mut(), NEXT_ENTRY_OFFSET, 7);
    assert_eq!(
        parse_directory_page(misaligned_next.bytes()),
        Err(DirectoryInfoError::InvalidNextEntryOffset)
    );

    let mut oversized_next =
        synthetic_directory_page(&[&[u16::from(b'A')], &[u16::from(b'B')]], &[0, 0]);
    let beyond = align_up(
        oversized_next.logical_length + 1,
        align_of::<FILE_ID_BOTH_DIR_INFO>(),
    );
    write_u32(
        oversized_next.bytes_mut(),
        NEXT_ENTRY_OFFSET,
        u32::try_from(beyond).expect("bounded synthetic offset"),
    );
    assert_eq!(
        parse_directory_page(oversized_next.bytes()),
        Err(DirectoryInfoError::InvalidNextEntryOffset)
    );
}

#[test]
fn volume_policy_directory_parser_has_a_finite_entry_bound() {
    let names = vec![vec![u16::from(b'A')]; MAX_ENTRIES_PER_PAGE + 1];
    let name_refs = names.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let aliases = vec![0u8; name_refs.len()];
    let page = synthetic_directory_page(&name_refs, &aliases);
    assert_eq!(
        parse_directory_page(page.bytes()),
        Err(DirectoryInfoError::EntryBoundExceeded)
    );
}

#[test]
fn volume_policy_actual_retained_volume_query_is_read_only_and_repeatable() {
    let fixture = Fixture::new("retained-volume");
    let (volume_root, components, expected_identity) = open_retained_fixture_volume(&fixture.root);
    let granted_access = query_granted_access(&volume_root).expect("query retained handle access");
    let write_access = FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER;
    assert_eq!(granted_access & write_access, 0);

    let before_first = fs_boundary::directory_identity(&volume_root)
        .expect("identity before first read-only query");
    let first = query_short_name_creation_state(&volume_root);
    let after_first = fs_boundary::directory_identity(&volume_root)
        .expect("identity after first read-only query");
    let before_second = fs_boundary::directory_identity(&volume_root)
        .expect("identity before second read-only query");
    let second = query_short_name_creation_state(&volume_root);
    let after_second = fs_boundary::directory_identity(&volume_root)
        .expect("identity after second read-only query");

    let identity_stable = [before_first, after_first, before_second, after_second]
        .into_iter()
        .all(|identity| identity == expected_identity);
    assert!(identity_stable);
    let same_result = first == second;
    let eligible = first
        .ok()
        .and_then(|value| classify_query_observation(value).ok())
        .is_some()
        && second
            .ok()
            .and_then(|value| classify_query_observation(value).ok())
            .is_some();

    let component_opened = Cell::new(false);
    if eligible {
        let first_component = components.first().expect("fixture has a user component");
        let opened = volume_root
            .open_dir_nofollow(first_component)
            .expect("component becomes eligible only after query two");
        component_opened.set(true);
        drop(opened);
    }
    assert_eq!(component_opened.get(), eligible);

    println!(
        "VOLUME_POLICY_RETAINED_QUERY query_1={} query_2={} same_result={} identity_stable={} component_opened={} granted_access=0x{granted_access:08X}",
        query_label(&first),
        query_label(&second),
        same_result,
        identity_stable,
        component_opened.get(),
    );
    if let (Ok(first), Ok(second)) = (&first, &second) {
        println!(
            "VOLUME_POLICY_RETAINED_FIELDS first_flags=0x{:08X} first_mask=0x{:08X} first_version={} first_reserved={} first_bytes={} second_flags=0x{:08X} second_mask=0x{:08X} second_version={} second_reserved={} second_bytes={}",
            first.output.volume_flags,
            first.output.flag_mask,
            first.output.version,
            first.output.reserved,
            first.information_bytes,
            second.output.volume_flags,
            second.output.flag_mask,
            second.output.version,
            second.output.reserved,
            second.information_bytes,
        );
    }
}

#[test]
fn volume_policy_actual_directory_enumeration_is_bounded_resumable_and_alias_free() {
    let empty_fixture = Fixture::new("empty-enumeration");
    let empty_root = empty_fixture.open();
    let empty = enumerate_directory_short_names(&empty_root).expect("enumerate empty fixture");
    assert_eq!(empty.user_entries(), 0);
    assert_eq!(empty.short_name_aliases, 0);

    let multiple_fixture = Fixture::new("paged-enumeration");
    let multiple_root = multiple_fixture.open();
    for index in 0..80u32 {
        multiple_root
            .write(format!("F{index:07}.TXT"), b"synthetic")
            .expect("create bounded 8.3-compatible fixture entry");
    }
    let multiple =
        enumerate_directory_short_names(&multiple_root).expect("enumerate paged fixture");
    assert_eq!(multiple.user_entries(), 80);
    assert!(multiple.pages >= 2);
    assert_eq!(multiple.short_name_aliases, 0);

    let mutation_fixture = Fixture::new("mutation-enumeration");
    let mutation_root = mutation_fixture.open();
    mutation_root
        .write("A.TXT", b"synthetic")
        .expect("create initial retained entry");
    let before =
        enumerate_directory_short_names(&mutation_root).expect("initial restart enumeration");
    assert_eq!(before.user_entries(), 1);
    mutation_root
        .write("B.TXT", b"synthetic")
        .expect("mutate fixture through retained handle");
    let after = enumerate_directory_short_names(&mutation_root)
        .expect("restart enumeration observes current directory state");
    assert_eq!(after.user_entries(), 2);
    assert_eq!(after.short_name_aliases, 0);

    println!(
        "VOLUME_POLICY_DIRECTORY_ENUM empty_user_entries={} paged_user_entries={} paged_calls={} aliases={} restart_before={} restart_after={}",
        empty.user_entries(),
        multiple.user_entries(),
        multiple.pages,
        multiple.short_name_aliases + after.short_name_aliases,
        before.user_entries(),
        after.user_entries(),
    );
}

#[test]
fn volume_policy_actual_production_ordering_uses_one_retained_authority() {
    let fixture = Fixture::new("production-order");
    let (volume_root, components, expected_identity) = open_retained_fixture_volume(&fixture.root);
    let mut io = RetainedVolumeIo {
        directory: &volume_root,
    };
    let prepare_count = Cell::new(0usize);
    let open_count = Cell::new(0usize);
    let outcome = qualify_twice_before_component_open(
        &mut io,
        expected_identity,
        || {
            prepare_count.set(prepare_count.get() + 1);
            Ok(())
        },
        || {
            let first_component = components
                .first()
                .ok_or(QualificationError::PersistentVolumeStateAmbiguous)?;
            let opened = volume_root
                .open_dir_nofollow(first_component)
                .map_err(|_| QualificationError::PersistentVolumeStateAmbiguous)?;
            open_count.set(open_count.get() + 1);
            drop(opened);
            Ok(())
        },
    );
    match outcome {
        Ok(_) => {
            assert_eq!(prepare_count.get(), 1);
            assert_eq!(open_count.get(), 1);
        }
        Err(_) => assert_eq!(open_count.get(), 0),
    }
    println!(
        "VOLUME_POLICY_ORDERING outcome={} preparation_calls={} component_open_calls={}",
        if outcome.is_ok() {
            "ELIGIBLE"
        } else {
            "REJECTED"
        },
        prepare_count.get(),
        open_count.get(),
    );
}
