#![cfg(windows)]

use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use cap_fs_ext::{FollowSymlinks, MetadataExt, OpenOptionsFollowExt, OpenOptionsSyncExt};
use cap_std::fs::{Dir, File, OpenOptions, OpenOptionsExt};
use cap_std::{ambient_authority, AmbientAuthority};
use windows_sys::Wdk::Storage::FileSystem::{
    FileAccessInformation, FileIsRemoteDeviceInformation, FileModeInformation,
    FileRenameInformation, NtQueryInformationFile, NtSetInformationFile, FILE_ACCESS_INFORMATION,
    FILE_MODE_INFORMATION, FILE_RENAME_INFORMATION, FILE_WRITE_THROUGH,
};
use windows_sys::Wdk::System::SystemServices::FILE_IS_REMOTE_DEVICE_INFORMATION;
use windows_sys::Win32::Foundation::{
    GetLastError, RtlNtStatusToDosError, ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, GENERIC_READ,
    GENERIC_WRITE, HANDLE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileIdInfo, FlushFileBuffers, GetFileInformationByHandleEx, GetVolumeInformationByHandleW,
    LockFileEx, UnlockFileEx, DELETE, FILE_ID_INFO, FILE_READ_DATA, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, LOCKFILE_EXCLUSIVE_LOCK,
    LOCKFILE_FAIL_IMMEDIATELY,
};
use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, OVERLAPPED};

const LOCK_LEAF: &str = "session.lock";
const LOCK_MAGIC: &[u8] = b"SAFECLONE-RT1S-LOCK\n";
const RECORD_MAGIC: &[u8; 8] = b"RT1SREC1";
const PAYLOAD_LEN: usize = 48;
const RECORD_CHECK_LEN: usize = 32;
const MAX_RECORD_BYTES: usize = 512;
const PENDING_PREFIX: &str = ".pending-";
const PENDING_SUFFIX: &str = ".scdp";
const FINAL_PREFIX: &str = "capsule-";
const FINAL_SUFFIX: &str = ".scdp";
const FIXTURE_PREFIX: &str = "safeclone-generation-test-";
const CHILD_MODE_ENV: &str = "SAFECLONE_TEST_GENERATION_CHILD_MODE";
const CHILD_ROOT_ENV: &str = "SAFECLONE_TEST_GENERATION_CHILD_ROOT";
const CHILD_CHECKPOINT_ENV: &str = "SAFECLONE_TEST_GENERATION_CHECKPOINT";
const CHILD_GENERATION_ENV: &str = "SAFECLONE_TEST_GENERATION_GENERATION";
const CHILD_PENDING_ENV: &str = "SAFECLONE_TEST_GENERATION_PENDING";
const CHILD_TEST_NAME: &str = "generation_child_worker";
const LOCK_READY_LEAF: &str = "lab-lock-ready";
const LOCK_RELEASE_LEAF: &str = "lab-lock-release";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SyntheticRecord {
    generation: u64,
    previous_tag: [u8; RECORD_CHECK_LEN],
    record_check: [u8; RECORD_CHECK_LEN],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChainError {
    DuplicateOrFork,
    Gap,
    WrongPredecessor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReaderState {
    CreateIncomplete,
    Authoritative {
        head: u64,
    },
    PrivateOrphansPresent {
        head: Option<u64>,
        orphan_count: usize,
    },
    CorruptState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Checkpoint {
    P0,
    P1,
    P2,
    P3,
    P4,
    P5,
    P6,
    P7,
}

impl Checkpoint {
    const ALL: [Self; 8] = [
        Self::P0,
        Self::P1,
        Self::P2,
        Self::P3,
        Self::P4,
        Self::P5,
        Self::P6,
        Self::P7,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::P0 => "P0",
            Self::P1 => "P1",
            Self::P2 => "P2",
            Self::P3 => "P3",
            Self::P4 => "P4",
            Self::P5 => "P5",
            Self::P6 => "P6",
            Self::P7 => "P7",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|checkpoint| checkpoint.as_str() == value)
    }

    fn abort_if(self, current: Option<Self>) {
        if current == Some(self) {
            std::process::abort();
        }
    }
}

#[derive(Debug)]
struct CommitEvidence {
    root_at_start: FileIdentity,
    root_before_rename: FileIdentity,
    root_after_commit: FileIdentity,
    pending_before_rename: FileIdentity,
    same_handle_after_rename: FileIdentity,
    final_reopen: FileIdentity,
    mode: u32,
    access: u32,
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
        let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = temp_parent.join(format!(
            "{FIXTURE_PREFIX}{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create synthetic native root");
        let fixture = Self { root, temp_parent };
        require_local_ntfs(&fixture.open());
        fixture
    }

    fn open(&self) -> Dir {
        open_ambient_dir(&self.root, ambient_authority()).expect("open synthetic retained root")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let safe_name = self
            .root
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.starts_with(FIXTURE_PREFIX));
        if self.root.parent() == Some(self.temp_parent.as_path()) && safe_name {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn open_ambient_dir(path: &Path, authority: AmbientAuthority) -> io::Result<Dir> {
    Dir::open_ambient_dir(path, authority)
}

struct ExclusiveSessionLock {
    file: File,
    range: OVERLAPPED,
}

impl ExclusiveSessionLock {
    fn acquire(root: &Dir) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        let mut file = root.open_with(LOCK_LEAF, &options)?;
        validate_regular_one_link(&file)?;
        if read_file_bounded(&mut file, LOCK_MAGIC.len() + 1)? != LOCK_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "lock record is not committed",
            ));
        }

        let mut range = OVERLAPPED::default();
        // SAFETY: `file` is a live synchronous file handle and `range` is a
        // valid OVERLAPPED value whose zero offsets select byte range [0, 1).
        let acquired = unsafe {
            LockFileEx(
                file.as_raw_handle() as HANDLE,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut range,
            )
        };
        if acquired == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { file, range })
    }
}

impl Drop for ExclusiveSessionLock {
    fn drop(&mut self) {
        // SAFETY: this object owns the live file handle and exact OVERLAPPED
        // range used by the successful LockFileEx call.
        let _ = unsafe {
            UnlockFileEx(
                self.file.as_raw_handle() as HANDLE,
                0,
                1,
                0,
                &mut self.range,
            )
        };
    }
}

fn require_local_ntfs(root: &Dir) {
    let handle = root.as_raw_handle() as HANDLE;
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut remote = FILE_IS_REMOTE_DEVICE_INFORMATION::default();
    // SAFETY: `handle` is a live retained directory handle and both output
    // buffers are correctly sized writable ABI values.
    let status = unsafe {
        NtQueryInformationFile(
            handle,
            &mut io_status,
            (&mut remote as *mut FILE_IS_REMOTE_DEVICE_INFORMATION).cast(),
            u32::try_from(size_of::<FILE_IS_REMOTE_DEVICE_INFORMATION>())
                .expect("remote query size fits u32"),
            FileIsRemoteDeviceInformation,
        )
    };
    assert!(status >= 0, "remote-device query must succeed");
    assert!(!remote.IsRemote, "native fixture must be local");

    let mut filesystem_name = [0u16; 16];
    // SAFETY: the retained handle is valid and the filesystem output buffer
    // is writable; all unused optional outputs are null.
    let queried = unsafe {
        GetVolumeInformationByHandleW(
            handle,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            filesystem_name.as_mut_ptr(),
            filesystem_name.len() as u32,
        )
    };
    assert_ne!(queried, 0, "filesystem query must succeed");
    let end = filesystem_name
        .iter()
        .position(|unit| *unit == 0)
        .expect("filesystem name is terminated");
    assert!(utf16_ascii_eq_ignore_case(&filesystem_name[..end], b"NTFS"));
}

fn utf16_ascii_eq_ignore_case(actual: &[u16], expected: &[u8]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            u8::try_from(*actual).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
        })
}

fn initialize_lock(root: &Dir) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No)
        .sync(true);
    let mut file = root.open_with(LOCK_LEAF, &options)?;
    validate_regular_one_link(&file)?;
    file.write_all(LOCK_MAGIC)?;
    flush_file(&file)?;
    if read_file_bounded(&mut file, LOCK_MAGIC.len() + 1)? != LOCK_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "lock read-back mismatch",
        ));
    }
    Ok(())
}

fn create_lock_without_explicit_flush(root: &Dir, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No)
        .sync(true);
    let mut file = root.open_with(LOCK_LEAF, &options)?;
    file.write_all(bytes)
}

fn create_pending(root: &Dir, leaf: &str) -> io::Result<File> {
    if !is_valid_pending_leaf(leaf) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid pending leaf",
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No)
        .sync(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    root.open_with(leaf, &options)
}

fn open_regular_read(root: &Dir, leaf: &str) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = root.open_with(leaf, &options)?;
    validate_regular_one_link(&file)?;
    Ok(file)
}

fn validate_regular_one_link(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "entry is not one ordinary one-link file",
        ));
    }
    Ok(())
}

fn file_identity<T: AsRawHandle>(handle: &T) -> io::Result<FileIdentity> {
    let mut information = FILE_ID_INFO::default();
    // SAFETY: `handle` is live and `information` is a correctly sized writable
    // FILE_ID_INFO buffer.
    let queried = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle() as HANDLE,
            FileIdInfo,
            (&mut information as *mut FILE_ID_INFO).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>()).expect("identity size fits u32"),
        )
    };
    if queried == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(FileIdentity {
            volume_serial: information.VolumeSerialNumber,
            file_id: information.FileId.Identifier,
        })
    }
}

fn query_file_mode(file: &File) -> io::Result<u32> {
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut information = FILE_MODE_INFORMATION::default();
    // SAFETY: `file` is live and the information/status blocks are writable
    // and correctly sized for FileModeInformation.
    let status = unsafe {
        NtQueryInformationFile(
            file.as_raw_handle() as HANDLE,
            &mut io_status,
            (&mut information as *mut FILE_MODE_INFORMATION).cast(),
            u32::try_from(size_of::<FILE_MODE_INFORMATION>()).expect("mode size fits u32"),
            FileModeInformation,
        )
    };
    ntstatus_result(status, information.Mode)
}

fn query_file_access(file: &File) -> io::Result<u32> {
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut information = FILE_ACCESS_INFORMATION::default();
    // SAFETY: `file` is live and the information/status blocks are writable
    // and correctly sized for FileAccessInformation.
    let status = unsafe {
        NtQueryInformationFile(
            file.as_raw_handle() as HANDLE,
            &mut io_status,
            (&mut information as *mut FILE_ACCESS_INFORMATION).cast(),
            u32::try_from(size_of::<FILE_ACCESS_INFORMATION>()).expect("access size fits u32"),
            FileAccessInformation,
        )
    };
    ntstatus_result(status, information.AccessFlags)
}

fn ntstatus_result<T>(status: i32, success: T) -> io::Result<T> {
    if status < 0 {
        // SAFETY: this translates the NTSTATUS returned by the immediately
        // preceding native call and has no pointer preconditions.
        let error = unsafe { RtlNtStatusToDosError(status) };
        Err(io::Error::from_raw_os_error(error as i32))
    } else {
        Ok(success)
    }
}

fn flush_file<T: AsRawHandle>(file: &T) -> io::Result<()> {
    // SAFETY: `file` supplies a live handle with write access for all required
    // generation and lock-file calls.
    let flushed = unsafe { FlushFileBuffers(file.as_raw_handle() as HANDLE) };
    if flushed == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn exclusive_rename_same_handle(file: &File, root: &Dir, final_leaf: &str) -> io::Result<()> {
    validate_leaf(OsStr::new(final_leaf))?;
    let target = OsStr::new(final_leaf).encode_wide().collect::<Vec<_>>();
    let target_bytes = target
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or_else(|| io::Error::other("rename target length overflow"))?;
    let buffer_bytes = offset_of!(FILE_RENAME_INFORMATION, FileName)
        .checked_add(target_bytes)
        .ok_or_else(|| io::Error::other("rename buffer length overflow"))?;
    let buffer_size = u32::try_from(buffer_bytes)
        .map_err(|_| io::Error::other("rename buffer exceeds API limit"))?;
    let words = buffer_bytes
        .checked_add(size_of::<usize>() - 1)
        .ok_or_else(|| io::Error::other("rename alignment overflow"))?
        / size_of::<usize>();
    let mut storage = vec![0usize; words];
    let information = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();

    // SAFETY: `storage` is usize-aligned and sized for the fixed header plus
    // the exact non-NUL UTF-16 leaf. Every field is initialized before use.
    unsafe {
        (*information).Anonymous.ReplaceIfExists = false;
        (*information).RootDirectory = root.as_raw_handle() as HANDLE;
        (*information).FileNameLength = u32::try_from(target_bytes)
            .map_err(|_| io::Error::other("rename leaf exceeds API limit"))?;
        ptr::copy_nonoverlapping(
            target.as_ptr(),
            (*information).FileName.as_mut_ptr(),
            target.len(),
        );
    }

    let mut io_status = IO_STATUS_BLOCK::default();
    // SAFETY: `file` is the live DELETE-capable write-through generation
    // handle, `root` is the retained target directory, and the aligned buffer
    // remains live for this synchronous call.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle() as HANDLE,
            &mut io_status,
            information.cast(),
            buffer_size,
            FileRenameInformation,
        )
    };
    ntstatus_result(status, ())
}

fn validate_leaf(leaf: &OsStr) -> io::Result<()> {
    let mut components = Path::new(leaf).components();
    let one_normal = matches!(
        components.next(),
        Some(Component::Normal(component)) if component == leaf
    ) && components.next().is_none();
    let forbidden = leaf.encode_wide().any(|unit| {
        unit == 0 || unit == u16::from(b'/') || unit == u16::from(b'\\') || unit == u16::from(b':')
    });
    if one_normal && !forbidden {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rename target is not one normal leaf",
        ))
    }
}

fn final_leaf(generation: u64) -> String {
    format!("{FINAL_PREFIX}{generation:016X}{FINAL_SUFFIX}")
}

fn pending_leaf(label: &str) -> String {
    format!("{PENDING_PREFIX}{label}{PENDING_SUFFIX}")
}

fn is_valid_pending_leaf(leaf: &str) -> bool {
    let Some(body) = leaf
        .strip_prefix(PENDING_PREFIX)
        .and_then(|name| name.strip_suffix(PENDING_SUFFIX))
    else {
        return false;
    };
    !body.is_empty()
        && body.len() <= 32
        && body
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
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

fn synthetic_tag(generation: u64) -> [u8; RECORD_CHECK_LEN] {
    let generation_bytes = generation.to_le_bytes();
    let mut tag = [0u8; RECORD_CHECK_LEN];
    for (index, byte) in tag.iter_mut().enumerate() {
        *byte = generation_bytes[index % generation_bytes.len()]
            ^ u8::try_from(index).expect("tag index fits u8")
            ^ 0xA5;
    }
    tag
}

fn synthetic_payload(generation: u64) -> [u8; PAYLOAD_LEN] {
    let generation_bytes = generation.to_be_bytes();
    let mut payload = [0u8; PAYLOAD_LEN];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = generation_bytes[index % generation_bytes.len()]
            .wrapping_add(u8::try_from(index).expect("payload index fits u8"))
            ^ 0x5A;
    }
    payload
}

fn synthetic_record_bytes(generation: u64) -> Vec<u8> {
    assert_ne!(generation, 0);
    let previous_tag = if generation == 1 {
        [0u8; RECORD_CHECK_LEN]
    } else {
        synthetic_tag(generation - 1)
    };
    let payload = synthetic_payload(generation);
    let mut bytes = Vec::with_capacity(
        RECORD_MAGIC.len()
            + size_of::<u64>()
            + previous_tag.len()
            + size_of::<u32>()
            + payload.len()
            + RECORD_CHECK_LEN,
    );
    bytes.extend_from_slice(RECORD_MAGIC);
    bytes.extend_from_slice(&generation.to_le_bytes());
    bytes.extend_from_slice(&previous_tag);
    bytes.extend_from_slice(&(PAYLOAD_LEN as u32).to_le_bytes());
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&synthetic_tag(generation));
    bytes
}

fn parse_synthetic_record(bytes: &[u8], name_generation: u64) -> io::Result<SyntheticRecord> {
    let expected = synthetic_record_bytes(name_generation);
    if bytes != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic record byte validation failed",
        ));
    }
    let generation_offset = RECORD_MAGIC.len();
    let previous_offset = generation_offset + size_of::<u64>();
    let check_offset = expected.len() - RECORD_CHECK_LEN;
    let generation = u64::from_le_bytes(
        bytes[generation_offset..previous_offset]
            .try_into()
            .expect("generation field has fixed size"),
    );
    let previous_tag = bytes[previous_offset..previous_offset + RECORD_CHECK_LEN]
        .try_into()
        .expect("previous tag has fixed size");
    let record_check = bytes[check_offset..]
        .try_into()
        .expect("record check has fixed size");
    Ok(SyntheticRecord {
        generation,
        previous_tag,
        record_check,
    })
}

fn select_linear_chain(mut records: Vec<SyntheticRecord>) -> Result<Option<u64>, ChainError> {
    if records.is_empty() {
        return Ok(None);
    }
    records.sort_by_key(|record| record.generation);
    let mut expected_generation = 1u64;
    let mut expected_previous = [0u8; RECORD_CHECK_LEN];
    for record in records {
        if record.generation < expected_generation {
            return Err(ChainError::DuplicateOrFork);
        }
        if record.generation > expected_generation {
            return Err(ChainError::Gap);
        }
        if record.previous_tag != expected_previous {
            return Err(ChainError::WrongPredecessor);
        }
        expected_previous = record.record_check;
        expected_generation = expected_generation.checked_add(1).ok_or(ChainError::Gap)?;
    }
    Ok(Some(expected_generation - 1))
}

fn read_file_bounded(file: &mut File, limit: usize) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).expect("test bound fits u64"))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_leaf_bounded(root: &Dir, leaf: &str, limit: usize) -> io::Result<Vec<u8>> {
    let mut file = open_regular_read(root, leaf)?;
    let before = file_identity(&file)?;
    let bytes = read_file_bounded(&mut file, limit)?;
    let after = file_identity(&file)?;
    let reopened = open_regular_read(root, leaf)?;
    let reopened_identity = file_identity(&reopened)?;
    if before != after || after != reopened_identity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file identity changed during read",
        ));
    }
    Ok(bytes)
}

fn leaf_is_absent(root: &Dir, leaf: &str) -> bool {
    root.symlink_metadata(leaf)
        .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
}

fn commit_generation(
    root: &Dir,
    generation: u64,
    pending: &str,
    checkpoint: Option<Checkpoint>,
) -> io::Result<CommitEvidence> {
    let root_at_start = file_identity(root)?;
    let _lock = ExclusiveSessionLock::acquire(root)?;
    Checkpoint::P0.abort_if(checkpoint);

    let expected = synthetic_record_bytes(generation);
    let mut file = create_pending(root, pending)?;
    validate_regular_one_link(&file)?;
    let mode = query_file_mode(&file)?;
    let access = query_file_access(&file)?;
    if mode & FILE_WRITE_THROUGH == 0
        || access & (FILE_READ_DATA | FILE_WRITE_DATA | DELETE)
            != FILE_READ_DATA | FILE_WRITE_DATA | DELETE
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "generation handle contract is not available",
        ));
    }

    file.write_all(&expected[..RECORD_MAGIC.len()])?;
    Checkpoint::P1.abort_if(checkpoint);
    file.write_all(&expected[RECORD_MAGIC.len()..])?;
    Checkpoint::P2.abort_if(checkpoint);

    flush_file(&file)?;
    Checkpoint::P3.abort_if(checkpoint);
    if read_file_bounded(&mut file, MAX_RECORD_BYTES)? != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pending read-back mismatch",
        ));
    }
    parse_synthetic_record(&expected, generation)?;
    Checkpoint::P4.abort_if(checkpoint);

    let pending_before_rename = file_identity(&file)?;
    let independent_pending = open_regular_read(root, pending)?;
    if file_identity(&independent_pending)? != pending_before_rename {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pending identity changed before rename",
        ));
    }
    let root_before_rename = file_identity(root)?;
    if root_before_rename != root_at_start {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "retained state root identity changed before rename",
        ));
    }

    let final_name = final_leaf(generation);
    exclusive_rename_same_handle(&file, root, &final_name)?;
    let same_handle_after_rename = file_identity(&file)?;
    if same_handle_after_rename != pending_before_rename {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "renamed handle identity changed",
        ));
    }
    Checkpoint::P5.abort_if(checkpoint);

    flush_file(&file)?;
    Checkpoint::P6.abort_if(checkpoint);

    let mut final_file = open_regular_read(root, &final_name)?;
    let final_reopen = file_identity(&final_file)?;
    if final_reopen != pending_before_rename
        || read_file_bounded(&mut final_file, MAX_RECORD_BYTES)? != expected
        || !leaf_is_absent(root, pending)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "final generation verification failed",
        ));
    }
    let root_after_commit = file_identity(root)?;
    if root_after_commit != root_at_start {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "retained state root identity changed after commit",
        ));
    }
    Checkpoint::P7.abort_if(checkpoint);

    Ok(CommitEvidence {
        root_at_start,
        root_before_rename,
        root_after_commit,
        pending_before_rename,
        same_handle_after_rename,
        final_reopen,
        mode,
        access,
    })
}

fn observe_reader_state(root: &Dir) -> ReaderState {
    let Ok(entries) = root.entries() else {
        return ReaderState::CorruptState;
    };
    let mut saw_lock = false;
    let mut lock_valid = false;
    let mut orphan_count = 0usize;
    let mut records = Vec::new();

    for entry in entries {
        let Ok(entry) = entry else {
            return ReaderState::CorruptState;
        };
        let Ok(name) = entry.file_name().into_string() else {
            return ReaderState::CorruptState;
        };
        let Ok(metadata) = root.symlink_metadata(&name) else {
            return ReaderState::CorruptState;
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
            return ReaderState::CorruptState;
        }

        if name == LOCK_LEAF {
            if saw_lock {
                return ReaderState::CorruptState;
            }
            saw_lock = true;
            lock_valid = read_leaf_bounded(root, &name, LOCK_MAGIC.len() + 1)
                .is_ok_and(|bytes| bytes == LOCK_MAGIC);
        } else if is_valid_pending_leaf(&name) {
            orphan_count = match orphan_count.checked_add(1) {
                Some(count) => count,
                None => return ReaderState::CorruptState,
            };
        } else if let Some(generation) = parse_final_leaf(&name) {
            let Ok(bytes) = read_leaf_bounded(root, &name, MAX_RECORD_BYTES) else {
                return ReaderState::CorruptState;
            };
            let Ok(record) = parse_synthetic_record(&bytes, generation) else {
                return ReaderState::CorruptState;
            };
            records.push(record);
        } else {
            return ReaderState::CorruptState;
        }
    }

    if !saw_lock || !lock_valid {
        return if records.is_empty() && orphan_count == 0 {
            ReaderState::CreateIncomplete
        } else {
            ReaderState::CorruptState
        };
    }
    let head = match select_linear_chain(records) {
        Ok(head) => head,
        Err(_) => return ReaderState::CorruptState,
    };
    if orphan_count != 0 {
        ReaderState::PrivateOrphansPresent { head, orphan_count }
    } else if let Some(head) = head {
        ReaderState::Authoritative { head }
    } else {
        ReaderState::CreateIncomplete
    }
}

fn create_leaf(root: &Dir, leaf: &str, bytes: &[u8]) -> io::Result<FileIdentity> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut file = root.open_with(leaf, &options)?;
    file.write_all(bytes)?;
    file.flush()?;
    file_identity(&file)
}

fn spawn_checkpoint_child(
    root: &Path,
    generation: u64,
    pending: &str,
    checkpoint: Checkpoint,
) -> io::Result<std::process::ExitStatus> {
    Command::new(std::env::current_exe()?)
        .arg(CHILD_TEST_NAME)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MODE_ENV, "checkpoint")
        .env(CHILD_ROOT_ENV, root)
        .env(CHILD_GENERATION_ENV, generation.to_string())
        .env(CHILD_PENDING_ENV, pending)
        .env(CHILD_CHECKPOINT_ENV, checkpoint.as_str())
        .env("RUST_TEST_THREADS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
}

fn spawn_lock_holder(root: &Path) -> io::Result<Child> {
    Command::new(std::env::current_exe()?)
        .arg(CHILD_TEST_NAME)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MODE_ENV, "lock-holder")
        .env(CHILD_ROOT_ENV, root)
        .env("RUST_TEST_THREADS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

fn wait_for_leaf(root: &Dir, leaf: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if root.symlink_metadata(leaf).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.kill()?;
    child.wait()
}

fn checkpoint_child() {
    let root_path = PathBuf::from(
        std::env::var_os(CHILD_ROOT_ENV).expect("child synthetic root is configured"),
    );
    let root =
        open_ambient_dir(&root_path, ambient_authority()).expect("child opens retained root");
    require_local_ntfs(&root);
    let generation = std::env::var(CHILD_GENERATION_ENV)
        .expect("child generation is configured")
        .parse::<u64>()
        .expect("child generation is bounded integer");
    let pending = std::env::var(CHILD_PENDING_ENV).expect("child pending leaf is configured");
    let checkpoint = Checkpoint::parse(
        &std::env::var(CHILD_CHECKPOINT_ENV).expect("child checkpoint is configured"),
    )
    .expect("child checkpoint is recognized");
    commit_generation(&root, generation, &pending, Some(checkpoint))
        .expect("checkpoint must terminate before returning");
    panic!("checkpoint child returned without terminating");
}

fn lock_holder_child() {
    let root_path = PathBuf::from(
        std::env::var_os(CHILD_ROOT_ENV).expect("child synthetic root is configured"),
    );
    let root =
        open_ambient_dir(&root_path, ambient_authority()).expect("child opens retained root");
    let _lock = ExclusiveSessionLock::acquire(&root).expect("child acquires session lock");
    create_leaf(&root, LOCK_READY_LEAF, b"ready").expect("child creates ready marker");
    assert!(
        wait_for_leaf(&root, LOCK_RELEASE_LEAF, Duration::from_secs(10)),
        "parent releases lock-holder child"
    );
}

#[test]
fn generation_child_worker() {
    let Some(mode) = std::env::var_os(CHILD_MODE_ENV) else {
        return;
    };
    match mode.to_str() {
        Some("checkpoint") => checkpoint_child(),
        Some("lock-holder") => lock_holder_child(),
        _ => panic!("unrecognized child mode"),
    }
}

#[test]
fn write_through_flush_rename_and_identity_sequence_commits_generation() {
    let fixture = Fixture::new("primary");
    let root = fixture.open();
    initialize_lock(&root).expect("initialize lock");
    let evidence =
        commit_generation(&root, 1, &pending_leaf("PRIMARY"), None).expect("commit generation one");

    assert_eq!(evidence.root_at_start, evidence.root_before_rename);
    assert_eq!(evidence.root_at_start, evidence.root_after_commit);
    assert_eq!(
        evidence.pending_before_rename,
        evidence.same_handle_after_rename
    );
    assert_eq!(evidence.pending_before_rename, evidence.final_reopen);
    assert_ne!(evidence.mode & FILE_WRITE_THROUGH, 0);
    assert_eq!(
        evidence.access & (FILE_READ_DATA | FILE_WRITE_DATA | DELETE),
        FILE_READ_DATA | FILE_WRITE_DATA | DELETE
    );
    assert_eq!(
        observe_reader_state(&root),
        ReaderState::Authoritative { head: 1 }
    );
}

#[test]
fn interruption_checkpoints_are_classified_from_disk_state_only() {
    for checkpoint in Checkpoint::ALL {
        let fixture = Fixture::new(checkpoint.as_str());
        let root = fixture.open();
        initialize_lock(&root).expect("initialize lock");
        let pending = pending_leaf(checkpoint.as_str());

        let status = spawn_checkpoint_child(&fixture.root, 1, &pending, checkpoint)
            .expect("run checkpoint child");
        assert!(
            !status.success(),
            "checkpoint child must terminate abruptly"
        );

        let expected = match checkpoint {
            Checkpoint::P0 => ReaderState::CreateIncomplete,
            Checkpoint::P1 | Checkpoint::P2 | Checkpoint::P3 | Checkpoint::P4 => {
                ReaderState::PrivateOrphansPresent {
                    head: None,
                    orphan_count: 1,
                }
            }
            Checkpoint::P5 | Checkpoint::P6 | Checkpoint::P7 => {
                ReaderState::Authoritative { head: 1 }
            }
        };
        assert_eq!(observe_reader_state(&root), expected);
        drop(ExclusiveSessionLock::acquire(&root).expect("abrupt exit releases lock"));
    }
}

#[test]
fn generation_two_pre_and_post_rename_interruptions_preserve_chain_rules() {
    for (checkpoint, expected) in [
        (
            Checkpoint::P4,
            ReaderState::PrivateOrphansPresent {
                head: Some(1),
                orphan_count: 1,
            },
        ),
        (Checkpoint::P5, ReaderState::Authoritative { head: 2 }),
    ] {
        let fixture = Fixture::new(&format!("gen2-{}", checkpoint.as_str()));
        let root = fixture.open();
        initialize_lock(&root).expect("initialize lock");
        commit_generation(&root, 1, &pending_leaf("GEN1"), None).expect("commit generation one");
        let generation_one = final_leaf(1);
        let identity_before = file_identity(
            &open_regular_read(&root, &generation_one).expect("open generation one before child"),
        )
        .expect("query generation one identity");
        let bytes_before = read_leaf_bounded(&root, &generation_one, MAX_RECORD_BYTES)
            .expect("read generation one before child");

        let status = spawn_checkpoint_child(&fixture.root, 2, &pending_leaf("GEN2"), checkpoint)
            .expect("run generation-two child");
        assert!(!status.success());
        assert_eq!(observe_reader_state(&root), expected);
        assert_eq!(
            file_identity(
                &open_regular_read(&root, &generation_one)
                    .expect("open generation one after child")
            )
            .expect("query generation one identity after child"),
            identity_before
        );
        assert_eq!(
            read_leaf_bounded(&root, &generation_one, MAX_RECORD_BYTES)
                .expect("read generation one after child"),
            bytes_before
        );
    }
}

#[test]
fn existing_final_generation_is_never_replaced() {
    let fixture = Fixture::new("no-clobber");
    let root = fixture.open();
    initialize_lock(&root).expect("initialize lock");
    commit_generation(&root, 1, &pending_leaf("FIRST"), None).expect("commit generation one");
    let final_name = final_leaf(1);
    let final_before = open_regular_read(&root, &final_name).expect("open existing generation");
    let identity_before = file_identity(&final_before).expect("query existing identity");
    let bytes_before =
        read_leaf_bounded(&root, &final_name, MAX_RECORD_BYTES).expect("read existing generation");

    commit_generation(&root, 1, &pending_leaf("COLLISION"), None)
        .expect_err("exclusive rename must reject existing final generation");

    let final_after = open_regular_read(&root, &final_name).expect("reopen existing generation");
    assert_eq!(
        file_identity(&final_after).expect("query unchanged identity"),
        identity_before
    );
    assert_eq!(
        read_leaf_bounded(&root, &final_name, MAX_RECORD_BYTES).expect("read unchanged generation"),
        bytes_before
    );
    assert_eq!(
        observe_reader_state(&root),
        ReaderState::PrivateOrphansPresent {
            head: Some(1),
            orphan_count: 1,
        }
    );
}

#[test]
fn destination_inserted_after_absence_observation_is_not_clobbered() {
    let fixture = Fixture::new("rename-race");
    let root = fixture.open();
    initialize_lock(&root).expect("initialize lock");
    let _lock = ExclusiveSessionLock::acquire(&root).expect("acquire mutation lock");
    let pending_name = pending_leaf("RACE");
    let expected = synthetic_record_bytes(1);
    let mut pending = create_pending(&root, &pending_name).expect("create pending generation");
    pending
        .write_all(&expected)
        .expect("write pending generation");
    flush_file(&pending).expect("flush pending generation");
    assert!(leaf_is_absent(&root, &final_leaf(1)));

    let raced_bytes = b"synthetic-racing-destination";
    let raced_identity =
        create_leaf(&root, &final_leaf(1), raced_bytes).expect("insert racing destination");
    exclusive_rename_same_handle(&pending, &root, &final_leaf(1))
        .expect_err("exclusive primitive rejects raced destination");

    assert_eq!(
        file_identity(&open_regular_read(&root, &final_leaf(1)).expect("open racing destination"))
            .expect("query racing destination identity"),
        raced_identity
    );
    assert_eq!(
        read_leaf_bounded(&root, &final_leaf(1), MAX_RECORD_BYTES)
            .expect("read racing destination"),
        raced_bytes
    );
    assert!(!leaf_is_absent(&root, &pending_name));
}

#[test]
fn final_reopen_identity_mismatch_fails_closed() {
    let fixture = Fixture::new("identity-injection");
    let root = fixture.open();
    initialize_lock(&root).expect("initialize lock");
    let _lock = ExclusiveSessionLock::acquire(&root).expect("acquire mutation lock");
    let pending_name = pending_leaf("IDENTITY");
    let final_name = final_leaf(1);
    let expected = synthetic_record_bytes(1);
    let mut pending = create_pending(&root, &pending_name).expect("create pending generation");
    pending
        .write_all(&expected)
        .expect("write pending generation");
    flush_file(&pending).expect("flush pending generation");
    let expected_identity = file_identity(&pending).expect("query pending identity");
    exclusive_rename_same_handle(&pending, &root, &final_name).expect("rename pending generation");
    flush_file(&pending).expect("post-rename flush");

    exclusive_rename_same_handle(&pending, &root, "lab-displaced-generation")
        .expect("adversarially displace committed name");
    create_leaf(&root, &final_name, &expected).expect("inject same-byte replacement");
    let reopened = open_regular_read(&root, &final_name).expect("reopen injected generation");
    assert_ne!(
        file_identity(&reopened).expect("query injected identity"),
        expected_identity,
        "same-byte name replacement must not satisfy commit identity continuity"
    );
}

#[test]
fn copied_state_root_cannot_satisfy_retained_root_identity_binding() {
    let source_fixture = Fixture::new("root-binding-source");
    let source = source_fixture.open();
    initialize_lock(&source).expect("initialize source lock");
    commit_generation(&source, 1, &pending_leaf("ROOTBIND"), None)
        .expect("commit source generation");
    let expected_root_identity = file_identity(&source).expect("query source root identity");

    let copied_fixture = Fixture::new("root-binding-copy");
    fs::copy(
        source_fixture.root.join(LOCK_LEAF),
        copied_fixture.root.join(LOCK_LEAF),
    )
    .expect("copy synthetic lock record");
    fs::copy(
        source_fixture.root.join(final_leaf(1)),
        copied_fixture.root.join(final_leaf(1)),
    )
    .expect("copy synthetic generation record");
    let copied = copied_fixture.open();

    assert_ne!(
        file_identity(&copied).expect("query copied root identity"),
        expected_root_identity,
        "a copied directory must not satisfy the retained source-root identity"
    );
}

#[test]
fn lockfileex_serializes_cooperating_processes_without_waiting() {
    let fixture = Fixture::new("lock-contention");
    let root = fixture.open();
    initialize_lock(&root).expect("initialize lock");
    let mut child = spawn_lock_holder(&fixture.root).expect("spawn lock-holder child");
    assert!(
        wait_for_leaf(&root, LOCK_READY_LEAF, Duration::from_secs(10)),
        "lock-holder child must report readiness"
    );

    assert!(
        ExclusiveSessionLock::acquire(&root).is_err(),
        "second process/handle lock must fail immediately"
    );
    create_leaf(&root, LOCK_RELEASE_LEAF, b"release").expect("release child holder");
    let status = wait_for_child(&mut child, Duration::from_secs(10)).expect("wait for lock child");
    assert!(status.success(), "lock-holder child exits cleanly");
    drop(ExclusiveSessionLock::acquire(&root).expect("lock is acquirable after release"));
}

#[test]
fn lock_initialization_interruption_states_are_create_incomplete() {
    let absent = Fixture::new("lock-absent");
    assert_eq!(
        observe_reader_state(&absent.open()),
        ReaderState::CreateIncomplete
    );

    let created = Fixture::new("lock-created");
    create_lock_without_explicit_flush(&created.open(), b"").expect("create empty lock");
    assert_eq!(
        observe_reader_state(&created.open()),
        ReaderState::CreateIncomplete
    );

    let partial = Fixture::new("lock-partial");
    create_lock_without_explicit_flush(&partial.open(), &LOCK_MAGIC[..5])
        .expect("create partial lock");
    assert_eq!(
        observe_reader_state(&partial.open()),
        ReaderState::CreateIncomplete
    );

    let full_before_explicit_flush = Fixture::new("lock-full-write-through");
    let root = full_before_explicit_flush.open();
    create_lock_without_explicit_flush(&root, LOCK_MAGIC).expect("write full lock magic");
    assert_eq!(observe_reader_state(&root), ReaderState::CreateIncomplete);
    drop(ExclusiveSessionLock::acquire(&root).expect("valid fixed magic is lockable"));

    let committed = Fixture::new("lock-committed");
    let root = committed.open();
    initialize_lock(&root).expect("flush and validate lock");
    assert_eq!(observe_reader_state(&root), ReaderState::CreateIncomplete);
    drop(ExclusiveSessionLock::acquire(&root).expect("committed lock is lockable"));
}

#[test]
fn generation_chain_reader_rejects_gap_duplicate_fork_and_wrong_predecessor() {
    let generation_one =
        parse_synthetic_record(&synthetic_record_bytes(1), 1).expect("parse generation one");
    let generation_two =
        parse_synthetic_record(&synthetic_record_bytes(2), 2).expect("parse generation two");
    let generation_three =
        parse_synthetic_record(&synthetic_record_bytes(3), 3).expect("parse generation three");

    assert_eq!(
        select_linear_chain(vec![generation_one.clone()]),
        Ok(Some(1))
    );
    assert_eq!(
        select_linear_chain(vec![generation_two.clone(), generation_one.clone()]),
        Ok(Some(2))
    );
    assert_eq!(
        select_linear_chain(vec![generation_one.clone(), generation_three]),
        Err(ChainError::Gap)
    );
    assert_eq!(
        select_linear_chain(vec![generation_two.clone()]),
        Err(ChainError::Gap)
    );
    assert_eq!(
        select_linear_chain(vec![
            generation_one.clone(),
            generation_two.clone(),
            generation_two.clone(),
        ]),
        Err(ChainError::DuplicateOrFork)
    );
    let mut fork = generation_two;
    fork.previous_tag = [0xFF; RECORD_CHECK_LEN];
    assert_eq!(
        select_linear_chain(vec![generation_one, fork]),
        Err(ChainError::WrongPredecessor)
    );
}

#[test]
fn reader_rejects_malformed_and_unexpected_final_entries() {
    for (label, leaf, bytes) in [
        (
            "malformed-final",
            "capsule-000000000000000g.scdp",
            synthetic_record_bytes(1),
        ),
        (
            "unexpected-generation",
            "capsule-0000000000000002.scdp",
            synthetic_record_bytes(2),
        ),
        (
            "unexpected-entry",
            "unexpected.scdp",
            synthetic_record_bytes(1),
        ),
    ] {
        let fixture = Fixture::new(label);
        let root = fixture.open();
        initialize_lock(&root).expect("initialize lock");
        create_leaf(&root, leaf, &bytes).expect("create invalid reader fixture");
        assert_eq!(observe_reader_state(&root), ReaderState::CorruptState);
    }
}

#[test]
fn complete_pending_record_is_never_adopted_as_authority() {
    let fixture = Fixture::new("pending-never-authority");
    let root = fixture.open();
    initialize_lock(&root).expect("initialize lock");
    create_leaf(&root, &pending_leaf("COMPLETE"), &synthetic_record_bytes(1))
        .expect("create complete pending record");
    assert_eq!(
        observe_reader_state(&root),
        ReaderState::PrivateOrphansPresent {
            head: None,
            orphan_count: 1,
        }
    );
}

#[test]
fn directory_handle_flush_is_observational_not_commit_authority() {
    let fixture = Fixture::new("directory-flush");
    let root = fixture.open();
    let identity_before = file_identity(&root).expect("query root identity before probe");
    // SAFETY: this is an observational call on the live retained synthetic
    // directory handle. Its result is deliberately not used as commit proof.
    let succeeded = unsafe { FlushFileBuffers(root.as_raw_handle() as HANDLE) } != 0;
    let outcome = if succeeded {
        "SUCCESS"
    } else {
        // SAFETY: this reads the thread-local error from the immediately
        // preceding failed FlushFileBuffers call.
        match unsafe { GetLastError() } {
            ERROR_ACCESS_DENIED => "FAILURE_ACCESS_DENIED",
            ERROR_INVALID_HANDLE => "FAILURE_INVALID_HANDLE",
            _ => "FAILURE_OTHER",
        }
    };
    assert_eq!(
        file_identity(&root).expect("query root identity after probe"),
        identity_before
    );
    println!("generation_directory_handle_flush={outcome}");
}
