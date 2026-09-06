//! Retained-handle physical-identity regression tests.
//!
//! This test creates an empty synthetic directory outside the
//! repository. It never creates a candidate workspace or writes reconstructed
//! plaintext.

use std::fs;
use std::io;
use std::mem::size_of;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use windows_sys::Wdk::Storage::FileSystem::{
    FileIsRemoteDeviceInformation, NtQueryInformationFile,
};
use windows_sys::Wdk::System::SystemServices::FILE_IS_REMOTE_DEVICE_INFORMATION;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    FileIdInfo, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_ID_INFO, FILE_NAME_OPENED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::*;

const FIXTURE_PREFIX: &str = "R7C";
const INITIAL_ROOT: &str = "identity-root-a";
const RENAMED_ROOT: &str = "identity-root-b";

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity128 {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

fn query_file_identity(handle: &impl AsRawHandle) -> io::Result<FileIdentity128> {
    let mut identity = FILE_ID_INFO::default();
    // SAFETY: the retained directory handle and exact-size writable
    // FILE_ID_INFO remain live for the synchronous query.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle() as HANDLE,
            FileIdInfo,
            (&mut identity as *mut FILE_ID_INFO).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>())
                .map_err(|_| io::Error::other("file identity structure size"))?,
        )
    };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity128 {
        volume_serial_number: identity.VolumeSerialNumber,
        file_id: identity.FileId.Identifier,
    })
}

struct SharedDeleteHandleQuery<'a> {
    handle: &'a fs::File,
}

impl HandleQuery for SharedDeleteHandleQuery<'_> {
    fn is_remote(&self) -> Result<bool, ()> {
        let mut io_status = IO_STATUS_BLOCK::default();
        let mut remote = FILE_IS_REMOTE_DEVICE_INFORMATION::default();
        // SAFETY: the retained directory handle and exact ABI outputs remain
        // live for the synchronous query.
        let status = unsafe {
            NtQueryInformationFile(
                self.handle.as_raw_handle() as HANDLE,
                &mut io_status,
                (&mut remote as *mut FILE_IS_REMOTE_DEVICE_INFORMATION).cast(),
                u32::try_from(size_of::<FILE_IS_REMOTE_DEVICE_INFORMATION>()).map_err(|_| ())?,
                FileIsRemoteDeviceInformation,
            )
        };
        if status < 0 {
            return Err(());
        }
        Ok(remote.IsRemote)
    }

    fn filesystem_name(&self) -> Result<Vec<u16>, ()> {
        let mut filesystem = [0u16; 16];
        // SAFETY: the retained directory handle and fixed writable filesystem
        // name buffer remain live for the synchronous query.
        let queried = unsafe {
            GetVolumeInformationByHandleW(
                self.handle.as_raw_handle() as HANDLE,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                filesystem.as_mut_ptr(),
                u32::try_from(filesystem.len()).map_err(|_| ())?,
            )
        };
        if queried == 0 {
            return Err(());
        }
        read_nul_terminated(&filesystem)
    }

    fn final_guid_path(&self) -> Result<Vec<u16>, ()> {
        let mut buffer = vec![0u16; FINAL_PATH_BUFFER_UNITS];
        // SAFETY: the retained directory handle and exact writable buffer
        // remain live for the synchronous query.
        let written = unsafe {
            GetFinalPathNameByHandleW(
                self.handle.as_raw_handle() as HANDLE,
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).map_err(|_| ())?,
                FILE_NAME_OPENED | VOLUME_NAME_GUID,
            )
        };
        let written = usize::try_from(written).map_err(|_| ())?;
        if written == 0 || written >= buffer.len() {
            return Err(());
        }
        buffer.truncate(written);
        if std::char::decode_utf16(buffer.iter().copied()).any(|unit| unit.is_err()) {
            return Err(());
        }
        Ok(buffer)
    }
}

fn open_qualified_candidate(path: &Path) -> (fs::File, TrustedVolumeAnchor) {
    let preflight = preflight_source_path(path).expect("qualify synthetic local NTFS directory");
    let anchor = preflight.path.anchor().clone();
    let mut options = fs::OpenOptions::new();
    options
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let retained = options
        .open(path)
        .expect("open shared-delete retained synthetic directory");
    assert!(
        retained
            .metadata()
            .expect("read retained synthetic root metadata")
            .is_dir(),
        "retained synthetic root must be a directory"
    );
    confirm_with_query(&SharedDeleteHandleQuery { handle: &retained }, &anchor)
        .expect("confirm retained synthetic directory on selected local NTFS");
    (retained, anchor)
}

struct Fixture {
    parent: PathBuf,
    temp_parent: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);

        let temp_parent = std::env::temp_dir();
        let workspace = std::env::current_dir().expect("read current directory");
        assert!(
            !temp_parent.starts_with(&workspace) && !workspace.starts_with(&temp_parent),
            "identity test fixture must be outside the repository"
        );
        let initial = u64::from(std::process::id()) + NEXT.fetch_add(1, Ordering::Relaxed);
        let parent = (0..1_024u64)
            .find_map(|attempt| {
                let value = initial.wrapping_add(attempt) & 0x0FFF_FFFF;
                let candidate = temp_parent.join(format!("{FIXTURE_PREFIX}{value:07X}"));
                match fs::create_dir(&candidate) {
                    Ok(()) => Some(candidate),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                    Err(_) => panic!("create synthetic identity fixture"),
                }
            })
            .expect("bounded synthetic identity fixture namespace");
        Self {
            parent,
            temp_parent,
        }
    }

    fn initial_root(&self) -> PathBuf {
        self.parent.join(INITIAL_ROOT)
    }

    fn renamed_root(&self) -> PathBuf {
        self.parent.join(RENAMED_ROOT)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let safe_name = self
            .parent
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| {
                name.len() == 10
                    && name.starts_with(FIXTURE_PREFIX)
                    && name[FIXTURE_PREFIX.len()..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
            });
        if self.parent.parent() == Some(self.temp_parent.as_path()) && safe_name {
            let _ = fs::remove_dir_all(&self.parent);
        }
    }
}

#[test]
fn retained_candidate_like_handle_exposes_stable_same_volume_identity() {
    let fixture = Fixture::new();
    let initial_root = fixture.initial_root();
    let renamed_root = fixture.renamed_root();
    fs::create_dir(&initial_root).expect("create empty synthetic identity root");

    let (retained_root, anchor) = open_qualified_candidate(&initial_root);
    let first_guid_path = SharedDeleteHandleQuery {
        handle: &retained_root,
    }
    .final_guid_path()
    .expect("query selected volume GUID through retained root handle");
    assert!(
        anchor.matches_handle_path(&first_guid_path),
        "retained handle must select the locality anchor"
    );

    let before = query_file_identity(&retained_root).expect("query first FILE_ID_INFO");
    let repeated = query_file_identity(&retained_root).expect("repeat FILE_ID_INFO query");
    assert!(
        before == repeated,
        "volume serial and FileId128 must be stable on the retained handle"
    );

    fs::rename(&initial_root, &renamed_root).expect("rename synthetic root on the same volume");
    let renamed_preflight =
        preflight_source_path(&renamed_root).expect("requalify renamed synthetic root");
    assert!(
        renamed_preflight.path.anchor() == &anchor,
        "renamed path must select the same TrustedVolumeAnchor"
    );
    confirm_with_query(
        &SharedDeleteHandleQuery {
            handle: &retained_root,
        },
        &anchor,
    )
    .expect("reconfirm renamed retained root on selected local NTFS");
    let renamed_guid_path = SharedDeleteHandleQuery {
        handle: &retained_root,
    }
    .final_guid_path()
    .expect("query volume GUID after same-volume rename");
    assert!(
        anchor.matches_handle_path(&renamed_guid_path),
        "renamed retained handle must preserve the selected volume anchor"
    );
    let after_rename =
        query_file_identity(&retained_root).expect("query FILE_ID_INFO after rename");
    assert!(
        before == after_rename,
        "same-volume rename must preserve observed FILE_ID_INFO identity"
    );

    drop(retained_root);
    fs::remove_dir(&renamed_root).expect("remove empty synthetic identity root");
    fs::create_dir(&renamed_root).expect("recreate empty synthetic identity root");
    let (recreated_root, recreated_anchor) = open_qualified_candidate(&renamed_root);
    assert!(
        recreated_anchor == anchor,
        "recreated root must remain on the selected volume"
    );
    let recreated =
        query_file_identity(&recreated_root).expect("query recreated root FILE_ID_INFO");
    assert!(
        recreated.volume_serial_number == before.volume_serial_number,
        "recreated root must retain the volume context on this test row"
    );
    assert!(
        recreated.file_id != before.file_id,
        "delete and recreate must produce a distinct FileId128 on this test row"
    );
}
