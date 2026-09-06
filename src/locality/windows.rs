use std::ffi::{OsStr, OsString};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr;

use cap_std::fs::Dir;
use windows_sys::Wdk::Storage::FileSystem::{
    FileIsRemoteDeviceInformation, NtQueryInformationFile,
};
use windows_sys::Wdk::System::SystemServices::FILE_IS_REMOTE_DEVICE_INFORMATION;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, QueryDosDeviceW, FILE_NAME_OPENED, VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::{
    ConfirmedLocalOutputParent, ConfirmedLocalSource, ConfirmedLocalVolumePath,
    ConfirmedRoundTripApplyPaths, ConfirmedRoundTripCreatePaths, LocalityError,
    PreflightedOutputPath, PreflightedRoundTripApplyPaths, PreflightedRoundTripCreatePaths,
    PreflightedSourcePath,
};
use crate::detection::is_git_metadata_component;
use crate::fs_boundary::{self, TrustedVolumeAnchor, TrustedVolumePath};

const MAX_LOCAL_VOLUMES: usize = 256;
const DOS_DEVICE_BUFFER_UNITS: usize = 32_768;
const VOLUME_NAME_BUFFER_UNITS: usize = 1_024;
const FINAL_PATH_BUFFER_UNITS: usize = 32_768;

pub(super) fn preflight_source_path(source: &Path) -> Result<PreflightedSourcePath, LocalityError> {
    let resolver = StandardAbsoluteResolver;
    let namespace = WindowsNamespace;
    preflight_source_with(source, &resolver, &namespace)
}

pub(super) fn preflight_clone_paths(
    source: &Path,
    output: &Path,
) -> Result<(PreflightedSourcePath, PreflightedOutputPath), LocalityError> {
    let resolver = StandardAbsoluteResolver;
    let namespace = WindowsNamespace;
    preflight_clone_with(source, output, &resolver, &namespace)
}

pub(super) fn preflight_roundtrip_create_paths(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
) -> Result<PreflightedRoundTripCreatePaths, LocalityError> {
    let resolver = StandardAbsoluteResolver;
    let namespace = WindowsNamespace;

    // Classify all three user paths before selecting or opening anything.
    let original = classify_source_path(original, &resolver)?;
    let ai = classify_output_path(ai_workspace, &resolver)?;
    let state = classify_output_path(private_state, &resolver)?;

    let original = finish_source_preflight(original, &namespace)?;
    let ai = finish_output_preflight(ai, &namespace)?;
    let state = finish_output_preflight(state, &namespace)?;
    Ok(PreflightedRoundTripCreatePaths {
        original: original.path,
        ai_parent: ai.parent,
        ai_leaf: ai.output_leaf,
        state_parent: state.parent,
        state_leaf: state.output_leaf,
    })
}

pub(super) fn preflight_roundtrip_state_path(
    private_state: &Path,
) -> Result<PreflightedSourcePath, LocalityError> {
    let resolver = StandardAbsoluteResolver;
    let namespace = WindowsNamespace;
    let state = classify_source_path(private_state, &resolver)?;
    finish_source_preflight(state, &namespace)
}

pub(super) fn preflight_roundtrip_apply_paths(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
    candidate: &Path,
) -> Result<PreflightedRoundTripApplyPaths, LocalityError> {
    let resolver = StandardAbsoluteResolver;
    let namespace = WindowsNamespace;

    // Fix all four lexical path classes before any namespace query, then
    // select every OS-generated local-volume anchor before any handle open.
    let original = classify_source_path(original, &resolver)?;
    let ai = classify_output_path(ai_workspace, &resolver)?;
    let state = classify_output_path(private_state, &resolver)?;
    let candidate = classify_output_path(candidate, &resolver)?;

    let original = finish_source_preflight(original, &namespace)?;
    let ai = finish_output_preflight(ai, &namespace)?;
    let state = finish_output_preflight(state, &namespace)?;
    let candidate = finish_output_preflight(candidate, &namespace)?;
    Ok(PreflightedRoundTripApplyPaths {
        original: original.path,
        ai_parent: ai.parent,
        ai_leaf: ai.output_leaf,
        state_parent: state.parent,
        state_leaf: state.output_leaf,
        candidate_parent: candidate.parent,
        candidate_leaf: candidate.output_leaf,
    })
}

fn preflight_source_with(
    source: &Path,
    resolver: &impl AbsoluteResolver,
    namespace: &impl NamespaceAdapter,
) -> Result<PreflightedSourcePath, LocalityError> {
    let classified = classify_source_path(source, resolver)?;
    finish_source_preflight(classified, namespace)
}

fn finish_source_preflight(
    classified: ClassifiedPath,
    namespace: &impl NamespaceAdapter,
) -> Result<PreflightedSourcePath, LocalityError> {
    let anchor = select_local_volume(classified.drive, namespace)?;
    let path = TrustedVolumePath::new(anchor, classified.components)
        .map_err(|_| LocalityError::UnsupportedPathClass)?;
    Ok(PreflightedSourcePath { path })
}

#[cfg(test)]
fn preflight_output_with(
    output: &Path,
    resolver: &impl AbsoluteResolver,
    namespace: &impl NamespaceAdapter,
) -> Result<PreflightedOutputPath, LocalityError> {
    let classified = classify_output_path(output, resolver)?;
    finish_output_preflight(classified, namespace)
}

fn finish_output_preflight(
    classified: ClassifiedOutputPath,
    namespace: &impl NamespaceAdapter,
) -> Result<PreflightedOutputPath, LocalityError> {
    let ClassifiedOutputPath {
        drive,
        parent_components,
        output_leaf,
    } = classified;
    let anchor = select_local_volume(drive, namespace)?;
    let parent = TrustedVolumePath::new(anchor, parent_components)
        .map_err(|_| LocalityError::UnsupportedPathClass)?;
    Ok(PreflightedOutputPath {
        parent,
        output_leaf,
    })
}

fn preflight_clone_with(
    source: &Path,
    output: &Path,
    resolver: &impl AbsoluteResolver,
    namespace: &impl NamespaceAdapter,
) -> Result<(PreflightedSourcePath, PreflightedOutputPath), LocalityError> {
    let source = classify_source_path(source, resolver)?;
    let output = classify_output_path(output, resolver)?;
    let source = finish_source_preflight(source, namespace)?;
    let output = finish_output_preflight(output, namespace)?;
    Ok((source, output))
}

fn classify_source_path(
    source: &Path,
    resolver: &impl AbsoluteResolver,
) -> Result<ClassifiedPath, LocalityError> {
    let classified = classify_path(source, resolver)?;
    reject_git_metadata_boundary(&classified.components)?;
    Ok(classified)
}

fn classify_output_path(
    output: &Path,
    resolver: &impl AbsoluteResolver,
) -> Result<ClassifiedOutputPath, LocalityError> {
    let mut classified = classify_path(output, resolver)?;
    reject_git_metadata_boundary(&classified.components)?;
    let output_leaf = classified
        .components
        .pop()
        .ok_or(LocalityError::UnsupportedPathClass)?;
    if !valid_normal_component(&output_leaf) {
        return Err(LocalityError::UnsupportedPathClass);
    }
    Ok(ClassifiedOutputPath {
        drive: classified.drive,
        parent_components: classified.components,
        output_leaf,
    })
}

pub(super) fn open_and_confirm_source(
    source: PreflightedSourcePath,
) -> Result<ConfirmedLocalSource, LocalityError> {
    let opened = fs_boundary::open_trusted_volume_dir_nofollow(&source.path)
        .map_err(|_| LocalityError::CapabilityOpenFailed)?;
    confirm_local_filesystem(&opened.directory, source.path.anchor())?;
    let identity = opened
        .ancestor_identities
        .last()
        .copied()
        .ok_or(LocalityError::CapabilityOpenFailed)?;
    fs_boundary::reconfirm_opened_directory(&opened.directory, identity)
        .map_err(|_| LocalityError::CapabilityOpenFailed)?;
    Ok(ConfirmedLocalSource {
        directory: opened.directory,
        identity,
    })
}

pub(super) fn open_and_confirm_output_parent(
    output: PreflightedOutputPath,
) -> Result<ConfirmedLocalOutputParent, LocalityError> {
    let opened = fs_boundary::open_trusted_volume_dir_nofollow(&output.parent)
        .map_err(|_| LocalityError::CapabilityOpenFailed)?;
    confirm_local_filesystem(&opened.directory, output.parent.anchor())?;
    let parent_identity = opened
        .ancestor_identities
        .last()
        .copied()
        .ok_or(LocalityError::CapabilityOpenFailed)?;
    fs_boundary::reconfirm_opened_directory(&opened.directory, parent_identity)
        .map_err(|_| LocalityError::CapabilityOpenFailed)?;
    Ok(ConfirmedLocalOutputParent {
        directory: opened.directory,
        output_leaf: output.output_leaf,
        ancestor_identities: opened.ancestor_identities,
    })
}

pub(super) fn open_and_confirm_roundtrip_volumes(
    paths: PreflightedRoundTripCreatePaths,
) -> Result<ConfirmedRoundTripCreatePaths, LocalityError> {
    // Each call opens only an OS-enumerated volume-GUID root and confirms the
    // handle against that selected anchor. User components remain unopened.
    let original = open_and_confirm_volume_path(paths.original)?;
    let ai_parent = open_and_confirm_volume_path(paths.ai_parent)?;
    let state_parent = open_and_confirm_volume_path(paths.state_parent)?;
    Ok(ConfirmedRoundTripCreatePaths {
        original,
        ai_parent,
        ai_leaf: paths.ai_leaf,
        state_parent,
        state_leaf: paths.state_leaf,
    })
}

pub(super) fn open_and_confirm_roundtrip_state_volume(
    path: PreflightedSourcePath,
) -> Result<ConfirmedLocalVolumePath, LocalityError> {
    open_and_confirm_volume_path(path.path)
}

pub(super) fn open_and_confirm_roundtrip_apply_volumes(
    paths: PreflightedRoundTripApplyPaths,
) -> Result<ConfirmedRoundTripApplyPaths, LocalityError> {
    let original = open_and_confirm_volume_path(paths.original)?;
    let ai_parent = open_and_confirm_volume_path(paths.ai_parent)?;
    let state_parent = open_and_confirm_volume_path(paths.state_parent)?;
    let candidate_parent = open_and_confirm_volume_path(paths.candidate_parent)?;
    Ok(ConfirmedRoundTripApplyPaths {
        original,
        ai_parent,
        ai_leaf: paths.ai_leaf,
        state_parent,
        state_leaf: paths.state_leaf,
        candidate_parent,
        candidate_leaf: paths.candidate_leaf,
    })
}

fn open_and_confirm_volume_path(
    path: TrustedVolumePath,
) -> Result<ConfirmedLocalVolumePath, LocalityError> {
    let volume_root = fs_boundary::open_trusted_volume_root_nofollow(path.anchor())
        .map_err(|_| LocalityError::CapabilityOpenFailed)?;
    confirm_local_filesystem(&volume_root, path.anchor())?;
    let identity = fs_boundary::directory_identity(&volume_root)
        .map_err(|_| LocalityError::CapabilityOpenFailed)?;
    fs_boundary::reconfirm_opened_directory(&volume_root, identity)
        .map_err(|_| LocalityError::CapabilityOpenFailed)?;
    let anchor = path.anchor().clone();
    Ok(ConfirmedLocalVolumePath {
        volume_root,
        components: path.components().to_vec(),
        anchor,
    })
}

struct ClassifiedPath {
    drive: u8,
    components: Vec<OsString>,
}

struct ClassifiedOutputPath {
    drive: u8,
    parent_components: Vec<OsString>,
    output_leaf: OsString,
}

trait AbsoluteResolver {
    fn absolute(&self, path: &Path) -> Result<PathBuf, ()>;
}

struct StandardAbsoluteResolver;

impl AbsoluteResolver for StandardAbsoluteResolver {
    fn absolute(&self, path: &Path) -> Result<PathBuf, ()> {
        std::path::absolute(path).map_err(|_| ())
    }
}

fn classify_path(
    original: &Path,
    resolver: &impl AbsoluteResolver,
) -> Result<ClassifiedPath, LocalityError> {
    if original.as_os_str().is_empty() || contains_nul(original.as_os_str()) {
        return Err(LocalityError::UnsupportedPathClass);
    }

    let mut components = original.components();
    let first = components
        .next()
        .ok_or(LocalityError::UnsupportedPathClass)?;
    let absolute = match first {
        Component::Prefix(prefix) => match prefix.kind() {
            Prefix::Disk(_) => {
                if !matches!(components.next(), Some(Component::RootDir)) {
                    return Err(LocalityError::UnsupportedPathClass);
                }
                None
            }
            Prefix::Verbatim(_)
            | Prefix::VerbatimUNC(_, _)
            | Prefix::VerbatimDisk(_)
            | Prefix::DeviceNS(_)
            | Prefix::UNC(_, _) => return Err(LocalityError::UnsupportedPathClass),
        },
        Component::RootDir => return Err(LocalityError::UnsupportedPathClass),
        Component::CurDir | Component::ParentDir | Component::Normal(_) => Some(
            resolver
                .absolute(original)
                .map_err(|_| LocalityError::UnsupportedPathClass)?,
        ),
    };

    classify_absolute_disk(absolute.as_deref().unwrap_or(original))
}

fn classify_absolute_disk(path: &Path) -> Result<ClassifiedPath, LocalityError> {
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) if drive.is_ascii_alphabetic() => drive.to_ascii_uppercase(),
            _ => return Err(LocalityError::UnsupportedPathClass),
        },
        _ => return Err(LocalityError::UnsupportedPathClass),
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(LocalityError::UnsupportedPathClass);
    }

    let mut validated = Vec::new();
    for component in components {
        match component {
            Component::Normal(name) if valid_normal_component(name) => {
                validated.push(name.to_owned());
            }
            _ => return Err(LocalityError::UnsupportedPathClass),
        }
    }
    Ok(ClassifiedPath {
        drive,
        components: validated,
    })
}

fn valid_normal_component(component: &OsStr) -> bool {
    !component.is_empty()
        && component.encode_wide().all(|unit| {
            unit != 0
                && unit != u16::from(b'/')
                && unit != u16::from(b'\\')
                && unit != u16::from(b':')
        })
        && matches!(
            Path::new(component).components().next(),
            Some(Component::Normal(_))
        )
        && Path::new(component).components().count() == 1
}

fn reject_git_metadata_boundary(components: &[OsString]) -> Result<(), LocalityError> {
    if components
        .iter()
        .any(|component| is_git_metadata_component(component))
    {
        Err(LocalityError::GitMetadataBoundaryRejected)
    } else {
        Ok(())
    }
}

fn contains_nul(value: &OsStr) -> bool {
    value.encode_wide().any(|unit| unit == 0)
}

trait NamespaceAdapter {
    fn query_dos_device(&self, device_name: &[u16]) -> Result<Vec<u16>, ()>;
    fn enumerate_local_volumes(&self) -> Result<Vec<Vec<u16>>, ()>;
}

struct WindowsNamespace;

impl NamespaceAdapter for WindowsNamespace {
    fn query_dos_device(&self, device_name: &[u16]) -> Result<Vec<u16>, ()> {
        let mut terminated = Vec::with_capacity(device_name.len().checked_add(1).ok_or(())?);
        terminated.extend_from_slice(device_name);
        terminated.push(0);

        let mut buffer = vec![0u16; DOS_DEVICE_BUFFER_UNITS];
        // SAFETY: `terminated` is NUL terminated and `buffer` is writable for
        // the exact fixed capacity passed to QueryDosDeviceW.
        let written = unsafe {
            QueryDosDeviceW(
                terminated.as_ptr(),
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).map_err(|_| ())?,
            )
        };
        bounded_query_result(buffer, usize::try_from(written).map_err(|_| ())?)
    }

    fn enumerate_local_volumes(&self) -> Result<Vec<Vec<u16>>, ()> {
        let mut buffer = [0u16; VOLUME_NAME_BUFFER_UNITS];
        // SAFETY: `buffer` is writable for the fixed capacity supplied.
        let handle = unsafe {
            FindFirstVolumeW(
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).map_err(|_| ())?,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(());
        }
        let mut guard = VolumeEnumeration::new(handle);
        let mut volumes = Vec::new();

        loop {
            if volumes.len() >= MAX_LOCAL_VOLUMES {
                return Err(());
            }
            volumes.push(read_nul_terminated(&buffer)?);
            buffer.fill(0);
            // SAFETY: the enumeration handle remains owned by `guard` and the
            // fixed buffer is writable for the supplied capacity.
            let found = unsafe {
                FindNextVolumeW(
                    guard.handle(),
                    buffer.as_mut_ptr(),
                    u32::try_from(buffer.len()).map_err(|_| ())?,
                )
            };
            if found != 0 {
                continue;
            }
            // SAFETY: GetLastError reads thread-local status for the immediately
            // preceding failed FindNextVolumeW call.
            if unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
                return Err(());
            }
            break;
        }

        guard.close()?;
        Ok(volumes)
    }
}

struct VolumeEnumeration {
    handle: Option<HANDLE>,
}

impl VolumeEnumeration {
    fn new(handle: HANDLE) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    fn handle(&self) -> HANDLE {
        self.handle.expect("live volume enumeration handle")
    }

    fn close(&mut self) -> Result<(), ()> {
        let handle = self.handle.take().ok_or(())?;
        // SAFETY: the handle came from FindFirstVolumeW and is closed once.
        if unsafe { FindVolumeClose(handle) } == 0 {
            return Err(());
        }
        Ok(())
    }
}

impl Drop for VolumeEnumeration {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            // SAFETY: best-effort close of the still-owned enumeration handle.
            unsafe {
                FindVolumeClose(handle);
            }
        }
    }
}

fn select_local_volume(
    drive: u8,
    namespace: &impl NamespaceAdapter,
) -> Result<TrustedVolumeAnchor, LocalityError> {
    let drive_name = [u16::from(drive), u16::from(b':')];
    let initial = current_mapping(
        namespace
            .query_dos_device(&drive_name)
            .map_err(|_| LocalityError::LocalityUnavailable)?,
    )?;
    let volume_names = namespace
        .enumerate_local_volumes()
        .map_err(|_| LocalityError::LocalityUnavailable)?;
    if volume_names.len() > MAX_LOCAL_VOLUMES {
        return Err(LocalityError::LocalityUnavailable);
    }

    let mut matched = None;
    let mut match_count = 0usize;
    for volume_name in volume_names {
        let anchor = TrustedVolumeAnchor::parse_enumerated(&volume_name)
            .map_err(|_| LocalityError::LocalityUnavailable)?;
        let mapping = current_mapping(
            namespace
                .query_dos_device(anchor.device_name())
                .map_err(|_| LocalityError::LocalityUnavailable)?,
        )?;
        if mapping == initial {
            match_count = match_count
                .checked_add(1)
                .ok_or(LocalityError::LocalityUnavailable)?;
            matched = Some(anchor);
        }
    }
    if match_count != 1 {
        return Err(LocalityError::LocalVolumeNotProven);
    }

    let final_mapping = current_mapping(
        namespace
            .query_dos_device(&drive_name)
            .map_err(|_| LocalityError::LocalityUnavailable)?,
    )?;
    if final_mapping != initial {
        return Err(LocalityError::PreflightChanged);
    }
    matched.ok_or(LocalityError::LocalVolumeNotProven)
}

fn current_mapping(raw: Vec<u16>) -> Result<Vec<u16>, LocalityError> {
    if raw.len() < 3 || raw[raw.len() - 2..] != [0, 0] {
        return Err(LocalityError::LocalityUnavailable);
    }
    let mut first = None;
    let mut cursor = 0usize;
    loop {
        let relative_end = raw[cursor..]
            .iter()
            .position(|unit| *unit == 0)
            .ok_or(LocalityError::LocalityUnavailable)?;
        let end = cursor
            .checked_add(relative_end)
            .ok_or(LocalityError::LocalityUnavailable)?;
        if end == cursor {
            if first.is_none() || raw[cursor..].iter().any(|unit| *unit != 0) {
                return Err(LocalityError::LocalityUnavailable);
            }
            break;
        }
        if std::char::decode_utf16(raw[cursor..end].iter().copied()).any(|unit| unit.is_err()) {
            return Err(LocalityError::LocalityUnavailable);
        }
        if first.is_none() {
            first = Some(raw[cursor..end].to_vec());
        }
        cursor = end
            .checked_add(1)
            .ok_or(LocalityError::LocalityUnavailable)?;
        if cursor >= raw.len() {
            return Err(LocalityError::LocalityUnavailable);
        }
    }
    first.ok_or(LocalityError::LocalityUnavailable)
}

fn bounded_query_result(mut buffer: Vec<u16>, written: usize) -> Result<Vec<u16>, ()> {
    if written == 0 || written >= buffer.len() {
        return Err(());
    }
    buffer.truncate(written);
    Ok(buffer)
}

fn read_nul_terminated(buffer: &[u16]) -> Result<Vec<u16>, ()> {
    let end = buffer.iter().position(|unit| *unit == 0).ok_or(())?;
    if end == 0 || std::char::decode_utf16(buffer[..end].iter().copied()).any(|unit| unit.is_err())
    {
        return Err(());
    }
    Ok(buffer[..end].to_vec())
}

trait HandleQuery {
    fn is_remote(&self) -> Result<bool, ()>;
    fn filesystem_name(&self) -> Result<Vec<u16>, ()>;
    fn final_guid_path(&self) -> Result<Vec<u16>, ()>;
}

struct WindowsHandleQuery<'a> {
    directory: &'a Dir,
}

impl HandleQuery for WindowsHandleQuery<'_> {
    fn is_remote(&self) -> Result<bool, ()> {
        let mut io_status = IO_STATUS_BLOCK::default();
        let mut remote = FILE_IS_REMOTE_DEVICE_INFORMATION::default();
        // SAFETY: the retained directory handle is live and both outputs are
        // correctly sized writable ABI values.
        let status = unsafe {
            NtQueryInformationFile(
                self.directory.as_raw_handle() as HANDLE,
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
        // SAFETY: the retained directory handle is live and `filesystem` is a
        // writable fixed buffer. Optional outputs are deliberately null.
        let queried = unsafe {
            GetVolumeInformationByHandleW(
                self.directory.as_raw_handle() as HANDLE,
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
        // SAFETY: the retained directory handle is live and `buffer` is
        // writable for the exact fixed capacity supplied.
        let written = unsafe {
            GetFinalPathNameByHandleW(
                self.directory.as_raw_handle() as HANDLE,
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

fn confirm_local_filesystem(
    directory: &Dir,
    expected: &TrustedVolumeAnchor,
) -> Result<(), LocalityError> {
    confirm_with_query(&WindowsHandleQuery { directory }, expected)
}

fn confirm_with_query(
    query: &impl HandleQuery,
    expected: &TrustedVolumeAnchor,
) -> Result<(), LocalityError> {
    if query
        .is_remote()
        .map_err(|_| LocalityError::LocalityUnavailable)?
    {
        return Err(LocalityError::RemoteFilesystem);
    }
    let filesystem = query
        .filesystem_name()
        .map_err(|_| LocalityError::LocalityUnavailable)?;
    if !utf16_ascii_eq_ignore_case(&filesystem, b"NTFS") {
        return Err(LocalityError::UnsupportedFilesystem);
    }
    let final_path = query
        .final_guid_path()
        .map_err(|_| LocalityError::LocalityUnavailable)?;
    if !expected.matches_handle_path(&final_path) {
        return Err(LocalityError::HandleVolumeMismatch);
    }
    Ok(())
}

fn utf16_ascii_eq_ignore_case(actual: &[u16], expected: &[u8]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            u8::try_from(*actual).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
        })
}

#[cfg(test)]
mod short_name_tests;

#[cfg(test)]
mod alias_namespace_tests;

#[cfg(test)]
mod candidate_identity_tests;

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::os::windows::ffi::OsStringExt;

    use super::*;

    const GUID_ONE: &str = "00000000-0000-0000-0000-000000000001";
    const GUID_TWO: &str = "00000000-0000-0000-0000-000000000002";

    fn volume(guid: &str) -> Vec<u16> {
        format!("\\\\?\\Volume{{{guid}}}\\")
            .encode_utf16()
            .collect()
    }

    fn anchor(guid: &str) -> TrustedVolumeAnchor {
        TrustedVolumeAnchor::parse_enumerated(&volume(guid)).expect("valid synthetic volume")
    }

    fn multi(entries: &[&[u16]]) -> Vec<u16> {
        let mut result = Vec::new();
        for entry in entries {
            result.extend_from_slice(entry);
            result.push(0);
        }
        result.push(0);
        result
    }

    fn mapping(value: &str) -> Vec<u16> {
        let units = value.encode_utf16().collect::<Vec<_>>();
        multi(&[&units])
    }

    struct MockResolver {
        result: Result<PathBuf, ()>,
        calls: Cell<usize>,
    }

    impl MockResolver {
        fn returning(path: impl Into<PathBuf>) -> Self {
            Self {
                result: Ok(path.into()),
                calls: Cell::new(0),
            }
        }
    }

    impl AbsoluteResolver for MockResolver {
        fn absolute(&self, _path: &Path) -> Result<PathBuf, ()> {
            self.calls.set(self.calls.get() + 1);
            self.result.clone()
        }
    }

    struct MockNamespace {
        queries: RefCell<VecDeque<Result<Vec<u16>, ()>>>,
        volumes: Result<Vec<Vec<u16>>, ()>,
        query_calls: Cell<usize>,
        enumeration_calls: Cell<usize>,
    }

    impl MockNamespace {
        fn new(
            queries: impl IntoIterator<Item = Result<Vec<u16>, ()>>,
            volumes: Result<Vec<Vec<u16>>, ()>,
        ) -> Self {
            Self {
                queries: RefCell::new(queries.into_iter().collect()),
                volumes,
                query_calls: Cell::new(0),
                enumeration_calls: Cell::new(0),
            }
        }

        fn accepting() -> Self {
            let local = mapping(r"\Device\HarddiskVolume42");
            Self::new(
                [Ok(local.clone()), Ok(local.clone()), Ok(local)],
                Ok(vec![volume(GUID_ONE)]),
            )
        }
    }

    impl NamespaceAdapter for MockNamespace {
        fn query_dos_device(&self, _device_name: &[u16]) -> Result<Vec<u16>, ()> {
            self.query_calls.set(self.query_calls.get() + 1);
            self.queries.borrow_mut().pop_front().unwrap_or(Err(()))
        }

        fn enumerate_local_volumes(&self) -> Result<Vec<Vec<u16>>, ()> {
            self.enumeration_calls.set(self.enumeration_calls.get() + 1);
            self.volumes.clone()
        }
    }

    #[test]
    fn lexical_rejections_happen_before_resolution_or_namespace_queries() {
        let resolver = MockResolver::returning(r"C:\resolved");
        let rejected = [
            "",
            r"\\server\share\source",
            r"\\?\UNC\server\share\source",
            r"\\.\PIPE\source",
            r"\\?\Volume{00000000-0000-0000-0000-000000000001}\source",
            r"\\?\C:\source",
            r"C:source",
            r"\source",
        ];

        for input in rejected {
            let namespace = MockNamespace::new([], Err(()));
            assert_eq!(
                preflight_source_with(Path::new(input), &resolver, &namespace)
                    .expect_err("input class should reject"),
                LocalityError::UnsupportedPathClass
            );
            assert_eq!(namespace.query_calls.get(), 0);
            assert_eq!(namespace.enumeration_calls.get(), 0);
        }
        assert_eq!(resolver.calls.get(), 0);

        let embedded_nul = PathBuf::from(OsString::from_wide(&[
            u16::from(b'C'),
            u16::from(b':'),
            u16::from(b'\\'),
            u16::from(b'a'),
            0,
            u16::from(b'b'),
        ]));
        let namespace = MockNamespace::new([], Err(()));
        assert_eq!(
            preflight_source_with(&embedded_nul, &resolver, &namespace)
                .expect_err("embedded NUL rejects"),
            LocalityError::UnsupportedPathClass
        );
        assert_eq!(namespace.query_calls.get(), 0);
        assert_eq!(namespace.enumeration_calls.get(), 0);
    }

    #[test]
    fn git_metadata_boundaries_reject_before_namespace_queries() {
        let resolver = MockResolver::returning(r"Z:\must-not-be-used");
        for source in [
            r"C:\repo\.git",
            r"C:\repo\.GIT",
            r"C:\repo\.GiT",
            r"C:\repo\.git\objects",
            r"C:\repo\.GiT\worktrees\x",
        ] {
            let namespace = MockNamespace::new([], Err(()));
            assert_eq!(
                preflight_source_with(Path::new(source), &resolver, &namespace)
                    .expect_err("source git metadata boundary rejects"),
                LocalityError::GitMetadataBoundaryRejected
            );
            assert_eq!(namespace.query_calls.get(), 0);
            assert_eq!(namespace.enumeration_calls.get(), 0);
        }
        assert_eq!(resolver.calls.get(), 0);

        for output in [
            r"C:\repo\.git\safe-output",
            r"C:\repo\.GIT\safe-output",
            r"C:\repo\.git",
            r"C:\repo\.GiT",
        ] {
            let namespace = MockNamespace::new([], Err(()));
            assert_eq!(
                preflight_output_with(Path::new(output), &resolver, &namespace)
                    .expect_err("output git metadata boundary rejects"),
                LocalityError::GitMetadataBoundaryRejected
            );
            assert_eq!(namespace.query_calls.get(), 0);
            assert_eq!(namespace.enumeration_calls.get(), 0);
        }
        assert_eq!(resolver.calls.get(), 0);
    }

    #[test]
    fn relative_git_boundary_rejection_uses_only_the_absolute_resolver() {
        let resolver = MockResolver::returning(r"C:\workspace\.git\objects");
        let namespace = MockNamespace::new([], Err(()));

        assert_eq!(
            preflight_source_with(Path::new(r"relative\source"), &resolver, &namespace)
                .expect_err("resolved git metadata boundary rejects"),
            LocalityError::GitMetadataBoundaryRejected
        );
        assert_eq!(resolver.calls.get(), 1);
        assert_eq!(namespace.query_calls.get(), 0);
        assert_eq!(namespace.enumeration_calls.get(), 0);
    }

    #[test]
    fn clone_classifies_both_boundaries_before_any_namespace_query() {
        let resolver = MockResolver::returning(r"Z:\must-not-be-used");
        let namespace = MockNamespace::new([], Err(()));

        assert_eq!(
            preflight_clone_with(
                Path::new(r"C:\ordinary\source"),
                Path::new(r"C:\output\.git\published"),
                &resolver,
                &namespace,
            )
            .expect_err("output git metadata rejects before source namespace proof"),
            LocalityError::GitMetadataBoundaryRejected
        );
        assert_eq!(resolver.calls.get(), 0);
        assert_eq!(namespace.query_calls.get(), 0);
        assert_eq!(namespace.enumeration_calls.get(), 0);
    }

    #[test]
    fn non_git_components_and_literal_trailing_forms_remain_distinct() {
        let resolver = MockResolver::returning(r"Z:\must-not-be-used");
        for component in [
            ".github",
            ".gitignore",
            ".gitattributes",
            "git",
            "my.git",
            "git-data",
            ".git.",
            ".git ",
            "ordinary",
        ] {
            let source = PathBuf::from(format!(r"C:\repo\{component}\source"));
            assert!(classify_source_path(&source, &resolver).is_ok());
            let output = PathBuf::from(format!(r"C:\repo\{component}"));
            assert!(classify_output_path(&output, &resolver).is_ok());
        }
        assert_eq!(resolver.calls.get(), 0);
    }

    #[test]
    fn relative_resolution_is_injected_and_reclassified() {
        let resolver = MockResolver::returning(r"C:\resolved\source");
        let namespace = MockNamespace::accepting();
        let token = preflight_source_with(Path::new(r"relative\source"), &resolver, &namespace)
            .expect("ordinary relative path resolves to disk-rooted form");
        assert_eq!(resolver.calls.get(), 1);
        assert_eq!(namespace.query_calls.get(), 3);
        assert!(!format!("{token:?}").contains("relative"));

        let resolver = MockResolver::returning(r"\\server\share\source");
        let namespace = MockNamespace::new([], Err(()));
        assert_eq!(
            preflight_source_with(Path::new("relative"), &resolver, &namespace)
                .expect_err("UNC absolute result rejects"),
            LocalityError::UnsupportedPathClass
        );
        assert_eq!(resolver.calls.get(), 1);
        assert_eq!(namespace.query_calls.get(), 0);
    }

    #[test]
    fn absolute_disk_shape_and_output_leaf_are_strict() {
        let resolver = MockResolver::returning(r"Z:\must-not-be-used");
        let namespace = MockNamespace::accepting();
        preflight_source_with(Path::new(r"C:\ordinary\source"), &resolver, &namespace)
            .expect("ordinary disk-rooted source accepted");
        assert_eq!(resolver.calls.get(), 0);

        let resolver = MockResolver::returning(r"Z:\must-not-be-used");
        let namespace = MockNamespace::accepting();
        preflight_source_with(Path::new(r"C:\"), &resolver, &namespace)
            .expect("source volume root remains allowed");
        assert_eq!(resolver.calls.get(), 0);

        for output in [r"C:\", r"C:\parent\..", r"C:\parent\bad:name"] {
            let resolver = MockResolver::returning(r"Z:\must-not-be-used");
            let namespace = MockNamespace::new([], Err(()));
            assert_eq!(
                preflight_output_with(Path::new(output), &resolver, &namespace)
                    .expect_err("malformed output rejects"),
                LocalityError::UnsupportedPathClass
            );
            assert_eq!(namespace.query_calls.get(), 0);
        }
    }

    #[test]
    fn positive_membership_selects_exactly_one_current_volume_mapping() {
        let a = mapping(r"\Device\HarddiskVolume10");
        let b = mapping(r"\Device\HarddiskVolume11");
        let namespace = MockNamespace::new(
            [Ok(a.clone()), Ok(b), Ok(a.clone()), Ok(a)],
            Ok(vec![volume(GUID_ONE), volume(GUID_TWO)]),
        );

        assert_eq!(select_local_volume(b'C', &namespace), Ok(anchor(GUID_TWO)));
        assert_eq!(namespace.query_calls.get(), 4);
        assert_eq!(namespace.enumeration_calls.get(), 1);
    }

    #[test]
    fn positive_membership_rejects_zero_multiple_and_stale_only_matches() {
        let a = mapping(r"\Device\HarddiskVolume10");
        let b_units = r"\Device\HarddiskVolume11"
            .encode_utf16()
            .collect::<Vec<_>>();
        let a_units = r"\Device\HarddiskVolume10"
            .encode_utf16()
            .collect::<Vec<_>>();
        let b = multi(&[&b_units]);

        let none = MockNamespace::new([Ok(a.clone()), Ok(b.clone())], Ok(vec![volume(GUID_ONE)]));
        assert_eq!(
            select_local_volume(b'C', &none),
            Err(LocalityError::LocalVolumeNotProven)
        );

        let duplicate = MockNamespace::new(
            [Ok(a.clone()), Ok(a.clone()), Ok(a.clone())],
            Ok(vec![volume(GUID_ONE), volume(GUID_TWO)]),
        );
        assert_eq!(
            select_local_volume(b'C', &duplicate),
            Err(LocalityError::LocalVolumeNotProven)
        );

        let stale_only = MockNamespace::new(
            [Ok(a), Ok(multi(&[&b_units, &a_units]))],
            Ok(vec![volume(GUID_ONE)]),
        );
        assert_eq!(
            select_local_volume(b'C', &stale_only),
            Err(LocalityError::LocalVolumeNotProven)
        );
    }

    #[test]
    fn namespace_errors_and_malformed_results_fail_closed() {
        let valid = mapping(r"\Device\HarddiskVolume10");
        let cases = [
            MockNamespace::new([Err(())], Ok(vec![])),
            MockNamespace::new([Ok(vec![0, 0, 0])], Ok(vec![])),
            MockNamespace::new([Ok(vec![u16::from(b'A'), 0])], Ok(vec![])),
            MockNamespace::new([Ok(vec![u16::from(b'A'), 0, 0xD800, 0, 0])], Ok(vec![])),
            MockNamespace::new(
                [Ok(vec![u16::from(b'A'), 0, 0, u16::from(b'B'), 0, 0])],
                Ok(vec![]),
            ),
            MockNamespace::new([Ok(valid.clone())], Err(())),
            MockNamespace::new([Ok(valid.clone()), Err(())], Ok(vec![volume(GUID_ONE)])),
            MockNamespace::new(
                [Ok(valid.clone())],
                Ok(vec![r"\\?\not-a-volume\".encode_utf16().collect()]),
            ),
        ];
        for namespace in cases {
            assert_eq!(
                select_local_volume(b'C', &namespace),
                Err(LocalityError::LocalityUnavailable)
            );
        }

        let mut too_many = Vec::new();
        for index in 0..=MAX_LOCAL_VOLUMES {
            too_many.push(volume(&format!("00000000-0000-0000-0000-{index:012x}")));
        }
        let namespace = MockNamespace::new([Ok(valid)], Ok(too_many));
        assert_eq!(
            select_local_volume(b'C', &namespace),
            Err(LocalityError::LocalityUnavailable)
        );
        assert_eq!(namespace.query_calls.get(), 1);

        assert_eq!(bounded_query_result(vec![0; 8], 0), Err(()));
        assert_eq!(bounded_query_result(vec![0; 8], 8), Err(()));
    }

    #[test]
    fn mapping_change_and_provider_like_nonmembership_fail_closed() {
        let a = mapping(r"\Device\HarddiskVolume10");
        let changed = MockNamespace::new(
            [
                Ok(a.clone()),
                Ok(a.clone()),
                Ok(mapping(r"\Device\HarddiskVolume99")),
            ],
            Ok(vec![volume(GUID_ONE)]),
        );
        assert_eq!(
            select_local_volume(b'C', &changed),
            Err(LocalityError::PreflightChanged)
        );

        let third_party = mapping(r"\Device\ArbitraryThirdPartyRedirector\opaque");
        let no_positive_match =
            MockNamespace::new([Ok(third_party), Ok(a)], Ok(vec![volume(GUID_ONE)]));
        assert_eq!(
            select_local_volume(b'C', &no_positive_match),
            Err(LocalityError::LocalVolumeNotProven)
        );
    }

    struct MockHandleQuery {
        remote: Result<bool, ()>,
        filesystem: Result<Vec<u16>, ()>,
        final_path: Result<Vec<u16>, ()>,
        calls: RefCell<Vec<&'static str>>,
    }

    impl MockHandleQuery {
        fn local_ntfs(final_path: Vec<u16>) -> Self {
            Self {
                remote: Ok(false),
                filesystem: Ok("NTFS".encode_utf16().collect()),
                final_path: Ok(final_path),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl HandleQuery for MockHandleQuery {
        fn is_remote(&self) -> Result<bool, ()> {
            self.calls.borrow_mut().push("remote");
            self.remote
        }

        fn filesystem_name(&self) -> Result<Vec<u16>, ()> {
            self.calls.borrow_mut().push("filesystem");
            self.filesystem.clone()
        }

        fn final_guid_path(&self) -> Result<Vec<u16>, ()> {
            self.calls.borrow_mut().push("volume");
            self.final_path.clone()
        }
    }

    fn final_path(guid: &str, suffix: &str) -> Vec<u16> {
        format!("\\\\?\\Volume{{{guid}}}\\{suffix}")
            .encode_utf16()
            .collect()
    }

    #[test]
    fn layer_two_stops_before_later_queries_when_remote_or_query_fails() {
        for remote in [Ok(true), Err(())] {
            let query = MockHandleQuery {
                remote,
                filesystem: Ok("NTFS".encode_utf16().collect()),
                final_path: Ok(final_path(GUID_ONE, "source")),
                calls: RefCell::new(Vec::new()),
            };
            let expected_error = if remote == Ok(true) {
                LocalityError::RemoteFilesystem
            } else {
                LocalityError::LocalityUnavailable
            };
            assert_eq!(
                confirm_with_query(&query, &anchor(GUID_ONE)),
                Err(expected_error)
            );
            assert_eq!(*query.calls.borrow(), vec!["remote"]);
        }
    }

    #[test]
    fn layer_two_requires_exact_ntfs_before_volume_identity() {
        for filesystem in ["ReFS", "CsvFS", "unknown"] {
            let query = MockHandleQuery {
                remote: Ok(false),
                filesystem: Ok(filesystem.encode_utf16().collect()),
                final_path: Ok(final_path(GUID_ONE, "source")),
                calls: RefCell::new(Vec::new()),
            };
            assert_eq!(
                confirm_with_query(&query, &anchor(GUID_ONE)),
                Err(LocalityError::UnsupportedFilesystem)
            );
            assert_eq!(*query.calls.borrow(), vec!["remote", "filesystem"]);
        }

        let query = MockHandleQuery {
            remote: Ok(false),
            filesystem: Err(()),
            final_path: Ok(final_path(GUID_ONE, "source")),
            calls: RefCell::new(Vec::new()),
        };
        assert_eq!(
            confirm_with_query(&query, &anchor(GUID_ONE)),
            Err(LocalityError::LocalityUnavailable)
        );
        assert_eq!(*query.calls.borrow(), vec!["remote", "filesystem"]);
    }

    #[test]
    fn layer_two_requires_preflighted_volume_identity() {
        let matching = MockHandleQuery::local_ntfs(final_path(GUID_ONE, "source"));
        assert_eq!(confirm_with_query(&matching, &anchor(GUID_ONE)), Ok(()));
        assert_eq!(
            *matching.calls.borrow(),
            vec!["remote", "filesystem", "volume"]
        );

        let mismatch = MockHandleQuery::local_ntfs(final_path(GUID_TWO, "source"));
        assert_eq!(
            confirm_with_query(&mismatch, &anchor(GUID_ONE)),
            Err(LocalityError::HandleVolumeMismatch)
        );

        let failure = MockHandleQuery {
            remote: Ok(false),
            filesystem: Ok("nTfS".encode_utf16().collect()),
            final_path: Err(()),
            calls: RefCell::new(Vec::new()),
        };
        assert_eq!(
            confirm_with_query(&failure, &anchor(GUID_ONE)),
            Err(LocalityError::LocalityUnavailable)
        );
    }
}
