//! Low-level conversion from preflighted authority into directory capabilities.

#[cfg(any(windows, test))]
use std::ffi::OsString;
#[cfg(windows)]
use std::fmt;
#[cfg(any(windows, test))]
use std::path::{Component, Path};

#[cfg(any(windows, test))]
use cap_fs_ext::DirExt;
use cap_fs_ext::MetadataExt;
#[cfg(any(windows, test))]
use cap_std::ambient_authority;
use cap_std::fs::Dir;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FilesystemIdentity {
    device: u64,
    inode: u64,
}

impl FilesystemIdentity {
    #[cfg(test)]
    pub(crate) const fn synthetic(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BoundaryError {
    #[cfg(any(windows, test))]
    PathRejected,
    #[cfg(any(windows, test))]
    OpenFailed,
    IdentityUnavailable,
    #[cfg(test)]
    ForbiddenIdentity,
}

pub(crate) fn directory_identity(directory: &Dir) -> Result<FilesystemIdentity, BoundaryError> {
    let metadata = directory
        .dir_metadata()
        .map_err(|_| BoundaryError::IdentityUnavailable)?;
    if !metadata.is_dir() {
        return Err(BoundaryError::IdentityUnavailable);
    }
    Ok(FilesystemIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

pub(crate) fn metadata_identity(metadata: &cap_std::fs::Metadata) -> FilesystemIdentity {
    FilesystemIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(windows)]
const VOLUME_GUID_ROOT_UNITS: usize = 49;
#[cfg(windows)]
const VOLUME_GUID_PREFIX_UNITS: usize = 48;

/// An anchor copied from Windows volume enumeration, never from user input.
#[cfg(windows)]
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct TrustedVolumeAnchor {
    units: [u16; VOLUME_GUID_ROOT_UNITS],
}

#[cfg(windows)]
impl TrustedVolumeAnchor {
    pub(crate) fn parse_enumerated(units: &[u16]) -> Result<Self, BoundaryError> {
        if units.len() != VOLUME_GUID_ROOT_UNITS
            || !utf16_ascii_eq_ignore_case_bytes(&units[..11], br"\\?\Volume{")
            || units[47] != u16::from(b'}')
            || units[48] != u16::from(b'\\')
        {
            return Err(BoundaryError::PathRejected);
        }
        for (index, unit) in units[11..47].iter().enumerate() {
            let valid = matches!(index, 8 | 13 | 18 | 23)
                .then_some(*unit == u16::from(b'-'))
                .unwrap_or_else(|| ascii_hex(*unit));
            if !valid {
                return Err(BoundaryError::PathRejected);
            }
        }

        let mut anchor = [0u16; VOLUME_GUID_ROOT_UNITS];
        anchor.copy_from_slice(units);
        Ok(Self { units: anchor })
    }

    pub(crate) fn device_name(&self) -> &[u16] {
        &self.units[4..VOLUME_GUID_PREFIX_UNITS]
    }

    pub(crate) fn as_os_string(&self) -> OsString {
        use std::os::windows::ffi::OsStringExt;

        OsString::from_wide(&self.units)
    }

    pub(crate) fn matches_handle_path(&self, returned: &[u16]) -> bool {
        if returned.len() < VOLUME_GUID_PREFIX_UNITS
            || !utf16_ascii_eq_ignore_case_units(
                &returned[..VOLUME_GUID_PREFIX_UNITS],
                &self.units[..VOLUME_GUID_PREFIX_UNITS],
            )
        {
            return false;
        }
        returned.len() == VOLUME_GUID_PREFIX_UNITS
            || returned[VOLUME_GUID_PREFIX_UNITS] == u16::from(b'\\')
    }

    /// Canonical candidate identity Volume GUID bytes. The OS-enumerated textual UUID
    /// order is decoded directly; Windows' mixed-endian in-memory `GUID`
    /// representation is never used as persistent authority.
    pub(crate) fn canonical_guid_bytes(&self) -> [u8; 16] {
        let mut output = [0u8; 16];
        let mut high = None;
        let mut cursor = 0usize;
        for unit in &self.units[11..47] {
            if *unit == u16::from(b'-') {
                continue;
            }
            let nibble = ascii_hex_nibble(*unit)
                .expect("TrustedVolumeAnchor construction validated every GUID digit");
            if let Some(upper) = high.take() {
                output[cursor] = (upper << 4) | nibble;
                cursor += 1;
            } else {
                high = Some(nibble);
            }
        }
        debug_assert!(high.is_none());
        debug_assert_eq!(cursor, output.len());
        output
    }
}

#[cfg(windows)]
fn ascii_hex_nibble(unit: u16) -> Option<u8> {
    match unit {
        value if value >= u16::from(b'0') && value <= u16::from(b'9') => {
            Some(u8::try_from(value - u16::from(b'0')).ok()?)
        }
        value if value >= u16::from(b'a') && value <= u16::from(b'f') => Some(
            u8::try_from(value - u16::from(b'a'))
                .ok()?
                .checked_add(10)?,
        ),
        value if value >= u16::from(b'A') && value <= u16::from(b'F') => Some(
            u8::try_from(value - u16::from(b'A'))
                .ok()?
                .checked_add(10)?,
        ),
        _ => None,
    }
}

#[cfg(windows)]
impl fmt::Debug for TrustedVolumeAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedVolumeAnchor")
            .field("state", &"os-enumerated")
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
#[derive(Clone)]
pub(crate) struct TrustedVolumePath {
    anchor: TrustedVolumeAnchor,
    components: Vec<OsString>,
}

#[cfg(windows)]
impl TrustedVolumePath {
    pub(crate) fn new(
        anchor: TrustedVolumeAnchor,
        components: Vec<OsString>,
    ) -> Result<Self, BoundaryError> {
        if components
            .iter()
            .any(|component| !valid_normal_component(component))
        {
            return Err(BoundaryError::PathRejected);
        }
        Ok(Self { anchor, components })
    }

    pub(crate) fn anchor(&self) -> &TrustedVolumeAnchor {
        &self.anchor
    }

    pub(crate) fn components(&self) -> &[OsString] {
        &self.components
    }
}

#[cfg(windows)]
impl fmt::Debug for TrustedVolumePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedVolumePath")
            .field("anchor", &self.anchor)
            .field("component_count", &self.components.len())
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
pub(crate) struct OpenedDirectory {
    pub(crate) directory: Dir,
    pub(crate) ancestor_identities: Vec<FilesystemIdentity>,
}

/// Open only the trusted volume root. Round-trip qualification uses this
/// narrower step so every selected volume can be queried before any
/// user-supplied component becomes eligible for an open.
#[cfg(windows)]
pub(crate) fn open_trusted_volume_root_nofollow(
    anchor: &TrustedVolumeAnchor,
) -> Result<Dir, BoundaryError> {
    let directory = Dir::open_ambient_dir(anchor.as_os_string(), ambient_authority())
        .map_err(|_| BoundaryError::OpenFailed)?;
    reject_reparse_handle(&directory)?;
    Ok(directory)
}

/// Open only the OS-enumerated volume root ambiently, then traverse every
/// validated component relative to retained capabilities without following a
/// reparse point.
#[cfg(windows)]
pub(crate) fn open_trusted_volume_dir_nofollow(
    path: &TrustedVolumePath,
) -> Result<OpenedDirectory, BoundaryError> {
    let mut directory = open_trusted_volume_root_nofollow(&path.anchor)?;
    let mut ancestor_identities = vec![directory_identity(&directory)?];

    for name in &path.components {
        let relative_metadata = directory
            .symlink_metadata(name)
            .map_err(|_| BoundaryError::OpenFailed)?;
        if relative_metadata.file_type().is_symlink() || !relative_metadata.is_dir() {
            return Err(BoundaryError::PathRejected);
        }

        let opened = directory
            .open_dir_nofollow(name)
            .map_err(|_| BoundaryError::OpenFailed)?;
        reject_reparse_handle(&opened)?;
        let opened_identity = directory_identity(&opened)?;
        if metadata_identity(&relative_metadata) != opened_identity {
            return Err(BoundaryError::IdentityUnavailable);
        }
        ancestor_identities.push(opened_identity);
        directory = opened;
    }

    Ok(OpenedDirectory {
        directory,
        ancestor_identities,
    })
}

#[cfg(windows)]
pub(crate) fn reconfirm_opened_directory(
    directory: &Dir,
    expected: FilesystemIdentity,
) -> Result<(), BoundaryError> {
    reject_reparse_handle(directory)?;
    if directory_identity(directory)? != expected {
        return Err(BoundaryError::IdentityUnavailable);
    }
    Ok(())
}

#[cfg(windows)]
fn reject_reparse_handle(directory: &Dir) -> Result<(), BoundaryError> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO,
    };

    let mut information = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: the retained directory handle is live and `information` is a
    // correctly sized writable buffer for FileAttributeTagInfo.
    let queried = unsafe {
        GetFileInformationByHandleEx(
            directory.as_raw_handle() as HANDLE,
            FileAttributeTagInfo,
            (&mut information as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>())
                .map_err(|_| BoundaryError::IdentityUnavailable)?,
        )
    };
    if queried == 0 || information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(BoundaryError::PathRejected);
    }
    Ok(())
}

#[cfg(windows)]
fn valid_normal_component(component: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;

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

#[cfg(windows)]
fn ascii_hex(unit: u16) -> bool {
    u8::try_from(unit).is_ok_and(|unit| unit.is_ascii_hexdigit())
}

#[cfg(windows)]
fn utf16_ascii_eq_ignore_case_bytes(actual: &[u16], expected: &[u8]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            u8::try_from(*actual).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
        })
}

#[cfg(windows)]
fn utf16_ascii_eq_ignore_case_units(actual: &[u16], expected: &[u16]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            match (u8::try_from(*actual), u8::try_from(*expected)) {
                (Ok(actual), Ok(expected)) => actual.eq_ignore_ascii_case(&expected),
                _ => actual == expected,
            }
        })
}

// Crate tests retain a raw-path seam for testing low-level staging mechanics.
// It is not compiled into the supported library API.
#[cfg(test)]
pub(crate) fn open_ambient_dir_nofollow(path: &Path) -> Result<Dir, BoundaryError> {
    let absolute = std::path::absolute(path).map_err(|_| BoundaryError::PathRejected)?;
    open_absolute_dir_nofollow(&absolute, None)
}

#[cfg(test)]
pub(crate) fn open_parent_nofollow_excluding(
    path: &Path,
    forbidden: FilesystemIdentity,
) -> Result<(Dir, OsString), BoundaryError> {
    let absolute = std::path::absolute(path).map_err(|_| BoundaryError::PathRejected)?;
    let leaf = match absolute.components().next_back() {
        Some(Component::Normal(leaf)) => leaf.to_owned(),
        _ => return Err(BoundaryError::PathRejected),
    };
    let parent = absolute.parent().ok_or(BoundaryError::PathRejected)?;
    let directory = open_absolute_dir_nofollow(parent, Some(forbidden))?;
    Ok((directory, leaf))
}

#[cfg(test)]
fn open_absolute_dir_nofollow(
    absolute: &Path,
    forbidden: Option<FilesystemIdentity>,
) -> Result<Dir, BoundaryError> {
    use std::path::PathBuf;

    let mut anchor = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => anchor.push(component.as_os_str()),
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => return Err(BoundaryError::PathRejected),
        }
    }
    if anchor.as_os_str().is_empty() {
        return Err(BoundaryError::PathRejected);
    }

    let mut directory = Dir::open_ambient_dir(&anchor, ambient_authority())
        .map_err(|_| BoundaryError::OpenFailed)?;
    reject_forbidden_identity(&directory, forbidden)?;
    for component in absolute.components() {
        match component {
            Component::Normal(name) => {
                directory = directory
                    .open_dir_nofollow(name)
                    .map_err(|_| BoundaryError::OpenFailed)?;
                reject_forbidden_identity(&directory, forbidden)?;
            }
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            Component::ParentDir => return Err(BoundaryError::PathRejected),
        }
    }
    Ok(directory)
}

#[cfg(test)]
fn reject_forbidden_identity(
    directory: &Dir,
    forbidden: Option<FilesystemIdentity>,
) -> Result<(), BoundaryError> {
    if forbidden.is_some_and(|forbidden| directory_identity(directory).ok() == Some(forbidden)) {
        return Err(BoundaryError::ForbiddenIdentity);
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod candidate_guid_tests {
    use super::*;

    fn anchor(value: &str) -> TrustedVolumeAnchor {
        TrustedVolumeAnchor::parse_enumerated(&value.encode_utf16().collect::<Vec<_>>())
            .expect("OS-generated Volume GUID shape")
    }

    #[test]
    fn candidate_guid_canonicalization_is_case_independent_textual_uuid_order() {
        let lower = anchor(r"\\?\Volume{00112233-4455-6677-8899-aabbccddeeff}\");
        let upper = anchor(r"\\?\VOLUME{00112233-4455-6677-8899-AABBCCDDEEFF}\");
        let expected = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert_eq!(lower.canonical_guid_bytes(), expected);
        assert_eq!(upper.canonical_guid_bytes(), expected);

        let windows_memory_endian = [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert_ne!(lower.canonical_guid_bytes(), windows_memory_endian);
    }
}
