//! Read-only, capability-relative filesystem inventory.

use std::ffi::OsStr;
use std::fmt;
use std::path::Path;

use cap_fs_ext::DirExt;
use cap_std::fs::Dir;

use crate::detection::{classify_path, is_git_metadata_component, DetectedKind};
#[cfg(test)]
use crate::fs_boundary;

pub const DEFAULT_MAX_DEPTH: usize = 64;
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_depth: usize,
    pub max_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Inventory {
    pub total_entries: usize,
    pub regular_files: usize,
    pub directories: usize,
    pub link_like_entries: usize,
    pub git_metadata_entries: usize,
    pub special_entries: usize,
    pub text_or_code_candidates: usize,
    pub unsupported_files: usize,
    pub unknown_files: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryError {
    RootRejected,
    TraversalFailed,
    DepthLimitExceeded,
    EntryLimitExceeded,
}

impl fmt::Display for InventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RootRejected => "source root rejected",
            Self::TraversalFailed => "filesystem inventory could not be completed consistently",
            Self::DepthLimitExceeded => "filesystem inventory depth limit exceeded",
            Self::EntryLimitExceeded => "filesystem inventory entry limit exceeded",
        })
    }
}

#[cfg(test)]
fn inspect_with_hook(
    source: &Path,
    limits: Limits,
    before_child_open: impl FnMut(&OsStr, usize),
) -> Result<Inventory, InventoryError> {
    match inspect_regular_files_with_hook(source, limits, before_child_open, |_, _, _| {
        Ok::<(), std::convert::Infallible>(())
    }) {
        Ok(inventory) => Ok(inventory),
        Err(StreamingError::Inventory(error)) => Err(error),
        Err(StreamingError::Component(never)) => match never {},
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum StreamingError<E> {
    Inventory(InventoryError),
    Component(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObservedComponent {
    Directory,
    RegularFile(DetectedKind),
}

#[cfg(test)]
fn inspect_regular_files_with_hook<E>(
    source: &Path,
    limits: Limits,
    before_child_open: impl FnMut(&OsStr, usize),
    mut on_regular_file: impl FnMut(&Dir, &OsStr, DetectedKind) -> Result<(), E>,
) -> Result<Inventory, StreamingError<E>> {
    let root = open_root_nofollow(source).map_err(StreamingError::Inventory)?;
    inspect_components_with_hook(
        root,
        limits,
        before_child_open,
        |directory, name, component| match component {
            ObservedComponent::Directory => Ok(()),
            ObservedComponent::RegularFile(kind) => on_regular_file(directory, name, kind),
        },
    )
}

pub(crate) fn inspect_components_with_hook<E>(
    root: Dir,
    limits: Limits,
    before_child_open: impl FnMut(&OsStr, usize),
    mut on_component: impl FnMut(&Dir, &OsStr, ObservedComponent) -> Result<(), E>,
) -> Result<Inventory, StreamingError<E>> {
    inspect_open_root_with_state_and_hook(
        root,
        (),
        limits,
        before_child_open,
        |directory, _state, name, component| {
            on_component(directory, name, component)?;
            Ok(match component {
                ObservedComponent::Directory => Some(()),
                ObservedComponent::RegularFile(_) => None,
            })
        },
    )
}

/// Walk an already-open source root while carrying caller-owned state for the
/// corresponding directory. Returning `Some` for a directory supplies the
/// child state; regular files must return `None`.
pub(crate) fn inspect_open_root_with_state<S, E>(
    root: Dir,
    root_state: S,
    limits: Limits,
    on_component: impl FnMut(&Dir, &S, &OsStr, ObservedComponent) -> Result<Option<S>, E>,
) -> Result<Inventory, StreamingError<E>> {
    inspect_open_root_with_state_and_hook(root, root_state, limits, |_, _| {}, on_component)
}

fn inspect_open_root_with_state_and_hook<S, E>(
    root: Dir,
    root_state: S,
    limits: Limits,
    mut before_child_open: impl FnMut(&OsStr, usize),
    mut on_component: impl FnMut(&Dir, &S, &OsStr, ObservedComponent) -> Result<Option<S>, E>,
) -> Result<Inventory, StreamingError<E>> {
    let mut inventory = Inventory::default();
    walk_directory_depth_first(
        root,
        root_state,
        0,
        limits,
        &mut inventory,
        &mut before_child_open,
        &mut on_component,
    )?;
    Ok(inventory)
}

/// Walk one open directory before returning to its parent iterator. The
/// recursive call keeps only the current directory chain alive, so directory
/// capabilities and caller state are bounded by `max_depth`, not sibling
/// width.
fn walk_directory_depth_first<S, E>(
    directory: Dir,
    directory_state: S,
    depth: usize,
    limits: Limits,
    inventory: &mut Inventory,
    before_child_open: &mut impl FnMut(&OsStr, usize),
    on_component: &mut impl FnMut(&Dir, &S, &OsStr, ObservedComponent) -> Result<Option<S>, E>,
) -> Result<(), StreamingError<E>> {
    let entries = directory
        .entries()
        .map_err(|_| StreamingError::Inventory(InventoryError::TraversalFailed))?;

    for entry in entries {
        let entry =
            entry.map_err(|_| StreamingError::Inventory(InventoryError::TraversalFailed))?;
        inventory.total_entries =
            inventory
                .total_entries
                .checked_add(1)
                .ok_or(StreamingError::Inventory(
                    InventoryError::EntryLimitExceeded,
                ))?;
        if inventory.total_entries > limits.max_entries {
            return Err(StreamingError::Inventory(
                InventoryError::EntryLimitExceeded,
            ));
        }

        let name = entry.file_name();
        if is_git_metadata_component(&name) {
            inventory.git_metadata_entries += 1;
            continue;
        }

        before_child_open(&name, depth);
        match directory.open_dir_nofollow(&name) {
            Ok(child) => {
                let child_depth = depth.checked_add(1).ok_or(StreamingError::Inventory(
                    InventoryError::DepthLimitExceeded,
                ))?;
                if child_depth > limits.max_depth {
                    return Err(StreamingError::Inventory(
                        InventoryError::DepthLimitExceeded,
                    ));
                }
                inventory.directories += 1;
                let child_state = on_component(
                    &directory,
                    &directory_state,
                    &name,
                    ObservedComponent::Directory,
                )
                .map_err(StreamingError::Component)?
                .ok_or(StreamingError::Inventory(InventoryError::TraversalFailed))?;
                walk_directory_depth_first(
                    child,
                    child_state,
                    child_depth,
                    limits,
                    inventory,
                    before_child_open,
                    on_component,
                )?;
            }
            Err(_) => {
                let kind = classify_non_directory(&entry, &name, inventory)
                    .map_err(StreamingError::Inventory)?;
                if let Some(kind) = kind {
                    if on_component(
                        &directory,
                        &directory_state,
                        &name,
                        ObservedComponent::RegularFile(kind),
                    )
                    .map_err(StreamingError::Component)?
                    .is_some()
                    {
                        return Err(StreamingError::Inventory(InventoryError::TraversalFailed));
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
fn open_root_nofollow(source: &Path) -> Result<Dir, InventoryError> {
    fs_boundary::open_ambient_dir_nofollow(source).map_err(|_| InventoryError::RootRejected)
}

fn classify_non_directory(
    entry: &cap_std::fs::DirEntry,
    name: &OsStr,
    inventory: &mut Inventory,
) -> Result<Option<DetectedKind>, InventoryError> {
    let file_type = entry
        .file_type()
        .map_err(|_| InventoryError::TraversalFailed)?;

    if file_type.is_symlink() {
        inventory.link_like_entries += 1;
        return Ok(None);
    }
    if file_type.is_dir() {
        return Err(InventoryError::TraversalFailed);
    }
    if !file_type.is_file() {
        inventory.special_entries += 1;
        return Ok(None);
    }

    inventory.regular_files += 1;
    let kind = classify_path(Path::new(name), false);
    match kind {
        DetectedKind::TextOrCodeCandidate => inventory.text_or_code_candidates += 1,
        DetectedKind::Unsupported => inventory.unsupported_files += 1,
        DetectedKind::Unknown => inventory.unknown_files += 1,
        DetectedKind::LinkLikeEntry | DetectedKind::GitMetadata => {
            return Err(InventoryError::TraversalFailed);
        }
    }
    Ok(Some(kind))
}

#[cfg(test)]
mod tests {
    #[cfg(any(unix, windows))]
    use super::Inventory;
    use super::{inspect_with_hook, InventoryError, Limits};
    use std::convert::Infallible;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    struct ActiveState {
        active: Arc<AtomicUsize>,
    }

    impl ActiveState {
        fn new(active: &Arc<AtomicUsize>, peak: &Arc<AtomicUsize>) -> Self {
            let current = active.fetch_add(1, Ordering::Relaxed) + 1;
            peak.fetch_max(current, Ordering::Relaxed);
            Self {
                active: Arc::clone(active),
            }
        }
    }

    impl Drop for ActiveState {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::Relaxed);
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("safeclone-{label}-{}-{id}", std::process::id()));
            fs::create_dir(&path).expect("create isolated test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(any(unix, windows))]
    fn assert_directory_to_link_race_did_not_escape(result: Result<Inventory, InventoryError>) {
        match result {
            Ok(inventory) => {
                assert_eq!(inventory.total_entries, 1);
                assert_eq!(inventory.directories, 0);
                assert_eq!(inventory.regular_files, 0);
                assert_eq!(inventory.text_or_code_candidates, 0);
                assert_eq!(inventory.unsupported_files, 0);
                assert_eq!(inventory.unknown_files, 0);
                assert_eq!(inventory.git_metadata_entries, 0);
                assert_eq!(
                    inventory.link_like_entries + inventory.special_entries,
                    1,
                    "the raced entry must remain structurally excluded"
                );
            }
            Err(error) => assert_eq!(error, InventoryError::TraversalFailed),
        }
    }

    #[cfg(unix)]
    #[test]
    fn link_replaced_by_normal_directory_cannot_reach_old_target() {
        use std::os::unix::fs::symlink;

        let fixture = TestDirectory::new("race");
        let source = fixture.0.join("source");
        let outside = fixture.0.join("outside");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&outside).expect("create outside");
        fs::write(outside.join("outside.pdf"), b"not inventory input").expect("write fixture");
        symlink(&outside, source.join("child")).expect("create symlink");

        let mut replaced = false;
        let inventory = inspect_with_hook(&source, Limits::default(), |name, _| {
            if !replaced && name == "child" {
                fs::remove_file(source.join("child")).expect("remove symlink");
                fs::create_dir(source.join("child")).expect("replace with directory");
                fs::write(source.join("child/inside.rs"), b"fn main() {}")
                    .expect("write replacement fixture");
                replaced = true;
            }
        })
        .expect("normal replacement remains safely inside root");

        assert!(replaced);
        assert_eq!(inventory.directories, 1);
        assert_eq!(inventory.text_or_code_candidates, 1);
        assert_eq!(inventory.unsupported_files, 0);
        assert_eq!(inventory.regular_files, 1);
    }

    #[cfg(unix)]
    #[test]
    fn normal_directory_replaced_by_external_symlink_is_never_followed() {
        use std::os::unix::fs::symlink;

        let fixture = TestDirectory::new("directory-to-symlink-race");
        let source = fixture.0.join("source");
        let outside = fixture.0.join("outside");
        let child = source.join("child");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&outside).expect("create outside");
        fs::create_dir(&child).expect("create ordinary child directory");
        fs::write(outside.join("outside.rs"), b"must not be inventoried")
            .expect("write external fixture");

        let mut replaced = false;
        let mut outside_observed = false;
        let result = inspect_with_hook(&source, Limits::default(), |name, _| {
            if name == "outside.rs" {
                outside_observed = true;
            }
            if !replaced && name == "child" {
                fs::remove_dir(&child).expect("remove ordinary child directory");
                symlink(&outside, &child).expect("replace child with external symlink");
                replaced = true;
            }
        });

        fs::remove_file(&child).expect("remove replacement symlink without following it");
        assert!(replaced);
        assert!(!outside_observed, "external file must never be enumerated");
        assert_directory_to_link_race_did_not_escape(result);
    }

    #[test]
    fn zero_entry_limit_fails_closed() {
        let fixture = TestDirectory::new("entry-limit");
        fs::write(fixture.0.join("one.rs"), b"ignored").expect("write fixture");

        let result = inspect_with_hook(
            &fixture.0,
            Limits {
                max_depth: 1,
                max_entries: 0,
            },
            |_, _| {},
        );

        assert_eq!(result, Err(InventoryError::EntryLimitExceeded));
    }

    #[test]
    fn wide_siblings_keep_live_directory_state_bounded_by_depth() {
        let fixture = TestDirectory::new("wide-depth-first");
        let source = fixture.0.join("source");
        fs::create_dir(&source).expect("create source");
        let width = 256;
        for index in 0..width {
            fs::create_dir(source.join(format!("child-{index:03}")))
                .expect("create sibling directory");
        }

        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let root = super::open_root_nofollow(&source).expect("open source root");
        let inventory = super::inspect_open_root_with_state(
            root,
            ActiveState::new(&active, &peak),
            Limits::default(),
            |_, _, _, component| match component {
                super::ObservedComponent::Directory => {
                    Ok::<Option<ActiveState>, Infallible>(Some(ActiveState::new(&active, &peak)))
                }
                super::ObservedComponent::RegularFile(_) => {
                    Ok::<Option<ActiveState>, Infallible>(None)
                }
            },
        )
        .expect("wide sibling tree is inventoryable");

        assert_eq!(inventory.directories, width);
        assert_eq!(inventory.regular_files, 0);
        assert_eq!(peak.load(Ordering::Relaxed), 2);
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn disappearing_entry_fails_instead_of_returning_partial_inventory() {
        let fixture = TestDirectory::new("traversal-error");
        fs::create_dir(fixture.0.join("child")).expect("create child");
        let mut removed = false;

        let result = inspect_with_hook(&fixture.0, Limits::default(), |name, _| {
            if !removed && name == "child" {
                fs::remove_dir(fixture.0.join("child")).expect("remove child during traversal");
                removed = true;
            }
        });

        assert!(removed);
        assert_eq!(result, Err(InventoryError::TraversalFailed));
    }

    #[cfg(windows)]
    #[test]
    fn junction_replaced_by_normal_directory_cannot_reach_old_target() {
        let fixture = TestDirectory::new("junction-race");
        let source = fixture.0.join("source");
        let outside = fixture.0.join("outside");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&outside).expect("create outside");
        fs::write(outside.join("outside.pdf"), b"not inventory input").expect("write fixture");
        let junction = source.join("child");
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .status()
            .expect("run mklink");
        assert!(status.success(), "create junction fixture");

        let mut replaced = false;
        let inventory = inspect_with_hook(&source, Limits::default(), |name, _| {
            if !replaced && name == "child" {
                fs::remove_dir(&junction).expect("remove junction");
                fs::create_dir(&junction).expect("replace with directory");
                fs::write(junction.join("inside.rs"), b"fn main() {}")
                    .expect("write replacement fixture");
                replaced = true;
            }
        })
        .expect("normal replacement remains safely inside root");

        assert!(replaced);
        assert_eq!(inventory.directories, 1);
        assert_eq!(inventory.text_or_code_candidates, 1);
        assert_eq!(inventory.unsupported_files, 0);
        assert_eq!(inventory.regular_files, 1);
    }

    #[cfg(windows)]
    #[test]
    fn normal_directory_replaced_by_external_junction_is_never_followed() {
        let fixture = TestDirectory::new("directory-to-junction-race");
        let source = fixture.0.join("source");
        let outside = fixture.0.join("outside");
        let child = source.join("child");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&outside).expect("create outside");
        fs::create_dir(&child).expect("create ordinary child directory");
        fs::write(outside.join("outside.rs"), b"must not be inventoried")
            .expect("write external fixture");

        let mut replaced = false;
        let mut outside_observed = false;
        let result = inspect_with_hook(&source, Limits::default(), |name, _| {
            if name == "outside.rs" {
                outside_observed = true;
            }
            if !replaced && name == "child" {
                fs::remove_dir(&child).expect("remove ordinary child directory");
                let status = std::process::Command::new("cmd")
                    .args(["/c", "mklink", "/J"])
                    .arg(&child)
                    .arg(&outside)
                    .status()
                    .expect("run mklink");
                assert!(status.success(), "replace child with external junction");
                replaced = true;
            }
        });

        fs::remove_dir(&child).expect("remove replacement junction without following it");
        assert!(replaced);
        assert!(!outside_observed, "external file must never be enumerated");
        assert_directory_to_link_race_did_not_escape(result);
    }
}
