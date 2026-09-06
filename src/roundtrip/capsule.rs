//! Retained-root immutable capsule generation store.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path};
use std::ptr;

use cap_fs_ext::{FollowSymlinks, MetadataExt, OpenOptionsFollowExt, OpenOptionsSyncExt};
use cap_std::fs::{Dir, File, OpenOptions, OpenOptionsExt};
use windows_sys::Wdk::Storage::FileSystem::{
    FileAccessInformation, FileModeInformation, FileRenameInformation, NtQueryInformationFile,
    NtSetInformationFile, FILE_ACCESS_INFORMATION, FILE_MODE_INFORMATION, FILE_RENAME_INFORMATION,
    FILE_WRITE_THROUGH,
};
use windows_sys::Win32::Foundation::{
    GetLastError, RtlNtStatusToDosError, ERROR_LOCK_VIOLATION, GENERIC_READ, GENERIC_WRITE, HANDLE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileStreamInfo, FlushFileBuffers, GetFileInformationByHandleEx, LockFileEx, UnlockFileEx,
    DELETE, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STREAM_INFO,
    FILE_WRITE_DATA, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
};
use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, OVERLAPPED};

use super::canonical::CanonicalWriter;
use super::crypto::{constant_time_equal, hmac_tag, system_random, KeyPurpose, KeySchedule};
use super::dpapi::{
    unprotect_closed_tombstone, unprotect_live_capsule,
    unprotect_manifest_authenticated_with_schedule, unprotect_manifest_with_schedule,
    AuthenticatedLiveCapsule, AuthenticatedManifestBytes, AuthenticatedTombstone, EnvelopeRole,
    OuterHeaderV1, MAX_CAPSULE_FILE_BYTES, MAX_MANIFEST_FILE_BYTES,
};
pub use super::observe::FileIdentity;
use super::observe::{
    self, file_identity, manifest_leaf, EntryKind, PrivateLeafRole, QualifiedPrivateStateRoot,
};
use super::schema::ManifestPhase;
use super::token::encode_base32_128;
use super::{Error, Result};

pub const MAX_STATE_ROOT_ENTRIES: usize = observe::MAX_DIRECTORY_ENTRIES;
pub const LOCK_LEAF: &str = observe::LOCK_LEAF;
pub const LOCK_MAGIC: &[u8] = b"SAFECLONE-RT1-LOCK\n";
const MAX_STREAM_QUERY_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreClassification {
    CreateIncomplete,
    AuthoritativeLive,
    Closed,
    PrivateOrphansPresent,
}

pub enum AuthorityHead {
    Live(Box<AuthenticatedLiveCapsule>),
    Closed(Box<AuthenticatedTombstone>),
}

impl AuthorityHead {
    pub fn live(&self) -> Option<&AuthenticatedLiveCapsule> {
        match self {
            Self::Live(live) => Some(live),
            Self::Closed(_) => None,
        }
    }

    pub fn closed(&self) -> Option<&AuthenticatedTombstone> {
        match self {
            Self::Live(_) => None,
            Self::Closed(closed) => Some(closed),
        }
    }

    pub fn generation(&self) -> u64 {
        match self {
            Self::Live(live) => live.capsule().generation,
            Self::Closed(closed) => closed.tombstone().generation,
        }
    }
}

pub struct StoreObservation {
    pub classification: StoreClassification,
    pub orphan_count: u32,
    pub manifest_count: u32,
    head: Option<AuthorityHead>,
}

impl StoreObservation {
    pub fn head(&self) -> Option<&AuthorityHead> {
        self.head.as_ref()
    }

    pub fn live_head(&self) -> Option<&AuthenticatedLiveCapsule> {
        self.head.as_ref().and_then(AuthorityHead::live)
    }

    pub fn closed_head(&self) -> Option<&AuthenticatedTombstone> {
        self.head.as_ref().and_then(AuthorityHead::closed)
    }

    pub(crate) fn into_live_head(self) -> Option<Box<AuthenticatedLiveCapsule>> {
        match self.head {
            Some(AuthorityHead::Live(live)) => Some(live),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitEvidence {
    pub generation: u64,
    pub root_identity: FileIdentity,
    pub generation_identity: FileIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestEvidence {
    pub root_identity: FileIdentity,
    pub manifest_identity: FileIdentity,
}

#[derive(Debug, Eq, PartialEq)]
struct PersistedManifestEvidence {
    public: ManifestEvidence,
    manifest_commitment: [u8; 32],
}

#[derive(Clone, Copy)]
pub(crate) struct ReviewManifestEvidence {
    root_identity: FileIdentity,
    manifest_identity: FileIdentity,
    review_id: [u8; 16],
    phase: ManifestPhase,
    prior_generation: u64,
    owning_generation: u64,
    manifest_commitment: [u8; 32],
}

#[derive(Clone, Copy)]
struct ManifestWriteBinding {
    review_id: [u8; 16],
    phase: ManifestPhase,
    owning_generation: u64,
    expected_commitment: Option<[u8; 32]>,
}

pub struct GenerationStore {
    authority: QualifiedPrivateStateRoot,
}

impl GenerationStore {
    /// Consumes the non-forgeable alias-aware authority produced by the
    /// accepted locality and volume-policy boundary.
    // This construction seam is intentionally dormant outside tests until
    // session creation supplies an accepted private-root lifecycle.
    #[allow(dead_code)]
    pub(crate) const fn from_qualified_root(authority: QualifiedPrivateStateRoot) -> Self {
        Self { authority }
    }

    pub const fn root_identity(&self) -> FileIdentity {
        self.authority.root_identity()
    }

    #[cfg(test)]
    fn selected_short_name_mode(&self) -> observe::ShortNameMode {
        self.authority.selected_mode()
    }

    fn root(&self) -> &Dir {
        self.authority.root()
    }

    pub fn state_root_identity_commitment(&self, schedule: &KeySchedule<'_>) -> Result<[u8; 32]> {
        state_root_commitment(schedule, self.root_identity())
    }

    pub fn initialize_lock(&self) -> Result<()> {
        #[cfg(test)]
        {
            self.initialize_lock_impl(false)
        }
        #[cfg(not(test))]
        {
            self.initialize_lock_impl()
        }
    }

    fn initialize_lock_impl(&self, #[cfg(test)] force_post_create_failure: bool) -> Result<()> {
        let pre_create = self.authority.observe_root()?;
        if !pre_create.entries().is_empty() {
            return Err(Error::FilesystemFailure);
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
        self.authority.requery_before_mutation()?;
        let mut file = self
            .root()
            .open_with(LOCK_LEAF, &options)
            .map_err(|_| Error::FilesystemFailure)?;
        validate_regular_one_link_stream_clean(&file)?;
        require_write_through_delete_access(&file)?;
        let post_create = self.authority.observe_root()?;
        #[cfg(test)]
        if force_post_create_failure {
            return Err(Error::AliasIdentityMismatch);
        }
        self.authority
            .bind_created(&post_create, LOCK_LEAF, EntryKind::File, &file)?;
        file.write_all(LOCK_MAGIC)
            .map_err(|_| Error::FilesystemFailure)?;
        flush_file(&file)?;
        if read_file_bounded(&mut file, LOCK_MAGIC.len() + 1)? != LOCK_MAGIC {
            return Err(Error::FilesystemFailure);
        }
        Ok(())
    }

    pub fn acquire_mutation_lock(&self) -> Result<MutationLock> {
        MutationLock::acquire(&self.authority)
    }

    pub fn read(&self) -> Result<StoreObservation> {
        self.read_internal(None)
    }

    pub(crate) fn read_while_locked(&self, lock: &mut MutationLock) -> Result<StoreObservation> {
        if !lock.held || lock.root_identity != self.root_identity() {
            return Err(Error::FilesystemFailure);
        }
        self.read_internal(Some(&mut lock.file))
    }

    fn read_internal(&self, mut held_lock_file: Option<&mut File>) -> Result<StoreObservation> {
        let namespace = self.authority.observe_root()?;
        let mut saw_lock = false;
        let mut lock_valid = false;
        let mut capsule_leaves = BTreeMap::new();
        let mut manifest_leaves = BTreeMap::new();
        let mut pending_count = 0usize;
        for entry in namespace.entries() {
            if entry.entry_kind() != EntryKind::File {
                return Err(Error::CorruptState);
            }
            let name = entry.canonical_long_name();
            if entry.role() == PrivateLeafRole::Lock {
                if saw_lock {
                    return Err(Error::CorruptState);
                }
                saw_lock = true;
                let mut opened_lock;
                let lock_file = if let Some(file) = held_lock_file.as_deref_mut() {
                    validate_regular_one_link_stream_clean(file)?;
                    self.authority.verify_opened_entry(entry, file)?;
                    file
                } else {
                    opened_lock = self.open_observed_regular(entry)?;
                    &mut opened_lock
                };
                let size =
                    usize::try_from(lock_file.metadata().map_err(|_| Error::CorruptState)?.len())
                        .map_err(|_| Error::CorruptState)?;
                lock_valid = size == LOCK_MAGIC.len()
                    && read_lock_file_bounded(lock_file, LOCK_MAGIC.len() + 1)? == LOCK_MAGIC;
                continue;
            }
            if entry.role() == PrivateLeafRole::Unrecognized {
                return Err(Error::CorruptState);
            }
            let file = self.open_observed_regular(entry)?;
            let size = usize::try_from(file.metadata().map_err(|_| Error::CorruptState)?.len())
                .map_err(|_| Error::CorruptState)?;
            if let PrivateLeafRole::Capsule(generation) = entry.role() {
                if size > MAX_CAPSULE_FILE_BYTES
                    || capsule_leaves.insert(generation, entry).is_some()
                {
                    return Err(Error::CorruptState);
                }
            } else if matches!(entry.role(), PrivateLeafRole::Manifest { .. }) {
                if size > MAX_MANIFEST_FILE_BYTES
                    || manifest_leaves.insert(name.to_owned(), entry).is_some()
                {
                    return Err(Error::CorruptState);
                }
            } else if entry.role() == PrivateLeafRole::Pending {
                if size > MAX_MANIFEST_FILE_BYTES {
                    return Err(Error::CorruptState);
                }
                pending_count = pending_count.checked_add(1).ok_or(Error::CorruptState)?;
            } else {
                return Err(Error::CorruptState);
            }
        }

        if !saw_lock || !lock_valid {
            return if capsule_leaves.is_empty() && manifest_leaves.is_empty() && pending_count == 0
            {
                Ok(StoreObservation {
                    classification: StoreClassification::CreateIncomplete,
                    orphan_count: 0,
                    manifest_count: 0,
                    head: None,
                })
            } else {
                Err(Error::CorruptState)
            };
        }

        for (index, generation) in capsule_leaves.keys().copied().enumerate() {
            let expected = u64::try_from(index)
                .map_err(|_| Error::CorruptState)?
                .checked_add(1)
                .ok_or(Error::CorruptState)?;
            if generation != expected {
                return Err(Error::CorruptState);
            }
        }

        let mut last_live: Option<AuthenticatedLiveCapsule> = None;
        let mut closed: Option<AuthenticatedTombstone> = None;
        let mut manifest_references = BTreeMap::new();
        let capsule_count = capsule_leaves.len();
        for (index, (generation, entry)) in capsule_leaves.iter().enumerate() {
            if closed.is_some() {
                return Err(Error::CorruptState);
            }
            let bytes = self.read_observed_leaf_bounded(entry, MAX_CAPSULE_FILE_BYTES)?;
            if *generation == 1 {
                let live = unprotect_live_capsule(&bytes, None).map_err(|_| Error::CorruptState)?;
                record_manifest_reference(&live, &mut manifest_references)?;
                last_live = Some(live);
                continue;
            }
            let prior = last_live.as_ref().ok_or(Error::CorruptState)?;
            match unprotect_live_capsule(&bytes, Some(prior)) {
                Ok(live) => {
                    record_manifest_reference(&live, &mut manifest_references)?;
                    last_live = Some(live);
                }
                Err(_) => {
                    let tombstone = unprotect_closed_tombstone(prior, &bytes)
                        .map_err(|_| Error::CorruptState)?;
                    if index + 1 != capsule_count {
                        return Err(Error::CorruptState);
                    }
                    closed = Some(tombstone);
                }
            }
        }

        let manifest_count =
            u32::try_from(manifest_leaves.len()).map_err(|_| Error::CorruptState)?;
        let mut unreferenced_manifest_count = 0usize;
        for (leaf, entry) in &manifest_leaves {
            if let Some(expected_generation) = manifest_references.get(leaf) {
                let owner = last_live.as_ref().ok_or(Error::CorruptState)?;
                let bytes = self.read_observed_leaf_bounded(entry, MAX_MANIFEST_FILE_BYTES)?;
                let private = unprotect_manifest_with_schedule(
                    &owner.key_schedule(),
                    *expected_generation,
                    &bytes,
                )
                .map_err(|_| Error::CorruptState)?;
                drop(private);
            } else {
                unreferenced_manifest_count = unreferenced_manifest_count
                    .checked_add(1)
                    .ok_or(Error::CorruptState)?;
            }
        }
        let orphan_count_usize = pending_count
            .checked_add(unreferenced_manifest_count)
            .ok_or(Error::CorruptState)?;
        let orphan_count = u32::try_from(orphan_count_usize).map_err(|_| Error::CorruptState)?;

        if let Some(closed) = closed {
            let tombstone = closed.tombstone();
            if tombstone.retained_manifest_count != manifest_count
                || tombstone.retained_private_orphan_count != orphan_count
            {
                return Err(Error::CorruptState);
            }
            return Ok(StoreObservation {
                classification: StoreClassification::Closed,
                orphan_count,
                manifest_count,
                head: Some(AuthorityHead::Closed(Box::new(closed))),
            });
        }
        if let Some(live) = last_live {
            validate_root_binding(&live, self.root_identity())?;
            return Ok(StoreObservation {
                classification: if orphan_count == 0 {
                    StoreClassification::AuthoritativeLive
                } else {
                    StoreClassification::PrivateOrphansPresent
                },
                orphan_count,
                manifest_count,
                head: Some(AuthorityHead::Live(Box::new(live))),
            });
        }
        Ok(StoreObservation {
            classification: if orphan_count == 0 {
                StoreClassification::CreateIncomplete
            } else {
                StoreClassification::PrivateOrphansPresent
            },
            orphan_count,
            manifest_count,
            head: None,
        })
    }

    fn open_observed_regular(&self, entry: &observe::ObservedNamespaceEntry) -> Result<File> {
        let file = open_regular_read(self.root(), entry.canonical_long_name())?;
        self.authority.verify_opened_entry(entry, &file)?;
        Ok(file)
    }

    fn read_observed_leaf_bounded(
        &self,
        entry: &observe::ObservedNamespaceEntry,
        limit: usize,
    ) -> Result<Vec<u8>> {
        let mut file = self.open_observed_regular(entry)?;
        let before = file_identity(&file)?;
        let bytes = read_file_bounded(&mut file, limit)?;
        let after = file_identity(&file)?;
        let reopened = self.open_observed_regular(entry)?;
        if before != after || after != file_identity(&reopened)? {
            return Err(Error::CorruptState);
        }
        Ok(bytes)
    }

    /// Persists one already-DPAPI-protected private manifest. The final leaf
    /// remains empty until its post-create alias, namespace, and identity gate
    /// has succeeded; a failure is retained as a private orphan.
    pub fn persist_manifest(
        &self,
        lock: &mut MutationLock,
        owner: &AuthenticatedLiveCapsule,
        review_id: [u8; 16],
        phase: ManifestPhase,
        protected_manifest: &[u8],
    ) -> Result<ManifestEvidence> {
        #[cfg(test)]
        {
            let persisted = self.persist_manifest_impl(
                lock,
                owner,
                ManifestWriteBinding {
                    review_id,
                    phase,
                    owning_generation: owner.capsule().generation,
                    expected_commitment: None,
                },
                protected_manifest,
                false,
            )?;
            Ok(persisted.public)
        }
        #[cfg(not(test))]
        {
            let persisted = self.persist_manifest_impl(
                lock,
                owner,
                ManifestWriteBinding {
                    review_id,
                    phase,
                    owning_generation: owner.capsule().generation,
                    expected_commitment: None,
                },
                protected_manifest,
            )?;
            Ok(persisted.public)
        }
    }

    /// Commits a manifest which may be referenced only by the immediately
    /// following review capsule. The returned in-memory evidence cannot be
    /// reconstructed after interruption and therefore cannot adopt an orphan.
    pub(crate) fn persist_next_review_manifest(
        &self,
        lock: &mut MutationLock,
        owner: &AuthenticatedLiveCapsule,
        review_id: [u8; 16],
        manifest_commitment: [u8; 32],
        protected_manifest: &[u8],
    ) -> Result<ReviewManifestEvidence> {
        self.persist_next_manifest(
            lock,
            owner,
            review_id,
            ManifestPhase::Review,
            manifest_commitment,
            protected_manifest,
        )
    }

    pub(crate) fn persist_next_apply_manifest(
        &self,
        lock: &mut MutationLock,
        owner: &AuthenticatedLiveCapsule,
        review_id: [u8; 16],
        manifest_commitment: [u8; 32],
        protected_manifest: &[u8],
    ) -> Result<ReviewManifestEvidence> {
        self.persist_next_manifest(
            lock,
            owner,
            review_id,
            ManifestPhase::ApplyResult,
            manifest_commitment,
            protected_manifest,
        )
    }

    fn persist_next_manifest(
        &self,
        lock: &mut MutationLock,
        owner: &AuthenticatedLiveCapsule,
        review_id: [u8; 16],
        phase: ManifestPhase,
        manifest_commitment: [u8; 32],
        protected_manifest: &[u8],
    ) -> Result<ReviewManifestEvidence> {
        let owning_generation = owner
            .capsule()
            .generation
            .checked_add(1)
            .ok_or(Error::InvalidState)?;
        let binding = ManifestWriteBinding {
            review_id,
            phase,
            owning_generation,
            expected_commitment: Some(manifest_commitment),
        };
        #[cfg(test)]
        let persisted =
            self.persist_manifest_impl(lock, owner, binding, protected_manifest, false)?;
        #[cfg(not(test))]
        let persisted = self.persist_manifest_impl(lock, owner, binding, protected_manifest)?;
        Ok(ReviewManifestEvidence {
            root_identity: persisted.public.root_identity,
            manifest_identity: persisted.public.manifest_identity,
            review_id,
            phase,
            prior_generation: owner.capsule().generation,
            owning_generation,
            manifest_commitment: persisted.manifest_commitment,
        })
    }

    fn persist_manifest_impl(
        &self,
        lock: &mut MutationLock,
        owner: &AuthenticatedLiveCapsule,
        binding: ManifestWriteBinding,
        protected_manifest: &[u8],
        #[cfg(test)] force_post_create_failure: bool,
    ) -> Result<PersistedManifestEvidence> {
        if !lock.held || lock.root_identity != self.root_identity() {
            return Err(Error::FilesystemFailure);
        }
        let observation = self.read_internal(Some(&mut lock.file))?;
        if observation.classification != StoreClassification::AuthoritativeLive {
            return Err(Error::InvalidState);
        }
        let current = observation.live_head().ok_or(Error::InvalidState)?;
        if current.capsule().generation != owner.capsule().generation
            || current.capsule().session_id != owner.capsule().session_id
            || !constant_time_equal(current.tag(), owner.tag())
        {
            return Err(Error::InvalidState);
        }
        let authenticated = unprotect_manifest_authenticated_with_schedule(
            &owner.key_schedule(),
            binding.owning_generation,
            protected_manifest,
        )?;
        if binding
            .expected_commitment
            .as_ref()
            .is_some_and(|expected| !constant_time_equal(expected, authenticated.commitment()))
        {
            return Err(Error::AuthenticationFailed);
        }
        let manifest_commitment = *authenticated.commitment();
        drop(authenticated);

        let leaf = manifest_leaf(&binding.review_id, binding.phase);
        self.authority.requery_before_mutation()?;
        let mut file = create_empty_private_file(self.root(), &leaf)?;
        validate_regular_one_link_stream_clean(&file)?;
        require_write_through_delete_access(&file).map_err(|_| Error::PrivateOrphansPresent)?;
        let post_create = self
            .authority
            .observe_root()
            .map_err(private_orphan_failure)?;
        let manifest_identity = self
            .authority
            .bind_created(&post_create, &leaf, EntryKind::File, &file)
            .map_err(private_orphan_failure)?;
        let entry = post_create
            .find_exact_long(&leaf)
            .map_err(private_orphan_failure)?;
        if !matches!(
            entry.role(),
            PrivateLeafRole::Manifest {
                review_id: observed,
                phase: observed_phase,
            } if observed == binding.review_id && observed_phase == binding.phase
        ) {
            return Err(Error::PrivateOrphansPresent);
        }
        #[cfg(test)]
        if force_post_create_failure {
            return Err(Error::AliasIdentityMismatch);
        }

        file.write_all(protected_manifest)
            .map_err(|_| Error::PrivateOrphansPresent)?;
        flush_file(&file).map_err(|_| Error::PrivateOrphansPresent)?;
        let readback = read_file_bounded(&mut file, MAX_MANIFEST_FILE_BYTES)
            .map_err(|_| Error::PrivateOrphansPresent)?;
        if readback != protected_manifest {
            return Err(Error::PrivateOrphansPresent);
        }
        let authenticated = unprotect_manifest_authenticated_with_schedule(
            &owner.key_schedule(),
            binding.owning_generation,
            &readback,
        )
        .map_err(|_| Error::PrivateOrphansPresent)?;
        if !constant_time_equal(authenticated.commitment(), &manifest_commitment) {
            return Err(Error::PrivateOrphansPresent);
        }
        drop(authenticated);
        self.authority.verify_root()?;
        self.authority.requery_policy()?;
        Ok(PersistedManifestEvidence {
            public: ManifestEvidence {
                root_identity: self.root_identity(),
                manifest_identity,
            },
            manifest_commitment,
        })
    }

    pub(crate) fn read_review_manifest(
        &self,
        lock: &mut MutationLock,
        owner: &AuthenticatedLiveCapsule,
        review_id: [u8; 16],
        phase: ManifestPhase,
    ) -> Result<(u64, AuthenticatedManifestBytes)> {
        if !lock.held || lock.root_identity != self.root_identity() {
            return Err(Error::FilesystemFailure);
        }
        let observation = self.read_internal(Some(&mut lock.file))?;
        let current = observation.live_head().ok_or(Error::InvalidState)?;
        if current.capsule().generation != owner.capsule().generation
            || current.capsule().session_id != owner.capsule().session_id
            || !constant_time_equal(current.tag(), owner.tag())
        {
            return Err(Error::InvalidState);
        }
        let leaf = manifest_leaf(&review_id, phase);
        let namespace = self.authority.observe_root()?;
        let entry = namespace.find_exact_long(&leaf)?;
        if !matches!(
            entry.role(),
            PrivateLeafRole::Manifest {
                review_id: observed,
                phase: observed_phase,
            } if observed == review_id && observed_phase == phase
        ) {
            return Err(Error::CorruptState);
        }
        let bytes = self.read_observed_leaf_bounded(entry, MAX_MANIFEST_FILE_BYTES)?;
        let (outer, _) = OuterHeaderV1::parse(&bytes, EnvelopeRole::Manifest)?;
        let maximum_generation = owner
            .capsule()
            .generation
            .checked_add(1)
            .ok_or(Error::InvalidState)?;
        if outer.session_id != owner.capsule().session_id || outer.generation > maximum_generation {
            return Err(Error::AuthenticationFailed);
        }
        let authenticated = unprotect_manifest_authenticated_with_schedule(
            &owner.key_schedule(),
            outer.generation,
            &bytes,
        )?;
        Ok((outer.generation, authenticated))
    }

    pub fn append_capsule_generation(
        &self,
        lock: &mut MutationLock,
        protected_generation: &[u8],
    ) -> Result<CommitEvidence> {
        #[cfg(test)]
        {
            self.append_impl(
                lock,
                protected_generation,
                None,
                approval_test_checkpoint(),
                false,
            )
        }
        #[cfg(not(test))]
        {
            self.append_impl(lock, protected_generation, None)
        }
    }

    pub(crate) fn append_review_capsule_generation(
        &self,
        lock: &mut MutationLock,
        protected_generation: &[u8],
        manifest: &ReviewManifestEvidence,
    ) -> Result<CommitEvidence> {
        #[cfg(test)]
        {
            self.append_impl(lock, protected_generation, Some(manifest), None, false)
        }
        #[cfg(not(test))]
        {
            self.append_impl(lock, protected_generation, Some(manifest))
        }
    }

    pub(crate) fn append_apply_capsule_generation(
        &self,
        lock: &mut MutationLock,
        protected_generation: &[u8],
        manifest: &ReviewManifestEvidence,
    ) -> Result<CommitEvidence> {
        self.append_review_capsule_generation(lock, protected_generation, manifest)
    }

    pub(crate) fn recover_next_apply_manifest_evidence(
        &self,
        lock: &mut MutationLock,
        owner: &AuthenticatedLiveCapsule,
        review_id: [u8; 16],
        expected_commitment: [u8; 32],
    ) -> Result<ReviewManifestEvidence> {
        if !lock.held || lock.root_identity != self.root_identity() {
            return Err(Error::FilesystemFailure);
        }
        let observation = self.read_internal(Some(&mut lock.file))?;
        let current = observation.live_head().ok_or(Error::InvalidState)?;
        if observation.classification != StoreClassification::PrivateOrphansPresent
            || observation.orphan_count != 1
            || current.capsule() != owner.capsule()
            || !constant_time_equal(current.tag(), owner.tag())
            || owner.capsule().session_state != super::schema::SessionState::ApplyIncomplete
        {
            return Err(Error::PrivateOrphansPresent);
        }
        let owning_generation = owner
            .capsule()
            .generation
            .checked_add(1)
            .ok_or(Error::InvalidState)?;
        let leaf = manifest_leaf(&review_id, ManifestPhase::ApplyResult);
        let namespace = self.authority.observe_root()?;
        let entry = namespace.find_exact_long(&leaf)?;
        if !matches!(
            entry.role(),
            PrivateLeafRole::Manifest {
                review_id: observed,
                phase: ManifestPhase::ApplyResult,
            } if observed == review_id
        ) {
            return Err(Error::PrivateOrphansPresent);
        }
        let file = self.open_observed_regular(entry)?;
        let manifest_identity = file_identity(&file)?;
        let bytes = self.read_observed_leaf_bounded(entry, MAX_MANIFEST_FILE_BYTES)?;
        let authenticated = unprotect_manifest_authenticated_with_schedule(
            &owner.key_schedule(),
            owning_generation,
            &bytes,
        )?;
        if !constant_time_equal(authenticated.commitment(), &expected_commitment) {
            return Err(Error::AuthenticationFailed);
        }
        Ok(ReviewManifestEvidence {
            root_identity: self.root_identity(),
            manifest_identity,
            review_id,
            phase: ManifestPhase::ApplyResult,
            prior_generation: owner.capsule().generation,
            owning_generation,
            manifest_commitment: expected_commitment,
        })
    }

    fn append_impl(
        &self,
        lock: &mut MutationLock,
        protected_generation: &[u8],
        review_manifest: Option<&ReviewManifestEvidence>,
        #[cfg(test)] checkpoint: Option<CommitCheckpoint>,
        #[cfg(test)] force_post_create_failure: bool,
    ) -> Result<CommitEvidence> {
        if !lock.held || lock.root_identity != self.root_identity() {
            return Err(Error::FilesystemFailure);
        }
        #[cfg(test)]
        abort_at(checkpoint, CommitCheckpoint::P0);
        let observation = self.read_internal(Some(&mut lock.file))?;
        if matches!(observation.head, Some(AuthorityHead::Closed(_))) {
            return Err(Error::InvalidState);
        }
        let (outer, _) = OuterHeaderV1::parse(protected_generation, EnvelopeRole::Capsule)?;
        let prior = observation.live_head();
        let expected_closed = match prior {
            None => {
                let live = unprotect_live_capsule(protected_generation, None)?;
                validate_root_binding(&live, self.root_identity())?;
                false
            }
            Some(prior) => match unprotect_live_capsule(protected_generation, Some(prior)) {
                Ok(live) => {
                    validate_root_binding(&live, self.root_identity())?;
                    false
                }
                Err(_) => {
                    unprotect_closed_tombstone(prior, protected_generation)?;
                    true
                }
            },
        };
        let expected_generation = match prior {
            None => 1,
            Some(head) => head
                .capsule()
                .generation
                .checked_add(1)
                .ok_or(Error::InvalidState)?,
        };
        if outer.generation != expected_generation {
            return Err(Error::InvalidState);
        }
        if observation.classification == StoreClassification::PrivateOrphansPresent {
            let Some(prior) = prior else {
                return Err(Error::PrivateOrphansPresent);
            };
            if expected_closed {
                let closed = unprotect_closed_tombstone(prior, protected_generation)?;
                if closed.tombstone().retained_manifest_count != observation.manifest_count
                    || closed.tombstone().retained_private_orphan_count != observation.orphan_count
                {
                    return Err(Error::InvalidState);
                }
            } else {
                let evidence = review_manifest.ok_or(Error::PrivateOrphansPresent)?;
                let next = unprotect_live_capsule(protected_generation, Some(prior))?;
                validate_review_manifest_evidence(
                    self,
                    &observation,
                    prior,
                    &next,
                    evidence,
                    expected_generation,
                )?;
            }
        } else if review_manifest.is_some() {
            return Err(Error::InvalidState);
        }

        let pending = pending_leaf()?;
        let _pre_create = self.authority.observe_root()?;
        self.authority.requery_before_mutation()?;
        let mut file = create_pending(self.root(), &pending)?;
        validate_regular_one_link_stream_clean(&file)?;
        require_write_through_delete_access(&file).map_err(private_orphan_failure)?;
        let post_create = self
            .authority
            .observe_root()
            .map_err(private_orphan_failure)?;
        let pending_identity = self
            .authority
            .bind_created(&post_create, &pending, EntryKind::File, &file)
            .map_err(private_orphan_failure)?;
        #[cfg(test)]
        if force_post_create_failure {
            return Err(Error::AliasIdentityMismatch);
        }
        let split = protected_generation.len().min(8);
        file.write_all(&protected_generation[..split])
            .map_err(|_| Error::PrivateOrphansPresent)?;
        #[cfg(test)]
        abort_at(checkpoint, CommitCheckpoint::P1);
        file.write_all(&protected_generation[split..])
            .map_err(|_| Error::PrivateOrphansPresent)?;
        #[cfg(test)]
        abort_at(checkpoint, CommitCheckpoint::P2);
        flush_file(&file).map_err(|_| Error::PrivateOrphansPresent)?;
        #[cfg(test)]
        abort_at(checkpoint, CommitCheckpoint::P3);
        let readback = read_file_bounded(&mut file, MAX_CAPSULE_FILE_BYTES)
            .map_err(|_| Error::PrivateOrphansPresent)?;
        if readback != protected_generation {
            return Err(Error::PrivateOrphansPresent);
        }
        validate_candidate(&readback, prior, expected_closed, self.root_identity())
            .map_err(|_| Error::PrivateOrphansPresent)?;
        #[cfg(test)]
        abort_at(checkpoint, CommitCheckpoint::P4);
        let pending_entry = post_create
            .find_exact_long(&pending)
            .map_err(|_| Error::PrivateOrphansPresent)?;
        let independent = self
            .open_observed_regular(pending_entry)
            .map_err(|_| Error::PrivateOrphansPresent)?;
        if file_identity(&independent).map_err(|_| Error::PrivateOrphansPresent)?
            != pending_identity
            || file_identity(self.root()).map_err(|_| Error::PrivateOrphansPresent)?
                != self.root_identity()
        {
            return Err(Error::PrivateOrphansPresent);
        }
        let final_name = observe::final_leaf(expected_generation);
        exclusive_rename_same_handle(&file, self.root(), &final_name)
            .map_err(|_| Error::PrivateOrphansPresent)?;
        if file_identity(&file).map_err(|_| Error::StateCommitUncertain)? != pending_identity {
            return Err(Error::StateCommitUncertain);
        }
        #[cfg(test)]
        abort_at(checkpoint, CommitCheckpoint::P5);

        let post_commit = (|| {
            flush_file(&file)?;
            #[cfg(test)]
            abort_at(checkpoint, CommitCheckpoint::P6);
            let post_rename = self.authority.observe_root()?;
            let final_identity =
                self.authority
                    .bind_created(&post_rename, &final_name, EntryKind::File, &file)?;
            let final_entry = post_rename.find_exact_long(&final_name)?;
            let mut reopened = self.open_observed_regular(final_entry)?;
            if final_identity != pending_identity
                || file_identity(&reopened)? != pending_identity
                || read_file_bounded(&mut reopened, MAX_CAPSULE_FILE_BYTES)? != protected_generation
                || post_rename
                    .entries()
                    .iter()
                    .any(|entry| entry.canonical_long_name() == pending)
                || !leaf_absent(self.root(), &pending)?
                || file_identity(self.root())? != self.root_identity()
            {
                return Err(Error::StateCommitUncertain);
            }
            validate_candidate(
                protected_generation,
                prior,
                expected_closed,
                self.root_identity(),
            )?;
            self.authority.requery_policy()?;
            #[cfg(test)]
            abort_at(checkpoint, CommitCheckpoint::P7);
            Ok(())
        })();
        if let Err(error) = post_commit {
            if committed_namespace_is_corrupt(error) {
                return Err(Error::CorruptState);
            }
            if post_commit_namespace_is_unclassifiable(error) {
                return Err(Error::StateCommitUncertain);
            }
            return self.resolve_post_commit(
                expected_generation,
                expected_closed,
                pending_identity,
            );
        }
        Ok(CommitEvidence {
            generation: expected_generation,
            root_identity: self.root_identity(),
            generation_identity: pending_identity,
        })
    }

    fn resolve_post_commit(
        &self,
        generation: u64,
        expected_closed: bool,
        identity: FileIdentity,
    ) -> Result<CommitEvidence> {
        let final_name = observe::final_leaf(generation);
        let final_identity = (|| {
            let namespace = self.authority.observe_root()?;
            let entry = namespace.find_exact_long(&final_name)?;
            let file = self.open_observed_regular(entry)?;
            file_identity(&file)
        })();
        match (self.read(), final_identity) {
            (Ok(observation), Ok(final_identity))
                if observation.head().is_some_and(|head| {
                    head.generation() == generation && (head.closed().is_some() == expected_closed)
                }) && final_identity == identity =>
            {
                Ok(CommitEvidence {
                    generation,
                    root_identity: self.root_identity(),
                    generation_identity: identity,
                })
            }
            (Err(error), _) if committed_namespace_is_corrupt(error) => Err(Error::CorruptState),
            (_, Err(error)) if committed_namespace_is_corrupt(error) => Err(Error::CorruptState),
            _ => Err(Error::StateCommitUncertain),
        }
    }
}

fn committed_namespace_is_corrupt(error: Error) -> bool {
    matches!(
        error,
        Error::CorruptState
            | Error::UnsupportedAliasNamespace
            | Error::AliasNamespaceAmbiguous
            | Error::AliasIdentityMismatch
    )
}

fn post_commit_namespace_is_unclassifiable(error: Error) -> bool {
    matches!(
        error,
        Error::CaseSensitiveDirectoryUnsupported
            | Error::PersistentVolumeQueryFailed
            | Error::PersistentVolumeStateAmbiguous
            | Error::FilesystemFailure
            | Error::BoundExceeded
    )
}

fn private_orphan_failure(error: Error) -> Error {
    match error {
        Error::UnsupportedAliasNamespace
        | Error::AliasNamespaceAmbiguous
        | Error::AliasIdentityMismatch
        | Error::CaseSensitiveDirectoryUnsupported
        | Error::PersistentVolumeQueryFailed
        | Error::PersistentVolumeStateAmbiguous
        | Error::BoundExceeded => error,
        _ => Error::PrivateOrphansPresent,
    }
}

pub struct MutationLock {
    file: File,
    range: OVERLAPPED,
    root_identity: FileIdentity,
    held: bool,
}

impl MutationLock {
    fn acquire(authority: &QualifiedPrivateStateRoot) -> Result<Self> {
        let namespace = authority.observe_root()?;
        let entry = namespace
            .entries()
            .iter()
            .find(|entry| entry.role() == PrivateLeafRole::Lock)
            .ok_or(Error::CreateIncomplete)?;
        if entry.entry_kind() != EntryKind::File {
            return Err(Error::CreateIncomplete);
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        let file = authority
            .root()
            .open_with(LOCK_LEAF, &options)
            .map_err(|_| Error::CreateIncomplete)?;
        validate_regular_one_link_stream_clean(&file)?;
        authority.verify_opened_entry(entry, &file)?;
        if usize::try_from(file.metadata().map_err(|_| Error::CreateIncomplete)?.len())
            .map_err(|_| Error::CreateIncomplete)?
            != LOCK_MAGIC.len()
        {
            return Err(Error::CreateIncomplete);
        }
        let mut range = OVERLAPPED::default();
        // SAFETY: `file` is a live synchronous file handle and the zeroed
        // OVERLAPPED offsets select exact byte range [0, 1).
        let locked = unsafe {
            LockFileEx(
                file.as_raw_handle() as HANDLE,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut range,
            )
        };
        if locked == 0 {
            // SAFETY: this reads the thread-local status of the immediately
            // preceding LockFileEx failure.
            return if unsafe { GetLastError() } == ERROR_LOCK_VIOLATION {
                Err(Error::LockContention)
            } else {
                Err(Error::FilesystemFailure)
            };
        }
        let mut lock = Self {
            file,
            range,
            root_identity: authority.root_identity(),
            held: true,
        };
        if read_file_bounded(&mut lock.file, LOCK_MAGIC.len() + 1)? != LOCK_MAGIC {
            return Err(Error::CreateIncomplete);
        }
        Ok(lock)
    }

    pub fn release(mut self) -> Result<()> {
        self.unlock()
    }

    fn unlock(&mut self) -> Result<()> {
        if !self.held {
            return Ok(());
        }
        // SAFETY: this is the live handle and exact OVERLAPPED range used by
        // the successful LockFileEx operation.
        let unlocked = unsafe {
            UnlockFileEx(
                self.file.as_raw_handle() as HANDLE,
                0,
                1,
                0,
                &mut self.range,
            )
        };
        if unlocked == 0 {
            Err(Error::FilesystemFailure)
        } else {
            self.held = false;
            Ok(())
        }
    }
}

impl Drop for MutationLock {
    fn drop(&mut self) {
        let _ = self.unlock();
    }
}

fn validate_candidate(
    bytes: &[u8],
    prior: Option<&AuthenticatedLiveCapsule>,
    expected_closed: bool,
    root_identity: FileIdentity,
) -> Result<()> {
    match (prior, expected_closed) {
        (None, false) => {
            let live = unprotect_live_capsule(bytes, None)?;
            validate_root_binding(&live, root_identity)?;
        }
        (Some(prior), false) => {
            let live = unprotect_live_capsule(bytes, Some(prior))?;
            validate_root_binding(&live, root_identity)?;
        }
        (Some(prior), true) => {
            unprotect_closed_tombstone(prior, bytes)?;
        }
        (None, true) => return Err(Error::InvalidState),
    }
    Ok(())
}

fn state_root_commitment(schedule: &KeySchedule<'_>, identity: FileIdentity) -> Result<[u8; 32]> {
    let mut writer = CanonicalWriter::new("safeclone/rt1/state-root", 128)?;
    writer.u64(identity.volume_serial)?;
    writer.bytes(&identity.file_id)?;
    let input = writer.finish();
    let key = schedule.derive(KeyPurpose::TreeCommit)?;
    hmac_tag(&key, &[&input])
}

fn validate_root_binding(live: &AuthenticatedLiveCapsule, identity: FileIdentity) -> Result<()> {
    let expected = state_root_commitment(&live.key_schedule(), identity)?;
    if constant_time_equal(&expected, &live.capsule().state_root_identity_commitment) {
        Ok(())
    } else {
        Err(Error::CorruptState)
    }
}

fn record_manifest_reference(
    live: &AuthenticatedLiveCapsule,
    references: &mut BTreeMap<String, u64>,
) -> Result<()> {
    let Some(review) = &live.capsule().current_review else {
        return Ok(());
    };
    let leaf = manifest_leaf(&review.review_id, review.manifest_phase);
    references.entry(leaf).or_insert(live.capsule().generation);
    Ok(())
}

fn validate_review_manifest_evidence(
    store: &GenerationStore,
    observation: &StoreObservation,
    prior: &AuthenticatedLiveCapsule,
    next: &AuthenticatedLiveCapsule,
    evidence: &ReviewManifestEvidence,
    expected_generation: u64,
) -> Result<()> {
    let review = next
        .capsule()
        .current_review
        .as_ref()
        .ok_or(Error::InvalidState)?;
    if observation.orphan_count != 1
        || evidence.root_identity != store.root_identity()
        || evidence.prior_generation != prior.capsule().generation
        || evidence.owning_generation != expected_generation
        || next.capsule().generation != expected_generation
        || !matches!(
            evidence.phase,
            ManifestPhase::Review | ManifestPhase::ApplyResult
        )
        || review.review_id != evidence.review_id
        || review.manifest_phase != evidence.phase
        || !constant_time_equal(&review.manifest_commitment, &evidence.manifest_commitment)
        || next.capsule().orphan_count_at_commit != 0
    {
        return Err(Error::InvalidState);
    }
    let leaf = manifest_leaf(&evidence.review_id, evidence.phase);
    let namespace = store.authority.observe_root()?;
    let entry = namespace.find_exact_long(&leaf)?;
    let file = store.open_observed_regular(entry)?;
    if file_identity(&file)? != evidence.manifest_identity {
        return Err(Error::PrivateOrphansPresent);
    }
    let bytes = store.read_observed_leaf_bounded(entry, MAX_MANIFEST_FILE_BYTES)?;
    let authenticated = unprotect_manifest_authenticated_with_schedule(
        &prior.key_schedule(),
        evidence.owning_generation,
        &bytes,
    )?;
    if !constant_time_equal(authenticated.commitment(), &evidence.manifest_commitment) {
        return Err(Error::AuthenticationFailed);
    }
    Ok(())
}

fn create_pending(root: &Dir, leaf: &str) -> Result<File> {
    if !observe::is_pending_leaf(leaf) {
        return Err(Error::InvalidState);
    }
    create_empty_private_file(root, leaf)
}

fn create_empty_private_file(root: &Dir, leaf: &str) -> Result<File> {
    validate_leaf(OsStr::new(leaf))?;
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
        .map_err(|_| Error::FilesystemFailure)
}

fn require_write_through_delete_access(file: &File) -> Result<()> {
    let mode = query_file_mode(file)?;
    let access = query_file_access(file)?;
    if mode & FILE_WRITE_THROUGH == 0
        || access & (FILE_READ_DATA | FILE_WRITE_DATA | DELETE)
            != FILE_READ_DATA | FILE_WRITE_DATA | DELETE
    {
        Err(Error::FilesystemFailure)
    } else {
        Ok(())
    }
}

fn open_regular_read(root: &Dir, leaf: &str) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .follow(FollowSymlinks::No)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    let file = root
        .open_with(leaf, &options)
        .map_err(|_| Error::FilesystemFailure)?;
    validate_regular_one_link_stream_clean(&file)?;
    Ok(file)
}

fn validate_regular_one_link_stream_clean(file: &File) -> Result<()> {
    observe::require_not_reparse(file)?;
    let metadata = file.metadata().map_err(|_| Error::FilesystemFailure)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1 {
        return Err(Error::CorruptState);
    }
    validate_default_stream_only(file)
}

fn validate_default_stream_only(file: &File) -> Result<()> {
    let word_count = MAX_STREAM_QUERY_BYTES.div_ceil(size_of::<usize>());
    let mut storage = vec![0usize; word_count];
    // SAFETY: `storage` is aligned and writable for the advertised byte size;
    // the file handle is live for the synchronous query.
    let queried = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileStreamInfo,
            storage.as_mut_ptr().cast(),
            u32::try_from(MAX_STREAM_QUERY_BYTES).map_err(|_| Error::FilesystemFailure)?,
        )
    };
    if queried == 0 {
        return Err(Error::FilesystemFailure);
    }
    let info = storage.as_ptr().cast::<FILE_STREAM_INFO>();
    // SAFETY: the successful query initialized at least the fixed first entry.
    let next = unsafe { (*info).NextEntryOffset };
    // SAFETY: same initialized fixed entry.
    let name_bytes =
        usize::try_from(unsafe { (*info).StreamNameLength }).map_err(|_| Error::CorruptState)?;
    let fixed = offset_of!(FILE_STREAM_INFO, StreamName);
    if next != 0 || name_bytes % 2 != 0 || fixed + name_bytes > MAX_STREAM_QUERY_BYTES {
        return Err(Error::CorruptState);
    }
    // SAFETY: StreamNameLength and the query buffer bounds were checked.
    let name = unsafe {
        std::slice::from_raw_parts((*info).StreamName.as_ptr(), name_bytes / size_of::<u16>())
    };
    let expected: Vec<u16> = OsStr::new("::$DATA").encode_wide().collect();
    if name != expected {
        return Err(Error::CorruptState);
    }
    Ok(())
}

fn query_file_mode(file: &File) -> Result<u32> {
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut information = FILE_MODE_INFORMATION::default();
    // SAFETY: live file and correctly sized writable output blocks.
    let status = unsafe {
        NtQueryInformationFile(
            file.as_raw_handle() as HANDLE,
            &mut io_status,
            (&mut information as *mut FILE_MODE_INFORMATION).cast(),
            u32::try_from(size_of::<FILE_MODE_INFORMATION>())
                .map_err(|_| Error::FilesystemFailure)?,
            FileModeInformation,
        )
    };
    ntstatus_result(status, information.Mode)
}

fn query_file_access(file: &File) -> Result<u32> {
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut information = FILE_ACCESS_INFORMATION::default();
    // SAFETY: live file and correctly sized writable output blocks.
    let status = unsafe {
        NtQueryInformationFile(
            file.as_raw_handle() as HANDLE,
            &mut io_status,
            (&mut information as *mut FILE_ACCESS_INFORMATION).cast(),
            u32::try_from(size_of::<FILE_ACCESS_INFORMATION>())
                .map_err(|_| Error::FilesystemFailure)?,
            FileAccessInformation,
        )
    };
    ntstatus_result(status, information.AccessFlags)
}

fn ntstatus_result<T>(status: i32, success: T) -> Result<T> {
    if status < 0 {
        // SAFETY: translates the NTSTATUS from the immediately preceding call.
        let _ = unsafe { RtlNtStatusToDosError(status) };
        Err(Error::FilesystemFailure)
    } else {
        Ok(success)
    }
}

fn flush_file<T: AsRawHandle>(file: &T) -> Result<()> {
    // SAFETY: caller supplies a live writable handle.
    if unsafe { FlushFileBuffers(file.as_raw_handle() as HANDLE) } == 0 {
        Err(Error::FilesystemFailure)
    } else {
        Ok(())
    }
}

fn exclusive_rename_same_handle(file: &File, root: &Dir, final_leaf: &str) -> Result<()> {
    validate_leaf(OsStr::new(final_leaf))?;
    let target = OsStr::new(final_leaf).encode_wide().collect::<Vec<_>>();
    let target_bytes = target
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(Error::FilesystemFailure)?;
    let buffer_bytes = offset_of!(FILE_RENAME_INFORMATION, FileName)
        .checked_add(target_bytes)
        .ok_or(Error::FilesystemFailure)?;
    let buffer_size = u32::try_from(buffer_bytes).map_err(|_| Error::FilesystemFailure)?;
    let words = buffer_bytes
        .checked_add(size_of::<usize>() - 1)
        .ok_or(Error::FilesystemFailure)?
        / size_of::<usize>();
    let mut storage = vec![0usize; words];
    let information = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: aligned storage is sized for the fixed header and exact non-NUL
    // UTF-16 leaf. Every field is initialized before the native call.
    unsafe {
        (*information).Anonymous.ReplaceIfExists = false;
        (*information).RootDirectory = root.as_raw_handle() as HANDLE;
        (*information).FileNameLength =
            u32::try_from(target_bytes).map_err(|_| Error::FilesystemFailure)?;
        ptr::copy_nonoverlapping(
            target.as_ptr(),
            (*information).FileName.as_mut_ptr(),
            target.len(),
        );
    }
    let mut io_status = IO_STATUS_BLOCK::default();
    // SAFETY: `file` is the live DELETE-capable write-through pending handle,
    // `root` is the retained target root, and storage lives through this call.
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

fn validate_leaf(leaf: &OsStr) -> Result<()> {
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
        Err(Error::InvalidState)
    }
}

fn read_file_bounded(file: &mut File, limit: usize) -> Result<Vec<u8>> {
    read_file_bounded_with(file, limit, filesystem_read_error)
}

fn read_lock_file_bounded(file: &mut File, limit: usize) -> Result<Vec<u8>> {
    read_file_bounded_with(file, limit, lock_read_error)
}

fn read_file_bounded_with(
    file: &mut File,
    limit: usize,
    map_read_error: fn(std::io::Error) -> Error,
) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0)).map_err(map_read_error)?;
    let take_limit = u64::try_from(limit)
        .map_err(|_| Error::BoundExceeded)?
        .checked_add(1)
        .ok_or(Error::BoundExceeded)?;
    let mut bytes = Vec::new();
    file.take(take_limit)
        .read_to_end(&mut bytes)
        .map_err(map_read_error)?;
    if bytes.len() > limit {
        return Err(Error::BoundExceeded);
    }
    Ok(bytes)
}

fn filesystem_read_error(_error: std::io::Error) -> Error {
    Error::FilesystemFailure
}

fn lock_read_error(error: std::io::Error) -> Error {
    if error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        == Some(ERROR_LOCK_VIOLATION)
    {
        Error::LockContention
    } else {
        Error::FilesystemFailure
    }
}

#[cfg(test)]
fn read_leaf_bounded(root: &Dir, leaf: &str, limit: usize) -> Result<Vec<u8>> {
    let mut file = open_regular_read(root, leaf)?;
    let before = file_identity(&file)?;
    let bytes = read_file_bounded(&mut file, limit)?;
    let after = file_identity(&file)?;
    let reopened = open_regular_read(root, leaf)?;
    if before != after || after != file_identity(&reopened)? {
        return Err(Error::CorruptState);
    }
    Ok(bytes)
}

fn leaf_absent(root: &Dir, leaf: &str) -> Result<bool> {
    match root.symlink_metadata(leaf) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(_) => Err(Error::FilesystemFailure),
    }
}

#[cfg(test)]
fn final_leaf(generation: u64) -> String {
    observe::final_leaf(generation)
}

fn pending_leaf() -> Result<String> {
    let mut random = [0u8; 16];
    system_random(&mut random)?;
    Ok(format!(
        "{}{}{}",
        observe::PENDING_PREFIX,
        encode_base32_128(&random),
        observe::PENDING_SUFFIX
    ))
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitCheckpoint {
    P0,
    P1,
    P2,
    P3,
    P4,
    P5,
    P6,
    P7,
}

#[cfg(test)]
fn approval_test_checkpoint() -> Option<CommitCheckpoint> {
    let value = std::env::var("SAFECLONE_TEST_APPROVAL_COMMIT_CHECKPOINT").ok()?;
    match value.as_str() {
        "P0" => Some(CommitCheckpoint::P0),
        "P1" => Some(CommitCheckpoint::P1),
        "P2" => Some(CommitCheckpoint::P2),
        "P3" => Some(CommitCheckpoint::P3),
        "P4" => Some(CommitCheckpoint::P4),
        "P5" => Some(CommitCheckpoint::P5),
        "P6" => Some(CommitCheckpoint::P6),
        "P7" => Some(CommitCheckpoint::P7),
        _ => None,
    }
}

#[cfg(test)]
fn abort_at(selected: Option<CommitCheckpoint>, current: CommitCheckpoint) {
    if selected == Some(current) {
        std::process::abort();
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use cap_std::ambient_authority;

    use super::*;
    use crate::roundtrip::crypto::SessionMasterSecret;
    use crate::roundtrip::dpapi::{
        protect_authenticated_manifest_bytes, protect_closed_tombstone,
        protect_initial_live_capsule, protect_next_live_capsule,
    };
    use crate::roundtrip::schema::tests::{active_capsule, tombstone};

    const FIXTURE_PREFIX: &str = "safeclone-capsule-";
    const CHILD_MODE_ENV: &str = "SAFECLONE_TEST_CAPSULE_CHILD_MODE";
    const CHILD_ROOT_ENV: &str = "SAFECLONE_TEST_CAPSULE_CHILD_ROOT";
    const CHILD_CHECKPOINT_ENV: &str = "SAFECLONE_TEST_CAPSULE_CHILD_CHECKPOINT";
    const CHILD_GENERATION_ENV: &str = "SAFECLONE_TEST_CAPSULE_CHILD_GENERATION";
    const CHILD_TEST_NAME: &str = "roundtrip::capsule::tests::capsule_child_worker";
    const READY_LEAF: &str = "lab-lock-ready";
    const RELEASE_LEAF: &str = "lab-lock-release";

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
            let workspace = std::env::current_dir().expect("current directory");
            assert!(!temp_parent.starts_with(&workspace));
            let root = temp_parent.join(format!(
                "{FIXTURE_PREFIX}{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).expect("create external synthetic fixture");
            let fixture = Self { root, temp_parent };
            drop(fixture.store());
            fixture
        }

        fn store(&self) -> GenerationStore {
            store_for_path(&self.root)
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

    fn store_for_path(path: &Path) -> GenerationStore {
        let retained = Dir::open_ambient_dir(path, ambient_authority())
            .expect("open controlled synthetic fixture");
        let authority = observe::qualify_synthetic_private_state_root(retained)
            .expect("qualify alias-aware synthetic private root");
        GenerationStore::from_qualified_root(authority)
    }

    fn master() -> SessionMasterSecret {
        SessionMasterSecret::from_bytes([0x77; 32])
    }

    fn protected_initial(store: &GenerationStore) -> Vec<u8> {
        let master = master();
        let mut capsule = active_capsule(1);
        capsule.state_root_identity_commitment = store
            .state_root_identity_commitment(&KeySchedule::new(&master, capsule.session_id))
            .expect("bind state root");
        protect_initial_live_capsule(&master, &capsule).expect("protect initial")
    }

    fn protected_next(store: &GenerationStore, prior: &AuthenticatedLiveCapsule) -> Vec<u8> {
        let mut capsule = active_capsule(prior.capsule().generation + 1);
        capsule.state_root_identity_commitment = store
            .state_root_identity_commitment(&prior.key_schedule())
            .expect("bind state root");
        protect_next_live_capsule(prior, &capsule).expect("protect next")
    }

    fn initialize_and_commit_one(store: &GenerationStore) -> CommitEvidence {
        store.initialize_lock().expect("initialize lock");
        let protected = protected_initial(store);
        let mut lock = store.acquire_mutation_lock().expect("acquire lock");
        let evidence = store
            .append_capsule_generation(&mut lock, &protected)
            .expect("commit generation one");
        lock.release().expect("release lock");
        evidence
    }

    fn create_leaf(root: &Dir, leaf: &str, bytes: &[u8]) -> FileIdentity {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        let mut file = root.open_with(leaf, &options).expect("create leaf");
        file.write_all(bytes).expect("write leaf");
        flush_file(&file).expect("flush leaf");
        file_identity(&file).expect("leaf identity")
    }

    impl CommitCheckpoint {
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
    }

    fn spawn_checkpoint_child(
        root: &Path,
        generation: u64,
        checkpoint: CommitCheckpoint,
    ) -> std::io::Result<std::process::ExitStatus> {
        Command::new(std::env::current_exe()?)
            .arg(CHILD_TEST_NAME)
            .arg("--exact")
            .arg("--nocapture")
            .env(CHILD_MODE_ENV, "checkpoint")
            .env(CHILD_ROOT_ENV, root)
            .env(CHILD_GENERATION_ENV, generation.to_string())
            .env(CHILD_CHECKPOINT_ENV, checkpoint.as_str())
            .env("RUST_TEST_THREADS", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    }

    fn spawn_lock_holder(root: &Path) -> std::io::Result<Child> {
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

    fn wait_for_path(path: &Path, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if path.exists() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }

    fn wait_for_child(child: &mut Child, timeout: Duration) -> std::io::Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
        child.kill()?;
        let _ = child.wait()?;
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "child timed out",
        ))
    }

    fn checkpoint_child() {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT_ENV).expect("root env"));
        let store = store_for_path(&root);
        let generation = std::env::var(CHILD_GENERATION_ENV)
            .expect("generation env")
            .parse::<u64>()
            .expect("generation integer");
        let checkpoint =
            CommitCheckpoint::parse(&std::env::var(CHILD_CHECKPOINT_ENV).expect("checkpoint env"))
                .expect("known checkpoint");
        let protected = if generation == 1 {
            protected_initial(&store)
        } else {
            let observation = store.read().expect("read prior");
            protected_next(&store, observation.live_head().expect("live prior"))
        };
        let mut lock = store.acquire_mutation_lock().expect("child lock");
        store
            .append_impl(&mut lock, &protected, None, Some(checkpoint), false)
            .expect("checkpoint aborts before return");
        panic!("checkpoint did not abort");
    }

    fn lock_holder_child() {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT_ENV).expect("root env"));
        let store = store_for_path(&root);
        let _lock = store.acquire_mutation_lock().expect("child lock");
        fs::write(root.join(READY_LEAF), b"ready").expect("ready marker");
        assert!(wait_for_path(
            &root.join(RELEASE_LEAF),
            Duration::from_secs(10)
        ));
    }

    #[test]
    fn capsule_child_worker() {
        let Some(mode) = std::env::var_os(CHILD_MODE_ENV) else {
            return;
        };
        match mode.to_str() {
            Some("checkpoint") => checkpoint_child(),
            Some("lock-holder") => lock_holder_child(),
            _ => panic!("unknown child mode"),
        }
    }

    #[test]
    fn production_sequence_commits_identity_bound_generation() {
        let fixture = Fixture::new("primary");
        let store = fixture.store();
        let evidence = initialize_and_commit_one(&store);
        assert_eq!(evidence.root_identity, store.root_identity());
        let final_file = open_regular_read(store.root(), &final_leaf(1)).expect("final file");
        assert_eq!(
            file_identity(&final_file).expect("final identity"),
            evidence.generation_identity
        );
        let observation = store.read().expect("read authority");
        assert_eq!(
            observation.classification,
            StoreClassification::AuthoritativeLive
        );
        assert_eq!(observation.head().map(AuthorityHead::generation), Some(1));
    }

    #[test]
    fn empty_first_lock_failure_never_writes_lock_magic() {
        let fixture = Fixture::new("empty-first-failure");
        let store = fixture.store();
        assert_eq!(
            store.initialize_lock_impl(true),
            Err(Error::AliasIdentityMismatch)
        );
        let empty = open_regular_read(store.root(), LOCK_LEAF).expect("retained empty lock");
        assert_eq!(empty.metadata().expect("empty metadata").len(), 0);
        assert_eq!(
            store.read().expect("classify empty lock").classification,
            StoreClassification::CreateIncomplete
        );
    }

    #[test]
    fn pending_and_manifest_gate_failures_leave_zero_bytes() {
        let pending_fixture = Fixture::new("pending-gate-failure");
        let pending_store = pending_fixture.store();
        pending_store.initialize_lock().expect("initialize lock");
        let protected = protected_initial(&pending_store);
        let mut pending_lock = pending_store
            .acquire_mutation_lock()
            .expect("pending failure lock");
        assert_eq!(
            pending_store.append_impl(&mut pending_lock, &protected, None, None, true),
            Err(Error::AliasIdentityMismatch)
        );
        pending_lock.release().expect("release pending lock");
        let pending_namespace = pending_store
            .authority
            .observe_root()
            .expect("observe empty pending");
        let pending_entry = pending_namespace
            .entries()
            .iter()
            .find(|entry| entry.role() == PrivateLeafRole::Pending)
            .expect("one retained pending entry");
        let pending_file = pending_store
            .open_observed_regular(pending_entry)
            .expect("open retained pending");
        assert_eq!(pending_file.metadata().expect("pending metadata").len(), 0);

        let manifest_fixture = Fixture::new("manifest-gate-failure");
        let manifest_store = manifest_fixture.store();
        initialize_and_commit_one(&manifest_store);
        let observation = manifest_store.read().expect("live manifest owner");
        let owner = observation.live_head().expect("live owner");
        let protected_manifest = protect_authenticated_manifest_bytes(owner, b"private fixture")
            .expect("protect manifest fixture");
        let mut manifest_lock = manifest_store
            .acquire_mutation_lock()
            .expect("manifest failure lock");
        assert_eq!(
            manifest_store.persist_manifest_impl(
                &mut manifest_lock,
                owner,
                ManifestWriteBinding {
                    review_id: [0x31; 16],
                    phase: ManifestPhase::Review,
                    owning_generation: owner.capsule().generation,
                    expected_commitment: None,
                },
                &protected_manifest,
                true,
            ),
            Err(Error::AliasIdentityMismatch)
        );
        manifest_lock.release().expect("release manifest lock");
        let manifest_namespace = manifest_store
            .authority
            .observe_root()
            .expect("observe empty manifest");
        let manifest_entry = manifest_namespace
            .entries()
            .iter()
            .find(|entry| matches!(entry.role(), PrivateLeafRole::Manifest { .. }))
            .expect("one retained manifest entry");
        let manifest_file = manifest_store
            .open_observed_regular(manifest_entry)
            .expect("open retained manifest");
        assert_eq!(
            manifest_file.metadata().expect("manifest metadata").len(),
            0
        );
    }

    #[test]
    fn committed_namespace_errors_preserve_commit_certainty() {
        for error in [
            Error::CorruptState,
            Error::UnsupportedAliasNamespace,
            Error::AliasNamespaceAmbiguous,
            Error::AliasIdentityMismatch,
        ] {
            assert!(committed_namespace_is_corrupt(error));
            assert!(!post_commit_namespace_is_unclassifiable(error));
        }
        for error in [
            Error::CaseSensitiveDirectoryUnsupported,
            Error::PersistentVolumeQueryFailed,
            Error::PersistentVolumeStateAmbiguous,
            Error::FilesystemFailure,
            Error::BoundExceeded,
        ] {
            assert!(!committed_namespace_is_corrupt(error));
            assert!(post_commit_namespace_is_unclassifiable(error));
        }
    }

    #[test]
    #[ignore = "requires an actual ordinary-user local NTFS volume with 8.3 creation enabled"]
    fn enabled_ntfs_private_store_is_alias_and_identity_bound() {
        let fixture = Fixture::new("actual-enabled");
        let store = fixture.store();
        assert_eq!(
            store.selected_short_name_mode(),
            observe::ShortNameMode::Enabled
        );
        let committed = initialize_and_commit_one(&store);
        let final_name = final_leaf(1);
        let after_rename = store
            .authority
            .observe_root()
            .expect("post-rename alias-aware observation");
        let final_entry = after_rename
            .find_exact_long(&final_name)
            .expect("canonical final record");
        let final_handle = store
            .open_observed_regular(final_entry)
            .expect("canonical-long retained-parent open");
        assert_eq!(
            file_identity(&final_handle).expect("opened final identity"),
            committed.generation_identity
        );
        assert_eq!(final_handle.metadata().expect("final metadata").nlink(), 1);

        let observation = store.read().expect("authoritative live store");
        let owner = observation.live_head().expect("live manifest owner");
        let protected_manifest =
            protect_authenticated_manifest_bytes(owner, b"synthetic private manifest")
                .expect("protect actual manifest fixture");
        let review_id = [0xA5; 16];
        let manifest_name = manifest_leaf(&review_id, ManifestPhase::Review);
        let mut lock = store.acquire_mutation_lock().expect("manifest lock");
        let manifest = store
            .persist_manifest(
                &mut lock,
                owner,
                review_id,
                ManifestPhase::Review,
                &protected_manifest,
            )
            .expect("empty-first manifest persistence");
        lock.release().expect("release manifest lock");

        let final_namespace = store
            .authority
            .observe_root()
            .expect("final private namespace");
        let manifest_entry = final_namespace
            .find_exact_long(&manifest_name)
            .expect("canonical manifest record");
        let manifest_handle = store
            .open_observed_regular(manifest_entry)
            .expect("canonical manifest open");
        assert_eq!(
            file_identity(&manifest_handle).expect("manifest identity"),
            manifest.manifest_identity
        );
        let alias_records = final_namespace
            .entries()
            .iter()
            .filter(|entry| entry.alias_present())
            .count();
        assert!(alias_records > 0, "enabled NTFS row generated aliases");
        println!(
            "PRIVATE_STORE mode=ENABLED alias_records={alias_records} canonical_identity=true nlink=1 lock_empty_first=true pending_empty_first=true manifest_empty_first=true post_rename=true"
        );
    }

    #[test]
    fn interruption_p0_through_p7_is_filesystem_classified() {
        for checkpoint in CommitCheckpoint::ALL {
            let fixture = Fixture::new(checkpoint.as_str());
            let store = fixture.store();
            store.initialize_lock().expect("initialize lock");
            let status = spawn_checkpoint_child(&fixture.root, 1, checkpoint)
                .expect("spawn checkpoint child");
            assert!(!status.success());
            let observation = store.read().expect("classify checkpoint");
            let expected = match checkpoint {
                CommitCheckpoint::P0 => StoreClassification::CreateIncomplete,
                CommitCheckpoint::P1
                | CommitCheckpoint::P2
                | CommitCheckpoint::P3
                | CommitCheckpoint::P4 => StoreClassification::PrivateOrphansPresent,
                CommitCheckpoint::P5 | CommitCheckpoint::P6 | CommitCheckpoint::P7 => {
                    StoreClassification::AuthoritativeLive
                }
            };
            assert_eq!(observation.classification, expected, "{checkpoint:?}");
            assert_eq!(
                observation.orphan_count,
                u32::from(matches!(
                    checkpoint,
                    CommitCheckpoint::P1
                        | CommitCheckpoint::P2
                        | CommitCheckpoint::P3
                        | CommitCheckpoint::P4
                ))
            );
            drop(store.acquire_mutation_lock().expect("abrupt exit unlocks"));
        }
    }

    #[test]
    fn generation_two_pre_and_post_rename_interruptions_preserve_generation_one() {
        for (checkpoint, classification, head, orphans) in [
            (
                CommitCheckpoint::P4,
                StoreClassification::PrivateOrphansPresent,
                1,
                1,
            ),
            (
                CommitCheckpoint::P5,
                StoreClassification::AuthoritativeLive,
                2,
                0,
            ),
        ] {
            let fixture = Fixture::new(&format!("gen2-{}", checkpoint.as_str()));
            let store = fixture.store();
            initialize_and_commit_one(&store);
            let before = read_leaf_bounded(store.root(), &final_leaf(1), MAX_CAPSULE_FILE_BYTES)
                .expect("generation one bytes");
            let identity = file_identity(
                &open_regular_read(store.root(), &final_leaf(1)).expect("generation one"),
            )
            .expect("generation one identity");
            let status = spawn_checkpoint_child(&fixture.root, 2, checkpoint)
                .expect("spawn checkpoint child");
            assert!(!status.success());
            let observation = store.read().expect("read state");
            assert_eq!(observation.classification, classification);
            assert_eq!(
                observation.head().map(AuthorityHead::generation),
                Some(head)
            );
            assert_eq!(observation.orphan_count, orphans);
            assert_eq!(
                read_leaf_bounded(store.root(), &final_leaf(1), MAX_CAPSULE_FILE_BYTES)
                    .expect("generation one unchanged"),
                before
            );
            assert_eq!(
                file_identity(
                    &open_regular_read(store.root(), &final_leaf(1)).expect("generation one")
                )
                .expect("identity unchanged"),
                identity
            );
        }
    }

    #[test]
    fn exclusive_rename_never_clobbers_an_existing_final() {
        let fixture = Fixture::new("no-clobber");
        let store = fixture.store();
        store.initialize_lock().expect("initialize lock");
        let pending = pending_leaf().expect("pending leaf");
        let protected = protected_initial(&store);
        let mut file = create_pending(store.root(), &pending).expect("pending file");
        file.write_all(&protected).expect("write pending");
        flush_file(&file).expect("flush pending");
        let final_name = final_leaf(1);
        let raced_bytes = b"synthetic-racing-destination";
        let raced_identity = create_leaf(store.root(), &final_name, raced_bytes);
        assert!(exclusive_rename_same_handle(&file, store.root(), &final_name).is_err());
        assert_eq!(
            file_identity(&open_regular_read(store.root(), &final_name).expect("raced final"))
                .expect("raced identity"),
            raced_identity
        );
        assert_eq!(
            read_leaf_bounded(store.root(), &final_name, 128).expect("raced bytes"),
            raced_bytes
        );
    }

    #[test]
    fn lockfileex_fails_immediately_then_releases_across_processes() {
        let fixture = Fixture::new("lock");
        let store = fixture.store();
        store.initialize_lock().expect("initialize lock");
        let mut child = spawn_lock_holder(&fixture.root).expect("spawn lock child");
        assert!(wait_for_path(
            &fixture.root.join(READY_LEAF),
            Duration::from_secs(10)
        ));
        assert!(matches!(
            store.acquire_mutation_lock(),
            Err(Error::LockContention)
        ));
        fs::write(fixture.root.join(RELEASE_LEAF), b"release").expect("release marker");
        wait_for_child(&mut child, Duration::from_secs(10)).expect("wait lock child");
        drop(store.acquire_mutation_lock().expect("lock released"));
    }

    #[test]
    fn pending_and_unreferenced_manifest_are_never_authority() {
        let fixture = Fixture::new("orphans");
        let store = fixture.store();
        store.initialize_lock().expect("initialize lock");
        create_leaf(
            store.root(),
            &pending_leaf().expect("pending leaf"),
            &protected_initial(&store),
        );
        let manifest = manifest_leaf(&[0; 16], ManifestPhase::Review);
        create_leaf(store.root(), &manifest, b"");
        let observation = store.read().expect("read orphan state");
        assert_eq!(
            observation.classification,
            StoreClassification::PrivateOrphansPresent
        );
        assert!(observation.head().is_none());
        assert_eq!(observation.orphan_count, 2);
    }

    #[test]
    fn close_may_record_but_never_adopt_a_retained_private_orphan() {
        let fixture = Fixture::new("close-orphan");
        let store = fixture.store();
        initialize_and_commit_one(&store);
        create_leaf(
            store.root(),
            &pending_leaf().expect("pending leaf"),
            &protected_initial(&store),
        );

        let observation = store.read().expect("orphan observation");
        assert_eq!(
            observation.classification,
            StoreClassification::PrivateOrphansPresent
        );
        let live = observation.live_head().expect("live authority");
        let mut close = tombstone(2);
        close.retained_private_orphan_count = 1;
        let protected = protect_closed_tombstone(live, &close).expect("protect close");
        let mut lock = store.acquire_mutation_lock().expect("close lock");
        store
            .append_capsule_generation(&mut lock, &protected)
            .expect("commit close with retained orphan");
        lock.release().expect("release close lock");

        let closed = store.read().expect("closed observation");
        assert_eq!(closed.classification, StoreClassification::Closed);
        assert_eq!(closed.orphan_count, 1);
        assert_eq!(closed.head().map(AuthorityHead::generation), Some(2));
    }

    #[test]
    fn lock_initialization_is_create_new_and_incomplete_states_are_not_repaired() {
        let absent_fixture = Fixture::new("lock-absent");
        let absent = absent_fixture.store();
        assert_eq!(
            absent
                .read()
                .expect("absent lock classification")
                .classification,
            StoreClassification::CreateIncomplete
        );
        assert!(matches!(
            absent.acquire_mutation_lock(),
            Err(Error::CreateIncomplete)
        ));

        for (label, bytes) in [
            ("lock-empty", &b""[..]),
            ("lock-partial", &LOCK_MAGIC[..LOCK_MAGIC.len() - 1]),
        ] {
            let fixture = Fixture::new(label);
            let store = fixture.store();
            create_leaf(store.root(), LOCK_LEAF, bytes);
            assert_eq!(
                store
                    .read()
                    .expect("incomplete lock classification")
                    .classification,
                StoreClassification::CreateIncomplete
            );
            assert!(matches!(
                store.acquire_mutation_lock(),
                Err(Error::CreateIncomplete)
            ));
            assert_eq!(store.initialize_lock(), Err(Error::FilesystemFailure));
        }

        let committed_fixture = Fixture::new("lock-committed");
        let committed = committed_fixture.store();
        committed
            .initialize_lock()
            .expect("initialize committed lock");
        assert_eq!(
            committed
                .read()
                .expect("committed lock classification")
                .classification,
            StoreClassification::CreateIncomplete
        );
        drop(
            committed
                .acquire_mutation_lock()
                .expect("committed lock is usable"),
        );
        assert_eq!(committed.initialize_lock(), Err(Error::FilesystemFailure));
    }

    #[test]
    fn root_copy_rejects_live_authority_but_closed_copy_is_terminal() {
        let source_fixture = Fixture::new("copy-source");
        let source = source_fixture.store();
        initialize_and_commit_one(&source);

        let live_copy_fixture = Fixture::new("copy-live");
        fs::copy(
            source_fixture.root.join(LOCK_LEAF),
            live_copy_fixture.root.join(LOCK_LEAF),
        )
        .expect("copy lock");
        fs::copy(
            source_fixture.root.join(final_leaf(1)),
            live_copy_fixture.root.join(final_leaf(1)),
        )
        .expect("copy generation");
        assert!(matches!(
            live_copy_fixture.store().read(),
            Err(Error::CorruptState)
        ));

        let observation = source.read().expect("read live source");
        let live = observation.live_head().expect("live head");
        let closed_payload = tombstone(2);
        let protected = protect_closed_tombstone(live, &closed_payload).expect("protect close");
        let mut lock = source.acquire_mutation_lock().expect("close lock");
        source
            .append_capsule_generation(&mut lock, &protected)
            .expect("commit close");
        lock.release().expect("release close lock");
        assert_eq!(
            source.read().expect("closed source").classification,
            StoreClassification::Closed
        );

        let closed_copy_fixture = Fixture::new("copy-closed");
        for leaf in [LOCK_LEAF.to_owned(), final_leaf(1), final_leaf(2)] {
            fs::copy(
                source_fixture.root.join(&leaf),
                closed_copy_fixture.root.join(&leaf),
            )
            .expect("copy closed entry");
        }
        let copied = closed_copy_fixture.store();
        assert_eq!(
            copied
                .read()
                .expect("copied close reports terminal")
                .classification,
            StoreClassification::Closed
        );
        let mut copied_lock = copied.acquire_mutation_lock().expect("copied lock");
        assert_eq!(
            copied.append_capsule_generation(&mut copied_lock, &protected),
            Err(Error::InvalidState)
        );
    }

    #[test]
    fn closed_tombstone_is_terminal_and_generation_one_is_rejected() {
        let fixture = Fixture::new("closed");
        let store = fixture.store();
        initialize_and_commit_one(&store);
        let observation = store.read().expect("live state");
        let live = observation.live_head().expect("live head");
        let protected_close = protect_closed_tombstone(live, &tombstone(2)).expect("protect close");
        let protected_next_live = protected_next(&store, live);
        let mut lock = store.acquire_mutation_lock().expect("close lock");
        store
            .append_capsule_generation(&mut lock, &protected_close)
            .expect("close commits");
        lock.release().expect("release close lock");
        assert_eq!(
            store.read().expect("closed state").classification,
            StoreClassification::Closed
        );
        let mut lock = store.acquire_mutation_lock().expect("terminal lock");
        assert_eq!(
            store.append_capsule_generation(&mut lock, &protected_next_live),
            Err(Error::InvalidState)
        );
        let mut invalid = tombstone(2);
        invalid.generation = 1;
        invalid.retained_capsule_generation_count = 1;
        assert_eq!(invalid.validate(), Err(Error::InvalidState));
    }

    #[test]
    fn reader_rejects_gap_unexpected_directory_hardlink_and_named_stream() {
        let gap_fixture = Fixture::new("gap");
        let gap = gap_fixture.store();
        gap.initialize_lock().expect("lock");
        create_leaf(gap.root(), &final_leaf(2), &protected_initial(&gap));
        assert!(matches!(gap.read(), Err(Error::CorruptState)));

        let directory_fixture = Fixture::new("directory");
        let directory = directory_fixture.store();
        directory.initialize_lock().expect("lock");
        fs::create_dir(directory_fixture.root.join("child")).expect("child directory");
        assert!(directory.read().is_err());

        let hardlink_fixture = Fixture::new("hardlink");
        let hardlink = hardlink_fixture.store();
        hardlink.initialize_lock().expect("lock");
        fs::hard_link(
            hardlink_fixture.root.join(LOCK_LEAF),
            hardlink_fixture.root.join("unexpected-link"),
        )
        .expect("create hard link");
        assert!(hardlink.read().is_err());

        let stream_fixture = Fixture::new("stream");
        let stream = stream_fixture.store();
        stream.initialize_lock().expect("lock");
        fs::write(
            stream_fixture.root.join(format!("{LOCK_LEAF}:synthetic")),
            b"stream",
        )
        .expect("create named stream");
        assert!(stream.read().is_err());
    }
}
