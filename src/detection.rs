//! Side-effect-free input classification primitives.

use std::ffi::OsStr;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectedKind {
    TextOrCodeCandidate,
    Unsupported,
    Unknown,
    LinkLikeEntry,
    GitMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ComponentInspectability {
    Inspectable,
    Uninspectable,
}

/// Classifies an extension and already-observed metadata without opening or
/// following the path. A candidate classification is not a safety verdict.
pub fn classify_path(path: &Path, is_link_like: bool) -> DetectedKind {
    if is_link_like {
        return DetectedKind::LinkLikeEntry;
    }

    if path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(".git"))
    }) {
        return DetectedKind::GitMetadata;
    }

    let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
        return DetectedKind::Unknown;
    };
    let extension = extension.to_ascii_lowercase();

    if matches!(
        extension.as_str(),
        "c" | "cc"
            | "cpp"
            | "css"
            | "go"
            | "h"
            | "hpp"
            | "html"
            | "java"
            | "js"
            | "json"
            | "md"
            | "py"
            | "rb"
            | "rs"
            | "sh"
            | "toml"
            | "ts"
            | "tsx"
            | "txt"
            | "yaml"
            | "yml"
    ) {
        DetectedKind::TextOrCodeCandidate
    } else if matches!(
        extension.as_str(),
        "7z" | "bin"
            | "doc"
            | "docx"
            | "exe"
            | "gz"
            | "jar"
            | "pdf"
            | "ppt"
            | "pptx"
            | "tar"
            | "xls"
            | "xlsx"
            | "zip"
    ) {
        DetectedKind::Unsupported
    } else {
        DetectedKind::Unknown
    }
}

/// Returns whether one already-observed component is repository metadata.
///
/// This is deliberately component-local so callers do not need to construct a
/// relative path merely to preserve the inventory `.git` exclusion semantics.
pub(crate) fn is_git_metadata_component(component: &OsStr) -> bool {
    component
        .to_str()
        .is_some_and(|value| value.eq_ignore_ascii_case(".git"))
}

#[cfg(test)]
mod tests {
    use super::is_git_metadata_component;
    use std::ffi::OsStr;

    #[test]
    fn git_metadata_component_semantics_are_ascii_case_insensitive_and_exact() {
        for component in [".git", ".GIT", ".GiT"] {
            assert!(is_git_metadata_component(OsStr::new(component)));
        }
        for component in [
            ".github",
            ".gitignore",
            ".gitattributes",
            "git",
            "my.git",
            "git-data",
            ".git.",
            ".git ",
        ] {
            assert!(!is_git_metadata_component(OsStr::new(component)));
        }
    }
}
