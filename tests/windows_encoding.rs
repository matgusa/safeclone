#![cfg(windows)]

//! Synthetic encoding probes only. Explicit code-page conversions here prove
//! fixture adversity; they never select a product path or simulate a host.
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr;

use windows_sys::Win32::Globalization::{WideCharToMultiByte, WC_NO_BEST_FIT_CHARS};

pub const UNICODE_PATHS: [&str; 6] = [
    "日本語資料/設定と説明.txt",
    "日本語資料/Ā-euro-€.txt",
    "日本語資料/非BMP-🚀-𐐷.txt",
    "日本語資料/全角ＡＢＣ.txt",
    "日本語資料/한글-Ж-Ā.txt",
    "日本語資料/space & apostrophe's-漢🚀.txt",
];

fn requires_replacement(text: &str, code_page: u32) -> bool {
    let wide: Vec<u16> = text.encode_utf16().collect();
    let mut output = [0u8; 1024];
    let mut replaced = 0;
    // SAFETY: live, bounded buffers with explicit lengths. No global locale or
    // console state is changed, and best-fit approximation is forbidden.
    let count = unsafe {
        WideCharToMultiByte(
            code_page,
            WC_NO_BEST_FIT_CHARS,
            wide.as_ptr(),
            i32::try_from(wide.len()).unwrap(),
            output.as_mut_ptr(),
            i32::try_from(output.len()).unwrap(),
            ptr::null(),
            &mut replaced,
        )
    };
    assert!(count > 0, "explicit fixture encoding query failed");
    replaced != 0
}

#[test]
fn fixtures_are_outside_932_and_1252_and_native_wide_is_exact() {
    for (text, outside_932, outside_1252) in [
        ("日本語資料", false, true),
        ("Ā-euro-€", true, true),
        ("非BMP-🚀-𐐷", true, true),
        ("한글-Ж-Ā", true, true),
    ] {
        assert_eq!(requires_replacement(text, 932), outside_932);
        assert_eq!(requires_replacement(text, 1252), outside_1252);
    }
    for path in UNICODE_PATHS {
        let expected: Vec<u16> = path.encode_utf16().collect();
        let native = OsString::from_wide(&expected);
        assert_eq!(native.encode_wide().collect::<Vec<_>>(), expected);
        assert_eq!(native.to_str().unwrap().as_bytes(), path.as_bytes());
        assert!(!path.contains('\u{fffd}'));
    }
    for wide in [vec![0xd800], vec![0xdc00], vec![0xd800, 0x61, 0xdc00]] {
        let native = OsString::from_wide(&wide);
        assert!(native.to_str().is_none());
        assert_eq!(native.encode_wide().collect::<Vec<_>>(), wide);
    }
}
