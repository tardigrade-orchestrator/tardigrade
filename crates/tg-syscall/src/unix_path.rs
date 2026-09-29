//! How long the path of a Unix socket may be.
//!
//! A **property of the kernel**, not a choice of ours: `sockaddr_un` has a field
//! `sun_path` of fixed size, and the path has to fit in including its null byte.
//!
//! ```text
//! sun_path                                        108 bytes
//! bind on 105 / 106 / 107 bytes                   OK
//! bind on 108 bytes   InvalidInput, raw_os_error None
//!                     "path must be shorter than SUN_LEN"
//! ```
//!
//! The refusal at 108 comes from the **standard library** and not from the
//! kernel (`raw_os_error()` is `None`) — it never reaches it. Hence a constant
//! here and not a classification of an `errno`.

pub const SUN_PATH: usize = 108;

pub const MAX_PATH: usize = SUN_PATH - 1;

#[must_use]
pub fn fits(path: &std::path::Path) -> bool {
    path.as_os_str().len() <= MAX_PATH
}

#[must_use]
pub fn headroom(prefix: &std::path::Path) -> Option<usize> {
    MAX_PATH.checked_sub(prefix.as_os_str().len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn the_constant_matches_the_kernel_struct() {
        // SAFETY: `sockaddr_un` is `repr(C)` and consists of a `sa_family_t` and
        // a byte field — all zeroes is a valid value. Only `.len()` of the field
        // is read, i.e. a property of the **type** and not of the content.
        let addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        assert_eq!(
            addr.sun_path.len(),
            SUN_PATH,
            "sockaddr_un has changed — the limit belongs re-measured, not adjusted"
        );
    }

    #[test]
    fn the_boundary_is_where_bind_says_it_is() {
        let dir = std::env::temp_dir().join(format!("sunpath-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("directory");
        let base = dir.as_os_str().len() + 1;

        for (total, expect_ok) in [(MAX_PATH, true), (MAX_PATH + 1, false)] {
            let path = dir.join("a".repeat(total - base));
            assert_eq!(path.as_os_str().len(), total);
            assert_eq!(fits(&path), expect_ok, "fits({total}) wrong");

            let bound = std::os::unix::net::UnixListener::bind(&path).is_ok();
            assert_eq!(
                bound, expect_ok,
                "bind({total}) and `fits` disagree — the constant is wrong"
            );
            let _ = std::fs::remove_file(&path);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_headroom_is_what_is_left() {
        assert_eq!(headroom(&PathBuf::from("/a")), Some(MAX_PATH - 2));
        assert_eq!(headroom(&PathBuf::from("x".repeat(MAX_PATH))), Some(0));
        assert_eq!(headroom(&PathBuf::from("x".repeat(MAX_PATH + 1))), None);
    }
}
