//! The proof that no eBPF is in play (invariant 1, ADR-0012).
//!
//! Phase 9 demands as an acceptance criterion "no BPF program loaded
//! (**demonstrably**)". The last word is this module's whole assignment: not to
//! claim that none is loaded, but to show it.
//!
//! The direct way there is `bpf(BPF_PROG_GET_NEXT_ID)` — the same enumeration
//! `bpftool prog list` uses. A test takes the set of program identifiers before
//! and after the network setup and compares them.
//!
//! The `unsafe` stands here because `rustix` wraps everything else this project
//! needs at the kernel — `bpf(2)` is not among them. The alternative would have
//! been a BPF library; pulling one into a project that excludes eBPF in order to
//! substantiate the exclusion would be grotesque.

use std::io;
use std::mem::size_of;

const BPF_PROG_GET_NEXT_ID: libc::c_int = 11;

#[repr(C)]
#[derive(Default)]
struct ProgGetNextId {
    start_id: u32,
    next_id: u32,
    open_flags: u32,
}

fn bpf(cmd: libc::c_int, attr: &mut ProgGetNextId) -> io::Result<libc::c_long> {
    // SAFETY: `libc::syscall` is variadic and unchecked; the safety hangs on
    // three assurances, all upheld here.
    //
    // 1. `SYS_bpf` expects exactly three arguments: command, pointer to
    //    `union bpf_attr`, size in bytes.
    // 2. The pointer stems from a live, exclusive reference to a `#[repr(C)]`
    //    aggregate of three `u32` without padding and without invariants; the
    //    kernel reads and writes at most the given
    //    `size_of::<ProgGetNextId>()` bytes.
    // 3. `size` is exactly the size of this aggregate. The kernel checks the
    //    size itself and refuses rather than reading beyond it.
    //
    // The call has no side effect apart from the return value: this command
    // only **reads**.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            std::ptr::from_mut(attr),
            size_of::<ProgGetNextId>(),
        )
    };

    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

pub fn loaded_programs() -> io::Result<Vec<u32>> {
    let mut ids = Vec::new();
    let mut attr = ProgGetNextId::default();

    loop {
        match bpf(BPF_PROG_GET_NEXT_ID, &mut attr) {
            Ok(_) => {
                ids.push(attr.next_id);
                attr.start_id = attr.next_id;
            }
            // `ENOENT` ends the enumeration: there is no higher identifier.
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => return Ok(ids),
            Err(err) => return Err(err),
        }
    }
}

#[must_use]
pub fn enumeration_available() -> bool {
    let mut attr = ProgGetNextId::default();
    match bpf(BPF_PROG_GET_NEXT_ID, &mut attr) {
        Ok(_) => true,
        Err(err) => err.raw_os_error() == Some(libc::ENOENT),
    }
}
