// library compontents to hook syscall
use use aya_ebpf::{
    programs::tracepoint::TracePointContext,
    maps::perf::PerfEventArray,
    maps::hash_map::HashMap,
    EbpfContext,
};
use aya_log_ebpf::info;
use core::mem;
use krust_ebpf_hooks_common::{
    EventType, SecurityEvent, RiskLevel,
    mmap_prot, mmap_flags, risk
}

// C definition for syscalls (mmap, mprotect, munmap) to have more reference look into man mmap and
// man mprotect via terminal or via browser
#[repr(C)]
struct SysMmapArgs {
    addr: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: u64,
    offset: u64,
}

#[repr(C)]
struct SysMprotectArgs {
    addr: u64,
    len: u64,
    prot: u64,
}

#[repr(C)]
struct SysMunmapArgs {
    addr: u64,
    len: u64,
}
