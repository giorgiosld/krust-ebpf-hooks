// Import needed to implement helper functions
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_get_current_comm},
    EbpfContext,
    maps::hash_map::HashMap,
    maps::perf::PerfEventArray,
    programs::tracepoint::TracePointContext,
};
use core::mem;
use krust_ebpf_hooks_common::{Process, RiskLevel, SecurityEvent};

/// Get current timestamp in nanoseconds
#[inline(always)]
pub fn get_timestamp_ns() -> u64 {
    unsafe { bpf_ktime_get_ns() }
}

/// Get current process information
#[inline(always)]
pub fn get_current_process_info() -> Process {
    // Returns a 64-bit value where the upper 32 bits represent the Thread Group ID (TGID) and the lower 32 bits represent the Process ID (PID)
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    // Returns a 64-bit value where the upper 32 bits contain the User ID (UID) and the lower 32 bits contain the Group ID (GID)
    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    
    let tgid = (pid_tgid >> 32) as u32; // Extract upper 32 bits by shifting right
    let pid = (pid_tgid & 0xFFFFFFFF) as u32; // Extract lower 32 bits with a bitmask
    let uid = (uid_gid >> 32) as u32; // Extract upper 32 bits
    let gid = (uid_gid & 0xFFFFFFFF) as u32; // Extract lower 32 bits
    
    let mut comm = [0u8; 16];
    // Converts the Rust array reference to a raw pointer that the C-like eBPF function can understand
    // the pointer is truncated to 16 bytes, represent the kernel's TASK_COMM_LEN
    unsafe { bpf_get_current_comm(&mut comm as *mut _ as *mut _, 16) };
    
    Process {
        pid,
        tgid,
        uid,
        gid,
        comm,
    }
}

/// Update process risk flags
#[inline(always)]
pub fn update_process_risks(
    risks: &mut HashMap<u32, u64>,
    tgid: u32,
    risk_flag: u64
) {
    match unsafe { risks.get(&tgid) } {
        Some(current_risks) => {
            let new_risks = *current_risks | risk_flag;
            unsafe { risks.insert(&tgid, &new_risks, 0) };
        }
        None => {
            unsafe { risks.insert(&tgid, &risk_flag, 0) };
        }
    }
}
