// library compontents to hook syscall
use aya_ebpf::{
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

pub fn handle_mmap(
    ctx: TracePointContext,
    events: &mut PerfEventArray<SecurityEvent>,
    memory_mappings: &mut HashMap<u64, u32>,
    process_risks: &mut HashMap<u32, u64>,
) -> Result<(), i64> {
    // Extract syscall arguments
    let args = unsafe { ctx.read_at::<SysMmapArgs>(16)? };
    
    // Get process info
    let process = utils::get_current_process_info();
    
    // Check if this is an anonymous executable mapping a potential security risk
    let is_anonymous = (args.flags & mmap_flags::MAP_ANONYMOUS as u64) != 0;
    let is_executable = (args.prot & mmap_prot::PROT_EXEC as u64) != 0;
    
    // Determine risk level
    let mut risk_level = RiskLevel::Low;
    if is_anonymous && is_executable {
        risk_level = RiskLevel::High;
        // Update process risk flags
        utils::update_process_risks(
            process_risks,
            process.tgid,
            risk::EXEC_AFTER_MMAP_ANONYMOUS
        );
    }
    
    // Create and send event
    let event = SecurityEvent {
        event_type: EventType::Mmap as u32,
        timestamp: utils::get_timestamp_ns(),
        process: process,
        retval: 0,  // Return value will be set by tracepoint exit
        risk_level: risk_level as u8,
        arg1: args.addr,
        arg2: args.len,
        arg3: args.prot,
        arg4: args.flags,
        str_buf: [0; 256],  // Not used for mmap
    };
    
    unsafe {
        events.output(&ctx, &event, 0);
        
        // Store mapping information for future reference
        if args.addr != 0 {
            memory_mappings.insert(&args.addr, &(args.prot as u32), 0);
        }
    }
    
    Ok(())
}
