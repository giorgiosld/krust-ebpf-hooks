#![no_std]
#![no_main]

use aya_ebpf::{
    maps::perf::PerfEventArray,
    maps::hash_map::HashMap,
    macros::{kprobe, map, tracepoint}, 
    programs::ProbeContext,
    programs::tracepoint::TracePointContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use core::mem;
use krust_ebpf_hooks_common::{SecurityEvent, EventType, Process, RiskLevel};

// import modules defined in tracepoints
mod tracepoints;
mod utils;

use tracepoints::memory;

// define maps
// PerfEventArray for sending events to userspace
#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<SecurityEvent> = PerfEventArray::new(0);

// HashMap for tracking memory mappings (addr -> protection flags)
#[map(name = "MEMORY_MAPPINGS")]
static mut MEMORY_MAPPINGS: HashMap<u64, u32> = HashMap::new(0);

// HashMap for tracking processes with specific risk factors
#[map(name = "PROCESS_RISKS")]
static mut PROCESS_RISKS: HashMap<u32, u64> = HashMap::new(0);

// Memroy operation tracepoints

#[tracepoint(name = "mmap_trace")]
pub fn mmap_trace(ctx: TracePointContext) -> u32 {
    match memory::handle_mmap(ctx, &mut EVENTS, &mut MEMORY_MAPPINGS, &mut PROCESS_RISKS) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}


#[kprobe]
pub fn krust_ebpf_hooks(ctx: ProbeContext) -> u32 {
    match try_krust_ebpf_hooks(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_krust_ebpf_hooks(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe called");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
