#![no_std]
#![no_main]

use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

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
