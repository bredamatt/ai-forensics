#![no_std]
#![no_main]

use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[tracepoint]
pub fn ai_forensics(ctx: TracePointContext) -> u32 {
    match try_ai_forensics(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ai_forensics(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint syscall called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
