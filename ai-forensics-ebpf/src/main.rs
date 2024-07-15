#![no_std]
#![no_main]

use core::ffi::c_int;
use aya_log_ebpf::info;

use aya_ebpf::{
    macros::{tracepoint, kprobe, kretprobe},
    programs::{TracePointContext, ProbeContext},
};

#[kretprobe]
pub fn kretprobe_malloc(ctx: ProbeContext) -> u32 {
    match try_kretprobe_malloc(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kretprobe_malloc(ctx: ProbeContext) -> Result<u32, u32> {
    let retval: c_int = ctx.ret().ok_or(1u32)?;
    info!(&ctx, "malloc returned: {}", retval);
    Ok(0)
}

#[kprobe]
pub fn kprobe_futex(ctx: ProbeContext) -> u32 {
    match try_kprobe_futex(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kprobe_futex(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe_futex invoked");
    Ok(0)
}

#[tracepoint]
pub fn tracepoint_mmap(ctx: TracePointContext) -> u32 {
    match try_tracepoint_mmap(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tracepoint_mmap(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint_mmap invoked");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
