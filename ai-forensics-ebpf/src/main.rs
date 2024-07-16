#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_ANY,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_printk},
    macros::{kprobe, kretprobe, map, tracepoint},
    maps::HashMap,
    programs::{ProbeContext, TracePointContext},
};
use aya_log_ebpf::info;
use core::ffi::c_int;

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

#[map]
static mut START_TIMES: HashMap<u64, u64> = HashMap::with_max_entries(1024, BPF_ANY);

#[tracepoint]
pub fn sys_enter_futex(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_futex(ctx) } {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

unsafe fn try_sys_enter_futex(ctx: TracePointContext) -> Result<u32, i64> {
    let pid = bpf_get_current_pid_tgid();
    let start_time = bpf_ktime_get_ns();

    START_TIMES.insert(&pid, &start_time, BPF_ANY as u64)?;
    Ok(0)
}

#[tracepoint]
pub fn sys_exit_futex(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_exit_futex(ctx) } {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

unsafe fn try_sys_exit_futex(ctx: TracePointContext) -> Result<u32, i64> {
    let pid = bpf_get_current_pid_tgid();
    let start_time = match START_TIMES.get(&pid) {
        Some(value) => value,
        None => return Err(1),
    };
    let end_time = bpf_ktime_get_ns();

    let duration = end_time - start_time;
    info!(
        &ctx,
        "futex call duration for pid {} was {} ns", pid, duration
    );

    START_TIMES.remove(&pid).map_err(|_| 1)?;

    Ok(0)
}

#[tracepoint]
pub fn sys_enter_mmap(ctx: TracePointContext) -> u32 {
    match try_sys_enter_mmap(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_mmap(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "sys_enter_mmap invoked");
    Ok(0)
}

#[tracepoint]
pub fn sys_exit_mmap(ctx: TracePointContext) -> u32 {
    match try_sys_exit_mmap(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_exit_mmap(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "sys_exit_mmap invoked");
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_read(ctx: TracePointContext) -> u32 {
    match try_sys_enter_read(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_read(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "sys_enter_read invoked");
    Ok(0)
}

#[tracepoint]
pub fn sys_exit_read(ctx: TracePointContext) -> u32 {
    match try_sys_exit_read(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_exit_read(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "sys_exit_read invoked");
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_close(ctx: TracePointContext) -> u32 {
    match try_sys_enter_close(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_close(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "sys_enter_close invoked");
    Ok(0)
}

#[tracepoint]
pub fn sys_exit_close(ctx: TracePointContext) -> u32 {
    match try_sys_exit_close(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_exit_close(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "sys_exit_close invoked");
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_munmap(ctx: TracePointContext) -> u32 {
    match try_sys_enter_munmap(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_munmap(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "sys_enter_munmap invoked");
    Ok(0)
}

#[tracepoint]
pub fn sys_exit_munmap(ctx: TracePointContext) -> u32 {
    match try_sys_exit_munmap(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_exit_munmap(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "sys_exit_munmap invoked");
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_brk(ctx: TracePointContext) -> u32 {
    match try_sys_enter_brk(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_brk(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "sys_enter_brk invoked");
    Ok(0)
}

#[tracepoint]
pub fn sys_exit_brk(ctx: TracePointContext) -> u32 {
    match try_sys_exit_brk(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_exit_brk(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "sys_exit_brk invoked");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
