#![no_std]
#![no_main]

use core::ffi::c_int;
use aya_log_ebpf::info;
use aya_ebpf::{
    maps::HashMap,
    macros::{tracepoint, map, kprobe, kretprobe},
    programs::{TracePointContext, ProbeContext},
    bindings::BPF_ANY,
    helpers::{bpf_printk, bpf_ktime_get_ns, bpf_get_current_pid_tgid},
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

/* 
#[kprobe]
pub fn futex_wait(ctx: ProbeContext) -> u32 {
    match try_futex_wait(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_futex_wait(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe_futex invoked");
    Ok(0)
}


#[kprobe]
pub fn futex_wake(ctx: ProbeContext) -> u32 {
    match try_futex_wake(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_futex_wake(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe_futex invoked");
    Ok(0)
}

*/ 


#[map]
static mut START_TIMES: HashMap<u64, u64> = HashMap::with_max_entries(1024, BPF_ANY);

#[tracepoint]
pub fn sys_enter_futex(ctx: TracePointContext) -> u32 {
    match unsafe {try_sys_enter_futex(ctx) } {
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
    match unsafe { try_sys_exit_futex(ctx)} {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

unsafe fn try_sys_exit_futex(ctx: TracePointContext) -> Result<u32, i64> {
    let pid = bpf_get_current_pid_tgid();
    let start_time = match START_TIMES.get(&pid) {
        Some(value) => value,
        None => return Err(1)
    };
    let end_time = bpf_ktime_get_ns();
    
    let duration = end_time - start_time;
    bpf_printk!(b"futex call duration: %llu ns\n", duration);
    
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
