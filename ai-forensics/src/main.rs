use aya::programs::{KProbe, TracePoint};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, error, warn, debug};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ai-forensics"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ai-forensics"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let sys_enter_mmap: &mut TracePoint = bpf.program_mut("sys_enter_mmap").unwrap().try_into()?;
    sys_enter_mmap.load()?;
    sys_enter_mmap.attach("syscalls", "sys_enter_mmap")?;

    
    let sys_enter_futex_tracepoint: &mut TracePoint = bpf.program_mut("sys_enter_futex").unwrap().try_into()?;
    if let Err(e) = sys_enter_futex_tracepoint.load() {
        error!("failed to load sys_enter_futex tracepoint: {}", e);
        return Err(e.into());
    }
    if let Err(e) = sys_enter_futex_tracepoint.attach("syscalls", "sys_enter_futex") {
        error!("failed to attach sys_enter_futex tracepoint: {}", e);
        return Err(e.into());
    }

    let sys_exit_futex_tracepoint: &mut TracePoint = bpf.program_mut("sys_exit_futex").unwrap().try_into()?;
    if let Err(e) = sys_exit_futex_tracepoint.load() {
        error!("failed to load sys_exit_futex tracepoint: {}", e);
        return Err(e.into());
    }
    if let Err(e) = sys_exit_futex_tracepoint.attach("syscalls", "sys_exit_futex") {
        error!("failed to attach sys_exit_futex tracepoint: {}", e);
        return Err(e.into());
    }

    /* 
    let futex_wait: &mut KProbe = bpf.program_mut("futex_wait").unwrap().try_into()?;
    futex_wait.load()?;
    // attach to start address
    futex_wait.attach("futex", 0)?;

    let futex_wake: &mut KProbe = bpf.program_mut("futex_wake").unwrap().try_into()?;
    futex_wake.load()?;
    // attach to start address
    futex_wake.attach("futex", 0)?;
    

    let malloc_kretprobe: &mut KProbe = bpf.program_mut("kretprobe_malloc").unwrap().try_into()?;
    malloc_kretprobe.load()?;
    // attach to return address
    malloc_kretprobe.attach("malloc", 0)?;

    */ 

    info!("Waiting for Ctrl-C...");
    
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
