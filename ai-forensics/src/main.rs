use aya::programs::{KProbe, TracePoint};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn, debug};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ai-forensics"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ai-forensics"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let mmap_tracepoint: &mut TracePoint = bpf.program_mut("mmap").unwrap().try_into()?;
    mmap_tracepoint.load()?;
    mmap_tracepoint.attach("syscall", "mmap")?;

    let futex_kprobe: &mut KProbe = bpf.program_mut("futex").unwrap().try_into()?;
    futex_kprobe.load()?;
    // attach to start address
    futex_kprobe.attach("futex", 0).unwrap().try_into()?;

    let malloc_kretprobe: &mut KProbe = bpf.program_mut("malloc").unwrap().try_into()?;
    malloc_kretprobe.loac()?;
    // attach to return address
    malloc_kretprobe.attach("malloc", 0).unwrap().try_into()?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
