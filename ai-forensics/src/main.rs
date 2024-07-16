mod ws_server;

use std::sync::mpsc;
use aya::programs::{KProbe, TracePoint};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{debug, error, info, warn};
use tokio::signal;
use crate::ws_server::start_websocket_server;

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

    let (tx_clients, mut rx_clients) = mpsc::channel();
    let (tx_logs, rx_logs) = mpsc::channel();
    start_websocket_server(tx_clients);

    let tracepoints = [
        "sys_enter_read",
        "sys_exit_read",
        "sys_enter_close",
        "sys_exit_close",
        "sys_enter_mmap",
        "sys_exit_mmap",
        "sys_enter_munmap",
        "sys_exit_munmap",
        "sys_enter_brk",
        "sys_exit_brk",
        "sys_enter_futex",
        "sys_exit_futex",
    ];

    for tp in tracepoints.iter() {
        let tracepoint: &mut TracePoint = bpf.program_mut(tp).unwrap().try_into()?;
        tracepoint.load()?;
        tracepoint.attach("syscalls", tp)?;
    }

    info!("Waiting for Ctrl-C...");

    // Spawn a task to distribute log messages to all websocket clients
    tokio::spawn(async move {
        let mut clients = Vec::new();
        loop {
            tokio::select! {
                Some(client_tx) = rx_clients.recv() => {
                    clients.push(client_tx);
                }
                Some(log_message) = rx_logs.recv() => {
                    let mut broken_clients = Vec::new();
                    for (index, mut client_tx) in clients.iter().enumerate() {
                        if client_tx.send(log_message.clone()).await.is_err() {
                            broken_clients.push(index);
                        }
                    }
                    for &index in broken_clients.iter().rev() {
                        clients.swap_remove(index);
                    }
                }
            }
        }
    });


    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
