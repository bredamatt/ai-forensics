# ai-forensics

This repository contains the code for a Linux user-space system that monitors kernel-level system calls.

In this case, the syscalls of particular interest are going to be those most commonly used by AI models.

Note that the tool can capture the syscalls executed both during:
- training
- runtime 

and hence can be extended based upon the types of investigation and control system that wants to be built, or performed.

### Identification process

The syscalls were identified using the `strace` tool on an `Ubuntu 22.04.3 aarch64` VM running on my Macbook,
whilst executing a very simple PyTorch neural network.

### How does eBPF work?

This tool is dependent upon `aya`, a Rust crate designed for simplifying eBPF development.
Fundamentally, an `aya` program interacts with kernel-space eBPF code via the use of special purpose maps that are accessed from the user-space.

There are four things which must be done for this to work:
**1. Loading eBPF Programs in User-Space**:
   - `aya` uses the `libbpf` library to load eBPF programs from user-space.
   - This eBPF bytecode is packaged into an ELF (Executable and Linkable Format) file, which is the standard binary format for eBPF programs.

**2. Verifying and Loading into Kernel**:
   - `aya` wraps a system call (`bpf() syscall`) which takes the eBPF bytecode, verifies it for safety, and loads it into the kernel.
   - During the verification process, the kernel ensures that the eBPF program is safe to run and adheres to the eBPF constraints (e.g., no loops, bounded instruction count).
   
**3.Attaching to Kernel Hooks**:
- Once loaded, the eBPF program can be attached to various hooks in the kernel, such as network events, tracepoints, kprobes, and more.
- `aya` provides abstractions for these attachment points, allowing users to easily attach eBPF programs to desired kernel hooks in Rust.

**4. Interacting with Kernel-Space**:
- The loaded eBPF program runs in kernel space but is managed and controlled from user space through the eBPF subsystem.
- This eBPF subsystem includes its own BPF file system, allowing multiple BPF programs to have accessed to shared objects
- Additionally, eBPF programs can be chained together via:
  - tailcalls,
  - BPF-to-BPF calls, or
  - a combination of these
- Interaction happens through eBPF maps, which are special data structures that allow sharing data between eBPF programs and user-space applications.
- `aya` offers APIs to create, update, and read these maps from user space, facilitating communication between user-space and kernel-space code.

***Based on these principles it is possible to create programs that are reactive to kernel-space observations.***

### What does this application do?

I explored using both:
- `kprobes`
- `tracepoints`

and found `kprobes` were more flexible, but `tracepoints` more stable as these were defined in the kernel.

in this application to log whenever a Linux VM running a PyTorch Neural Network invokes the following syscalls:
- `brk` for 
- `futex`
- `mmap`
- `mmunmap`
- `malloc` for memory allocations, happens on various points
- `open` for opening file descriptors
- `read` for reading from file descriptors
- `write` for writing to file descriptors
- `close` for closing file descriptors

Since AI models:


This was an opportunity to dig a bit deeper into this topic for as I think it is particularly relevant for safety and security engineering.


### Build Prerequisites

1. You need to have LLVM 18.
2. Install bpf-linker: `cargo install bpf-linker`
   - If you are on Mac Silicon, you need to use `cargo install --no-default-features bpf-linker`
   - The same applies if you are on a Debian based distribution, such as Ubuntu.

For details about `bpf-linker` see: https://github.com/aya-rs/bpf-linker.



### Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

### Build Userspace

```bash
cargo build
```

### Build eBPF and Userspace

```bash
cargo xtask build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
