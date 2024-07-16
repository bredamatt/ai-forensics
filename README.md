# ai-forensics

This repository contains the code for a Linux user-space system that monitors kernel-level system calls.
In this case, the syscalls of particular interest are going to be those most commonly used by AI models.

Note that the tool can capture the syscalls executed both during:
- training
- runtime 

and hence functionality can be extended based upon the types of investigation and control system that wants to be built, or performed.

### Identification process

The syscalls were identified using the `strace` tool on an `Ubuntu 22.04.3 aarch64` VM running on my Macbook,
whilst executing a very simple PyTorch neural network.
I used the following command:
```
$ cd models/
$ strace -f -e trace=open,read,close,mmap,munmap,brk,futex python predictions.py
```

There is a lot more to be done in identifying relevant syscalls for monitoring purposes.
In particular, more work needs to be done to map the pids associated with a model prediction process to the eBPF system, so that 
the right analysis can be made from the tracepoints.

Future work should include piping these tracepoints logs out of the kernel-space to some log-analyser for classification purposes.
The user-space system can then receive results back from this third-party service and potentially stop the AI agent if necessary.

### How does eBPF work?

The way this program does what it does is primarily because of eBPF.
However, `aya` makes eBPF engineering more intuitive.

Fundamentally, an `aya` user-space program interacts with kernel-space eBPF code via the use of special purpose maps.

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

and found `kprobes` were more flexible, but `tracepoints` more stable as these were pre-defined in the kernel.

I used a local Linux VM running a PyTorch Neural Network, and primarily saw the following syscalls:
- `brk` for controlling memory allocated to the data segment of a  process
- `futex` synchronisation between threads in user space 
- `mmap` maps files or devices into memory 
- `mmunmap` unmaps a mapped region of memory,. previously mapped my mmap
- `read` for reading from file descriptors into a buffer 
- `write` for writing to file descriptors from a buffer
- `close` for closing open file descriptors

Therefore, I added the tracepoints for these specifically.


### Build Prerequisites

1. You need to have LLVM 18.
2. Install bpf-linker: `cargo install bpf-linker`
   - If you are on Mac Silicon, you need to use `cargo install --no-default-features bpf-linker`
   - The same applies if you are on a Debian based distribution, such as Ubuntu.

For details about `bpf-linker` see: https://github.com/aya-rs/bpf-linker.

### Build eBPF

This will only build the eBPF code:

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
