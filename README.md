# krust-ebpf-hooks

A kernel-level security monitoring system developed in Rust using eBPF with the Aya framework.

## Overview

`krust-ebpf-hooks` hooks critical syscalls (`execve`, `ptrace`, `mmap`, `setuid`, etc.) to detect potential security anomalies and Advanced Persistent Threats (APT) in a kernel-agnostic and efficient manner. This project aims to provide a lightweight, high-performance solution for real-time system call monitoring with minimal performance impact.

## Features

- Kernel-level syscall hooking using eBPF technology
- Written in Rust for memory safety and performance
- Low-overhead monitoring of critical system calls
- Structured logging for security events
- Compatible with modern Linux kernels (6.0+)

## Requirements

- Linux kernel 5.5+ (tested on Debian 12 with kernel 6.1)
- Rust toolchain
- LLVM and Clang for eBPF compilation
- Linux headers matching your kernel version

## Quick Start

### Building

```bash
# Clone the repository
git clone https://github.com/giorgiosld/krust-ebpf-hooks.git
cd krust-ebpf-hooks

# Build the project
cargo build
```

### Running

```bash
# Requires root privileges to load eBPF programs
sudo ./target/debug/krust-ebpf-hooks-user
```

## Documentation

For more detailed information, see the documentation in the `docs/` directory:

- [Environment Setup](docs/environment-setup.md)

<!--
## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package krust-ebpf-hooks --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/krust-ebpf-hooks` can be
copied to a Linux server or VM and run there.
-->
