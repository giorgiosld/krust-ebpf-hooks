# Environment Setup Guide

This document details the setup process for the `krust-ebpf-hooks` development environment.

## Recommended Development Environment

For eBPF development, is Recommended to use a virtual machine with Debian 12 (Bookworm). This provides isolation for kernel-level development and allows for easy system restoration if issues arise.

### Why Debian 12?

- Kernel 6.1 LTS with mature eBPF support
- Stable base for development
- Widely used in enterprise server environments

### Why Use a VM?

eBPF programs run within the kernel context. Programming errors can potentially crash your system or cause kernel panics. A VM provides:

- Isolation from your host system
- Ability to take snapshots before testing potentially risky code
- Easy testing across different kernel versions
- Consistent, reproducible environment

## VM Setup with QEMU/KVM

QEMU with KVM provides near-native performance, which is important for accurate performance measurements when developing eBPF programs.

```bash
# Check if your CPU supports virtualization. If output greater than 0, the CPU support hardware virtualization.
egrep -c '(vmx|svm)' /proc/cpuinfo

# Check if KVM can be used. If kvm_intel is in the output, the kernel module are loaded.
lsmod | grep kvm

# Update your system first
sudo apt update && sudo apt upgrade -y

# Install KVM and management tools on the host
sudo apt install -y qemu-kvm qemu-system libvirt-daemon-system libvirt-clients virt-manager bridge-utils virtinst

# Start libvirt service
sudo systemctl enable --now libvirtd

# Create a default pool storage
sudo virsh pool-define-as default dir --target /var/lib/libvirt/images
sudo virsh pool-build default
sudo virsh pool-start default
sudo virsh pool-autostart default

# Download Debian 12 iso
wget -O ~/Downloads/vm/debian-12.9.0-amd64-netinst.iso https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.9.0-amd64-netinst.iso

# Create the Debian 12 VM via GUI
virt-manager
# Recommended specs:
# - 4GB+ RAM
# - 2+ CPU cores
# - 20GB+ disk space
# During installation uncheck "Debian desktop environment" and "GNOME", select instead "SSH server" and "standard system utilities"

# After VM creation update the system and install VM guest tools
# Fresh install comes without sudo and vim, is suggested to install, look online for some references to do that
sudo apt install -y qemu-guest-agent spice-vdagent
sudo systemctl enable --now qemu-guest-agent

# Install essential development tools
sudo apt install -y build-essential git curl libelf-dev llvm clang cmake

# Install additional dependencies for eBPF development
sudo apt install -y linux-headers-$(uname -r) pkg-config

# Optional: Create a VM snapshot via GUI
# Optional: For a convenient development setuo SSH access
# Optional: Setup the file sharing between Host and Guest

# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Add Rust components needed for eBPF development
rustup component add rust-src

# Install bpf-linker (required for Aya)
cargo install bpf-linker

# Install cargo-generate for using the Aya template
cargo install cargo-generate
```

# Verifying the Setup
To verify that your environment is correctly set up, you can check:
```bash
# Verify Rust installation
rustc --version

# Verify LLVM/Clang installation
clang --version

# Verify bpf-linker installation
bpf-linker --version

# Verify kernel headers are installed
ls -la /usr/src/linux-headers-$(uname -r)

# Verify kernel version (should be 6.1.x or higher)
uname -r
```

# Troubleshooting Common Issues
## Issue: openssl-sys
Due the fresh installation cargo is unable to find the OpenSSL package. 
```bash
sudo apt install -y libssl-dev
```
