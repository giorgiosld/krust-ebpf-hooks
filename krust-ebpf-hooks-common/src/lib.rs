//! # Security Monitoring Core Types
//! 
//! This module defines the core data structures and constants used by the eBPF-based
//! security monitoring system. These types facilitate communication between kernel-space
//! eBPF programs and user-space applications.
//!
//! The security monitoring system tracks various system calls and events to detect
//! potential security threats, with a focus on memory operations that might indicate
//! Advanced Persistent Threats (APTs).

#![no_std]

/// Enumeration of event types that the security monitoring system tracks.
/// 
/// These event types correspond to specific system calls or operations
/// that are of interest for security monitoring purposes. Each event type
/// has a unique identifier represented as a u32.
#[repr(u32)]
pub enum EventType {
    /// Memory mapping operation (corresponds to mmap syscall)
    Mmap = 0,
    /// Memory protection change operation (corresponds to mprotect syscall)
    Mprotect = 1,
    /// Memory unmapping operation (corresponds to munmap syscall)
    Munmap = 2,
} 

/// Categorization of security events by their potential risk to system integrity.
/// 
/// This enum allows for quick triage of security events based on their
/// potential impact or likelihood of being part of a malicious operation.
#[repr(u8)]
pub enum RiskLevel {
    /// Minimal potential security impact
    Low = 0,
    /// Moderate potential security impact, warrants attention
    Medium = 1,
    /// Significant potential security impact, requires investigation
    High = 2,
    /// Severe potential security impact, immediate action recommended
    Critical = 3,
}

/// Represents process context information for security events.
/// 
/// This structure captures the essential identifiers and metadata about
/// a process that triggered a security event, providing context for
/// analysis and correlation.
#[repr(C)]
pub struct Process {
    /// Process ID
    pub pid: u32,
    /// Thread group ID (usually the same as PID for single-threaded processes)
    pub tgid: u32,
    /// User ID that owns the process
    pub uid: u32,
    /// Group ID that owns the process
    pub gid: u32,
    /// Process name/command (null-terminated, max 16 bytes including null terminator)
    pub comm: [u8; 16],
}

/// Core data structure for security events transmitted from kernel to user space.
/// 
/// This structure encapsulates all relevant information about a security event,
/// including its type, timing, process context, and specific parameters.
/// It serves as the primary data exchange format between the eBPF programs
/// running in kernel space and the analysis components in user space.
#[repr(C)]
pub struct SecurityEvent {
    /// Classification of the event (from EventType enum)
    pub event_type: u32,
    /// Time when the event occurred (nanoseconds since system boot)
    pub timestamp: u64,
    /// Information about the process that triggered the event
    pub process: Process,
    /// System call return value or operation result
    pub retval: i64,
    /// Assessed security impact of this event (from RiskLevel enum)
    pub risk_level: u8,
    /// Event-specific argument #1 (semantics depend on event_type)
    pub arg1: u64,
    /// Event-specific argument #2 (semantics depend on event_type)
    pub arg2: u64,
    /// Event-specific argument #3 (semantics depend on event_type)
    pub arg3: u64,
    /// Event-specific argument #4 (semantics depend on event_type)
    pub arg4: u64,
    /// Buffer for string data such as file paths, command lines, etc.
    pub str_buf: [u8; 256],
}

/// Constants defining memory protection flags used with mmap/mprotect.
/// 
/// These flags control how memory pages can be accessed and are particularly
/// relevant for detecting potential code injection or execution of data.
pub mod mmap_prot {
    /// No access permissions
    pub const PROT_NONE: u32 = 0x0;
    /// Read permission
    pub const PROT_READ: u32 = 0x1;
    /// Write permission
    pub const PROT_WRITE: u32 = 0x2;
    /// Execute permission (critical for security monitoring)
    pub const PROT_EXEC: u32 = 0x4;
}

/// Constants defining memory mapping flags used with mmap.
/// 
/// These flags control how memory is allocated and mapped, which can
/// provide important context for security analysis.
pub mod mmap_flags {
    /// Updates are visible to other processes mapping the same region
    pub const MAP_SHARED: u32 = 0x01;
    /// Updates are not visible to other processes
    pub const MAP_PRIVATE: u32 = 0x02;
    /// Map at exactly the specified address
    pub const MAP_FIXED: u32 = 0x10;
    /// Don't use a file, initialize to zero (potential indicator of JIT compilation or code injection)
    pub const MAP_ANONYMOUS: u32 = 0x20;
}

/// Bit flags for specific risk patterns that can be detected.
/// 
/// These constants define specific patterns of behavior that might
/// indicate malicious activity. They are designed to be used as bit
/// flags to efficiently track multiple risk factors.
pub mod risk {
    /// Execution permission granted to anonymous memory potential code injection
    pub const EXEC_AFTER_MMAP_ANONYMOUS: u64 = 1 << 0;
    /// Change in memory protection potential for bypass of W^X protection
    pub const MEMORY_PROTECTION_CHANGE: u64 = 1 << 1;
}
