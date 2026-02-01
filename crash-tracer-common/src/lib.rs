#![no_std]

// Let's consider these as crashes
pub const SIGILL: i32 = 4;
pub const SIGABRT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGSEGV: i32 = 11;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SchedExecEvent {
    pub pid: u32,
    pub boottime: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignalDeliverEvent {
    // process information
    pub pid: u32,
    pub tid: u32,
    pub cmd: [u8; 16],

    // Signal info
    pub signal: i32,
    pub si_code: i32,
    pub fault_addr: u64,

    pub timestamp_ns: u64,

    // Registers (x86_64)
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: u64,

    // Stack trace IDs (resolved in userspace)
    pub kernel_stack_id: i64,
    pub user_stack_id: i64,
}

impl SignalDeliverEvent {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            tid: 0,
            cmd: [0u8; 16],
            signal: 0,
            si_code: 0,
            fault_addr: 0,
            timestamp_ns: 0,
            rip: 0,
            rsp: 0,
            rbp: 0,
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rflags: 0,
            kernel_stack_id: -1,
            user_stack_id: -1,
        }
    }
    #[inline]
    pub const fn is_crash_signal(sig: i32) -> bool {
        matches!(sig, SIGILL | SIGABRT | SIGBUS | SIGFPE | SIGSEGV)
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SignalDeliverEvent {}
