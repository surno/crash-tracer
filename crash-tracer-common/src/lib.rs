#![no_std]

// Let's consider these as crashes
pub const SIGILL: i32 = 4;
pub const SIGABRT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGSEGV: i32 = 11;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CrashEvent {
    // process information
    pub pid: u32,
    pub tid: u32,
    pub cmd: [u8; 16],

    // Signal info
    pub signal: i32,
    pub si_code: i32,

    pub timestamp_ns: u64,
}

impl CrashEvent {
    #[inline]
    pub const fn is_crash_signal(sig: i32) -> bool {
        matches!(sig, SIGILL | SIGABRT | SIGBUS | SIGFPE | SIGSEGV)
    }
}
