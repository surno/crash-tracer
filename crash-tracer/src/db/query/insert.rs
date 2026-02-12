pub const INSERT_PROCESS: &str =
    "INSERT INTO processes (pid, boottime, runtime, cwd, cmdline) VALUES ($1, $2, $3, $4, $5) ON CONFLICT(pid, boottime) DO UPDATE SET runtime=excluded.runtime, cwd=excluded.cwd, cmdline=excluded.cmdline";

pub const INSERT_PROCESS_MAPS: &str =
    "INSERT INTO memory_maps (process_id, line_num, content) VALUES ($1, $2, $3)";

pub const INSERT_CRASHES: &str = "INSERT INTO crashes (process_id, signal, si_code, fault_addr, timestamp_ns, tid, cmd, exit_code, rip, rsp, rbp, rax, 
rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15, rflags, kernel_stack_id, user_stack_id, boottime) 
VALUES ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29)";

pub const INSERT_STACK_FRAMES: &str =
    "INSERT INTO stack_frames (crash_id, frame_index, ip) VALUES ($1, $2, $3)";

pub const INSERT_STACK_DUMP: &str =
    "INSERT INTO stack_dumps (crash_id, rsp, length, data) VALUES ($1, $2, $3, $4)";

pub const INSERT_ARTIFACT: &str = "INSERT INTO artifacts (crash_id, process_id, filename, full_path, content) VALUES ($1, $2, $3, $4, $5)";
