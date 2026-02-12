use aya::maps::stack_trace::StackTrace;
use crash_tracer_common::{SignalDeliverEvent, StackDump};
use sqlx::Row;
use sqlx::SqlitePool;

use crate::db::query::insert::INSERT_ARTIFACT;
use crate::{
    db::query::insert::{
        INSERT_CRASHES, INSERT_PROCESS, INSERT_PROCESS_MAPS, INSERT_STACK_DUMP, INSERT_STACK_FRAMES,
    },
    state::map::ProcessInfo,
};

mod query;
mod schema;

pub struct Registers {
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
}

pub struct ArtifactData {
    pub filename: String,
    pub full_path: String,
    pub content: Option<Vec<u8>>,
}

pub struct CrashReportData {
    pub cmd: String,
    pub pid: u32,
    pub tid: u32,
    pub signal: i32,
    pub si_code: i32,
    pub fault_addr: u64,
    pub exit_code: Option<u32>,
    pub runtime: String,
    pub registers: Registers,   // sub-struct with all register values
    pub stack_frames: Vec<u64>, // instruction pointers in order
    pub stack_dump: Option<(u64, Vec<u8>)>, // (rsp, data)
    pub memory_maps: Vec<String>,
    pub artifacts: Vec<ArtifactData>,
}

pub struct CrashDb {
    pool: SqlitePool,
}

impl CrashDb {
    pub async fn new(db_path: &std::path::Path) -> anyhow::Result<Self> {
        let url = format!("sqlite:{}?mode=rwc", db_path.display());
        let pool = SqlitePool::connect(&url).await?;
        let db = Self { pool };
        db.run_migrations().await?;
        Ok(db)
    }

    async fn run_migrations(&self) -> anyhow::Result<()> {
        sqlx::raw_sql(schema::SCHEMA).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn insert_process(&self, info: &ProcessInfo) -> anyhow::Result<i64> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(INSERT_PROCESS)
            .bind(info.pid as i64)
            .bind(info.boottime as i64)
            .bind(info.runtime.to_string())
            .bind(&info.cwd)
            .bind(&info.cmdline)
            .execute(&mut *tx)
            .await?;

        let row = sqlx::query("SELECT id FROM processes WHERE pid=$1 AND boottime=$2")
            .bind(info.pid as i64)
            .bind(info.boottime as i64)
            .fetch_one(&mut *tx)
            .await?;
        let id: i64 = row.try_get("id")?;

        // Clear old maps in case this is a re-exec with updated mappings
        sqlx::query("DELETE FROM memory_maps WHERE process_id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        for (idx, map) in info.maps.iter().enumerate() {
            sqlx::query(INSERT_PROCESS_MAPS)
                .bind(id)
                .bind(idx as i64)
                .bind(map)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(id)
    }

    pub async fn insert_crash(
        &self,
        crash: &SignalDeliverEvent,
        stack_trace: Option<&StackTrace>,
        stack_dump: Option<&StackDump>,
    ) -> anyhow::Result<Option<i64>> {
        let mut tx = self.pool.begin().await?;

        let Some(result) = sqlx::query("SELECT id FROM processes WHERE pid=$1 AND boottime=$2")
            .bind(crash.pid as i64)
            .bind(crash.boottime as i64)
            .fetch_optional(&mut *tx)
            .await?
        else {
            log::warn!(
                "No process found for crash pid={}, likely missed exec event",
                crash.pid
            );
            return Ok(None);
        };

        let id: i64 = result.try_get("id")?;

        let crash_id = sqlx::query(INSERT_CRASHES)
            .bind(id)
            .bind(crash.signal)
            .bind(crash.si_code)
            .bind(crash.fault_addr as i64)
            .bind(crash.timestamp_ns as i64)
            .bind(crash.tid)
            .bind(
                std::str::from_utf8(&crash.cmd)
                    .unwrap_or("<unknown>")
                    .trim_end_matches('\0'),
            )
            .bind(None::<i64>)
            .bind(crash.rip as i64)
            .bind(crash.rsp as i64)
            .bind(crash.rbp as i64)
            .bind(crash.rax as i64)
            .bind(crash.rbx as i64)
            .bind(crash.rcx as i64)
            .bind(crash.rdx as i64)
            .bind(crash.rsi as i64)
            .bind(crash.rdi as i64)
            .bind(crash.r8 as i64)
            .bind(crash.r9 as i64)
            .bind(crash.r10 as i64)
            .bind(crash.r11 as i64)
            .bind(crash.r12 as i64)
            .bind(crash.r13 as i64)
            .bind(crash.r14 as i64)
            .bind(crash.r15 as i64)
            .bind(crash.rflags as i64)
            .bind(crash.kernel_stack_id)
            .bind(crash.user_stack_id)
            .bind(crash.boottime as i64)
            .execute(&mut *tx)
            .await?
            .last_insert_rowid();

        if let Some(frames) = stack_trace {
            for (idx, frame) in frames.frames().iter().enumerate() {
                sqlx::query(INSERT_STACK_FRAMES)
                    .bind(crash_id)
                    .bind(idx as i64)
                    .bind(frame.ip as i64)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        if let Some(dump) = stack_dump {
            sqlx::query(INSERT_STACK_DUMP)
                .bind(crash_id)
                .bind(dump.rsp as i64)
                .bind(dump.len)
                .bind(&dump.data[..])
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;

        Ok(Some(crash_id))
    }

    pub async fn complete_crash(
        &self,
        pid: u32,
        boottime: u64,
        exit_code: u32,
    ) -> anyhow::Result<Option<i64>> {
        let Some(proc_row) = sqlx::query("SELECT id FROM processes WHERE pid=$1 AND boottime=$2")
            .bind(pid as i64)
            .bind(boottime as i64)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Ok(None);
        };

        let id: i64 = proc_row.try_get("id")?;

        let Some(crash_row) =
            sqlx::query("SELECT id FROM crashes WHERE process_id = $1 AND status = 'pending'")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
        else {
            return Ok(None);
        };

        let crash_id: i64 = crash_row.try_get("id")?;

        sqlx::query("UPDATE crashes SET status = 'complete', exit_code = $1 WHERE id = $2")
            .bind(exit_code as i64)
            .bind(crash_id)
            .execute(&self.pool)
            .await?;

        Ok(Some(crash_id))
    }

    pub async fn insert_artifact(
        &self,
        pid: u64,
        boottime: u64,
        filename: String,
        full_path: String,
        content: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        let Some(proc_row) = sqlx::query("SELECT id FROM processes WHERE pid=$1 AND boottime=$2")
            .bind(pid as i64)
            .bind(boottime as i64)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Ok(());
        };

        let process_id: i64 = proc_row.try_get("id")?;

        let Some(crash_row) = sqlx::query("SELECT id FROM crashes WHERE process_id=$1")
            .bind(process_id)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Ok(());
        };

        let crash_id: i64 = crash_row.try_get("id")?;

        sqlx::query(INSERT_ARTIFACT)
            .bind(crash_id)
            .bind(process_id)
            .bind(filename)
            .bind(full_path)
            .bind(content)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn get_crash_report_data(&self, crash_id: i64) -> anyhow::Result<CrashReportData> {
        let crash_row = sqlx::query(
            "SELECT c.*, p.runtime, p.cwd, p.cmdline, p.pid as process_pid
             FROM crashes c
             JOIN processes p ON c.process_id = p.id
             WHERE c.id = $1",
        )
        .bind(crash_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Unable to find crash when retrieving report data."))?;

        let process_id: i64 = crash_row.try_get("process_id")?;

        let registers = Registers {
            rip: crash_row.try_get::<i64, _>("rip")? as u64,
            rsp: crash_row.try_get::<i64, _>("rsp")? as u64,
            rbp: crash_row.try_get::<i64, _>("rbp")? as u64,
            rax: crash_row.try_get::<i64, _>("rax")? as u64,
            rbx: crash_row.try_get::<i64, _>("rbx")? as u64,
            rcx: crash_row.try_get::<i64, _>("rcx")? as u64,
            rdx: crash_row.try_get::<i64, _>("rdx")? as u64,
            rsi: crash_row.try_get::<i64, _>("rsi")? as u64,
            rdi: crash_row.try_get::<i64, _>("rdi")? as u64,
            r8: crash_row.try_get::<i64, _>("r8")? as u64,
            r9: crash_row.try_get::<i64, _>("r9")? as u64,
            r10: crash_row.try_get::<i64, _>("r10")? as u64,
            r11: crash_row.try_get::<i64, _>("r11")? as u64,
            r12: crash_row.try_get::<i64, _>("r12")? as u64,
            r13: crash_row.try_get::<i64, _>("r13")? as u64,
            r14: crash_row.try_get::<i64, _>("r14")? as u64,
            r15: crash_row.try_get::<i64, _>("r15")? as u64,
            rflags: crash_row.try_get::<i64, _>("rflags")? as u64,
        };

        let frame_rows =
            sqlx::query("SELECT ip FROM stack_frames WHERE crash_id = $1 ORDER BY frame_index ASC")
                .bind(crash_id)
                .fetch_all(&self.pool)
                .await?;

        let stack_frames: Vec<u64> = frame_rows
            .iter()
            .map(|r| Ok(r.try_get::<i64, _>("ip")? as u64))
            .collect::<Result<Vec<_>, sqlx::Error>>()?;

        let stack_dump = match sqlx::query(
            "SELECT rsp, length, data FROM stack_dumps WHERE crash_id = $1",
        )
        .bind(crash_id)
        .fetch_optional(&self.pool)
        .await?
        {
            Some(r) => {
                let rsp = r.try_get::<i64, _>("rsp")? as u64;
                let len = r.try_get::<i32, _>("length")? as usize;
                let data: Vec<u8> = r.try_get("data")?;
                Some((rsp, data[..len.min(data.len())].to_vec()))
            }
            None => None,
        };

        let map_rows = sqlx::query(
            "SELECT content FROM memory_maps WHERE process_id = $1 ORDER BY line_num ASC",
        )
        .bind(process_id)
        .fetch_all(&self.pool)
        .await?;

        let memory_maps: Vec<String> = map_rows
            .iter()
            .map(|r| r.try_get("content"))
            .collect::<Result<Vec<_>, _>>()?;

        let artifact_rows =
            sqlx::query("SELECT filename, full_path, content FROM artifacts WHERE crash_id = $1")
                .bind(crash_id)
                .fetch_all(&self.pool)
                .await?;

        let artifacts: Vec<ArtifactData> = artifact_rows
            .iter()
            .map(|r| {
                Ok(ArtifactData {
                    filename: r.try_get("filename")?,
                    full_path: r.try_get("full_path")?,
                    content: r.try_get("content").ok(),
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;

        let exit_code: Option<i32> = crash_row.try_get("exit_code").ok();

        Ok(CrashReportData {
            cmd: crash_row.try_get("cmd")?,
            pid: crash_row.try_get::<i32, _>("process_pid")? as u32,
            tid: crash_row.try_get::<i32, _>("tid")? as u32,
            signal: crash_row.try_get("signal")?,
            si_code: crash_row.try_get("si_code")?,
            fault_addr: crash_row.try_get::<i64, _>("fault_addr")? as u64,
            exit_code: exit_code.map(|c| c as u32),
            runtime: crash_row.try_get("runtime")?,
            registers,
            stack_frames,
            stack_dump,
            memory_maps,
            artifacts,
        })
    }

    pub async fn cleanup_process(&self, pid: u32, boottime: u64) -> anyhow::Result<()> {
        let result = sqlx::query("SELECT id FROM processes WHERE pid=$1 AND boottime=$2")
            .bind(pid as i64)
            .bind(boottime as i64)
            .fetch_optional(&self.pool)
            .await?;

        let Some(row) = result else {
            return Ok(());
        };

        let process_id: i64 = row.try_get("id")?;

        let crash_ids: Vec<i64> = sqlx::query("SELECT id FROM crashes WHERE process_id=$1")
            .bind(process_id)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .filter_map(|r| r.try_get("id").ok())
            .collect();

        let mut tx = self.pool.begin().await?;

        for crash_id in &crash_ids {
            sqlx::query("DELETE FROM stack_frames WHERE crash_id=$1")
                .bind(crash_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM stack_dumps WHERE crash_id=$1")
                .bind(crash_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM artifacts WHERE crash_id=$1")
                .bind(crash_id)
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query("DELETE FROM crashes WHERE process_id=$1")
            .bind(process_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("DELETE FROM memory_maps WHERE process_id=$1")
            .bind(process_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("DELETE FROM processes WHERE id=$1")
            .bind(process_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }
}
