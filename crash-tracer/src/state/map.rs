use std::{
    collections::HashMap,
    fmt::{self, Display},
    fs::OpenOptions,
    hash::Hash,
    io::{BufRead, BufReader},
};

use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeKind {
    Native,
    Jvm,
    V8,
    Il2Cpp,
    Mono,
    CoreClr,
    Python,
}

pub struct ProcessInfo {
    pub pid: u32,
    pub boottime: u64,
    pub maps: Vec<String>,
    pub runtime: RuntimeKind,
    pub cwd: Option<String>,
    pub cmdline: Option<String>,
}

#[repr(C)]
#[derive(PartialEq, Eq, Hash)]
struct MapKey {
    pid: u32,
    boottime: u64,
}
const MAX_TRACKED_PROCESSES: usize = 4096;

pub struct MemoryMap {
    memory_map: HashMap<MapKey, ProcessInfo>,
}

impl MemoryMap {
    pub fn new() -> Self {
        Self {
            memory_map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, pid: u32, boottime: u64) {
        if self.memory_map.len() >= MAX_TRACKED_PROCESSES {
            log::warn!(
                "Memory map exceeded {} entries, pruning stale entries",
                MAX_TRACKED_PROCESSES
            );
            self.memory_map
                .retain(|key, _| std::fs::metadata(format!("/proc/{}", key.pid)).is_ok());
        }

        let maps = match self.read_map(pid) {
            Ok(maps) => maps,
            Err(e) => {
                log::warn!("Failed to read /proc/{}/maps: {e}", pid);
                return;
            }
        };

        let runtime = self.detect_runtime(&maps);

        let cwd = std::fs::read_link(format!("/proc/{}/cwd", pid))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        let cmdline = std::fs::read(format!("/proc/{}/cmdline", pid))
            .ok()
            .map(|bytes| {
                bytes
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            });

        self.memory_map.insert(
            MapKey { pid, boottime },
            ProcessInfo {
                pid,
                boottime,
                maps,
                runtime,
                cwd,
                cmdline,
            },
        );
    }

    pub fn get(&self, pid: u32, boottime: u64) -> Option<&ProcessInfo> {
        self.memory_map.get(&MapKey { pid, boottime })
    }

    pub fn remove(&mut self, pid: u32, boottime: u64) {
        self.memory_map.remove(&MapKey { pid, boottime });
    }

    fn read_map(&mut self, pid: u32) -> Result<Vec<String>, anyhow::Error> {
        let file = OpenOptions::new()
            .read(true)
            .open(format!("/proc/{}/maps", pid))?;
        let reader = BufReader::new(file);

        reader
            .lines()
            .map(|x| {
                let line = x?;
                Ok(line)
            })
            .collect()
    }

    // detect a possible runtime in the process. this logic does assume that there is
    // a sole primary runtime. There are cases where multiple runtimes are used, but it is rare.
    // we do first match rather than handle those for now. an example is Jython
    fn detect_runtime(&self, maps: &[String]) -> RuntimeKind {
        for line in maps {
            if let Some(path) = line.split_whitespace().last() {
                if path.contains("libjvm.so") {
                    return RuntimeKind::Jvm;
                }
                if path.contains("libil2cpp.so") {
                    return RuntimeKind::Il2Cpp;
                }
                if path.contains("libnode.so") || path.contains("libv8.so") {
                    return RuntimeKind::V8;
                }
                if path.contains("libcoreclr.so") {
                    return RuntimeKind::CoreClr;
                }
                if path.contains("libmonosgen") {
                    return RuntimeKind::Mono;
                }
                if path.contains("libpython3") {
                    return RuntimeKind::Python;
                }
            }
        }
        RuntimeKind::Native
    }
}

impl RuntimeKind {
    pub fn to_id(&self) -> u32 {
        match self {
            RuntimeKind::Native => 0,
            RuntimeKind::Jvm => 1,
            RuntimeKind::V8 => 2,
            RuntimeKind::Il2Cpp => 3,
            RuntimeKind::Mono => 4,
            RuntimeKind::CoreClr => 5,
            RuntimeKind::Python => 6,
        }
    }
}

impl Display for RuntimeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeKind::CoreClr => {
                write!(f, "CoreClr")
            }
            RuntimeKind::Il2Cpp => {
                write!(f, "Il2Cpp")
            }
            RuntimeKind::Jvm => {
                write!(f, "Jvm")
            }
            RuntimeKind::Mono => {
                write!(f, "Mono")
            }
            RuntimeKind::Native => {
                write!(f, "Native")
            }
            RuntimeKind::Python => {
                write!(f, "Python")
            }
            RuntimeKind::V8 => {
                write!(f, "V8")
            }
        }
    }
}
