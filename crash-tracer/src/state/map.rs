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
    pub maps: Vec<String>,
    pub runtime: RuntimeKind,
}

#[repr(C)]
#[derive(PartialEq, Eq, Hash)]
struct MapKey {
    pid: u32,
    boottime: u64,
}
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
        if let Ok(maps) = self.read_map(pid) {
            let runtime = self.detect_runtime(&maps);
            self.memory_map
                .insert(MapKey { pid, boottime }, ProcessInfo { maps, runtime });
        }
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
