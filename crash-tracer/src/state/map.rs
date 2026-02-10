use std::{
    collections::HashMap,
    fs::OpenOptions,
    hash::Hash,
    io::{BufRead, BufReader},
};

use anyhow::Result;

#[repr(C)]
#[derive(PartialEq, Eq, Hash)]
struct MapKey {
    pid: u32,
    boottime: u64,
}
pub struct MemoryMap {
    memory_map: HashMap<MapKey, Vec<String>>,
}

impl MemoryMap {
    pub fn new() -> Self {
        Self {
            memory_map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, pid: u32, boottime: u64) {
        if let Ok(entry) = self.read_map(pid) {
            self.memory_map.insert(MapKey { pid, boottime }, entry);
        }
    }

    pub fn get(&self, pid: u32, boottime: u64) -> Option<&Vec<String>> {
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
}
