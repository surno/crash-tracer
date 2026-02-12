pub const SCHEMA: &str = "
      PRAGMA journal_mode=WAL;
      PRAGMA foreign_keys=ON;
                                                                                                                                                                                                
      CREATE TABLE IF NOT EXISTS processes (                                                                                                                                                    
          id          INTEGER PRIMARY KEY AUTOINCREMENT,                                                                                                                                        
          pid         INTEGER NOT NULL,                                                                                                                                                         
          boottime    INTEGER NOT NULL,                                                                                                                                                         
          runtime     TEXT NOT NULL,                                                                                                                                                            
          cwd         TEXT,                                                                                                                                                                     
          cmdline     TEXT,                                                                                                                                                                     
          created_at  TEXT NOT NULL DEFAULT (datetime('now')),                                                                                                                                  
          UNIQUE(pid, boottime)                                                                                                                                                                 
      );                                                                                                                                                                                        
                                                                                                                                                                                                
      CREATE TABLE IF NOT EXISTS memory_maps (                                                                                                                                                  
          id          INTEGER PRIMARY KEY AUTOINCREMENT,                                                                                                                                        
          process_id  INTEGER NOT NULL REFERENCES processes(id),                                                                                                                                
          line_num    INTEGER NOT NULL,                                                                                                                                                         
          content     TEXT NOT NULL                                                                                                                                                             
      );                                                                                                                                                                                        
                                                                                                                                                                                                
      CREATE TABLE IF NOT EXISTS crashes (                                                                                                                                                      
          id              INTEGER PRIMARY KEY AUTOINCREMENT,                                                                                                                                    
          process_id      INTEGER NOT NULL REFERENCES processes(id),
          boottime        INTEGER NOT NULL,                                                                                                                            
          status          TEXT NOT NULL DEFAULT 'pending',                                                                                                                                      
          signal          INTEGER NOT NULL,                                                                                                                                                     
          si_code         INTEGER NOT NULL,                                                                                                                                                     
          fault_addr      INTEGER NOT NULL,                                                                                                                                                     
          timestamp_ns    INTEGER NOT NULL,                                                                                                                                                     
          tid             INTEGER NOT NULL,                                                                                                                                                     
          cmd             TEXT NOT NULL,                                                                                                                                                        
          exit_code       INTEGER,                                                                                                                                                              
          rip INTEGER NOT NULL, rsp INTEGER NOT NULL, rbp INTEGER NOT NULL,                                                                                                                     
          rax INTEGER NOT NULL, rbx INTEGER NOT NULL, rcx INTEGER NOT NULL,                                                                                                                     
          rdx INTEGER NOT NULL, rsi INTEGER NOT NULL, rdi INTEGER NOT NULL,                                                                                                                     
          r8  INTEGER NOT NULL, r9  INTEGER NOT NULL, r10 INTEGER NOT NULL,                                                                                                                     
          r11 INTEGER NOT NULL, r12 INTEGER NOT NULL, r13 INTEGER NOT NULL,                                                                                                                     
          r14 INTEGER NOT NULL, r15 INTEGER NOT NULL, rflags INTEGER NOT NULL,                                                                                                                  
          kernel_stack_id INTEGER,                                                                                                                                                              
          user_stack_id   INTEGER,                                                                                                                                                              
          created_at      TEXT NOT NULL DEFAULT (datetime('now'))                                                                                                                               
      );                                                                                                                                                                                        
                                                                                                                                                                                                
      CREATE TABLE IF NOT EXISTS stack_frames (                                                                                                                                                 
          id          INTEGER PRIMARY KEY AUTOINCREMENT,                                                                                                                                        
          crash_id    INTEGER NOT NULL REFERENCES crashes(id),                                                                                                                                  
          frame_index INTEGER NOT NULL,                                                                                                                                                         
          ip          INTEGER NOT NULL                                                                                                                                                          
      );                                                                                                                                                                                        
                                                                                                                                                                                                
      CREATE TABLE IF NOT EXISTS stack_dumps (                                                                                                                                                  
          id          INTEGER PRIMARY KEY AUTOINCREMENT,                                                                                                                                        
          crash_id    INTEGER NOT NULL REFERENCES crashes(id),                                                                                                                                  
          rsp         INTEGER NOT NULL,                                                                                                                                                         
          length      INTEGER NOT NULL,                                                                                                                                                         
          data        BLOB NOT NULL                                                                                                                                                             
      );                                                                                                                                                                                        
                                                                                                                                                                                                
      CREATE TABLE IF NOT EXISTS artifacts (                                                                                                                                                    
          id          INTEGER PRIMARY KEY AUTOINCREMENT,                                                                                                                                        
          crash_id    INTEGER REFERENCES crashes(id),                                                                                                                                           
          process_id  INTEGER NOT NULL REFERENCES processes(id),                                                                                                                                
          filename    TEXT NOT NULL,                                                                                                                                                            
          full_path   TEXT NOT NULL,                                                                                                                                                            
          content     BLOB,                                                                                                                                                                     
          created_at  TEXT NOT NULL DEFAULT (datetime('now'))                                                                                                                                   
      );                                                                                                                                                                                        
                                                                                                                                                                                                
      CREATE INDEX IF NOT EXISTS idx_crashes_process ON crashes(process_id);                                                                                                                    
      CREATE INDEX IF NOT EXISTS idx_crashes_status ON crashes(status);                                                                                                                         
      CREATE INDEX IF NOT EXISTS idx_artifacts_process ON artifacts(process_id);                                                                                                                
      CREATE INDEX IF NOT EXISTS idx_artifacts_crash ON artifacts(crash_id);                                                                                                                    
      CREATE INDEX IF NOT EXISTS idx_memory_maps_process ON memory_maps(process_id);                                                                                                            
      ";
