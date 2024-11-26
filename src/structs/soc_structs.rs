use std::fmt;

pub struct SessionStatus {
    pub host: String,
    pub user: String,
    pub audit_status: bool,
}

pub struct LogFiles {
    pub audit_file: String,
    pub event_file: String,
}

#[derive(Debug)]
pub enum AuditEventType {
    AudEnable,
    AudDisable,
}

pub mod multithread{
    use std::sync::{Arc, Mutex};

    pub struct FileMutexes {
        pub audit_mutex: Arc<Mutex<std::fs::File>>,
        pub event_mutex: Arc<Mutex<std::fs::File>>,
    }
}

impl fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
