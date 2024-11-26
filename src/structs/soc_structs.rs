pub struct SessionStatus {
    pub host: String,
    pub user: String,
    pub audit_status: bool,
}

pub struct LogFiles {
    pub audit_file: String,
    pub event_file: String,
}

pub enum AuditEventType {
    AudEnable,
}

pub mod multithread{
    use std::sync::{Arc, Mutex};

    pub struct FileMutexes {
        pub audit_file: Arc<Mutex<std::fs::File>>,
        pub event_file: Arc<Mutex<std::fs::File>>,
    }
}
