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
    UserLogon,
    FailLogon,
    NetSenConn,
    NetSenDisconn,
    HostSenConn,
    HostSenDisconn
}

#[derive(Debug)]
pub enum SecurityEventType {
    Warning,
    Critical
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

impl fmt::Display for SecurityEventType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
