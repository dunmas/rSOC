use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub struct SessionStatus {
    pub host: String,
    pub user: String,
    pub is_admin: bool,
    pub sensor_list: Arc<Mutex<HashMap<String, (mpsc::Sender<String>, String, String, bool)>>>,
}

pub struct LogFiles {
    pub audit_file: String,
    pub event_file: String,
    pub rules_file: String,
}

#[derive(Debug)]
pub enum AuditEventType {
    AudEnable,
    AudDisable,
    SenEnable,
    SenDisable,
    UserLogon,
    FailLogon,
    NetSenConn,
    NetSenDisconn,
    HostSenConn,
    HostSenDisconn,
    RulesUpdate,
    AudLogAccess,
    EvtLogAccess,
    ServOff,
    ServOn,
}

pub mod multithread {
    use std::sync::{Arc, Mutex};

    pub struct FileMutexes {
        pub audit_mutex: Arc<Mutex<std::fs::File>>,
        pub event_mutex: Arc<Mutex<std::fs::File>>,
        pub rules_mutex: Arc<Mutex<std::fs::File>>,
    }
}

impl fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
