use std::fmt;
use std::collections::HashMap;
use tokio::sync::mpsc;
use std::sync::{Arc, Mutex};

pub struct SessionStatus<'a> {
    pub host: String,
    pub user: String,
    pub audit_status: bool,
    pub sensor_list: Arc<Mutex<HashMap<String, (mpsc::Sender<&'a str>, String, String, bool)>>>,
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
    UserLogon,
    FailLogon,
    NetSenConn,
    NetSenDisconn,
    HostSenConn,
    HostSenDisconn
}

pub mod multithread{
    use std::sync::{Arc, Mutex};

    pub struct FileMutexes {
        pub audit_mutex: Arc<Mutex<std::fs::File>>,
        pub event_mutex: Arc<Mutex<std::fs::File>>,
    }
}

pub mod host_level_rules {

}

impl fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
