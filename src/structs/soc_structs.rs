use std::fmt;
use std::collections::HashMap;

pub struct SessionStatus {
    pub host: String,
    pub user: String,
    pub audit_status: bool,
    pub sensor_list: HashMap<String, (String, String)>,
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

// "event_type" field is required
pub mod net_level_rules {
    use super::SecurityEventType;

    pub struct NetLevelRules {
        ip_v4: IPv4Rule,
    }

    pub struct IPv4Rule {
        name: String,
        description: String,
        event_type: SecurityEventType,
        trasport_protocol: String,
        src_ip: String,
        dst_ip: String,
        ttl: String,
        checksum: String,
        src_port: String,
        dst_port: String,
        payload_contains: String,
    }
}

pub mod host_level_rules {

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
