use crate::file_manager::file_manager::audit_handler::write_audit_event;
use crate::file_manager::file_manager::user_file_handler;
use crate::structs::soc_structs::multithread::FileMutexes;
use crate::structs::soc_structs::AuditEventType;
use futures::lock::Mutex;
use pnet::packet::MutPacketData;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::SystemTime;

pub fn authenticate(
    username: &String,
    password: &String,
    users_file: &String,
    host: String,
    file_mutexes: &FileMutexes,
    log_file: String,
    audit_status: bool,
) -> (bool, String, bool) {
    let user_map = user_file_handler::get_user_map(users_file);
    let mut hasher = Sha256::new();
    hasher.update(password);
    let pass_hash = hasher.finalize();

    if !user_map.contains_key(username) || user_map[username].0 != format!("{:x}", pass_hash) {
        write_audit_event(
            SystemTime::now(),
            host,
            username.clone(),
            AuditEventType::FailLogon,
            "Authentication failure".to_string(),
            &file_mutexes,
            &log_file,
            audit_status,
        );
        println!("Wrong credentials. Goodbye.");
        return (false, "".to_string(), false);
    }

    write_audit_event(
        SystemTime::now(),
        host,
        username.clone(),
        AuditEventType::UserLogon,
        "User authenticated".to_string(),
        &file_mutexes,
        &log_file,
        audit_status,
    );
    (true, username.to_string(), user_map[username].1)
}
