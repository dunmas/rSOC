use futures::lock::Mutex;
use pnet::packet::MutPacketData;
use sha2::{Sha256, Digest};
use crate::file_manager::file_manager::user_file_handler;
use crate::file_manager::file_manager::audit_handler::write_audit_event;
use std::sync::Arc;
use std::time::SystemTime;
use crate::structs::soc_structs::AuditEventType;
use crate::structs::soc_structs::multithread::FileMutexes;

pub fn authentificate(username: &String, password: &String, users_file: &String, host: String, file_mutexes: &FileMutexes, log_file: String, audit_status: bool) -> (bool, String, bool) {
    let user_map = user_file_handler::get_user_map(users_file);
    let mut hasher = Sha256::new();
    hasher.update(password);
    let pass_hash = hasher.finalize();

    if !user_map.contains_key(username) 
    || user_map[username].0 != format!("{:x}", pass_hash) {
        write_audit_event(SystemTime::now(), host, username.clone(), AuditEventType::FailLogon, "Authentication failure".to_string(), &file_mutexes, &log_file, audit_status);
        println!("Wrong credentials. Goodbye.");
        return (false, "".to_string(), false);
    }

    write_audit_event(SystemTime::now(), host, username.clone(), AuditEventType::UserLogon, "User authenticated".to_string(), &file_mutexes, &log_file, audit_status);
    (true, username.to_string(), user_map[username].1)
}