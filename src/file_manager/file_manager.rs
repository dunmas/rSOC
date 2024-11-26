pub mod user_file_handler {
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{Write, BufReader, BufRead};
    use std::path::Path;

    // password "admin" in SHA-256 
    const BASIC_USER: &str = "admin[:|:]8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918[:|:]1";

    pub fn get_user_map(user_file: &str) -> HashMap<String, (String, bool)> {
        let path = Path::new(user_file);
        if !path.exists() {
            println!("User file existance error. Creating default file.");

            let mut f = File::create(path).unwrap();
            let _ = f.write_all(BASIC_USER.as_bytes()) ;
        }

        let file = File::open(path).expect("File opening error.");
        let reader = BufReader::new(file);
        let mut result: HashMap<String, (String, bool)> = HashMap::new();

        for line in reader.lines() {
            let line = line.expect("Line reading error.");
            let parts: Vec<&str> = line.split("[:|:]").collect();
            if parts.len() == 3 {
                let is_admin = if parts[2] == "1" { true } else { false };
                result.entry(parts[0].to_string()).or_insert_with(|| {(parts[1].to_string(), is_admin)});
            } else {
                println!("Wrong user string format: '{}'", &line);
                continue;
            }
        }

        result
    }
}

pub mod audit_handler {
    use std::time::SystemTime;
    use std::fs::File;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use crate::structs::soc_structs::{AuditEventType, LogFiles};
    use crate::structs::soc_structs::multithread::FileMutexes;

    pub fn prepare_file_mutexes(log_files: &LogFiles) -> FileMutexes {
        let audit_path = Path::new(&log_files.audit_file);
        let event_path = Path::new(&log_files.event_file);

        if !audit_path.exists() {
            let _f = File::create(audit_path).unwrap();
        }

        if !event_path.exists() {
            let _f = File::create(event_path).unwrap();
        }

        let audit_file = File::open(audit_path).expect("Audit file opening error.");
        let event_file = File::open(event_path).expect("Audit file opening error.");

        FileMutexes {
            audit_mutex: Arc::new(Mutex::new(audit_file)),
            event_mutex: Arc::new(Mutex::new(event_file)),
        }

    }

    pub fn get_10_latest_audit_messages() {

    }

    pub fn write_audit_event(timestamp: SystemTime, host: String, user: String, event_type: AuditEventType, message: String, log_files: &LogFiles) -> bool {
        let status: bool = true;

        // let mut file = file.lock().unwrap(); // Блокируем доступ к файлу
        // writeln!(file, "{}", content)?;
        status
    }

    pub fn change_audit_status(audit_status: &mut bool, host: String, user: String, log_files: &LogFiles) {
        *audit_status = !*audit_status;
        let audit_message: String = if audit_status == &true { "Audit enabled".to_string() } else { "Audit disabled".to_string() };
        write_audit_event(SystemTime::now(), host, user, AuditEventType::AudEnable, audit_message, log_files);
    }
}

pub mod event_handler {

}