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
    use std::io::{Read, Write};
    use std::fs::OpenOptions;
    use std::sync::{Arc, Mutex};
    use chrono::DateTime;
    use chrono::offset::Utc;

    use std::mem;
    
    use crate::structs::soc_structs::{AuditEventType, LogFiles};
    use crate::structs::soc_structs::multithread::FileMutexes;

    pub fn prepare_file_mutexes(log_files: &LogFiles) -> FileMutexes {
        let audit_file = OpenOptions::new()
                                .append(true)
                                .create(true)
                                .read(true)
                                .open(&log_files.audit_file)
                                .unwrap();
        let event_file = OpenOptions::new()
                                .append(true)
                                .create(true)
                                .read(true)
                                .open(&log_files.event_file)
                                .unwrap();

        FileMutexes {
            audit_mutex: Arc::new(Mutex::new(audit_file)),
            event_mutex: Arc::new(Mutex::new(event_file)),
        }

    }

    pub fn get_10_latest_audit_messages(file_mutexes: &FileMutexes) {
        let mut audit_file = file_mutexes.audit_mutex.lock().unwrap();
        let buf: &mut String = &mut "".to_owned(); 

        match (*audit_file).read_to_string(buf){
            Ok(_) => {
                let strings:Vec<&str> = buf.split("\n").collect::<Vec<&str>>();
                let size = strings.len();
                let mut top_count = if size < 11 { size } else { 11 };
                let mut data_vec: Vec<String> = vec!["".to_string()];
                
                while top_count > 0 {
                    data_vec.push(strings[size - top_count].to_string());
                    top_count = top_count - 1;
                }

                console_output(data_vec);
            },
            Err(e) => println!("Error occured while reading from audit file: {}", e)
        }
    }

    pub fn write_audit_event(timestamp: SystemTime, host: String, user: String, event_type: AuditEventType, message: String, file_mutexes: &FileMutexes, log_file: &String) -> bool {
        let mut audit_file = file_mutexes.audit_mutex.lock().unwrap();
        let time_string: DateTime<Utc> = timestamp.into();
        let params_list = vec![time_string.format("%d-%m-%Y %H:%M").to_string(),
                                            host,
                                            user,
                                            event_type.to_string(),
                                            message]; 
        
        let result = match writeln!(audit_file, "{}", params_list.join("[:|:]")) {
            Ok(_) => true,
            Err(_e) => false
        };

        if result {
            let _ = mem::replace(&mut *audit_file,
            OpenOptions::new()
            .append(true)
            .create(true)
            .read(true)
            .open(&log_file)
            .unwrap());
        }

        result
    }

    pub fn change_audit_status(audit_status: &mut bool, host: String, user: String, file_mutexes: &FileMutexes, log_file: &String) -> (bool, bool) {
        *audit_status = !*audit_status;

        if *audit_status {
            (true, write_audit_event(SystemTime::now(), host, user, AuditEventType::AudEnable, "Audit enabled".to_string(), file_mutexes, log_file))
        } else {
            (false, write_audit_event(SystemTime::now(), host, user, AuditEventType::AudDisable, "Audit disabled".to_string(), file_mutexes, log_file))
        }
    }

    fn console_output(data_vec: Vec<String>) {
        let mut result = String::from("------------------------------------------------------------------------------------------\n\
                                               || --- Time --- || --- Hostname --- || --- User --- || --- Event --- || --- Message --- ||\n\
                                               ------------------------------------------------------------------------------------------\n");

        for log_string in data_vec {
            if log_string.is_empty() { continue; }

            let string_params = log_string.split("[:|:]");

            for param in string_params {
                result = result + "|| " + param + " ";
            }

            result = result + "||\n";
        }

        print!("{}", result + "------------------------------------------------------------------------------------------\n");
    }
}

pub mod event_handler {

}