use crate::file_manager::file_manager::audit_handler::{
    change_audit_status, get_10_latest_audit_messages, write_audit_event,
};
use crate::file_manager::file_manager::event_handler::get_10_latest_event_messages;
use crate::sensor_handler::rule_handler::{add_rule, delete_rule, get_rules_list};
use crate::sensor_handler::sensor_handler::{change_sensor_state, get_sensor_list};
use crate::structs::soc_structs::multithread::FileMutexes;
use crate::structs::soc_structs::{AuditEventType, LogFiles, SessionStatus};
use regex::Regex;
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

const MAIN_MENU: &str = "\
        ------------------------------------------------------\n\
        Hello! This is rSOC Management Server command console.\n\
        ------------------------------------------------------\n\
        Please, select option:\n\
        1) Event log\n\
        2) Sensors settings\n\
        3) Audit settings\n\
        4) Rules settings\n\
        5) Exit\n\
        ------------------------------------------------------";
const EVENT_MENU: &str = "\
            ------------------------------------------------------\n\
            Select option:\n\
            1) Check overall events (10 latest)\n\
            2) Check sensor events (10 latest)\n\
            3) Back\n\
            ------------------------------------------------------";
const SENSORS_MENU: &str = "\
            ------------------------------------------------------\n\
            Select option:\n\
            1) List of sensors\n\
            2) Start/stop sensor\n\
            3) Back\n\
            ------------------------------------------------------";
const AUDIT_MENU: &str = "\
            ------------------------------------------------------\n\
            Select option:\n\
            1) Start/stop system audit\n\
            2) Check audit log (10 latest)\n\
            3) Back\n\
            ------------------------------------------------------";
const RULE_MENU: &str = "\
            ------------------------------------------------------\n\
            Select option:\n\
            1) Get rules list\n\
            2) Add rule\n\
            3) Delete rule\n\
            4) Back\n\
            ------------------------------------------------------";

macro_rules! pause {
    () => {{
        println!(
            "------------------------------------------------------\n\
             Press enter to continue..."
        );
        let mut buffer = String::new();

        std::io::stdin()
            .read_line(&mut buffer)
            .expect("Failed to read line");
    }};
}

pub async fn main_menu(
    session_status: &mut SessionStatus,
    log_files: &LogFiles,
    tx: tokio::sync::mpsc::Sender<String>,
    file_mutexes: &FileMutexes,
    audit_status: &Arc<Mutex<bool>>,
) {
    loop {
        println!("{}", MAIN_MENU);
        let choise = get_user_choice();

        match choise.as_str() {
            "1" => event_menu(
                session_status,
                &file_mutexes,
                &log_files.audit_file,
                audit_status,
            ),
            "2" => sensors_menu(
                session_status,
                &file_mutexes,
                &log_files.audit_file,
                audit_status,
            ),
            "3" => audit_menu(
                session_status,
                &file_mutexes,
                &log_files.audit_file,
                audit_status,
            ),
            "4" => rule_menu(session_status, &file_mutexes, &log_files.rules_file),
            "5" => {
                println!("Goodbye.");
                tx.send("stop".to_string()).await.unwrap();
                return;
            }
            _ => println!("Undefined option. Try again.\n"),
        }
    }
}

pub fn get_user_choice() -> String {
    let mut choice = String::new();
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut choice).expect("Input error.");
    choice.trim().to_string()
}

fn event_menu(
    session_status: &mut SessionStatus,
    file_mutexes: &FileMutexes,
    log_file: &String,
    audit_status: &Arc<Mutex<bool>>,
) {
    loop {
        println!("{}", EVENT_MENU);
        let choise = get_user_choice();

        match choise.as_str() {
            "1" => {
                get_10_latest_event_messages(file_mutexes, "");
                let aud_status = audit_status.lock().unwrap();
                write_audit_event(
                    SystemTime::now(),
                    session_status.host.clone(),
                    session_status.user.clone(),
                    AuditEventType::EvtLogAccess,
                    "Event log has been checked".to_string(),
                    file_mutexes,
                    log_file,
                    *aud_status,
                );
                pause!();
            }
            "2" => {
                println!("Please, enter name of the sensor:");
                let required_sensor = get_user_choice();
                get_10_latest_event_messages(file_mutexes, &required_sensor);
                let aud_status = audit_status.lock().unwrap();
                write_audit_event(
                    SystemTime::now(),
                    session_status.host.clone(),
                    session_status.user.clone(),
                    AuditEventType::EvtLogAccess,
                    "Event log has been checked".to_string(),
                    file_mutexes,
                    log_file,
                    *aud_status,
                );
                pause!();
            }
            "3" => break,
            _ => println!("Undefined option. Try again."),
        }
    }
}

fn sensors_menu(
    session_status: &mut SessionStatus,
    file_mutexes: &FileMutexes,
    log_file: &String,
    audit_status: &Arc<Mutex<bool>>,
) {
    loop {
        println!("{}", SENSORS_MENU);
        let choise = get_user_choice();

        match choise.as_str() {
            "1" => {
                get_sensor_list(session_status);
                println!(" ");
                pause!();
            }
            "2" => {
                if !session_status.is_admin {
                    println!("Admin privileges required.");
                    continue;
                }

                println!("Enter address of sensor to change it's status:");
                let sensor_ip = &get_user_choice();

                let aud_stat = audit_status.lock().unwrap();
                let operation_status: (bool, bool, bool) = change_sensor_state(
                    sensor_ip,
                    session_status,
                    file_mutexes,
                    log_file,
                    *aud_stat,
                );
                if !operation_status.2 {
                    println!("There is no sensor with this IP.");
                    break;
                }
                if !operation_status.1 {
                    println!("Error occured with audit logging.");
                    break;
                }
                if !operation_status.0 {
                    println!("System audit disabled")
                } else {
                    println!("System audit enabled")
                };
                pause!();
            }
            "3" => break,
            _ => println!("Undefined option. Try again."),
        }
    }
}

fn audit_menu(
    session_status: &mut SessionStatus,
    file_mutexes: &FileMutexes,
    log_file: &String,
    audit_status: &Arc<Mutex<bool>>,
) {
    loop {
        println!("{}", AUDIT_MENU);
        let choise = get_user_choice();

        match choise.as_str() {
            "1" => {
                if !session_status.is_admin {
                    println!("Admin privileges required.");
                    continue;
                }

                let operation_status: (bool, bool) = change_audit_status(
                    audit_status,
                    session_status.host.clone(),
                    session_status.user.clone(),
                    file_mutexes,
                    log_file,
                );
                if !operation_status.1 {
                    println!("Error occured with audit logging.");
                    break;
                }
                if !operation_status.0 {
                    println!("System audit disabled")
                } else {
                    println!("System audit enabled")
                };
                pause!();
            }
            "2" => {
                get_10_latest_audit_messages(file_mutexes);
                let aud_status = audit_status.lock().unwrap();
                write_audit_event(
                    SystemTime::now(),
                    session_status.host.clone(),
                    session_status.user.clone(),
                    AuditEventType::AudLogAccess,
                    "Audit log has been checked".to_string(),
                    file_mutexes,
                    log_file,
                    *aud_status,
                );
                pause!();
            }
            "3" => break,
            _ => println!("Undefined option. Try again."),
        }
    }
}

fn rule_menu(session_status: &mut SessionStatus, file_mutexes: &FileMutexes, rule_file: &String) {
    loop {
        println!("{}", RULE_MENU);
        let choise = get_user_choice();

        match choise.as_str() {
            "1" => {
                println!("What type of rules you want to get? (net/host)");
                let rule_level = get_user_choice();

                match rule_level.as_str() {
                    "net" => {
                        get_rules_list("net", file_mutexes);
                    }
                    "host" => {
                        get_rules_list("host", file_mutexes);
                    }
                    _ => {
                        println!("Undefined rule level. Try 'net' or 'host'")
                    }
                }
                pause!();
            }
            "2" => {
                if !session_status.is_admin {
                    println!("Admin privileges required.");
                    continue;
                }

                let _rule_map = add_rule_interface();
                if !_rule_map.1 {
                    break;
                }
                let level = _rule_map.0 .0.get("level").unwrap().to_string();
                let name = _rule_map.0 .0.get("name").unwrap().to_string();
                let desc = _rule_map.0 .0.get("description").unwrap().to_string();
                let payload = _rule_map.0 .0.get("payload").unwrap().to_string();

                add_rule(
                    level,
                    name,
                    payload,
                    desc,
                    &_rule_map.0 .1,
                    rule_file,
                    file_mutexes,
                );
                pause!();
            }
            "3" => {
                if !session_status.is_admin {
                    println!("Admin privileges required.");
                    continue;
                }

                println!("What type of rule you want to delete? (net/host)");
                let rule_level = get_user_choice();
                if rule_level != "net" && rule_level != "host" {
                    println!("Undefined rule level. Try 'net' or 'host'");
                    continue;
                }

                println!("Enter rule hash (from rules list):");
                let rule_hash = get_user_choice();
                delete_rule(&rule_level, &rule_hash, rule_file, file_mutexes);
                pause!();
            }
            "4" => break,
            _ => println!("Undefined option. Try again."),
        }
    }
}

fn add_rule_interface() -> ((HashMap<String, String>, HashMap<String, String>), bool) {
    let mut basic_fields: HashMap<String, String> = vec![
        ("level".to_string(), "".to_string()),
        ("name".to_string(), "".to_string()),
        ("payload".to_string(), "".to_string()),
        ("description".to_string(), "".to_string()),
    ]
    .into_iter()
    .collect();
    let mut optional_fields_map: HashMap<String, String> = HashMap::new();
    let level: &str;

    println!("Enter rule level (net/host): ");
    match get_user_choice().as_str() {
        "net" => {
            basic_fields.insert("level".to_string(), "net".to_string());
            optional_fields_map.insert("protocol".to_string(), "ipv4".to_string());
            level = "net";
        }
        "host" => {
            basic_fields.insert("level".to_string(), "host".to_string());
            level = "host";
        }
        _ => {
            println!("Wrong rule level. Try again.");
            return ((HashMap::new(), HashMap::new()), false);
        }
    }

    println!("Enter rule name: ");
    let data = get_user_choice();
    if data.is_empty() {
        println!("Can't write empty value. Try again.");
        return ((HashMap::new(), HashMap::new()), false);
    }
    basic_fields.insert("name".to_string(), data);

    println!("Enter rule description: ");
    let data = get_user_choice();
    if data.is_empty() {
        println!("Can't write empty value. Try again.");
        return ((HashMap::new(), HashMap::new()), false);
    }
    basic_fields.insert("description".to_string(), data);

    if level == "host" {
        println!("Enter rule payload: ");
        let data = get_user_choice();
        if data.is_empty() {
            println!("Can't write empty value. Try again.");
            return ((HashMap::new(), HashMap::new()), false);
        }
        basic_fields.insert("payload".to_string(), data);
    } else {
        basic_fields.insert("payload".to_string(), " ".to_string());

        let mut net_payload_flag = false;
        while !net_payload_flag {
            println!("What field you want to setup as trigger? (src/dst/both): ");
            let re = Regex::new(r"^([0-9a-f]{2}[:]){5}([0-9a-f]{2})$").unwrap();
            let mut mac_addr_str: String;

            match get_user_choice().as_str() {
                "src" => {
                    println!("Enter source MAC-address (':' as separator):");
                    mac_addr_str = get_user_choice().as_str().to_lowercase();
                    if re.is_match(mac_addr_str.as_str()) {
                        net_payload_flag = true;
                        optional_fields_map.insert("src".to_string(), mac_addr_str);
                        optional_fields_map.insert("dst".to_string(), " ".to_string());
                    } else {
                        println!("Wrong MAC format. Try again");
                    }
                }
                "dst" => {
                    println!("Enter destination MAC-address (':' as separator):");
                    mac_addr_str = get_user_choice().as_str().to_lowercase();
                    if re.is_match(mac_addr_str.as_str()) {
                        net_payload_flag = true;
                        optional_fields_map.insert("dst".to_string(), mac_addr_str);
                        optional_fields_map.insert("src".to_string(), " ".to_string());
                    } else {
                        println!("Wrong MAC format. Try again");
                    }
                }
                "both" => {
                    println!("Enter source MAC-address (':' as separator):");
                    mac_addr_str = get_user_choice().as_str().to_lowercase();
                    if re.is_match(mac_addr_str.as_str()) {
                        optional_fields_map.insert("src".to_string(), mac_addr_str);
                    } else {
                        println!("Wrong MAC format. Try again");
                    }

                    println!("Enter destination MAC-address (':' as separator):");
                    mac_addr_str = get_user_choice().as_str().to_lowercase();
                    if re.is_match(mac_addr_str.as_str()) {
                        net_payload_flag = true;
                        optional_fields_map.insert("dst".to_string(), mac_addr_str);
                    } else {
                        println!("Wrong MAC format. Try again");
                    }
                }
                _ => {
                    println!("Error parsing parameter. Try again");
                }
            }
        }
    }

    ((basic_fields, optional_fields_map), true)
}
