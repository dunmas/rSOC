use std::io::{self, Write};
use std::collections::HashMap;
use std::sync::mpsc;

use futures::channel::mpsc::{Receiver, Sender};

use crate::file_manager::file_manager::audit_handler::{change_audit_status, prepare_file_mutexes, get_10_latest_audit_messages};
use crate::structs::soc_structs::multithread::FileMutexes;
use crate::structs::soc_structs::{SessionStatus, LogFiles};
use crate::file_manager::file_manager::event_handler::get_10_latest_event_messages;
use crate::sensor_handler::rule_handler::{get_rules_list, add_rule, delete_rule};
use crate::sensor_handler::sensor_handler::{get_sensor_list, change_sensor_state, update_sensor_rules};

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
            3) Update rules\n\
            4) Back\n\
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

pub async fn main_menu<'a>(session_status: &mut SessionStatus<'a>, log_files: &LogFiles, tx: tokio::sync::mpsc::Sender<&str>) {
    let file_mutexes: FileMutexes = prepare_file_mutexes(log_files);
    // add rules file checker

    loop {
        println!("{}", MAIN_MENU);
        let choise = get_user_choice();
        let tx_copy = tx.clone();

        match choise.as_str() {
            "1" => event_menu(&file_mutexes),
            "2" => sensors_menu(session_status, &file_mutexes, &log_files.audit_file, &log_files.rules_file, tx_copy),
            "3" => audit_menu(session_status, &file_mutexes, &log_files.audit_file),
            "4" => rule_menu(&log_files.rules_file),
            "5" => {
                println!("Goodbye.");
                tx.send("stop").await.unwrap();
                return;
            }
            _ => println!("Undefined option. Try again.\n"),
        }
    }
}

fn get_user_choice() -> String {
    let mut choice = String::new();
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut choice).expect("Input error.");
    choice.trim().to_string()
}

fn event_menu(file_mutexes: &FileMutexes) {
    loop {
        println!("{}", EVENT_MENU);
        let choise = get_user_choice();

        match choise.as_str() {
            "1" => {
                get_10_latest_event_messages(file_mutexes,"");
                pause!();
            }
            "2" => {
                println!("Please, enter name of the sensor:");
                let required_sensor = get_user_choice();
                get_10_latest_event_messages(file_mutexes,&required_sensor);
                pause!();
            }
            "3" => break,
            _ => println!("Undefined option. Try again."),
        }
    }
}

fn sensors_menu(session_status: &mut SessionStatus, file_mutexes: &FileMutexes, log_file: &String, rules_file: &String, tx: tokio::sync::mpsc::Sender<&str>) {
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
                println!("Enter address of sensor to change it's status:");
                let sensor_ip = &get_user_choice();

                let operation_status: (bool, bool, bool) = change_sensor_state(sensor_ip, session_status, file_mutexes, log_file);
                if !operation_status.2 { println!("There is no sensor with this IP."); break; }
                if !operation_status.1 { println!("Error occured with audit logging."); break; }
                if !operation_status.0 { println!("System audit disabled")} else {println!("System audit enabled")};
                pause!();
            }
            "3" => {
                println!("Enter address of sensor to change it's status:");
                let sensor_ip = &get_user_choice();

                let status = update_sensor_rules(sensor_ip, session_status, file_mutexes, log_file, rules_file, tx.clone());
                if !status { println!("Error while updateing rules.") }
                pause!();
            }
            "4" => break,
            _ => println!("Undefined option. Try again."),
        }
    }
}

fn audit_menu(session_status: &mut SessionStatus, file_mutexes: &FileMutexes, log_file: &String) {
    loop {
        println!("{}", AUDIT_MENU);
        let choise = get_user_choice();

        match choise.as_str() {
            "1" => {
                let operation_status: (bool, bool) = change_audit_status(&mut session_status.audit_status, session_status.host.clone(), session_status.user.clone(), file_mutexes, log_file);
                if !operation_status.1 {println!("Error occured with audit logging."); break;}
                if !operation_status.0 {println!("System audit disabled")} else {println!("System audit enabled")};
                pause!();
            }
            "2" => {
                get_10_latest_audit_messages(file_mutexes);
                pause!();
            }
            "3" => break,
            _ => println!("Undefined option. Try again."),
        }
    }
}

fn rule_menu(rule_file: &String) {
    loop {
        println!("{}", RULE_MENU);
        let choise = get_user_choice();

        match choise.as_str() {
            "1" => {
                println!("What type of rules you want to get? (net/host)");
                let rule_level = get_user_choice();

                match rule_level.as_str() {
                    "net" => { get_rules_list("net", rule_file); },
                    "host" => { get_rules_list("host", rule_file); },
                    _ => { println!("Undefined rule level. Try 'net' or 'host'") },
                }
                pause!();
            }
            "2" => {
                let _rule_map = add_rule_interface();
                if !_rule_map.1 { break; }
                let level = _rule_map.0.0.get("level").unwrap().to_string();
                let name = _rule_map.0.0.get("name").unwrap().to_string();
                let desc = _rule_map.0.0.get("description").unwrap().to_string();
                
                add_rule(level,
                        name, 
                     desc,
                      &_rule_map.0.1,
                       rule_file);
                pause!();
            }
            "3" => {
                println!("What type of rule you want to delete? (net/host)");
                let rule_level = get_user_choice();
                if rule_level != "net" && rule_level != "host" {
                    println!("Undefined rule level. Try 'net' or 'host'");
                    continue;
                }

                println!("Enter rule hash (from rules list):");
                let rule_hash = get_user_choice();
                delete_rule(&rule_level, &rule_hash, rule_file);
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
    ].into_iter().collect();
    let mut optional_fields_map: HashMap<String, String> = HashMap::new();

    println!("Enter rule level (net/host): ");
    match get_user_choice().as_str() {
        "net" => {
            basic_fields.insert("level".to_string(), "net".to_string());
            println!("Enter rule protocol: ");
            optional_fields_map.insert("protocol".to_string(), get_user_choice());
        },
        "host" => { basic_fields.insert("level".to_string(), "host".to_string()); },
        _ => { println!("Wrong rule level. Try again."); return ((HashMap::new(), HashMap::new()), false); }
    }

    println!("Enter rule name: ");
    basic_fields.insert("name".to_string(), get_user_choice());

    println!("Enter rule description: ");
    basic_fields.insert("description".to_string(), get_user_choice());

    println!("Enter rule payload: ");
    basic_fields.insert("payload".to_string(), get_user_choice());

    let mut count: u32 = 0;
    let mut cycle_flag = false;

    while !cycle_flag {
        println!("Enter count of optional fields: ");
        match get_user_choice().parse::<u32>() {
            Ok(number) => { count = number; cycle_flag = true; },
            Err(_e) => { println!("Error parsing number. Try again"); }
        }
    }

    if count > 0 {
        for i in 0..count {
            println!("{}. Enter field name: ", i+1);
            let fname = get_user_choice();
            println!("{}. Enter field value: ", i+1);
            let fvalue = get_user_choice();
            optional_fields_map.insert(fname.to_string(), fvalue.to_string());
        }
    }

    ((basic_fields, optional_fields_map), true)
}