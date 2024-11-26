use std::io::{self, Write};

use crate::file_manager::file_manager::audit_handler::{change_audit_status, prepare_file_mutexes};
use crate::structs::soc_structs::multithread::FileMutexes;
use crate::structs::soc_structs::{SessionStatus, LogFiles};

const MAIN_MENU: &str = "\
        ------------------------------------------------------\n\
        Hello! This is rSOC Management Server command console.\n\
        ------------------------------------------------------\n\
        Please, select option:\n\
        1) Event log\n\
        2) Sensors settings\n\
        3) Audit settings\n\
        4) Exit\n\
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

macro_rules! pause {
    () => {{
        println!(
            "\
                ------------------------------------------------------\n\
                Press enter to continue..."
        );
        let mut buffer = String::new();

        std::io::stdin()
            .read_line(&mut buffer)
            .expect("Failed to read line");
    }};
}

pub fn main_menu(session_status: &mut SessionStatus, log_files: &LogFiles) {
    let file_mutexes: FileMutexes = prepare_file_mutexes(log_files);

    loop {
        println!("{}", MAIN_MENU);
        let choise = get_user_choice();

        match choise.as_str() {
            "1" => event_menu(),
            "2" => sensors_menu(),
            "3" => audit_menu(session_status, &file_mutexes),
            "4" => {
                println!("Goodbye.");
                break;
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

fn event_menu() {
    loop {
        println!("{}", EVENT_MENU);
        let choise = get_user_choice();

        match choise.as_str() {
            "1" => {
                println!("overall");
                pause!();
            }
            "2" => {
                println!("sensor");
                pause!();
            }
            "3" => break,
            _ => println!("Undefined option. Try again."),
        }
    }
}

fn sensors_menu() {
    loop {
        println!("{}", SENSORS_MENU);
        let choise = get_user_choice();

        match choise.as_str() {
            "1" => {
                println!("list");
                pause!();
            }
            "2" => {
                println!("start/stop");
                pause!();
            }
            "3" => {
                println!("update rules");
                pause!();
            }
            "4" => break,
            _ => println!("Undefined option. Try again."),
        }
    }
}

fn audit_menu(session_status: &mut SessionStatus, file_mutexes: &FileMutexes) {
    loop {
        println!("{}", AUDIT_MENU);
        let choise = get_user_choice();

        match choise.as_str() {
            "1" => {
                let operation_status: (bool, bool) = change_audit_status(&mut session_status.audit_status, session_status.host.clone(), session_status.user.clone(), file_mutexes);
                if !operation_status.1 {println!("Error occured with audit logging."); break;}
                if !operation_status.0 {println!("System audit disabled")} else {println!("System audit enabled")};
                pause!();
            }
            "2" => {
                println!("check log");
                pause!();
            }
            "3" => break,
            _ => println!("Undefined option. Try again."),
        }
    }
}
