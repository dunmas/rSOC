mod menu;
mod file_manager;
mod structs;
mod sensor_handler;
mod auth;

use clap::{Arg, Command};
use menu::menu::main_menu;
use std::collections::HashMap;
use structs::soc_structs::{SessionStatus, LogFiles};
use auth::auth::authentificate;

const USER_LIST_FILE: &str = "users.txt";
const AUDIT_LOG: &str = "audit.txt";
const EVENT_LOG: &str = "events.txt";
const RULES_FILE: &str = "rules.txt";
const HOSTNAME: &str = "MAMA-1 | Control centre";

fn main() {
    let matches = Command::new("rSOC")
        .version("0.0.1")
        .author("buran <bvran@proton.me>")
        .about("rSOC - Simple network and endpoint SOC implementation written on Rust\n\nThis is a Management Server - head unit of SOC")
        .arg(Arg::new("user")
                 .short('u')
                 .long("user")
                 .help("User to authentificate"))
                //  .arg_required_else_help(true)
        .arg(Arg::new("password")
                 .short('p')
                 .long("password")
                 .help("User's password"))
                //  .arg_required_else_help(true)
        .get_matches();

    // Временное выключение аутентификации на этапе разработки
    let username = "admin".to_string();
    // let username;
    // let input_username = matches.get_one::<String>("user").unwrap();
    // let input_password = matches.get_one::<String>("password").unwrap();
    // let auth_res = authentificate(&input_username, &input_password, &USER_LIST_FILE.to_string());
    // if auth_res.0 { username = auth_res.1; } else { return; }
    
    // test block
    let mut sensors: HashMap<String, (String, String)> = HashMap::new();
    sensors.insert("bobr".to_string(), ("host".to_string(), "192.168.17.5".to_string()));
    sensors.insert("GALYA".to_string(), ("host".to_string(), "172.16.5.1".to_string()));
    
    let current_session: &mut SessionStatus = &mut SessionStatus {
        host: HOSTNAME.to_string(),
        user: username,
        audit_status: true,
        sensor_list: sensors
    };

    main_menu(current_session, &LogFiles {audit_file: AUDIT_LOG.to_string(),
                                                                event_file: EVENT_LOG.to_string(),
                                                                rules_file: RULES_FILE.to_string()});
}