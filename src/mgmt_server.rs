use clap::{Arg, Command};
use sha2::{Sha256, Digest};

mod menu;
mod file_manager;
mod structs;

use menu::menu::main_menu;
use file_manager::file_manager::user_file_handler;
use structs::soc_structs::{SessionStatus, LogFiles};

const USER_LIST_FILE: &str = "users.txt";
const AUDIT_LOG: &str = "audit.txt";
const EVENT_LOG: &str = "events.txt";
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
                 .arg_required_else_help(true)
        .arg(Arg::new("password")
                 .short('p')
                 .long("password")
                 .help("User's password"))
                 .arg_required_else_help(true)
        .get_matches();

    let input_username = matches.get_one::<String>("user").unwrap();
    let input_password = matches.get_one::<String>("password").unwrap();
    let user_map = user_file_handler::get_user_map(USER_LIST_FILE);

    // Hash of input password
    let mut hasher = Sha256::new();
    hasher.update(input_password);
    let pass_hash = hasher.finalize();

    if !user_map.contains_key(input_username) 
    || user_map[input_username].0 != format!("{:x}", pass_hash) {
        println!("Wrong credentials. Goodbye.");
        return;
    }
    
    let current_session: &mut SessionStatus = &mut SessionStatus {
        host: HOSTNAME.to_string(),
        user: input_username.to_string(),
        audit_status: true
    };

    main_menu(current_session, &LogFiles {audit_file: AUDIT_LOG.to_string(), event_file: EVENT_LOG.to_string()});
}