use clap::{Arg, Command};
use menu::menu::main_menu;
mod menu;

const USER_LIST_FILE: &str = "users.txt";
const AUDIT_LOG: &str = "audit.txt";
const EVENT_LOG: &str = "events.txt";

fn main() {
    let matches = Command::new("rSOC")
        .version("0.0.1")
        .author("buran <bvran@proton.me>")
        .about("rSOC - Simple network and endpoint SOC implementation written on Rust\n\nThis is a Management Server - head unit of SOC")
        .arg(Arg::new("user")
                 .short('u')
                 .long("user")
                 .help("User to authentificate"))
        .arg(Arg::new("password")
                 .short('p')
                 .long("password")
                 .help("User's password"))
        .get_matches();

    // let username = matches.get_one::<String>("user").unwrap();
    // let password = matches.get_one::<String>("password").unwrap();
    // println!("{} and {}", username, password);

    main_menu();
}