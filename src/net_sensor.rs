use std::net::TcpStream;
use std::io::{Read, Write};
use crate::menu::menu::get_user_choice;
use clap::{Arg, Command};
use tokio::time::{sleep, Duration};
use std::fs::OpenOptions;
use crate::sensor_handler::rule_handler::get_rules_map;
use std::sync::{Arc, Mutex};

mod menu;
mod file_manager;
mod structs;
mod sensor_handler;
mod auth;

const USERNAME: &str = "net_admin";
const LEVEL: &str = "net";
const RULES_FILE: &str = "net_rules.txt";

#[tokio::main]
async fn main() {
    let matches = Command::new("rSOC")
        .version("0.0.1")
        .author("buran <bvran@proton.me>")
        .about("rSOC - Simple network and endpoint SOC implementation written on Rust\n\nThis is Network Sensor - traffic analyzer of SOC")
        .arg(Arg::new("rules_update")
                 .short('u')
                 .long("update")
                 .action(clap::ArgAction::SetTrue)
                 .help("Update sensor rules"))     
        .get_matches();

    println!("Enter IP of management server:");
    let mgmt_server = get_user_choice();

    match TcpStream::connect(mgmt_server.as_str()) {
        Ok(mut stream) => {
            let init_message = "init[:1:]".to_string() + LEVEL + "[:1:]" + USERNAME;
            let init_message_byte_fmt = init_message.as_bytes();
            let mut buffer = [0; 1024];
            stream.write(init_message_byte_fmt).unwrap();

            let _ = sleep(Duration::from_secs(1)).await;
            if matches.contains_id("rules_update") {
                stream.write(b"update").unwrap();
                let size = stream.read(&mut buffer).unwrap();
                match size {
                    0 => { println!("Server disconnected. Stop working..."); },
                    _ => {
                        let mut rules_file = OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .create(true)
                        .read(true)
                        .open(RULES_FILE)
                        .unwrap();

                        match write!(rules_file, "{}", String::from_utf8_lossy(&buffer[..size])) {
                            Ok(_) => { println!("Rules updated succesfully!") },
                            Err(e) => { println!("Error while writing to rule file: {}", e) }
                        };

                        return;
                     }
                }
            }

            loop {
                let size = stream.read(&mut buffer).unwrap();
                match size {
                    0 => { println!("Server disconnected. Stop working..."); },
                    _ => {
                        let rules_mutex = Arc::new(Mutex::new(OpenOptions::new()
                        .create(true)
                        .read(true)
                        .open(RULES_FILE)
                        .unwrap()));
                        
                        let rules_vec;
                        if let Some(data_vec) =  get_rules_map(&rules_mutex).get(LEVEL) {
                            rules_vec = data_vec;
                        } else {
                            println!("Error with parcing rules. Check rules file.");
                            break;
                        }

                        
                     }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
        }
    }
}
