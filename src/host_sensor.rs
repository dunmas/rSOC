mod auth;
mod file_manager;
mod menu;
mod sensor_handler;
mod structs;

use chrono::offset::Local;
use chrono::DateTime;
use clap::{Arg, Command};
use notify::event::RenameMode;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::time::{sleep, Duration};

// dir watching
use notify::{recommended_watcher, EventKind, RecursiveMode, Watcher};
use notify::event::ModifyKind;
use regex::Regex;
use std::fs::File;
use std::path::Path;
use std::sync::mpsc::channel;

use crate::menu::menu::get_user_choice;
use crate::sensor_handler::rule_handler::get_rules_map;

const CONFIG: &str = "host_sensor_config.txt";

#[tokio::main]
async fn main() {
    let matches = Command::new("rSOC")
        .version("0.1.0")
        .author("buran <bvran@proton.me>")
        .about("rSOC - Simple network and endpoint SOC implementation written on Rust\n\nThis is Host Sensor - directory files analyzer of SOC")
        .arg(Arg::new("rules_update")
                 .short('c')
                 .long("command")
                 .help("Type 'update' to update sensor rules. (BTW now you can type anything to update)"))     
        .get_matches();

    let mut sensor_name: String = String::new();
    let mut username: String = String::new();
    let mut rules_file: String = String::new();
    let mut control_path: String = String::new();

    let level: String = String::from("host");

    // config parcing
    {
        let mut conf_file = OpenOptions::new()
            .read(true) // Позволяем чтение
            .open(CONFIG)
            .unwrap();
        let buf: &mut String = &mut "".to_owned();

        match (conf_file).read_to_string(buf) {
            Ok(_) => {
                let strings = buf.split("\n");

                for line in strings {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if line.starts_with("#") {
                        continue;
                    }

                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() == 2 {
                        let key = parts[0].trim();
                        let value = parts[1].trim().trim_end_matches(';');

                        match key {
                            "sensor_name" => sensor_name = value.to_string(),
                            "username" => username = value.to_string(),
                            "rules_file" => rules_file = value.to_string(),
                            "control_path" => control_path = value.to_string(),
                            _ => println!("Weird parameter: {}", key),
                        }
                    }
                }
            }
            Err(e) => {
                println!("{}", e);
            }
        }
    }

    println!("Enter address (IP:port) of management server:");
    let mgmt_server = get_user_choice();

    match TcpStream::connect(mgmt_server.as_str()) {
        Ok(mut stream) => {
            let init_message = sensor_name + "[:1:]" + level.as_str() + "[:1:]" + username.as_str();
            let init_message_byte_fmt = init_message.as_bytes();
            let mut buffer = [0; 1024];
            stream.write(init_message_byte_fmt).unwrap();

            let _ = sleep(Duration::from_secs(1)).await;
            if matches.contains_id("rules_update") {
                stream.write(b"update").unwrap();
                let size = stream.read(&mut buffer).unwrap();
                match size {
                    0 => {
                        println!("Server disconnected. Stop working...");
                    }
                    _ => {
                        let mut rules_file = OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .create(true)
                            .read(true)
                            .open(rules_file)
                            .unwrap();

                        match write!(rules_file, "{}", String::from_utf8_lossy(&buffer[..size])) {
                            Ok(_) => {
                                println!("Rules updated succesfully!")
                            }
                            Err(e) => {
                                println!("Error while writing to rule file: {}", e)
                            }
                        };

                        return;
                    }
                }
            }

            let (tx, rx) = channel();
            let mut watcher;
        
            match recommended_watcher(tx) {
                Ok(wtr) => { watcher = wtr; },
                Err(e) => { println!("Failed to set up directory watcher: {}", e); return; }
            }
        
            match watcher.watch(Path::new(&control_path), RecursiveMode::Recursive) {
                Ok(_) => {},
                Err(e) => { println!("Failed to bind to directory: {}", e); return; }
            }

            let rules_mutex = Arc::new(Mutex::new(
                OpenOptions::new()
                    .append(true)
                    .create(true)
                    .read(true)
                    .open(rules_file)
                    .unwrap(),
            ));

            if let Some(_) = get_rules_map(&rules_mutex).get(level.as_str()) {
                // rules_vec = data_vec;
            } else {
                println!("Error with parcing rules. Check rules file.");
                return;
            }

            let all_rules_map = get_rules_map(&rules_mutex);
            let rules_vec = all_rules_map.get(level.as_str()).unwrap();

            loop {
                match rx.recv() {
                    Ok(event) => {
                        match event {
                            Ok(evt) => {
                                if evt.kind == EventKind::Access(notify::event::AccessKind::Close(notify::event::AccessMode::Write)) || evt.kind == EventKind::Modify(ModifyKind::Name(RenameMode::To))  {
                                    let file_path = &evt.paths[0];
                                    let mut file = File::open(file_path).unwrap();
                                    let mut contents = String::new();
                                    let _ = file.read_to_string(&mut contents);

                                    for rule in rules_vec {
                                        for pairs_vector_with_hash in rule {
                                            for pair in pairs_vector_with_hash.1 {
                                                if pair.0 == "payload" {
                                                    let regex = Regex::new(pair.1.as_str()).unwrap();

                                                    if regex.is_match(&contents) {
                                                        let timestamp: DateTime<Local> = SystemTime::now().into();
                                                        let cmd_string = "event".to_string()
                                                            + "[:3:]"
                                                            + &pairs_vector_with_hash.0
                                                            + "[:3:]"
                                                            + &timestamp.timestamp().to_string()
                                                            + "[:3:]"
                                                            + format!("{}", file_path.canonicalize().unwrap().display()).as_str();
                                                        
                                                        let cmd_string_byte_fmt = cmd_string.as_bytes();
                                                        match stream.write(cmd_string_byte_fmt) {
                                                            Ok(_) => {}
                                                            Err(_) => {
                                                                println!(
                                                                    "Troubles with connection. Stop working..."
                                                                );
                                                                return;
                                                            }
                                                        }

                                                        println!(
                                                            "Catch event! Rule hash: {} | Time: {} | Path: {}",
                                                            pairs_vector_with_hash.0,
                                                            timestamp.format("%d-%m-%Y %H:%M:%S"),
                                                            format!("{}", file_path.canonicalize().unwrap().display()).as_str()
                                                        );
                                                    }                                          
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            Err(e) => { println!("Client handling error: {}", e) }
                        }
                    }
                    Err(e) => eprintln!("Ошибка: {:?}", e),
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
        }
    }
}