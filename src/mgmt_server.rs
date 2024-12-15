mod menu;
mod file_manager;
mod structs;
mod sensor_handler;
mod auth;

// Network Communication
use std::io::{self, Read, Write};
use std::ops::DerefMut;
use std::thread;
use tokio::sync::mpsc;
use tokio::net::{TcpListener, TcpStream};
use tokio::spawn;
use tokio_tungstenite::tungstenite::ClientRequestBuilder;
use std::time::SystemTime;

//config parse
use std::fs::OpenOptions;
use std::io::BufRead;
use std::path::Path;

use clap::{Arg, Command};
use std::sync::{Arc, Mutex};
use futures::channel;
use menu::menu::main_menu;
use std::collections::HashMap;
use structs::soc_structs::{AuditEventType, LogFiles, SessionStatus};
use auth::auth::authenticate;
use sensor_handler::sensor_handler::handle_client;
use crate::structs::soc_structs::multithread::FileMutexes;
use crate::file_manager::file_manager::audit_handler::{prepare_file_mutexes, write_audit_event};
use crate::file_manager::file_manager::event_handler::write_security_event;
use chrono::{DateTime, Local};
use chrono::offset::Utc;

const CONFIG: &str = "server_config.txt";
// const USER_LIST_FILE: &str = "users.txt";
// const AUDIT_LOG: &str = "audit.txt";
// const EVENT_LOG: &str = "events.txt";
// const RULES_FILE: &str = "rules.txt";
// const HOSTNAME: &str = "Control centre";
// const LPORT: &str = "7777";

#[tokio::main]
async fn main() {
    let matches = Command::new("rSOC")
        .version("0.1.0")
        .author("buran <bvran@proton.me>")
        .about("rSOC - Simple network and endpoint SOC implementation written on Rust\n\nThis is a Management Server - head unit of SOC")
        .arg(Arg::new("user")
                 .short('u')
                 .long("user")
                 .help("User to authenticate"))
                 .arg_required_else_help(true)
        .arg(Arg::new("password")
                 .short('p')
                 .long("password")
                 .help("User's password"))
                 .arg_required_else_help(true)
        .get_matches();

    let mut user_list_file: String = String::new();
    let mut audit_log: String = String::new();
    let mut event_log: String = String::new();
    let mut rules_file: String = String::new();
    let mut hostname: String = String::new();
    let mut lport: String = String::new();
    let mut print_state = false;

    // config parcing
    {
        let mut conf_file = OpenOptions::new()
            .read(true) // Позволяем чтение
            .open(CONFIG).unwrap();
        let buf: &mut String = &mut "".to_owned();

        match (conf_file).read_to_string(buf){
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
                            "audit_log" => audit_log = value.to_string(),
                            "event_log" => event_log = value.to_string(),
                            "user_list_file" => user_list_file = value.to_string(),
                            "rules_file" => rules_file = value.to_string(),
                            "hostname" => hostname = value.to_string(),
                            "lport" => lport = value.to_string(),
                            "event_print" => print_state = if value == "0" { false } else { true },
                            _ => eprintln!("Неизвестный ключ: {}", key),
                        }
                    }
                }
            },
            Err(e) => { println!("{}", e);}
        }
    }
    
    let sensors: HashMap<String, (mpsc::Sender<String>, String, String, bool)> = HashMap::new();
    let sensors_mutex =  Arc::new(Mutex::new(sensors));
    let sensors_mutex_clone_for_rx = Arc::clone(&sensors_mutex);

    let log_files = LogFiles {audit_file: audit_log.clone(),
        event_file: event_log.clone(),
        rules_file: rules_file.clone()};

    let file_mutexes: FileMutexes = prepare_file_mutexes(&log_files);
    let file_mutexes_clone = FileMutexes {
        audit_mutex: Arc::clone(&file_mutexes.audit_mutex),
        event_mutex: Arc::clone(&file_mutexes.event_mutex),
        rules_mutex: Arc::clone(&file_mutexes.rules_mutex),
    };

    let is_admin;
    let username: String;
    let listener;
    let audit_status:Arc<Mutex<bool>> = Arc::new(Mutex::new(true));
    let audit_status_clone = Arc::clone(&audit_status);

    {
        let input_username = matches.get_one::<String>("user").unwrap();
        let input_password = matches.get_one::<String>("password").unwrap();
        let aud_stat = audit_status.lock().unwrap();
        let usr_list = user_list_file.clone();
        let hstnm = hostname.clone();
        let aud_log = audit_log.clone();
        let auth_res = authenticate(&input_username, &input_password, &usr_list, hstnm, &file_mutexes, aud_log, *aud_stat);
        if auth_res.0 { username = auth_res.1; is_admin = auth_res.2; } else { return; }
    }

    let hostname_clone = hostname.clone();
    let username_clone = username.clone();

    match TcpListener::bind("127.0.0.1:".to_string() + lport.as_str()).await {
        Ok(bind_res) => { listener = bind_res; },
        Err(e) => { println!("Failed to bind to {} port. Try again.\n{}", lport, e); return; }
    }

    {
        let aud_stat = audit_status_clone.lock().unwrap();
        let hst = hostname_clone.clone();
        let usr = username_clone.clone();
        write_audit_event(SystemTime::now(), hst, usr, AuditEventType::ServOn, "Management server turned on. Listener started".to_string(), &file_mutexes_clone, &audit_log, *aud_stat);
        println!("Start listening on {} port", lport);
    }
    
    let (tx, mut rx) = mpsc::channel::<String>(32);
  
    // console interface
    {
        let tx_clone = tx.clone();
        spawn(async move {
            let current_session: &mut SessionStatus = &mut SessionStatus {
                    host: hostname,
                    user: username,
                    is_admin: is_admin,
                    sensor_list: sensors_mutex
                };
            
            main_menu(current_session, &log_files, tx_clone, &file_mutexes, &audit_status).await;
        });
    }

    // sensors handling
    loop {
        tokio::select! {
            result = listener.accept() => match result {
                Ok((stream, addr)) => {
                    // check address format: port is required
                    let addr_str = format!("{}", addr);
                    let (client_tx, client_rx) = mpsc::channel::<String>(32);
                    let main_tx = tx.clone();
                    let sensors_mutex_clone_for_clients = Arc::clone(&sensors_mutex_clone_for_rx);
                    let server_tx_clone = tx.clone();
                    let ru_file = rules_file.clone();
                    spawn(async move {
                        if let Err(e) = handle_client(stream, addr_str, client_rx, &ru_file, Arc::clone(&sensors_mutex_clone_for_clients), client_tx, server_tx_clone).await {
                            println!("Error while client processing:\n{}", e);
                        }
                        main_tx.send("client_disc".to_string()).await.unwrap();
                    });
                },
                Err(e) => println!("Error while recieving connection:\n{}", e),
            },
            command = rx.recv() => match command {
                Some(ref cmd) if cmd == "stop" => {
                    println!("Stop listening...");
                    let aud_stat = audit_status_clone.lock().unwrap();
                    write_audit_event(SystemTime::now(), hostname_clone, username_clone, AuditEventType::ServOff, "Management server turned off".to_string(), &file_mutexes_clone, &audit_log, *aud_stat);
                    break;
                },
                Some(ref cmd) if cmd.starts_with("cl_disc") => {
                    // parced_cmd[1] - address of client, parced_cmd[2] - name of client, parced_cmd[3] - level of client, parced_cmd[4] - client username
                    let parced_cmd: Vec<&str> = cmd.split("[:1:]").collect();
                    sensors_mutex_clone_for_rx.lock().unwrap().remove(parced_cmd[1]);
                    println!("Client disconnected: {} ({})", parced_cmd[1].to_string(), parced_cmd[2].to_string());
                    let event_type = if parced_cmd[3] == "net" { AuditEventType::NetSenDisconn } else { AuditEventType::HostSenDisconn };

                    let aud_stat = audit_status_clone.lock().unwrap();
                    write_audit_event(SystemTime::now(), parced_cmd[2].to_string(), parced_cmd[4].to_string(), event_type, "Sensor disconnected. Type - ".to_string() + parced_cmd[3], &file_mutexes_clone, &audit_log, *aud_stat);
                }
                Some(ref cmd) if cmd.starts_with("init") => {
                    // parced_cmd[1] - name of client, parced_cmd[2] - client type, parced_cmd[3] - client user
                    let init_vec: Vec<&str> = cmd.split("[:1:]").collect();
                    let event_type = if init_vec[2] == "net" { AuditEventType::NetSenConn } else { AuditEventType::HostSenConn };
                    
                    let aud_stat = audit_status_clone.lock().unwrap();
                    write_audit_event(SystemTime::now(), init_vec[1].to_string(), init_vec[3].to_string(), event_type, "Sensor connected. Type - ".to_string() + init_vec[2], &file_mutexes_clone, &audit_log, *aud_stat);
                }
                Some(ref cmd) if cmd.starts_with("update") => {
                    // parced_cmd[1] - name of client, parced_cmd[2] - client user, parced_cmd[3] - client level
                    let init_vec: Vec<&str> = cmd.split("[:3:]").collect();
                    
                    let aud_stat = audit_status_clone.lock().unwrap();
                    write_audit_event(SystemTime::now(), init_vec[1].to_string(), init_vec[2].to_string(), AuditEventType::RulesUpdate, "Rules updated - ".to_string() + init_vec[3] + " level", &file_mutexes_clone, &audit_log, *aud_stat);
                }
                Some(ref cmd) if cmd.starts_with("event") => {
                    // parced_cmd[1] - rule hash, parced_cmd[2] - UNIX-time, parced_cmd[3] - sensor name, parced_cmd[4] - level, parced_cmd[5] - sensor_status
                    let parced_cmd: Vec<&str> = cmd.split("[:3:]").collect();
                    if parced_cmd[5] == "false" { continue; }
                    let net_level = if parced_cmd[4] == "net" { true } else { false };

                    let unix_time: i64 = parced_cmd[2].parse().unwrap();
                    // TIMEZONE.parse().unwrap()
                    let datetime: DateTime<Local> = DateTime::from_timestamp(unix_time, 0).unwrap().with_timezone(&Local);
                    let ev_log = event_log.clone();
                    write_security_event(datetime, parced_cmd[3].to_string(), parced_cmd[1].to_string(), net_level, &file_mutexes_clone, &event_log.clone());
                    if print_state {
                        println!("Event! Time: {}, Sensor: {}", datetime.format("%d-%m-%Y %H:%M:%S").to_string(), parced_cmd[3].to_string());
                    }
                }
                _ => {}
            }
        }
    }
}