mod menu;
mod file_manager;
mod structs;
mod sensor_handler;
mod auth;

// Network Communication
use std::io::{self, Read, Write};
use std::thread;
use tokio::sync::mpsc;
use tokio::net::{TcpListener, TcpStream};
use tokio::spawn;

use clap::{Arg, Command};
use std::sync::{Arc, Mutex};
use futures::channel;
use menu::menu::main_menu;
use std::collections::HashMap;
use structs::soc_structs::{SessionStatus, LogFiles};
use auth::auth::authentificate;
use sensor_handler::sensor_handler::handle_client;

const USER_LIST_FILE: &str = "users.txt";
const AUDIT_LOG: &str = "audit.txt";
const EVENT_LOG: &str = "events.txt";
const RULES_FILE: &str = "rules.txt";
const HOSTNAME: &str = "MAMA-1 | Control centre";
const LPORT: &str = "7777";

#[tokio::main]
async fn main() {
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
    
    let sensors: HashMap<String, (mpsc::Sender<String>, String, String, bool)> = HashMap::new();
    let sensors_mutex =  Arc::new(Mutex::new(sensors));

    let sensors_mutex_clone_for_rx = Arc::clone(&sensors_mutex);

    let listener;

    match TcpListener::bind("127.0.0.1:".to_string() + LPORT).await {
        Ok(bind_res) => { listener = bind_res; },
        Err(e) => { println!("Failed to bind to {} port. Try again.\n{}", LPORT, e); return; }
    }
    
    println!("Start listening on {} port", LPORT);
    let (tx, mut rx) = mpsc::channel::<String>(32);

    // console interface
    {
        let tx_clone = tx.clone();
        spawn(async move {
            let current_session: &mut SessionStatus = &mut SessionStatus {
                    host: HOSTNAME.to_string(),
                    user: username,
                    audit_status: true,
                    sensor_list: sensors_mutex
                };
            
                main_menu(current_session, &LogFiles {audit_file: AUDIT_LOG.to_string(),
                                                                event_file: EVENT_LOG.to_string(),
                                                                rules_file: RULES_FILE.to_string()},
                                                                tx_clone).await;
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
                    
                    spawn(async move {
                        if let Err(e) = handle_client(stream, addr_str, client_rx, &RULES_FILE.to_string(), Arc::clone(&sensors_mutex_clone_for_clients), client_tx, server_tx_clone).await {
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
                    break;
                },
                Some(ref cmd) if cmd.starts_with("cl_disc") => {
                    // parced_cmd[1] - address of client
                    let parced_cmd: Vec<&str> = cmd.split("[:1:]").collect();
                    sensors_mutex_clone_for_rx.lock().unwrap().remove(parced_cmd[1]);
                    println!("Client disconnected: {} ({})", parced_cmd[1].to_string(), parced_cmd[2].to_string());
                }
                _ => {}
            }
        }
    }
}