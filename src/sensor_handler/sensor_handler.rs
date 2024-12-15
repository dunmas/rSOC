use std::io::{self, BufRead};
use std::time::SystemTime;
use std::fs::{self, File};
use regex::Regex;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
use tokio::sync::mpsc;
use crate::structs::soc_structs::{SessionStatus, AuditEventType};
use crate::structs::soc_structs::multithread::FileMutexes;
use crate::file_manager::file_manager::audit_handler::write_audit_event;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

pub fn get_sensor_list(session_status: &mut SessionStatus) {
    let sensors_map = session_status.sensor_list.lock().unwrap();
    println!("----------------------------------------------------------------------------------------------\n\
             || ----- IP address ----- || ----- Hostname ----- || ----- Level ----- || ----- Status ----- ||\n\
             -----------------------------------------------------------------------------------------------");

    for (ip, info) in sensors_map.iter() {
        let status = if info.3 == true { "capturing" } else { "stopped" };
        let output_string = "|| ".to_string() + ip + " || " + &info.1 + " || " + &info.2 + " || " + status + " ||";
        println!("{}", output_string);
    }

    println!("---------------------------------------------------------------------------------------------");
}

pub fn change_sensor_state(sensor_ip: &String, session_status: &mut SessionStatus, file_mutexes: &FileMutexes, log_file: &String, audit_status: bool) -> (bool, bool, bool) {
    let mut sensors_map = session_status.sensor_list.lock().unwrap();

    for (ip, info) in sensors_map.iter_mut() {
        if sensor_ip == ip {
            info.3 = !info.3;

            if info.3 {
                return (true, write_audit_event(SystemTime::now(), (*info.1).to_string(), (*session_status.user).to_string(), AuditEventType::SenEnable, "Event logging enabled".to_string(), file_mutexes, log_file, audit_status), true)
            } else {
                return (false, write_audit_event(SystemTime::now(), (*info.1).to_string(), (*session_status.user).to_string(), AuditEventType::SenDisable, "Event logging disabled".to_string(), file_mutexes, log_file, audit_status), true)
            }
        }
    }

    (false, false, false)
}

fn get_rules_string_by_level(level: String, rule_file: &String) -> String {
    let mut tx_string = String::new();
    let opened_rules_file = fs::File::open(rule_file).unwrap();
    let reader = io::BufReader::new(opened_rules_file);
    let pattern = Regex::new(format!(r"level\[:1:\]{}\[:2:\]", level).as_str()).unwrap();

    for line in reader.lines() {
                if let Ok(l) = line {
                    if pattern.is_match(&l) {
                        tx_string.push_str(&l);
                        tx_string.push('\n');
                    }
                }
    }

    tx_string
}

pub async fn handle_client<'a>(mut stream: TcpStream, addr_str: String, mut client_rx: mpsc::Receiver<String>, rule_file: &String, sensors_mutex_clone: Arc<Mutex<HashMap<String, (mpsc::Sender<String>, String, String, bool)>>>, client_tx: mpsc::Sender<String>, server_tx: mpsc::Sender<String>) -> io::Result<()> {
    let mut init_buffer = [0; 1024];

    // Init string from client
    let n = stream.read(&mut init_buffer).await?;
    if n == 0 {
        return Ok(());
    }
    
    let raw_init_string = String::from_utf8_lossy(&init_buffer[..n]);
    // init_vec[0] - sensor_name, 1 - sensor_level, 2 - sensor user
    let init_vec: Vec<&str> = raw_init_string.split("[:1:]").collect();
    sensors_mutex_clone.lock().unwrap().insert(addr_str.clone(), (client_tx, init_vec[0].to_string(), init_vec[1].to_string(), true));

    println!("Client connected! IP: {}, Name: {}, Level: {}, User: {}", addr_str, init_vec[0], init_vec[1], init_vec[2]);
    server_tx.send("init[:1:]".to_string() + &raw_init_string).await.unwrap();

    let mut buffer = [0; 1024];
    loop {
        tokio::select! {
            // data stream from sensor
            result = stream.read(&mut buffer) => match result {
                Ok(n) if n == 0 => {
                    server_tx.send("cl_disc[:1:]".to_string() + &addr_str + "[:1:]" + &init_vec[0] + "[:1:]" + &init_vec[1] + "[:1:]" + &init_vec[2]).await.unwrap();
                    break;
                },
                Ok(n) => {
                    // getting some data from client to server
                    let raw_string = String::from_utf8_lossy(&buffer[..n]);
                    // cmd_vec[0] - command
                    let cmd_vec: Vec<&str> = raw_string.split("[:3:]").collect();

                    match cmd_vec[0] {
                        // has no any additional fields in splitted vector
                        "update" => {
                            let rules_str = get_rules_string_by_level(init_vec[1].to_string(), rule_file);
                            if let Err(e) = stream.write_all(rules_str.as_bytes()).await {
                                println!("Error while sending rules to client {}: {}", addr_str, e);
                                continue;
                            }

                            println!("Sended rules to {}", addr_str);
                            server_tx.send(raw_string.to_string() + "[:3:]" + init_vec[0] + "[:3:]" + init_vec[2] + "[:3:]" + init_vec[1]).await.unwrap();
                        },
                        // cmd_vec[1] - rule hash, cmd_vec[2] - UNIX-time
                        "event" => {
                            let status = if sensors_mutex_clone.lock().unwrap().get(&addr_str).unwrap().3 { "true" } else { "false" };
                            server_tx.send(raw_string.to_string() + "[:3:]" + init_vec[0] + "[:3:]" + init_vec[1]+ "[:3:]" + status).await.unwrap();
                        }
                        _ => {}
                    }
                }
                Err(e) => return Err(e),
            },
            // data stream from server interface to sensor
            message = client_rx.recv() => match message {
                Some(msg) => {
                    // sending some data from server interface to client
                    if let Err(e) = stream.write_all(msg.as_bytes()).await {
                        println!("Error while sending message to client {}: {}", addr_str, e);
                        continue;
                    }
                },
                None => break,
            }
        }
    }

    Ok(())
}