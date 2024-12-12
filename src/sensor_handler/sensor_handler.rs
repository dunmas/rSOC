use std::io::{self, Read, Write, BufRead};
use std::time::SystemTime;
use std::fs;
use regex::Regex;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};
use tokio::sync::mpsc;
use crate::structs::soc_structs::{SessionStatus, AuditEventType};
use crate::structs::soc_structs::multithread::FileMutexes;
use crate::file_manager::file_manager::audit_handler::write_audit_event;
use crate::sensor_handler::rule_handler::get_rules_map;

pub fn get_sensor_list(session_status: &mut SessionStatus) {
    let sensors_map = session_status.sensor_list.lock().unwrap();
    println!("----------------------------------------------------------------------------------------------\n\
             || ----- IP address ----- || ----- Hostname ----- || ----- Level ----- || ----- Status ----- ||\n\
             -----------------------------------------------------------------------------------------------");

    for (ip, info) in sensors_map.iter() {
        let status = if info.3 == true { "capturing" } else { "stopped" };
        let output_string = "|| ".to_string() + ip + " || " + &info.1 + " || " + &info.2 + " || " + status + " ||";
        print!("{}", output_string);
    }

    println!("---------------------------------------------------------------------------------------------");
}

pub fn change_sensor_state(sensor_ip: &String, session_status: &mut SessionStatus, file_mutexes: &FileMutexes, log_file: &String) -> (bool, bool, bool) {
    let mut sensors_map = session_status.sensor_list.lock().unwrap();

    for (ip, info) in sensors_map.iter_mut() {
        if sensor_ip == ip {
            info.3 = !info.3;

            if info.3 {
                return (true, write_audit_event(SystemTime::now(), (*info.1).to_string(), (*session_status.user).to_string(), AuditEventType::SenEnable, "Event logging enabled".to_string(), file_mutexes, log_file), true)
            } else {
                return (false, write_audit_event(SystemTime::now(), (*info.1).to_string(), (*session_status.user).to_string(), AuditEventType::SenDisable, "Event logging disabled".to_string(), file_mutexes, log_file), true)
            }
        }
    }

    (false, false, false)
}

pub async fn update_sensor_rules(sensor_ip: &String, session_status: &mut SessionStatus::<'_>, file_mutexes: &FileMutexes, log_file: &String, rule_file: &String, server_tx: tokio::sync::mpsc::Sender<&str>) -> bool {
    let mut sensors_map = session_status.sensor_list.lock().unwrap();
    let mut tx_string = String::new();

    for (ip, info) in sensors_map.iter_mut() {
        if sensor_ip == ip {
            let opened_rules_file = fs::File::open(rule_file).unwrap();
            let reader = io::BufReader::new(opened_rules_file);
            let pattern = Regex::new(format!(r"level\[:1:\]{}\[:2:\]", info.2).as_str()).unwrap();

            for line in reader.lines() {
                if let Ok(l) = line {
                    if pattern.is_match(&l) {
                        tx_string.push_str(&l);
                        tx_string.push('\n');
                    }
                }
            }

            // tokio::runtime::Builder::new_current_thread()
            //     .enable_all()
            //     .build()
            //     .unwrap()
            //     .block_on(async move {
            //         info.0.blocking_send(&tx_string).await.unwrap();
            // });   

            // info.0.send(&tx_string).await.unwrap(); 
                
            write_audit_event(SystemTime::now(), (*info.1).to_string(), (*session_status.user).to_string(), AuditEventType::RulesUpdate, "Sensor rules updated".to_string(), file_mutexes, log_file);
            return true;
        }
    }

    false
}


// TODO: get name and level from sensor in first connection
pub async fn handle_client(mut stream: TcpStream, addr_str: String, mut client_rx: mpsc::Receiver<&str>) -> io::Result<()> {
    let mut buffer = [0; 1024];
    loop {
        tokio::select! {
            // data stream from sensor
            result = stream.read(&mut buffer) => match result {
                Ok(n) if n == 0 => break,
                Ok(n) => {
                    // getting some data from client to server
                    let raw_string = String::from_utf8_lossy(&buffer[..n]);
                }
                Err(e) => return Err(e),
            },
            // data stream from server interface to sensor
            message = client_rx.recv() => match message {
                Some(msg) => {
                    // sending some data from server interface to client
                    if let Err(e) = stream.write_all(msg.as_bytes()).await {
                        println!("Error while sending message to client {}: {}", addr_str, e);
                        break;
                    }
                },
                None => break,
            }
        }
    }

    Ok(())
}