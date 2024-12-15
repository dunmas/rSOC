use std::net::TcpStream;
use std::io::{Read, Write};
use crate::menu::menu::get_user_choice;
use clap::{Arg, Command};
use tokio::time::{sleep, Duration};
use std::fs::OpenOptions;
use crate::sensor_handler::rule_handler::get_rules_map;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use chrono::DateTime;
use chrono::offset::Local;

// traffic sniffer
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};

mod menu;
mod file_manager;
mod structs;
mod sensor_handler;
mod auth;

const CONFIG: &str = "net_sensor_config.txt";

#[tokio::main]
async fn main() {
    let matches = Command::new("rSOC")
        .version("0.1.0")
        .author("buran <bvran@proton.me>")
        .about("rSOC - Simple network and endpoint SOC implementation written on Rust\n\nThis is Network Sensor - traffic analyzer of SOC")
        .arg(Arg::new("rules_update")
                 .short('c')
                 .long("command")
                 .help("Type 'update' to update sensor rules. (BTW now you can type anything to update)"))     
        .get_matches();

    let mut sensor_name: String = String::new();
    let mut username: String = String::new();
    let mut rules_file: String = String::new();
    let mut listen_interface: String = String::new();

    let level: String = String::from("net");

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
                            "listen_interface" => listen_interface = value.to_string(),
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

    let interfaces = datalink::interfaces();
    let interface;

    match interfaces.into_iter().find(|iface| iface.name == listen_interface) {
        Some(res) => { interface = res },
        _ => { println!("Can't find such interface. Check sensor settings."); return; }
    }

    println!("Enter address (IP:port) of management server:");
    let mgmt_server = get_user_choice();

    match TcpStream::connect(mgmt_server.as_str()) {
        Ok(mut stream) => {
            let init_message = sensor_name + "[:1:]" + &level.clone().to_string() + "[:1:]" + &username.clone().to_string();
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
                        .open(rules_file)
                        .unwrap();

                        match write!(rules_file, "{}", String::from_utf8_lossy(&buffer[..size])) {
                            Ok(_) => { println!("Rules updated succesfully!") },
                            Err(e) => { println!("Error while writing to rule file: {}", e) }
                        };

                        return;
                    }
                }
            }
            
            let rules_mutex = Arc::new(Mutex::new(OpenOptions::new()
            .append(true)
            .create(true)
            .read(true)
            .open(rules_file)
            .unwrap()));
                       
            if let Some(_) =  get_rules_map(&rules_mutex).get(level.as_str()) {
                // rules_vec = data_vec;
            } else {
                println!("Error with parcing rules. Check rules file.");
                return;
            }

            let all_rules_map = get_rules_map(&rules_mutex);
            let rules_vec = all_rules_map.get(level.as_str()).unwrap();

            // Packet tracer channel
            let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                _ => { println!("Failed to create channel"); return; },
            };

            loop {
                match rx.next() {
                    Ok(packet) => {
                        let ethernet_packet = EthernetPacket::new(packet).unwrap();

                        if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
                            for rule in rules_vec {
                                for pairs_vector in rule {

                                    if let Some((_key, _value)) = pairs_vector.1.iter().find(|(k, v)| *v == ethernet_packet.get_source().to_string() && k == "src") {
                                        if let Some((_key, _value)) = pairs_vector.1.iter().find(|(k, v)| *v == ethernet_packet.get_destination().to_string() && k == "dst") {
                                            let timestamp: DateTime<Local> = SystemTime::now().into();
                                            let cmd_string = "event".to_string() + "[:3:]" + &pairs_vector.0 + "[:3:]" + &timestamp.timestamp().to_string();
                                            let cmd_string_byte_fmt = cmd_string.as_bytes();
                                            match stream.write(cmd_string_byte_fmt) {
                                                Ok(_) => {},
                                                Err(_) => { println!("Troubles with connection. Stop working..."); return; }
                                            }
                                            println!("Catch event! Rule hash: {} | Time: {}", pairs_vector.0, timestamp.format("%d-%m-%Y %H:%M:%S"));
                                            break;
                                        } else if let Some((_key, _value)) = pairs_vector.1.iter().find(|(k, v)| *v == " ".to_string() && k == "dst") {
                                        
                                            let timestamp: DateTime<Local> = SystemTime::now().into();
                                            let cmd_string = "event".to_string() + "[:3:]" + &pairs_vector.0 + "[:3:]" + &timestamp.timestamp().to_string();
                                            let cmd_string_byte_fmt = cmd_string.as_bytes();
                                            match stream.write(cmd_string_byte_fmt) {
                                                Ok(_) => {},
                                                Err(_) => { println!("Troubles with connection. Stop working..."); return; }
                                            }
                                            println!("Catch event! Rule hash: {} | Time: {}", pairs_vector.0, timestamp.format("%d-%m-%Y %H:%M:%S"));
                                            break;
                                        }
                                    } else 
                                    if let Some((_key, _value)) = pairs_vector.1.iter().find(|(k, v)| *v == ethernet_packet.get_destination().to_string() && k == "dst") {
                                        if let Some((_key, _value)) = pairs_vector.1.iter().find(|(k, v)| *v == " ".to_string() && k == "src") {
                                        
                                            let timestamp: DateTime<Local> = SystemTime::now().into();
                                            let cmd_string = "event".to_string() + "[:3:]" + &pairs_vector.0 + "[:3:]" + &timestamp.timestamp().to_string();
                                            let cmd_string_byte_fmt = cmd_string.as_bytes();
                                            match stream.write(cmd_string_byte_fmt) {
                                                Ok(_) => {},
                                                Err(_) => { println!("Troubles with connection. Stop working..."); return; }
                                            }
                                            println!("Catch event! Rule hash: {} | Time: {}", pairs_vector.0, timestamp.format("%d-%m-%Y %H:%M:%S"));
                                            break;
                                        }
                                    } 
                                }
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("Error receiving packet: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
        }
    }
}
