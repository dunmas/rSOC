use std::io::{self, Read, Write};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};
use tokio::sync::mpsc;
use crate::structs::soc_structs::SessionStatus;

pub fn get_sensor_list(session_status: &mut SessionStatus) {
    let sensors_map = session_status.sensor_list.lock().unwrap();
    println!("---------------------------------------------------------------------------------------------\n\
             || ----- IP address ----- || ----- Hostname ----- || ----- User ----- || ----- Status ----- ||\n\
             ---------------------------------------------------------------------------------------------");

    for (ip, info) in sensors_map.iter() {
        let status = if info.3 == true { "capturing" } else { "stopped" };
        let output_string = "|| ".to_string() + ip + " || " + &info.1 + " || " + &info.2 + " || " + status + " ||";
        print!("{}", output_string);
    }

    println!("---------------------------------------------------------------------------------------------");
}

pub fn change_sensor_state() {

}

pub fn update_sensor_rules() {
    
}

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