use std::io::{self, Read, Write};
use tokio::{io::AsyncReadExt, net::{TcpListener, TcpStream}};

pub fn get_sensor_list() {

}

pub fn change_sensor_state() {

}

pub fn update_sensor_rules() {
    
}

pub async fn handle_client(mut stream: TcpStream) -> io::Result<()> {
    let mut buffer = [0; 1024];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => return Ok(()),
            Ok(n) => {},
            Err(e) => return Err(e)
        }
    }
}