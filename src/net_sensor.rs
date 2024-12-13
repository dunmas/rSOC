use std::net::TcpStream;
use std::io::{Read, Write};

fn main() {
    match TcpStream::connect("127.0.0.1:7777") {
        Ok(mut stream) => {
            let message = b"Tester[:1:]net[:1:]admin";
            stream.write(message).unwrap();

            let mut buffer = [0; 1024];
            let size = stream.read(&mut buffer).unwrap();
            println!("Received from server: {}", String::from_utf8_lossy(&buffer[..size]));
        }
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
        }
    }
}