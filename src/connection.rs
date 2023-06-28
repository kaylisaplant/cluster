use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

pub fn cread(addr: & str, port: i32) -> std::io::Result<String> {
    let listener = TcpListener::bind(format!("{}:{}", addr, port))?;
    let (mut stream, _) = listener.accept()?;

    let mut buf = [0; 1024];
    let mut message = String::new();

    loop {
        let bytes_read = stream.read(&mut buf)?;
        let s = std::str::from_utf8(&buf[..bytes_read]).unwrap();
        message.push_str(s);

        if bytes_read < buf.len() {
            break;
        }
    }

    Ok(message)
}

pub fn cwrite(addr: & str, port: i32, msg: & str) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(format!("{}:{}", addr, port))?;

    stream.write_all(msg.as_bytes())?;

    return Ok(())
}