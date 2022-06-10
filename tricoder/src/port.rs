use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Port {
    port: u16,
    is_open: bool,
}

impl Port {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn is_open(&self) -> bool {
        self.is_open
    }

    pub fn scan(socket_address: SocketAddr) -> Self {
        let timeout = Duration::from_secs(3);
        let is_open = TcpStream::connect_timeout(&socket_address, timeout).is_ok();
        Self {
            port: socket_address.port(),
            is_open,
        }
    }
}
