# socket-pktinfo

[![Build](https://github.com/pixsper/socket-pktinfo/actions/workflows/build.yml/badge.svg)](https://github.com/pixsper/socket-pktinfo/actions)
[![Cargo](https://img.shields.io/crates/v/socket-pktinfo.svg)](https://crates.io/crates/socket-pktinfo/)
[![docs.rs](https://img.shields.io/docsrs/socket-pktinfo)](https://docs.rs/socket-pktinfo/latest/socket-pktinfo/)
[![Rust version: 1.63+](https://img.shields.io/badge/rust%20version-1.63+-orange)](https://blog.rust-lang.org/2022/08/11/Rust-1.63.0.html)

Small library to allow cross-platform handling of IP_PKTINFO and IPV6_PKTINFO with socket2 crate. Primary use case for this crate is to determine if a UDP packet was sent to a unicast, broadcast or multicast IP address. Compatible with Windows, Linux and macOS.

## Example

```rust
use std::net::{Ipv4Addr, SocketAddrV4};
use socket2::{Domain, SockAddr};
use socket_pktinfo::PktInfoUdpSocket;

fn main() -> std::io::Result<()> {

    let mut buf = [0; 1024];
    let mut socket = PktInfoUdpSocket::new(Domain::IPV4)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8000).into())?;
        
    match socket.recv(&mut buf) {//!
         Ok((bytes_received, info)) => {
             println!("{} bytes received on interface index {} from src {} with destination ip {}",
              bytes_received, info.if_index, info.addr_src, info.addr_dst);
         }
         Err(e) => {
             eprintln!("Error receiving packet - {}", e);
         }
    }
     
    Ok(())
}
```