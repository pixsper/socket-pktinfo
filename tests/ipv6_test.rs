use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use socket_pktinfo::PktInfoUdpSocket;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

#[test]
fn test_ipv6() -> io::Result<()> {
    let port = 8000;
    let multicast_addr = Ipv6Addr::from_str("ff1e::1").unwrap();
    let unicast_socket_addr: SockAddr =
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port).into();
    let multicast_socket_addr: SockAddr = SocketAddr::new(multicast_addr.into(), port).into();

    let mut buf = [0; 8972];
    let mut socket = PktInfoUdpSocket::new(Domain::IPV6)?;
    socket.set_reuse_address(true)?;
    socket.join_multicast_v6(&multicast_addr, 1)?;
    socket.set_multicast_loopback(true)?;
    socket.bind(&unicast_socket_addr)?;

    {
        let output_socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        let data = "Hello";
        output_socket.send_to(data.as_bytes(), &unicast_socket_addr)?;
    }

    let (_, info) = socket.recv(&mut buf)?;
    println!(
        "Unicast packet received on interface {} from {} with src {}",
        info.if_index, info.addr, info.spec_dst
    );

    {
        let output_socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        let data = "Hello";
        output_socket.send_to(data.as_bytes(), &multicast_socket_addr)?;
    }

    let (_, info) = socket.recv(&mut buf)?;
    println!(
        "Multicast packet received on interface {} from {} with src {}",
        info.if_index, info.addr, info.spec_dst
    );

    Ok(())
}
