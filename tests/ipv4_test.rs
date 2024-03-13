use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use socket_pktinfo::PktInfoUdpSocket;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn test_ipv4() -> io::Result<()> {
    let port = 8000;
    let if_addr = Ipv4Addr::LOCALHOST;
    let multicast_addr = Ipv4Addr::new(238, 10, 20, 31);
    let unicast_socket_addr: SockAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port).into();
    let multicast_socket_addr: SockAddr = SocketAddr::new(multicast_addr.into(), port).into();

    let mut buf = [0; 8972];
    let mut socket = PktInfoUdpSocket::new(Domain::IPV4)?;
    socket.set_reuse_address(true)?;
    socket.join_multicast_v4(&multicast_addr, &if_addr)?;
    socket.set_multicast_loopback(true)?;
    socket.bind(&unicast_socket_addr)?;

    {
        let output_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        let data = "Hello";
        output_socket.send_to(data.as_bytes(), &unicast_socket_addr)?;
    }

    let (_, info) = socket.recv(&mut buf)?;
    println!(
        "Unicast packet received on interface {} from {} with src {}",
        info.if_index, info.addr, info.spec_dst
    );

    {
        let output_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
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
