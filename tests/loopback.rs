use socket2::Domain;
use socket_pktinfo::PktInfoUdpSocket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

fn check_loopback(domain: Domain, ip: IpAddr) {
    let receiver = PktInfoUdpSocket::new(domain).unwrap();
    receiver.bind(&SocketAddr::new(ip, 0).into()).unwrap();
    let shared = receiver.try_clone_std().unwrap();
    shared
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let sender = UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
    sender
        .send_to(b"pktinfo", shared.local_addr().unwrap())
        .unwrap();
    let mut data = [0; 32];
    let (length, info) = receiver.recv(&mut data).unwrap();
    assert_eq!(&data[..length], b"pktinfo");
    assert_eq!(info.addr_src, sender.local_addr().unwrap());
    assert_eq!(info.addr_dst, ip);
    assert_ne!(info.if_index, 0);
}

#[test]
fn ipv4_loopback_packet_info() {
    check_loopback(Domain::IPV4, Ipv4Addr::LOCALHOST.into());
}

#[test]
fn ipv6_loopback_packet_info() {
    check_loopback(Domain::IPV6, Ipv6Addr::LOCALHOST.into());
}
