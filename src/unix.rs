pub fn set_pktinfo(socket: RawSocket, payload: bool) -> io::Result<()> {
    unsafe { setsockopt(socket, IPPROTO_IP, IP_PKTINFO, payload as c_int) }
}
