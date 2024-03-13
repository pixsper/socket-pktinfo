use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::prelude::*;
use std::{io, mem, ptr};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use winapi::ctypes::{c_char, c_int};
use winapi::shared::minwindef::{DWORD, INT, LPDWORD};
use winapi::shared::ws2def::*;
use winapi::shared::ws2ipdef::*;
use winapi::um::mswsock::{LPFN_WSARECVMSG, WSAID_WSARECVMSG};
use winapi::um::winsock2 as winsock;
use winapi::um::winsock2::{LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE, SOCKET};

use crate::PktInfo;

const CMSG_HEADER_SIZE: usize = mem::size_of::<WSACMSGHDR>();
const PKTINFOV4_DATA_SIZE: usize = mem::size_of::<IN_PKTINFO>();
const PKTINFOV6_DATA_SIZE: usize = mem::size_of::<IN6_PKTINFO>();
const CONTROL_PKTINFOV4_BUFFER_SIZE: usize = CMSG_HEADER_SIZE + PKTINFOV4_DATA_SIZE;
const CONTROL_PKTINFOV6_BUFFER_SIZE: usize = CMSG_HEADER_SIZE + PKTINFOV6_DATA_SIZE + 8;

unsafe fn setsockopt<T>(socket: RawSocket, opt: c_int, val: c_int, payload: T) -> io::Result<()>
where
    T: Copy,
{
    let payload = &payload as *const T as *const c_char;
    if winsock::setsockopt(socket as _, opt, val, payload, mem::size_of::<T>() as c_int) == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(winsock::WSAGetLastError()))
    }
}

type WSARecvMsgExtension = unsafe extern "system" fn(
    s: SOCKET,
    lpMsg: LPWSAMSG,
    lpdwNumberOfBytesRecvd: LPDWORD,
    lpOverlapped: LPWSAOVERLAPPED,
    lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> INT;

fn locate_wsarecvmsg(socket: RawSocket) -> io::Result<WSARecvMsgExtension> {
    let mut fn_pointer: usize = 0;
    let mut byte_len: u32 = 0;

    let r = unsafe {
        winsock::WSAIoctl(
            socket as _,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &WSAID_WSARECVMSG as *const _ as *mut _,
            mem::size_of_val(&WSAID_WSARECVMSG) as DWORD,
            &mut fn_pointer as *const _ as *mut _,
            mem::size_of_val(&fn_pointer) as DWORD,
            &mut byte_len,
            ptr::null_mut(),
            None,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }

    if mem::size_of::<LPFN_WSARECVMSG>() != byte_len as _ {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Locating fn pointer to WSARecvMsg returned different expected bytes",
        ));
    }
    let cast_to_fn: LPFN_WSARECVMSG = unsafe { mem::transmute(fn_pointer) };

    match cast_to_fn {
        None => Err(io::Error::new(
            io::ErrorKind::Other,
            "WSARecvMsg extension not found",
        )),
        Some(extension) => Ok(extension),
    }
}

pub struct PktInfoUdpSocket {
    socket: Socket,
    domain: Domain,
    wsarecvmsg: WSARecvMsgExtension,
}

impl PktInfoUdpSocket {
    pub fn new(domain: Domain) -> io::Result<PktInfoUdpSocket> {
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

        match domain {
            Domain::IPV4 => unsafe {
                setsockopt(
                    socket.as_raw_socket(),
                    IPPROTO_IP,
                    IP_PKTINFO,
                    true as c_int,
                )?;
            },
            Domain::IPV6 => unsafe {
                setsockopt(
                    socket.as_raw_socket(),
                    IPPROTO_IPV6 as c_int,
                    IPV6_PKTINFO,
                    true as c_int,
                )?;
            },
            _ => return Err(Error::from(ErrorKind::Unsupported)),
        }

        let wsarecvmsg: WSARecvMsgExtension = locate_wsarecvmsg(socket.as_raw_socket())?;

        Ok(PktInfoUdpSocket {
            socket,
            domain,
            wsarecvmsg,
        })
    }

    pub fn domain(&self) -> Domain {
        self.domain
    }
    pub fn set_reuse_address(&mut self, reuse: bool) -> io::Result<()> {
        self.socket.set_reuse_address(reuse)
    }

    pub fn join_multicast_v4(&mut self, addr: &Ipv4Addr, interface: &Ipv4Addr) -> io::Result<()> {
        self.socket.join_multicast_v4(addr, interface)
    }

    pub fn set_multicast_if_v4(&mut self, interface: &Ipv4Addr) -> io::Result<()> {
        self.socket.set_multicast_if_v4(interface)
    }

    pub fn set_multicast_loop_v4(&mut self, loop_v4: bool) -> io::Result<()> {
        self.socket.set_multicast_loop_v4(loop_v4)
    }

    pub fn join_multicast_v6(&mut self, addr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        self.socket.join_multicast_v6(addr, interface)
    }

    pub fn set_multicast_if_v6(&mut self, interface: u32) -> io::Result<()> {
        self.socket.set_multicast_if_v6(interface)
    }

    pub fn set_multicast_loop_v6(&mut self, loop_v6: bool) -> io::Result<()> {
        self.socket.set_multicast_loop_v6(loop_v6)
    }

    pub fn set_nonblocking(&mut self, reuse: bool) -> io::Result<()> {
        self.socket.set_nonblocking(reuse)
    }

    pub fn bind(&mut self, addr: &SockAddr) -> io::Result<()> {
        self.socket.bind(addr)
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, PktInfo)> {
        let mut data = WSABUF {
            buf: buf.as_mut_ptr() as *mut i8,
            len: buf.len() as u32,
        };

        let mut control_buffer = [0; CONTROL_PKTINFOV6_BUFFER_SIZE]; // Allocate the largest possible buffer
        let control = WSABUF {
            buf: control_buffer.as_mut_ptr(),
            len: match self.domain {
                Domain::IPV4 => CONTROL_PKTINFOV4_BUFFER_SIZE as u32,
                Domain::IPV6 => CONTROL_PKTINFOV6_BUFFER_SIZE as u32,
                _ => unreachable!(),
            },
        };

        let mut addr: SOCKADDR_STORAGE = unsafe { mem::zeroed() };
        let mut wsa_msg = WSAMSG {
            name: &mut addr as *mut SOCKADDR_STORAGE as *mut SOCKADDR,
            namelen: mem::size_of_val(&addr) as i32,
            lpBuffers: &mut data,
            Control: control,
            dwBufferCount: 1,
            dwFlags: 0,
        };

        let mut read_bytes = 0;
        let error_code = {
            unsafe {
                (self.wsarecvmsg)(
                    self.socket.as_raw_socket() as _,
                    &mut wsa_msg,
                    &mut read_bytes,
                    ptr::null_mut(),
                    None,
                )
            }
        };

        if error_code != 0 {
            return Err(io::Error::last_os_error());
        }

        let addr_src = unsafe { SockAddr::new(addr, mem::size_of_val(&addr) as i32) }
            .as_socket()
            .unwrap();

        let mut info: Option<PktInfo> = None;

        if control.len as usize == CONTROL_PKTINFOV4_BUFFER_SIZE {
            let cmsg_header: WSACMSGHDR = unsafe { ptr::read_unaligned(control.buf as *const _) };
            if cmsg_header.cmsg_level == IPPROTO_IP && cmsg_header.cmsg_type == IP_PKTINFO {
                let interface_info: IN_PKTINFO =
                    unsafe { ptr::read_unaligned(control.buf.add(CMSG_HEADER_SIZE) as *const _) };

                let addr_dst_bytes = unsafe { interface_info.ipi_addr.S_un.S_un_b() };
                let addr_dst = IpAddr::V4(Ipv4Addr::from([
                    addr_dst_bytes.s_b1,
                    addr_dst_bytes.s_b2,
                    addr_dst_bytes.s_b3,
                    addr_dst_bytes.s_b4,
                ]));

                info = Some(PktInfo {
                    if_index: interface_info.ipi_ifindex as u64,
                    addr_src,
                    addr_dst,
                })
            }
        } else if control.len as usize == CONTROL_PKTINFOV6_BUFFER_SIZE {
            let cmsg_header: WSACMSGHDR = unsafe { ptr::read_unaligned(control.buf as *const _) };
            if cmsg_header.cmsg_level as u32 == IPPROTO_IPV6
                && cmsg_header.cmsg_type == IPV6_PKTINFO
            {
                let interface_info: IN6_PKTINFO =
                    unsafe { ptr::read_unaligned(control.buf.add(CMSG_HEADER_SIZE) as *const _) };

                let addr_dst_bytes = unsafe { interface_info.ipi6_addr.u.Byte() };
                let addr_dst = IpAddr::V6(Ipv6Addr::from(addr_dst_bytes.clone()));
                info = Some(PktInfo {
                    if_index: interface_info.ipi6_ifindex as u64,
                    addr_src,
                    addr_dst,
                })
            }
        }

        match info {
            None => Err(Error::new(
                ErrorKind::NotFound,
                "Failed to read PKTINFO from socket",
            )),
            Some(info) => Ok((read_bytes as usize, info)),
        }
    }
}
