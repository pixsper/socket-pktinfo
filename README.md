# socket-pktinfo

[![Build](https://github.com/pixsper/socket-pktinfo/actions/workflows/build.yml/badge.svg)](https://github.com/pixsper/socket-pktinfo/actions)
[![Cargo](https://img.shields.io/crates/v/socket-pktinfo.svg)](https://crates.io/crates/socket-pktinfo/)
[![docs.rs](https://img.shields.io/docsrs/socket-pktinfo)](https://docs.rs/mdns-sd/latest/socket-pktinfo/)

Small library to allow cross-platform handling of IP_PKTINFO and IPV6_PKTINFO with socket2 crate. Primary use case for this crate is to determine if a UDP packet was sent to a unicast, broadcast or multicast IP address. Compatible with Windows, Linux and macOS.

