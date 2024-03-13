#[cfg(windows)]
mod win;
#[cfg(windows)]
pub use win::*;

#[cfg(not(windows))]
mod unix;
#[cfg(not(windows))]
pub use unix::*;

/// Information about an incoming packet
///
#[derive(Debug, Clone)]
pub struct PktInfo {
    /// Interface index
    pub if_index: u64,
    /// Local address
    pub spec_dst: std::net::IpAddr,
    /// Header destination address
    pub addr: std::net::IpAddr,
}
