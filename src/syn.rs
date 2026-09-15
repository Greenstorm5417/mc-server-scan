//! Stateless TCP SYN scanner (Linux raw sockets) plus packet helpers.

use std::collections::HashSet;
use std::io::{self, ErrorKind};
use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use std::os::fd::AsRawFd;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::sync::mpsc;

use crate::ip::AddrSpace;

pub const DEFAULT_SRC_PORT: u16 = 41234;

#[derive(Clone, Copy)]
pub struct Target {
    pub ip: Ipv4Addr,
    pub port: u16,
}

/// Pause sending when the kernel still holds more than this many bytes.
const TX_SOFT_LIMIT: u32 = 24 * 1024;

pub fn open_send() -> io::Result<Socket> {
    let send = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(libc::IPPROTO_RAW)),
    )?;
    send.set_header_included_v4(true)?;
    send.set_nonblocking(true)?;
    force_sock_buf(
        send.as_raw_fd(),
        libc::SO_SNDBUFFORCE,
        libc::SO_SNDBUF,
        32 * 1024 * 1024,
    );
    Ok(send)
}

/// Capture SYN-ACKs. Prefers AF_PACKET so nftables/conntrack cannot hide them.
pub fn open_recv(src_ip: Ipv4Addr) -> io::Result<(Socket, &'static str)> {
    match open_packet_recv(src_ip) {
        Ok(sock) => Ok((sock, "af-packet")),
        Err(_) => Ok((open_raw_tcp_recv()?, "raw-tcp")),
    }
}

fn open_raw_tcp_recv() -> io::Result<Socket> {
    let recv = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
    recv.set_nonblocking(true)?;
    force_sock_buf(
        recv.as_raw_fd(),
        libc::SO_RCVBUFFORCE,
        libc::SO_RCVBUF,
        32 * 1024 * 1024,
    );
    Ok(recv)
}

fn open_packet_recv(src_ip: Ipv4Addr) -> io::Result<Socket> {
    let ifindex = ifindex_for_ip(src_ip)?;
    let proto = i32::from((libc::ETH_P_IP as u16).to_be());
    let recv = Socket::new(Domain::PACKET, Type::DGRAM, Some(Protocol::from(proto)))?;
    recv.set_nonblocking(true)?;
    force_sock_buf(
        recv.as_raw_fd(),
        libc::SO_RCVBUFFORCE,
        libc::SO_RCVBUF,
        32 * 1024 * 1024,
    );

    // SAFETY: we write a sockaddr_ll into zeroed storage and set len to its size.
    let (_, addr) = unsafe {
        SockAddr::try_init(|storage, len| {
            let ll = storage.cast::<libc::sockaddr_ll>();
            ll.write(libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as libc::sa_family_t,
                sll_protocol: (libc::ETH_P_IP as u16).to_be(),
                sll_ifindex: ifindex,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            });
            *len = libc::socklen_t::try_from(size_of::<libc::sockaddr_ll>()).unwrap_or(20);
            Ok(())
        })?
    };
    recv.bind(&addr)?;
    Ok(recv)
}

fn ifindex_for_ip(ip: Ipv4Addr) -> io::Result<i32> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a linked list into `head` on success.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    struct Free(*mut libc::ifaddrs);
    impl Drop for Free {
        fn drop(&mut self) {
            // SAFETY: `head` came from getifaddrs and is not used after free.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _free = Free(head);
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node in the getifaddrs list.
        let ifa = unsafe { &*cur };
        let addr = ifa.ifa_addr;
        if !addr.is_null() {
            // SAFETY: sockaddr.sa_family is always valid.
            let family = unsafe { (*addr).sa_family };
            if family == libc::AF_INET as libc::sa_family_t {
                // SAFETY: family is AF_INET, so this is sockaddr_in.
                let sin = unsafe { &*addr.cast::<libc::sockaddr_in>() };
                let found = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                if found == ip {
                    // SAFETY: ifa_name is a NUL-terminated interface name.
                    let idx = unsafe { libc::if_nametoindex(ifa.ifa_name) };
                    if idx == 0 {
                        return Err(io::Error::last_os_error());
                    }
                    return i32::try_from(idx)
                        .map_err(|_| io::Error::other("interface index does not fit i32"));
                }
            }
        }
        cur = ifa.ifa_next;
    }
    Err(io::Error::new(
        ErrorKind::NotFound,
        "no interface has the source IPv4",
    ))
}

fn force_sock_buf(fd: libc::c_int, force: libc::c_int, fallback: libc::c_int, bytes: libc::c_int) {
    let len = libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap_or(4);
    // SAFETY: `bytes` is a live c_int; setsockopt reads it as the option value.
    let rc =
        unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, force, (&raw const bytes).cast(), len) };
    if rc == 0 {
        return;
    }
    // SAFETY: same as above, ordinary SO_SNDBUF/SO_RCVBUF fallback.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            fallback,
            (&raw const bytes).cast(),
            len,
        );
    }
}

pub fn cookie(dst_ip: u32, dst_port: u16, secret: u32) -> u32 {
    let mut x = dst_ip ^ secret ^ (u32::from(dst_port) << 16);
    x = x.wrapping_mul(0x9E3779B1);
    x ^= x >> 16;
    x.wrapping_mul(0x85EBCA77)
}

pub fn write_syn(
    buf: &mut [u8; 40],
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ip_id: u16,
) {
    buf[0] = 0x45;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&40u16.to_be_bytes());
    buf[4..6].copy_from_slice(&ip_id.to_be_bytes());
    buf[6..8].copy_from_slice(&0u16.to_be_bytes());
    buf[8] = 64;
    buf[9] = 6;
    buf[10..12].copy_from_slice(&0u16.to_be_bytes());
    buf[12..16].copy_from_slice(&src_ip.to_be_bytes());
    buf[16..20].copy_from_slice(&dst_ip.to_be_bytes());
    buf[20..22].copy_from_slice(&src_port.to_be_bytes());
    buf[22..24].copy_from_slice(&dst_port.to_be_bytes());
    buf[24..28].copy_from_slice(&seq.to_be_bytes());
    buf[28..32].copy_from_slice(&0u32.to_be_bytes());
    buf[32] = 0x50;
    buf[33] = 0x02;
    buf[34..36].copy_from_slice(&65535u16.to_be_bytes());
    buf[36..38].copy_from_slice(&0u16.to_be_bytes());
    buf[38..40].copy_from_slice(&0u16.to_be_bytes());

    let ip_sum = internet_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let tcp_sum = tcp_checksum(src_ip, dst_ip, &buf[20..40]);
    buf[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
}

pub fn parse_syn_ack(pkt: &[u8], our_port: u16, secret: u32, ports: &[u16]) -> Option<Target> {
    if pkt.len() < 40 {
        return None;
    }
    if pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if ihl < 20 || pkt.len() < ihl + 20 {
        return None;
    }
    if pkt[9] != 6 {
        return None;
    }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff;
    if frag != 0 {
        return None;
    }
    let src_ip = u32::from_be_bytes(pkt[12..16].try_into().ok()?);
    let tcp = &pkt[ihl..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    if dst_port != our_port {
        return None;
    }
    if !ports.contains(&src_port) {
        return None;
    }
    let doff = usize::from(tcp[12] >> 4) * 4;
    if doff < 20 || tcp.len() < doff {
        return None;
    }
    let flags = tcp[13];
    if flags & 0x04 != 0 {
        return None;
    }
    if flags & 0x12 != 0x12 {
        return None;
    }
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    if ack != cookie(src_ip, src_port, secret).wrapping_add(1) {
        return None;
    }
    Some(Target {
        ip: Ipv4Addr::from(src_ip),
        port: src_port,
    })
}

fn checksum_add(mut data: &[u8]) -> u32 {
    let mut sum = 0u32;
    while data.len() >= 2 {
        sum += u16::from_be_bytes([data[0], data[1]]) as u32;
        data = &data[2..];
    }
    if let [b] = data {
        sum += u32::from(*b) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn internet_checksum(data: &[u8]) -> u16 {
    fold(checksum_add(data))
}

fn tcp_checksum(src: u32, dst: u32, tcp: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum += src >> 16;
    sum += src & 0xffff;
    sum += dst >> 16;
    sum += dst & 0xffff;
    sum += 6;
    sum += tcp.len() as u32;
    sum += checksum_add(tcp);
    fold(sum)
}

#[allow(clippy::too_many_arguments)]
pub fn send_loop(
    sock: Socket,
    space: AddrSpace,
    ports: Vec<u16>,
    src_ip: Ipv4Addr,
    src_port: u16,
    secret: u32,
    seed: u64,
    rate: f64,
    skip: u64,
    running: Arc<AtomicBool>,
    packets: Arc<AtomicU64>,
    send_ms: Arc<AtomicU64>,
    cursor: Arc<AtomicU64>,
) -> io::Result<()> {
    let src = u32::from(src_ip);
    let stride = space.stride(seed);
    let total = space.total;
    let ip_id = AtomicU16::new(1);
    let mut buf = [0u8; 40];
    let mut pacer = Pacer::new(rate);
    let started = Instant::now();
    let fd = sock.as_raw_fd();
    cursor.store(skip, Ordering::Relaxed);

    for n in skip..total {
        if !running.load(Ordering::Relaxed) {
            break;
        }
        let dst_ip = u32::from(space.ip_at_step(n, stride));
        for &dst_port in &ports {
            wait_tx_room(fd);
            let seq = cookie(dst_ip, dst_port, secret);
            let id = ip_id.fetch_add(1, Ordering::Relaxed);
            write_syn(&mut buf, src, dst_ip, src_port, dst_port, seq, id);
            let addr = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(dst_ip),
                dst_port,
            )));
            send_retry(&sock, &buf, &addr)?;
            packets.fetch_add(1, Ordering::Relaxed);
            pacer.wait();
        }
        cursor.store(n + 1, Ordering::Relaxed);
    }
    wait_tx_empty(fd);
    send_ms.store(
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    Ok(())
}

fn send_retry(sock: &Socket, buf: &[u8], addr: &SockAddr) -> io::Result<()> {
    loop {
        match sock.send_to(buf, addr) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_micros(200));
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e),
        }
    }
}

fn outq_bytes(fd: libc::c_int) -> u32 {
    let mut q: libc::c_int = 0;
    // SAFETY: TIOCOUTQ writes the socket send-queue size in bytes into `q`.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut q) };
    if rc < 0 {
        0
    } else {
        u32::try_from(q.max(0)).unwrap_or(0)
    }
}

fn wait_tx_room(fd: libc::c_int) {
    while outq_bytes(fd) > TX_SOFT_LIMIT {
        thread::sleep(Duration::from_micros(50));
    }
}

fn wait_tx_empty(fd: libc::c_int) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while outq_bytes(fd) > 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
}

#[allow(clippy::too_many_arguments)]
pub fn recv_loop(
    sock: Socket,
    src_port: u16,
    secret: u32,
    ports: Vec<u16>,
    running: Arc<AtomicBool>,
    sender_done: Arc<AtomicBool>,
    cooldown: Duration,
    open: Arc<AtomicU64>,
    tx: mpsc::Sender<Target>,
) -> io::Result<()> {
    let mut seen = HashSet::with_capacity(8192);
    let mut cooldown_until: Option<Instant> = None;
    let mut buf = [0u8; 512];
    let fd = sock.as_raw_fd();

    loop {
        if sender_done.load(Ordering::Relaxed) {
            if !running.load(Ordering::Relaxed) {
                break;
            }
            let until = *cooldown_until.get_or_insert_with(|| Instant::now() + cooldown);
            if Instant::now() >= until {
                break;
            }
        }

        let n = unsafe {
            // SAFETY: `buf` is a valid writable allocation; recv writes at most
            // buf.len() bytes and returns how many were initialized.
            libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0)
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted => {
                    thread::sleep(Duration::from_micros(200));
                    continue;
                }
                _ => return Err(e),
            }
        }
        let n = n as usize;
        let Some(tgt) = parse_syn_ack(&buf[..n], src_port, secret, &ports) else {
            continue;
        };
        let key = (u64::from(u32::from(tgt.ip)) << 16) | u64::from(tgt.port);
        if !seen.insert(key) {
            continue;
        }
        open.fetch_add(1, Ordering::Relaxed);
        if tx.try_send(tgt).is_err() {
            // channel full or closed: keep draining so the kernel rcvbuf
            // does not overflow; this hit is already counted in `open`.
        }
    }
    Ok(())
}

struct Pacer {
    start: Instant,
    sent: u64,
    rate: f64,
}

impl Pacer {
    fn new(rate: f64) -> Self {
        Self {
            start: Instant::now(),
            sent: 0,
            rate: rate.max(1.0),
        }
    }

    fn wait(&mut self) {
        self.sent += 1;
        let target = self.start + Duration::from_secs_f64(self.sent as f64 / self.rate);
        let now = Instant::now();
        if target <= now {
            return;
        }
        let d = target - now;
        if d > Duration::from_millis(1) {
            thread::sleep(d);
        } else {
            while Instant::now() < target {
                std::hint::spin_loop();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_verify() {
        let mut buf = [0u8; 40];
        write_syn(
            &mut buf,
            0xC0A8_0001,
            0x0808_0808,
            41234,
            25565,
            0x1111_2222,
            7,
        );
        assert_eq!(fold(checksum_add(&buf[..20])), 0);
        let src = 0xC0A8_0001;
        let dst = 0x0808_0808;
        let mut sum = 0u32;
        sum += src >> 16;
        sum += src & 0xffff;
        sum += dst >> 16;
        sum += dst & 0xffff;
        sum += 6;
        sum += 20;
        sum += checksum_add(&buf[20..40]);
        assert_eq!(fold(sum), 0);
    }

    #[test]
    fn cookie_roundtrip() {
        let ip = 0x0102_0304;
        let port = 25565;
        let secret = 0xAABB_CCDD;
        let mut buf = [0u8; 40];
        write_syn(
            &mut buf,
            0xC0A8_0001,
            ip,
            41234,
            port,
            cookie(ip, port, secret),
            1,
        );
        // synthesize a SYN-ACK: swap ports, set SYN+ACK, ack=seq+1
        let mut pkt = [0u8; 40];
        pkt[..20].copy_from_slice(&buf[..20]);
        pkt[12..16].copy_from_slice(&ip.to_be_bytes());
        pkt[16..20].copy_from_slice(&0xC0A8_0001u32.to_be_bytes());
        pkt[20..22].copy_from_slice(&port.to_be_bytes());
        pkt[22..24].copy_from_slice(&41234u16.to_be_bytes());
        pkt[24..28].copy_from_slice(&0u32.to_be_bytes());
        pkt[28..32].copy_from_slice(&cookie(ip, port, secret).wrapping_add(1).to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = 0x12;
        let hit = parse_syn_ack(&pkt, 41234, secret, &[25565]).unwrap();
        assert_eq!(hit.ip, Ipv4Addr::from(ip));
        assert_eq!(hit.port, 25565);
    }
}
