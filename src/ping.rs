//! Minecraft Server List Ping (1.7+) with early-abort JSON scraping.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const MAX_STATUS: usize = 256 * 1024;
const PROTOCOL_VERSION: i32 = -1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub online: i32,
    pub max: i32,
    pub version: Option<String>,
    pub motd: Option<String>,
}

pub async fn probe(ip: Ipv4Addr, port: u16, limit: Duration) -> Option<Status> {
    timeout(limit, probe_inner(ip, port)).await.ok().flatten()
}

async fn probe_inner(ip: Ipv4Addr, port: u16) -> Option<Status> {
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let stream = TcpStream::connect(addr).await.ok()?;
    let mut stream = tune(stream).ok()?;

    let mut req = [0u8; 64];
    let n = encode_handshake_and_status(&mut req, ip, port);
    stream.write_all(&req[..n]).await.ok()?;

    let mut buf = Vec::with_capacity(2048);
    loop {
        let mut chunk = [0u8; 2048];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return extract_status(&buf, true);
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(st) = extract_status(&buf, false) {
            return Some(st);
        }
        if buf.len() >= MAX_STATUS {
            return extract_status(&buf, true);
        }
    }
}

fn tune(stream: TcpStream) -> io::Result<TcpStream> {
    stream.set_nodelay(true)?;
    let std = stream.into_std()?;
    let sock = socket2::Socket::from(std);
    let _ = sock.set_linger(Some(Duration::ZERO));
    sock.set_nonblocking(true)?;
    TcpStream::from_std(sock.into())
}

fn encode_handshake_and_status(out: &mut [u8], ip: Ipv4Addr, port: u16) -> usize {
    let mut payload = [0u8; 48];
    let mut p = 0;
    p += write_varint(&mut payload[p..], PROTOCOL_VERSION);
    let mut addr = [0u8; 15];
    let addr_len = fmt_ipv4(ip, &mut addr);
    p += write_varint(&mut payload[p..], addr_len as i32);
    payload[p..p + addr_len].copy_from_slice(&addr[..addr_len]);
    p += addr_len;
    payload[p..p + 2].copy_from_slice(&port.to_be_bytes());
    p += 2;
    p += write_varint(&mut payload[p..], 1);

    let mut n = 0;
    n += write_packet(&mut out[n..], 0, &payload[..p]);
    n += write_packet(&mut out[n..], 0, &[]);
    n
}

fn fmt_ipv4(ip: Ipv4Addr, buf: &mut [u8; 15]) -> usize {
    let o = ip.octets();
    let mut n = 0;
    for (i, oct) in o.iter().enumerate() {
        if i > 0 {
            buf[n] = b'.';
            n += 1;
        }
        n += itoa_u8(*oct, &mut buf[n..]);
    }
    n
}

fn itoa_u8(v: u8, out: &mut [u8]) -> usize {
    if v >= 100 {
        out[0] = b'0' + v / 100;
        out[1] = b'0' + (v / 10) % 10;
        out[2] = b'0' + v % 10;
        3
    } else if v >= 10 {
        out[0] = b'0' + v / 10;
        out[1] = b'0' + v % 10;
        2
    } else {
        out[0] = b'0' + v;
        1
    }
}

fn write_packet(out: &mut [u8], id: i32, payload: &[u8]) -> usize {
    let mut idb = [0u8; 5];
    let idn = write_varint(&mut idb, id);
    let len = (idn + payload.len()) as i32;
    let mut n = write_varint(out, len);
    out[n..n + idn].copy_from_slice(&idb[..idn]);
    n += idn;
    out[n..n + payload.len()].copy_from_slice(payload);
    n + payload.len()
}

fn write_varint(out: &mut [u8], val: i32) -> usize {
    let mut u = val as u32;
    let mut n = 0;
    loop {
        let mut b = (u & 0x7f) as u8;
        u >>= 7;
        if u != 0 {
            b |= 0x80;
        }
        out[n] = b;
        n += 1;
        if u == 0 {
            return n;
        }
    }
}

pub fn extract_status(buf: &[u8], eof: bool) -> Option<Status> {
    let json_at = buf.iter().position(|&b| b == b'{')?;
    let json = &buf[json_at..];
    let players_at = find(json, b"\"players\"")?;
    let players = &json[players_at..];
    let online = json_i64_after_key(players, b"\"online\"", eof)? as i32;
    let max = json_i64_after_key(players, b"\"max\"", true).unwrap_or(0) as i32;
    let version = extract_version(json);
    let motd = extract_motd(json);
    Some(Status {
        online,
        max,
        version,
        motd,
    })
}

fn extract_version(json: &[u8]) -> Option<String> {
    let at = find(json, b"\"version\"")?;
    json_quoted_after_key(&json[at..], b"\"name\"", true)
}

fn extract_motd(json: &[u8]) -> Option<String> {
    let at = find(json, b"\"description\"")?;
    let rest = skip_ws(&json[at + b"\"description\"".len()..]);
    let rest = skip_char(rest, b':')?;
    let rest = skip_ws(rest);
    let raw = if rest.first() == Some(&b'"') {
        json_quoted(rest, true)?
    } else if rest.first() == Some(&b'{') {
        json_quoted_after_key(rest, b"\"text\"", true).unwrap_or_default()
    } else {
        return None;
    };
    let cleaned = strip_section(&raw);
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        None
    } else {
        Some(truncate(cleaned, 80))
    }
}

fn json_i64_after_key(hay: &[u8], key: &[u8], eof: bool) -> Option<i64> {
    let at = find(hay, key)?;
    let rest = skip_ws(&hay[at + key.len()..]);
    let rest = skip_char(rest, b':')?;
    let rest = skip_ws(rest);
    parse_i64(rest, eof)
}

fn json_quoted_after_key(hay: &[u8], key: &[u8], eof: bool) -> Option<String> {
    let at = find(hay, key)?;
    let rest = skip_ws(&hay[at + key.len()..]);
    let rest = skip_char(rest, b':')?;
    let rest = skip_ws(rest);
    json_quoted(rest, eof)
}

fn json_quoted(s: &[u8], eof: bool) -> Option<String> {
    if s.first() != Some(&b'"') {
        return None;
    }
    let mut out = String::new();
    let mut i = 1;
    while i < s.len() {
        match s[i] {
            b'"' => return Some(out),
            b'\\' if i + 1 < s.len() => {
                match s[i + 1] {
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    c => out.push(c as char),
                }
                i += 2;
            }
            b'\\' if !eof => return None,
            c => {
                // UTF-8: take this byte as-is via from_utf8 on a slice later is hard;
                // push char if ASCII, otherwise gather UTF-8 sequence.
                if c < 0x80 {
                    out.push(c as char);
                    i += 1;
                } else {
                    let w = utf8_width(c);
                    if i + w > s.len() {
                        return if eof { Some(out) } else { None };
                    }
                    if let Ok(ch) = std::str::from_utf8(&s[i..i + w]) {
                        out.push_str(ch);
                    }
                    i += w;
                }
            }
        }
    }
    if eof { Some(out) } else { None }
}

fn utf8_width(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b < 0xe0 {
        2
    } else if b < 0xf0 {
        3
    } else {
        4
    }
}

fn parse_i64(s: &[u8], eof: bool) -> Option<i64> {
    let mut i = 0;
    let neg = if s.first() == Some(&b'-') {
        i = 1;
        true
    } else {
        false
    };
    let start = i;
    while i < s.len() && s[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return None;
    }
    if i == s.len() && !eof {
        return None;
    }
    if i < s.len() && s[i] == b'.' {
        return None;
    }
    let n = std::str::from_utf8(&s[start..i])
        .ok()?
        .parse::<i64>()
        .ok()?;
    Some(if neg { -n } else { n })
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn skip_ws(s: &[u8]) -> &[u8] {
    let n = s
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(s.len());
    &s[n..]
}

fn skip_char(s: &[u8], c: u8) -> Option<&[u8]> {
    if s.first() == Some(&c) {
        Some(&s[1..])
    } else {
        None
    }
}

fn strip_section(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '§' {
            let _ = chars.next();
            continue;
        }
        if c == '\n' || c == '\r' {
            out.push(' ');
            continue;
        }
        out.push(c);
    }
    out
}

fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((i, _)) => s[..i].to_string(),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn extracts_online_before_favicon() {
        let json = br#"{"version":{"name":"1.21.1","protocol":767},"players":{"max":20,"online":7},"description":{"text":"Hello"},"favicon":"data:image/png;base64,AAAA"}"#;
        let st = extract_status(json, true).unwrap();
        assert_eq!(st.online, 7);
        assert_eq!(st.max, 20);
        assert_eq!(st.version.as_deref(), Some("1.21.1"));
        assert_eq!(st.motd.as_deref(), Some("Hello"));
    }

    #[test]
    fn ignores_online_mode_key() {
        let json = br#"{"enforcesSecureChat":true,"players":{"online":2,"max":8}}"#;
        let st = extract_status(json, true).unwrap();
        assert_eq!(st.online, 2);
    }

    #[test]
    fn incomplete_number_waits() {
        let json = br#"{"players":{"online":1"#;
        assert!(extract_status(json, false).is_none());
        let json = br#"{"players":{"online":12}"#;
        assert_eq!(extract_status(json, false).unwrap().online, 12);
    }

    #[test]
    fn fmt_ipv4_fits_dotted_quad() {
        let mut buf = [0u8; 15];
        let n = fmt_ipv4(Ipv4Addr::new(255, 255, 255, 255), &mut buf);
        assert_eq!(&buf[..n], b"255.255.255.255");
        let n = fmt_ipv4(Ipv4Addr::new(1, 2, 3, 4), &mut buf);
        assert_eq!(&buf[..n], b"1.2.3.4");
        let mut pkt = [0u8; 64];
        let n = encode_handshake_and_status(&mut pkt, Ipv4Addr::new(255, 255, 255, 255), 25565);
        assert!(n > 0 && n <= 64);
    }

    #[test]
    fn varint_minus_one() {
        let mut b = [0u8; 8];
        let n = write_varint(&mut b, -1);
        assert_eq!(&b[..n], &[0xff, 0xff, 0xff, 0xff, 0x0f]);
    }

    #[tokio::test]
    async fn slp_against_mock_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let json = r#"{"version":{"name":"1.20.4","protocol":765},"players":{"max":50,"online":4},"description":"mock"}"#;
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut tmp = [0u8; 256];
            let _ = sock.read(&mut tmp).await;
            let mut pkt = Vec::new();
            let mut inner = Vec::new();
            write_varint_vec(&mut inner, 0);
            write_varint_vec(&mut inner, json.len() as i32);
            inner.extend_from_slice(json.as_bytes());
            write_varint_vec(&mut pkt, inner.len() as i32);
            pkt.extend_from_slice(&inner);
            sock.write_all(&pkt).await.unwrap();
        });

        let ip = match addr.ip() {
            std::net::IpAddr::V4(v) => v,
            std::net::IpAddr::V6(_) => panic!("v4"),
        };
        let st = probe(ip, addr.port(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(st.online, 4);
        assert_eq!(st.max, 50);
        assert_eq!(st.version.as_deref(), Some("1.20.4"));
    }

    fn write_varint_vec(out: &mut Vec<u8>, val: i32) {
        let mut buf = [0u8; 5];
        let n = write_varint(&mut buf, val);
        out.extend_from_slice(&buf[..n]);
    }
}
