//! Usable IPv4 space, CIDR parsing, and a bijection used to shuffle scan order.

use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};

/// Inclusive IPv4 window. `end >= start`.
pub type Window = (u32, u32);

#[derive(Clone)]
pub struct AddrSpace {
    windows: Vec<Window>,
    prefix: Vec<u64>,
    pub total: u64,
}

impl AddrSpace {
    pub fn new(mut windows: Vec<Window>) -> Result<Self> {
        windows = merge(windows);
        windows.retain(|(a, b)| a <= b);
        if windows.is_empty() {
            bail!("address space is empty");
        }
        let mut prefix = Vec::with_capacity(windows.len());
        let mut acc = 0u64;
        for &(a, b) in &windows {
            prefix.push(acc);
            acc += u64::from(b) - u64::from(a) + 1;
        }
        Ok(Self {
            windows,
            prefix,
            total: acc,
        })
    }

    pub fn from_cidrs(
        cidrs: &[String],
        extra_excludes: &[Window],
        exclude_reserved: bool,
    ) -> Result<Self> {
        let mut includes = Vec::with_capacity(cidrs.len().max(1));
        if cidrs.is_empty() {
            includes.push((0, u32::MAX));
        } else {
            for c in cidrs {
                includes.push(parse_cidr(c)?);
            }
        }
        let mut excludes = extra_excludes.to_vec();
        if exclude_reserved {
            excludes.extend(reserved_ranges());
        }
        let windows = if excludes.is_empty() {
            merge(includes)
        } else {
            subtract(&merge(includes), &merge(excludes))
        };
        Self::new(windows).with_context(|| {
            if exclude_reserved {
                "address space is empty after subtracting reserved/bogon ranges; pass --include-reserved to scan them"
            } else {
                "address space is empty"
            }
        })
    }

    #[inline]
    pub fn nth(&self, n: u64) -> u32 {
        debug_assert!(n < self.total);
        let i = self.prefix.partition_point(|&p| p <= n).saturating_sub(1);
        let (start, _) = self.windows[i];
        start.wrapping_add((n - self.prefix[i]) as u32)
    }

    #[inline]
    pub fn ip_at_step(&self, n: u64, stride: u64) -> Ipv4Addr {
        Ipv4Addr::from(self.nth(permute_n(n, stride, self.total)))
    }

    pub fn stride(&self, seed: u64) -> u64 {
        pick_stride(self.total, seed)
    }
}

pub fn parse_cidr(s: &str) -> Result<Window> {
    let s = s.trim();
    if let Some((ip, pfx)) = s.split_once('/') {
        let ip: Ipv4Addr = ip.parse()?;
        let pfx: u32 = pfx.parse()?;
        if pfx > 32 {
            bail!("prefix {pfx} is invalid");
        }
        let ip = u32::from(ip);
        let mask = if pfx == 0 { 0 } else { u32::MAX << (32 - pfx) };
        let start = ip & mask;
        let end = start | !mask;
        Ok((start, end))
    } else {
        let ip = u32::from(s.parse::<Ipv4Addr>()?);
        Ok((ip, ip))
    }
}

pub fn reserved_ranges() -> Vec<Window> {
    merge(
        [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.31.196.0/24",
            "192.52.193.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "192.175.48.0/24",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
        ]
        .into_iter()
        .map(|c| parse_cidr(c).expect("static reserved CIDR"))
        .collect(),
    )
}

pub fn parse_exclude_file(path: &std::path::Path) -> Result<Vec<Window>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading exclude file {}", path.display()))?;
    parse_exclude_text(&text)
}

pub fn parse_exclude_text(text: &str) -> Result<Vec<Window>> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let line = line.split_whitespace().next().unwrap_or(line);
        out.push(parse_cidr(line).with_context(|| format!("exclude line {}: {line}", i + 1))?);
    }
    Ok(merge(out))
}

pub fn job_fingerprint(
    ranges: &[String],
    extra_excludes: &[Window],
    ports: &[u16],
    exclude_reserved: bool,
    total: u64,
) -> u64 {
    let mut h = 0xcbf2_9ac6_8422_9f47_u64;
    fn feed(h: &mut u64, bytes: &[u8]) {
        for &b in bytes {
            *h ^= u64::from(b);
            *h = h.wrapping_mul(0x1000_0000_01b3);
        }
    }
    feed(&mut h, &[u8::from(exclude_reserved)]);
    feed(&mut h, &total.to_le_bytes());
    let mut ranges: Vec<&[u8]> = ranges.iter().map(|r| r.as_bytes()).collect();
    ranges.sort_unstable();
    for r in ranges {
        feed(&mut h, r);
        feed(&mut h, &[0]);
    }
    for &(a, b) in extra_excludes {
        feed(&mut h, &a.to_le_bytes());
        feed(&mut h, &b.to_le_bytes());
    }
    for p in ports {
        feed(&mut h, &p.to_le_bytes());
    }
    h
}

pub fn merge(mut v: Vec<Window>) -> Vec<Window> {
    if v.is_empty() {
        return v;
    }
    v.sort_unstable();
    let mut out = Vec::with_capacity(v.len());
    let mut cur = v[0];
    for &(a, b) in &v[1..] {
        if u64::from(cur.1) + 1 >= u64::from(a) {
            cur.1 = cur.1.max(b);
        } else {
            out.push(cur);
            cur = (a, b);
        }
    }
    out.push(cur);
    out
}

pub fn subtract(includes: &[Window], excludes: &[Window]) -> Vec<Window> {
    let mut out = Vec::new();
    for &(a, b) in includes {
        subtract_one(a, b, excludes, &mut out);
    }
    out
}

fn subtract_one(a: u32, b: u32, excludes: &[Window], out: &mut Vec<Window>) {
    let mut cur = a;
    for &(x, y) in excludes {
        if y < cur || x > b {
            continue;
        }
        let lo = x.max(cur);
        if cur < lo {
            out.push((cur, lo - 1));
        }
        if y >= b {
            return;
        }
        cur = y.wrapping_add(1);
        if cur == 0 && y == u32::MAX {
            return;
        }
        if cur > b {
            return;
        }
    }
    if cur <= b {
        out.push((cur, b));
    }
}

#[inline]
pub fn permute_n(n: u64, stride: u64, total: u64) -> u64 {
    if total <= 1 {
        return 0;
    }
    let k = n + 1;
    ((k as u128 * u128::from(stride)) % u128::from(total)) as u64
}

pub fn pick_stride(total: u64, seed: u64) -> u64 {
    if total <= 1 {
        return 1;
    }
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15) % total;
    if s == 0 {
        s = 1;
    }
    while gcd(s, total) != 1 {
        s += 1;
        if s >= total {
            s = 1;
        }
    }
    s
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

pub fn detect_source_ip() -> std::io::Result<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.connect("1.1.1.1:80")?;
    match sock.local_addr()? {
        std::net::SocketAddr::V4(v) => Ok(*v.ip()),
        std::net::SocketAddr::V6(_) => Err(std::io::Error::other("default route is not IPv4")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_slash32() {
        assert_eq!(
            parse_cidr("1.2.3.4").unwrap(),
            parse_cidr("1.2.3.4/32").unwrap()
        );
    }

    #[test]
    fn cidr_slash8() {
        let (a, b) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(Ipv4Addr::from(a), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(Ipv4Addr::from(b), Ipv4Addr::new(10, 255, 255, 255));
    }

    #[test]
    fn default_space_skips_rfc1918_and_multicast() {
        let space = AddrSpace::from_cidrs(&[], &[], true).unwrap();
        assert_eq!(space.nth(0), u32::from(Ipv4Addr::new(1, 0, 0, 0)));
        let ten = u32::from(Ipv4Addr::new(10, 0, 0, 0));
        for i in [0, space.total / 2, space.total - 1] {
            let ip = space.nth(i);
            assert!(!(0x0A00_0000..=0x0AFF_FFFF).contains(&ip), "hit 10/8");
            assert!(ip < 0xE000_0000, "hit multicast/reserved");
            assert_ne!(ip, ten);
        }
        assert!(space.total > 3_000_000_000);
        assert!(space.total < 4_000_000_000);
        assert_eq!(
            Ipv4Addr::from(space.nth(space.total - 1)),
            Ipv4Addr::new(223, 255, 255, 255)
        );
    }

    #[test]
    fn permutor_visits_every_address_once() {
        let space = AddrSpace::new(vec![(10, 19)]).unwrap();
        let stride = space.stride(0xC0FFEE);
        let mut seen = [false; 10];
        for n in 0..space.total {
            let ip = space.nth(permute_n(n, stride, space.total));
            assert!((10..=19).contains(&ip));
            seen[(ip - 10) as usize] = true;
        }
        assert!(seen.iter().all(|&x| x));
    }

    #[test]
    fn subtract_middle() {
        let got = subtract(&[(0, 9)], &[(3, 5)]);
        assert_eq!(got, vec![(0, 2), (6, 9)]);
    }

    #[test]
    fn explicit_range_still_drops_rfc1918() {
        let space = AddrSpace::from_cidrs(&["8.0.0.0/6".into()], &[], true).unwrap();
        let ten = u32::from(Ipv4Addr::new(10, 0, 0, 0));
        let ten_end = u32::from(Ipv4Addr::new(10, 255, 255, 255));
        for i in [0, space.total / 2, space.total - 1] {
            let ip = space.nth(i);
            assert!(!(ten..=ten_end).contains(&ip), "hit 10/8 inside 8.0.0.0/6");
        }
        assert_eq!(space.total, (1u64 << 26) - (1u64 << 24));
    }

    #[test]
    fn private_range_needs_include_reserved() {
        let Err(err) = AddrSpace::from_cidrs(&["10.0.0.0/8".into()], &[], true) else {
            panic!("expected empty space");
        };
        assert!(err.to_string().contains("include-reserved"));
        let space = AddrSpace::from_cidrs(&["10.0.0.0/8".into()], &[], false).unwrap();
        assert_eq!(space.total, 1u64 << 24);
    }

    #[test]
    fn extra_excludes_punch_a_hole() {
        let space = AddrSpace::from_cidrs(
            &["10.0.0.0/8".into()],
            &[parse_cidr("10.1.0.0/16").unwrap()],
            false,
        )
        .unwrap();
        assert_eq!(space.total, (1u64 << 24) - (1u64 << 16));
        for i in [0, space.total / 2, space.total - 1] {
            let ip = space.nth(i);
            assert!(
                !(0x0A01_0000..=0x0A01_FFFF).contains(&ip),
                "hit excluded 10.1.0.0/16"
            );
        }
    }

    #[test]
    fn exclude_text_skips_comments() {
        let got = parse_exclude_text("# bogons\n10.0.0.0/8\n; skip\n127.0.0.1\n").unwrap();
        assert_eq!(got[0], parse_cidr("10.0.0.0/8").unwrap());
        assert_eq!(got[1], parse_cidr("127.0.0.1").unwrap());
    }
}
