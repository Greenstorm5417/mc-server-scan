//! Shared scan job: CLI and the web UI both drive this.

use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{MissedTickBehavior, interval};

use crate::ip::{self, AddrSpace};
use crate::state;
use crate::syn::{self, DEFAULT_SRC_PORT, Target};

pub const DEFAULT_HITS_FILE: &str = "servers.txt";

#[derive(Clone, Debug)]
pub struct ScanConfig {
    pub rate: Option<u64>,
    pub mbps: Option<f64>,
    pub ports: Vec<u16>,
    pub ranges: Vec<String>,
    pub excludes: Vec<String>,
    pub exclude_files: Vec<PathBuf>,
    pub include_reserved: bool,
    pub state: PathBuf,
    pub no_state: bool,
    pub fresh: bool,
    pub source_ip: Option<Ipv4Addr>,
    pub source_port: u16,
    pub timeout_ms: u64,
    pub connect: usize,
    pub ping: usize,
    pub min_players: i32,
    pub seed: Option<u64>,
    pub skip: u64,
    pub cooldown_ms: u64,
    pub tcp: bool,
    pub quiet: bool,
    pub hits_file: PathBuf,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            rate: None,
            mbps: None,
            ports: vec![25565],
            ranges: Vec::new(),
            excludes: Vec::new(),
            exclude_files: Vec::new(),
            include_reserved: false,
            state: PathBuf::from("mc-scan.state"),
            no_state: false,
            fresh: false,
            source_ip: None,
            source_port: DEFAULT_SRC_PORT,
            timeout_ms: 1500,
            connect: 16_384,
            ping: 1024,
            min_players: 1,
            seed: None,
            skip: 0,
            cooldown_ms: 12_000,
            tcp: false,
            quiet: false,
            hits_file: PathBuf::from(DEFAULT_HITS_FILE),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub online: i32,
    pub max: i32,
    pub version: Option<String>,
    pub motd: Option<String>,
}

impl Hit {
    pub fn line(&self) -> String {
        let mut s = format!("{}:{}  players={}/{}", self.ip, self.port, self.online, self.max);
        if let Some(v) = &self.version {
            s.push_str("  ");
            s.push_str(v);
        }
        if let Some(m) = &self.motd {
            s.push_str("  ");
            s.push_str(m);
        }
        s
    }
}

pub struct Stats {
    pub packets: Arc<AtomicU64>,
    pub open: Arc<AtomicU64>,
    pub live: Arc<AtomicU64>,
    pub pinged: Arc<AtomicU64>,
    pub send_ms: Arc<AtomicU64>,
}

impl Stats {
    fn new() -> Self {
        Self {
            packets: Arc::new(AtomicU64::new(0)),
            open: Arc::new(AtomicU64::new(0)),
            live: Arc::new(AtomicU64::new(0)),
            pinged: Arc::new(AtomicU64::new(0)),
            send_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    fn clear(&self) {
        self.packets.store(0, Ordering::Relaxed);
        self.open.store(0, Ordering::Relaxed);
        self.live.store(0, Ordering::Relaxed);
        self.pinged.store(0, Ordering::Relaxed);
        self.send_ms.store(0, Ordering::Relaxed);
    }
}

struct LiveInner {
    progress: String,
    hits: Vec<Hit>,
    logs: Vec<String>,
    error: Option<String>,
    mode: String,
    phase: Phase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Running,
    Stopping,
    Done,
}

pub struct Live {
    inner: Mutex<LiveInner>,
    tty: bool,
    quiet: bool,
    print_hits: bool,
    hits_file: Option<PathBuf>,
    pub stats: Stats,
    pub running: Arc<AtomicBool>,
    pub cursor: Arc<AtomicU64>,
    pub total_pkts: AtomicU64,
    pub total_addrs: AtomicU64,
}

impl Live {
    pub fn new(quiet: bool, print_hits: bool, hits_file: Option<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(LiveInner {
                progress: String::new(),
                hits: Vec::new(),
                logs: Vec::new(),
                error: None,
                mode: String::new(),
                phase: Phase::Idle,
            }),
            tty: io::stderr().is_terminal(),
            quiet,
            print_hits,
            hits_file,
            stats: Stats::new(),
            running: Arc::new(AtomicBool::new(false)),
            cursor: Arc::new(AtomicU64::new(0)),
            total_pkts: AtomicU64::new(0),
            total_addrs: AtomicU64::new(0),
        })
    }

    pub fn reset_for_run(&self, total_pkts: u64, total_addrs: u64, skip: u64) {
        self.stats.clear();
        self.cursor.store(skip, Ordering::Relaxed);
        self.total_pkts.store(total_pkts, Ordering::Relaxed);
        self.total_addrs.store(total_addrs, Ordering::Relaxed);
        self.running.store(true, Ordering::Relaxed);
        let mut g = self.inner.lock().expect("live lock");
        g.progress.clear();
        g.hits.clear();
        g.logs.clear();
        g.error = None;
        g.phase = Phase::Running;
    }

    pub fn phase(&self) -> Phase {
        self.inner.lock().expect("live lock").phase
    }

    pub fn set_phase(&self, phase: Phase) {
        self.inner.lock().expect("live lock").phase = phase;
        if phase != Phase::Running {
            self.running.store(false, Ordering::Relaxed);
        }
    }

    pub fn set_mode(&self, mode: &str) {
        self.inner.lock().expect("live lock").mode = mode.to_string();
    }

    pub fn mode(&self) -> String {
        self.inner.lock().expect("live lock").mode.clone()
    }

    pub fn set_notice(&self, err: String) {
        self.inner.lock().expect("live lock").error = Some(err);
    }

    pub fn set_error(&self, err: String) {
        self.banner(&format!("error: {err}"));
        let mut g = self.inner.lock().expect("live lock");
        g.error = Some(err);
        g.phase = Phase::Done;
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn error(&self) -> Option<String> {
        self.inner.lock().expect("live lock").error.clone()
    }

    pub fn snapshot_hits(&self, max: usize) -> Vec<Hit> {
        let g = self.inner.lock().expect("live lock");
        let n = g.hits.len();
        if n <= max {
            g.hits.clone()
        } else {
            g.hits[n - max..].to_vec()
        }
    }

    pub fn all_hit_lines(&self) -> String {
        let g = self.inner.lock().expect("live lock");
        let mut out = String::new();
        for h in &g.hits {
            out.push_str(&h.line());
            out.push('\n');
        }
        out
    }

    pub fn hit_count(&self) -> usize {
        self.inner.lock().expect("live lock").hits.len()
    }

    pub fn snapshot_logs(&self, max: usize) -> Vec<String> {
        let g = self.inner.lock().expect("live lock");
        let n = g.logs.len();
        if n <= max {
            g.logs.clone()
        } else {
            g.logs[n - max..].to_vec()
        }
    }

    pub fn progress_line(&self) -> String {
        self.inner.lock().expect("live lock").progress.clone()
    }

    pub fn request_stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        let mut g = self.inner.lock().expect("live lock");
        if g.phase == Phase::Running {
            g.phase = Phase::Stopping;
        }
    }

    fn set_progress(&self, line: String) {
        if self.quiet {
            let mut g = self.inner.lock().expect("live lock");
            g.progress = line;
            return;
        }
        let mut g = self.inner.lock().expect("live lock");
        g.progress.clone_from(&line);
        if self.tty {
            eprint!("\r\x1b[K{line}");
            let _ = io::stderr().flush();
        } else {
            eprintln!("{line}");
        }
    }

    fn hit(&self, hit: Hit) {
        let line = hit.line();
        {
            let mut g = self.inner.lock().expect("live lock");
            // ponytail: 50k in-memory cap; servers.txt still gets every line
            if g.hits.len() < 50_000 {
                g.hits.push(hit);
            }
            if self.tty && !self.quiet {
                eprint!("\r\x1b[K");
                let _ = io::stderr().flush();
            }
            if self.print_hits {
                println!("{line}");
                let _ = io::stdout().flush();
            }
            if self.tty && !self.quiet && !g.progress.is_empty() {
                eprint!("{}", g.progress);
                let _ = io::stderr().flush();
            }
        }
        if let Some(path) = &self.hits_file
            && let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path)
        {
            let _ = writeln!(f, "{line}");
        }
    }

    pub fn banner(&self, line: &str) {
        {
            let mut g = self.inner.lock().expect("live lock");
            if g.logs.len() >= 200 {
                g.logs.drain(..50);
            }
            g.logs.push(line.to_string());
        }
        if !self.quiet {
            eprintln!("{line}");
        }
    }

    fn finish_tty(&self) {
        if self.tty && !self.quiet {
            eprintln!();
        }
    }
}

pub struct RunOpts {
    pub cfg: ScanConfig,
    pub space: AddrSpace,
    pub ports: Vec<u16>,
    pub rate: f64,
    pub seed: u64,
    pub skip: u64,
    pub fingerprint: u64,
    pub total_pkts: u64,
    pub eta_s: f64,
    pub throttled: bool,
    pub resumed: bool,
}

pub fn prepare(cfg: ScanConfig) -> Result<RunOpts> {
    let extra_excludes = load_extra_excludes(&cfg)?;
    let exclude_reserved = !cfg.include_reserved;
    let space = AddrSpace::from_cidrs(&cfg.ranges, &extra_excludes, exclude_reserved)
        .context("building address space")?;

    let ports = {
        let mut p = cfg.ports.clone();
        p.sort_unstable();
        p.dedup();
        if p.is_empty() {
            bail!("need at least one port");
        }
        if p.contains(&0) {
            bail!("port 0 is invalid");
        }
        p
    };

    let fingerprint = ip::job_fingerprint(
        &cfg.ranges,
        &extra_excludes,
        &ports,
        exclude_reserved,
        space.total,
    );

    let mut seed = cfg.seed.unwrap_or_else(fresh_seed);
    let mut skip = cfg.skip;
    let mut resumed = false;
    if !cfg.no_state && !cfg.fresh {
        match state::load(&cfg.state) {
            Ok(Some(ckpt)) if ckpt.fingerprint == fingerprint && ckpt.total == space.total => {
                if cfg.seed.is_some() && cfg.seed != Some(ckpt.seed) {
                    eprintln!(
                        "state {} has seed {} (this run --seed {:?}); starting fresh",
                        cfg.state.display(),
                        ckpt.seed,
                        cfg.seed
                    );
                } else {
                    seed = ckpt.seed;
                    if cfg.skip == 0 {
                        skip = ckpt.index.min(space.total);
                    }
                    resumed = skip > 0 && skip < space.total;
                    if skip >= space.total {
                        eprintln!(
                            "state {} already finished this job; starting over",
                            cfg.state.display()
                        );
                        skip = 0;
                        seed = cfg.seed.unwrap_or_else(fresh_seed);
                        resumed = false;
                        state::clear(&cfg.state);
                    }
                }
            }
            Ok(Some(_)) => {
                eprintln!(
                    "state {} is for a different range/port set; starting fresh",
                    cfg.state.display()
                );
            }
            Ok(None) => {}
            Err(e) => eprintln!("ignoring unreadable state {}: {e:#}", cfg.state.display()),
        }
    }
    if cfg.fresh {
        state::clear(&cfg.state);
    }
    if skip >= space.total {
        bail!("--skip {} is past the {} address space", skip, space.total);
    }

    let remaining = space.total.saturating_sub(skip);
    let total_pkts = remaining.saturating_mul(ports.len() as u64);

    let explicit_rate = cfg.rate.is_some() || cfg.mbps.is_some();
    let mut rate = match cfg.mbps {
        Some(mbps) if mbps > 0.0 => ((mbps * 1_000_000.0) / 8.0 / 84.0).max(1.0),
        _ => cfg.rate.unwrap_or(300_000).max(1) as f64,
    };
    let throttled = !explicit_rate && remaining > 0 && remaining < 2_000_000 && rate > 8_000.0;
    if throttled {
        rate = 8_000.0;
    }
    let eta_s = total_pkts as f64 / rate;

    Ok(RunOpts {
        cfg,
        space,
        ports,
        rate,
        seed,
        skip,
        fingerprint,
        total_pkts,
        eta_s,
        throttled,
        resumed,
    })
}

fn fresh_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xC0FFEE)
        ^ u64::from(std::process::id())
}

fn load_extra_excludes(cfg: &ScanConfig) -> Result<Vec<ip::Window>> {
    let mut extra = Vec::new();
    for c in &cfg.excludes {
        extra.push(ip::parse_cidr(c).with_context(|| format!("--exclude {c}"))?);
    }
    for path in &cfg.exclude_files {
        extra.extend(ip::parse_exclude_file(path)?);
    }
    Ok(ip::merge(extra))
}

pub async fn run(opts: RunOpts, live: Arc<Live>) -> Result<()> {
    let RunOpts {
        cfg,
        space,
        ports,
        rate,
        seed,
        skip,
        fingerprint,
        total_pkts,
        eta_s,
        throttled,
        resumed,
    } = opts;

    live.reset_for_run(total_pkts, space.total, skip);

    let send = if cfg.tcp {
        None
    } else {
        syn::open_send().ok()
    };
    let syn_mode = send.is_some();
    let mode = if syn_mode { "syn" } else { "tcp" };
    live.set_mode(mode);

    live.banner(&format!(
        "mc-scan  {mode}-mode  {:.0} pps  ports={ports:?}  addrs={}  packets={}  eta~{}",
        rate,
        space.total,
        total_pkts,
        fmt_eta(eta_s),
    ));
    if resumed {
        live.banner(&format!(
            "resuming at {}/{}  seed={seed}  state={}",
            skip,
            space.total,
            cfg.state.display()
        ));
    } else if !cfg.no_state {
        live.banner(&format!("state {}", cfg.state.display()));
    }
    if throttled {
        live.banner(
            "capped at 8000 pps for this range (faster floods get dropped); pass --rate to override",
        );
    }
    if syn_mode {
        live.banner(&format!(
            "printing servers with players >= {}",
            cfg.min_players
        ));
    } else {
        if !cfg.tcp {
            live.banner(&format!(
                "no CAP_NET_RAW; TCP connect mode (~{} concurrent). run as root for ~300k pps SYN scan",
                cfg.connect
            ));
        }
        live.banner(&format!(
            "printing servers with players >= {}",
            cfg.min_players
        ));
    }

    let timeout = Duration::from_millis(cfg.timeout_ms);
    let min_players = cfg.min_players;
    let ping_n = cfg.ping.max(1);

    let progress = {
        let live = live.clone();
        tokio::spawn(async move {
            progress_loop(live, total_pkts).await;
        })
    };

    let saver = if cfg.no_state {
        None
    } else {
        let path = cfg.state.clone();
        let live = live.clone();
        let total = space.total;
        Some(tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut last = u64::MAX;
            while live.running.load(Ordering::Relaxed) {
                tick.tick().await;
                let idx = live.cursor.load(Ordering::Relaxed);
                if idx == last {
                    continue;
                }
                last = idx;
                let _ = state::save(
                    &path,
                    &state::Checkpoint {
                        seed,
                        index: idx,
                        total,
                        fingerprint,
                    },
                );
            }
        }))
    };

    let result = if let Some(send) = send {
        syn_scan(
            &cfg,
            space.clone(),
            ports.clone(),
            rate,
            seed,
            skip,
            send,
            live.clone(),
            timeout,
            min_players,
            ping_n,
        )
        .await
    } else {
        tcp_scan(
            &cfg,
            space.clone(),
            ports,
            seed,
            skip,
            live.clone(),
            timeout,
            min_players,
        )
        .await
    };

    live.running.store(false, Ordering::Relaxed);
    if let Some(saver) = saver {
        saver.abort();
        let _ = saver.await;
    }

    let idx = live.cursor.load(Ordering::Relaxed);
    if !cfg.no_state {
        if idx >= space.total {
            state::clear(&cfg.state);
            live.banner(&format!("scan complete; cleared {}", cfg.state.display()));
        } else {
            let _ = state::save(
                &cfg.state,
                &state::Checkpoint {
                    seed,
                    index: idx,
                    total: space.total,
                    fingerprint,
                },
            );
            live.banner(&format!(
                "saved {} at {}/{}  rerun the same command to continue",
                cfg.state.display(),
                idx,
                space.total
            ));
        }
    }

    let _ = progress.await;
    live.finish_tty();

    let scanned = live.stats.packets.load(Ordering::Relaxed);
    let send_ms = live.stats.send_ms.load(Ordering::Relaxed);
    let send_pps = if send_ms > 0 {
        scanned as f64 / (send_ms as f64 / 1000.0)
    } else {
        0.0
    };
    live.banner(&format!(
        "done  scanned={}  send={}ms  {:.0}pps  open={}  pinged={}  populated={}",
        scanned,
        send_ms,
        send_pps,
        live.stats.open.load(Ordering::Relaxed),
        live.stats.pinged.load(Ordering::Relaxed),
        live.stats.live.load(Ordering::Relaxed),
    ));
    live.set_phase(Phase::Done);
    result
}

#[allow(clippy::too_many_arguments)]
async fn syn_scan(
    cfg: &ScanConfig,
    space: AddrSpace,
    ports: Vec<u16>,
    rate: f64,
    seed: u64,
    skip: u64,
    send: socket2::Socket,
    live: Arc<Live>,
    timeout: Duration,
    min_players: i32,
    ping_n: usize,
) -> Result<()> {
    let src_ip = match cfg.source_ip {
        Some(ip) => ip,
        None => ip::detect_source_ip().context("detect source IP (or pass --source-ip)")?,
    };
    let secret = seed as u32 ^ 0xA5A5_5A5A;
    let (recv, recv_path) = syn::open_recv(src_ip).context("opening receive socket")?;
    live.banner(&format!("recv={recv_path}  source={src_ip}"));
    let sender_done = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Target>(16_384);

    let ping_task = {
        let live = live.clone();
        tokio::spawn(async move {
            dispatch_pings(rx, live, timeout, min_players, ping_n, false).await;
        })
    };

    let send_thread = {
        let ports = ports.clone();
        let running = live.running.clone();
        let packets = live.stats.packets.clone();
        let send_ms = live.stats.send_ms.clone();
        let cursor = live.cursor.clone();
        let src_port = cfg.source_port;
        std::thread::Builder::new()
            .name("syn-tx".into())
            .spawn(move || {
                syn::send_loop(
                    send, space, ports, src_ip, src_port, secret, seed, rate, skip, running,
                    packets, send_ms, cursor,
                )
            })
            .context("spawn syn-tx")?
    };

    let recv_thread = {
        let running = live.running.clone();
        let sender_done = sender_done.clone();
        let open = live.stats.open.clone();
        let src_port = cfg.source_port;
        let cooldown = Duration::from_millis(cfg.cooldown_ms);
        std::thread::Builder::new()
            .name("syn-rx".into())
            .spawn(move || {
                syn::recv_loop(
                    recv,
                    src_port,
                    secret,
                    ports,
                    running,
                    sender_done,
                    cooldown,
                    open,
                    tx,
                )
            })
            .context("spawn syn-rx")?
    };

    let send_res = tokio::task::spawn_blocking(move || send_thread.join())
        .await
        .context("join syn-tx task")?
        .expect("syn-tx panicked");
    sender_done.store(true, Ordering::Relaxed);

    let recv_res = tokio::task::spawn_blocking(move || recv_thread.join())
        .await
        .context("join syn-rx task")?
        .expect("syn-rx panicked");
    recv_res.context("SYN recv loop")?;
    ping_task.await.context("ping dispatcher")?;
    send_res.context("SYN send loop")?;
    Ok(())
}

async fn dispatch_pings(
    mut rx: mpsc::Receiver<Target>,
    live: Arc<Live>,
    timeout: Duration,
    min_players: i32,
    ping_n: usize,
    bump_open: bool,
) {
    let sem = Arc::new(Semaphore::new(ping_n));
    let mut inflight = tokio::task::JoinSet::new();
    while let Some(tgt) = rx.recv().await {
        let Ok(permit) = sem.clone().acquire_owned().await else {
            break;
        };
        let live = live.clone();
        inflight.spawn(async move {
            let _permit = permit;
            ping_one(tgt, timeout, min_players, &live, bump_open).await;
        });
    }
    while inflight.join_next().await.is_some() {}
}

async fn ping_one(
    tgt: Target,
    timeout: Duration,
    min_players: i32,
    live: &Live,
    bump_open: bool,
) {
    live.stats.pinged.fetch_add(1, Ordering::Relaxed);
    let Some(st) = crate::ping::probe(tgt.ip, tgt.port, timeout).await else {
        return;
    };
    if bump_open {
        live.stats.open.fetch_add(1, Ordering::Relaxed);
    }
    if st.online >= min_players {
        live.stats.live.fetch_add(1, Ordering::Relaxed);
        live.hit(Hit {
            ip: tgt.ip,
            port: tgt.port,
            online: st.online,
            max: st.max,
            version: st.version,
            motd: st.motd,
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn tcp_scan(
    cfg: &ScanConfig,
    space: AddrSpace,
    ports: Vec<u16>,
    seed: u64,
    skip: u64,
    live: Arc<Live>,
    timeout: Duration,
    min_players: i32,
) -> Result<()> {
    let total = space.total;
    let stride = space.stride(seed);
    live.cursor.store(skip, Ordering::Relaxed);
    let workers = cfg.connect.max(1);
    let ports = Arc::new(ports);
    let space = Arc::new(space);

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..workers {
        let next = live.cursor.clone();
        let space = space.clone();
        let ports = ports.clone();
        let live = live.clone();
        set.spawn(async move {
            loop {
                if !live.running.load(Ordering::Relaxed) {
                    break;
                }
                let n = next.fetch_add(1, Ordering::Relaxed);
                if n >= total {
                    break;
                }
                let ip = space.ip_at_step(n, stride);
                for &port in ports.iter() {
                    live.stats.packets.fetch_add(1, Ordering::Relaxed);
                    let tgt = Target { ip, port };
                    ping_one(tgt, timeout, min_players, &live, true).await;
                }
            }
        });
    }
    while set.join_next().await.is_some() {}
    Ok(())
}

async fn progress_loop(live: Arc<Live>, total_pkts: u64) {
    let mut tick = interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tick.tick().await;
    let start = Instant::now();
    while live.running.load(Ordering::Relaxed) {
        tick.tick().await;
        let done = live.stats.packets.load(Ordering::Relaxed);
        let elapsed = start.elapsed().as_secs_f64().max(1e-6);
        let pps = done as f64 / elapsed;
        let pct = if total_pkts == 0 {
            100.0
        } else {
            (done as f64 / total_pkts as f64) * 100.0
        };
        let remain = total_pkts.saturating_sub(done) as f64;
        let eta = if pps > 1.0 {
            remain / pps
        } else {
            f64::INFINITY
        };
        live.set_progress(format!(
            "{done}  {pps:.0}pps  {pct:.3}%  open={}  pinged={}  live={}  eta~{}",
            live.stats.open.load(Ordering::Relaxed),
            live.stats.pinged.load(Ordering::Relaxed),
            live.stats.live.load(Ordering::Relaxed),
            fmt_eta(eta),
        ));
    }
}

fn fmt_eta(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "?".into();
    }
    let s = secs as u64;
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{}s", s / 60, s % 60)
    } else {
        format!("{:.1}h", secs / 3600.0)
    }
}

pub fn parse_ports(s: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in s.split(|c: char| c == ',' || c.is_whitespace()) {
        if part.is_empty() {
            continue;
        }
        let p: u16 = part.parse().with_context(|| format!("port {part}"))?;
        if p == 0 {
            bail!("port 0 is invalid");
        }
        ports.push(p);
    }
    if ports.is_empty() {
        bail!("need at least one port");
    }
    Ok(ports)
}

pub fn parse_lines(s: &str) -> Vec<String> {
    s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_csv() {
        assert_eq!(parse_ports("25565, 25566").unwrap(), vec![25565, 25566]);
    }

    #[test]
    fn parse_lines_skips_comments() {
        let v = parse_lines("192.168.1.0/24\n# no\n10.0.0.0/8\n");
        assert_eq!(v, vec!["192.168.1.0/24", "10.0.0.0/8"]);
    }
}
