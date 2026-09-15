//! High-rate IPv4 Minecraft server scanner.
//!
//! SYN-scans port 25565 (masscan-style) then Server-List-Pings hosts that
//! answer. Prints servers with at least one player. Needs CAP_NET_RAW (root)
//! to hit ~300k packets/s on a 250 Mbps link; otherwise falls back to TCP
//! connect scanning.
//!
//! Pass `--listen` for a browser UI (HTMX, no extra JS build).

#![warn(clippy::undocumented_unsafe_blocks)]

mod ip;
mod ping;
mod scan;
mod state;
mod syn;
mod web;

use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use scan::ScanConfig;
use syn::DEFAULT_SRC_PORT;

/// Scan IPv4 for populated Minecraft servers.
#[derive(Parser, Debug)]
#[command(
    name = "mc-scan",
    version,
    about = "Scan IPv4 for Minecraft servers with players online"
)]
struct Args {
    /// Serve the web UI instead of scanning immediately (e.g. 8080 or 0.0.0.0:8080)
    #[arg(long, num_args = 0..=1, default_missing_value = "0.0.0.0:8080")]
    listen: Option<String>,

    /// SYN packets per second (ignored if --mbps is set). Default 300000,
    /// automatically capped to 8000 on ranges smaller than 2M addresses.
    #[arg(short, long)]
    rate: Option<u64>,

    /// Cap send rate by megabits/sec of SYN packets (~84 bytes on the wire)
    #[arg(long)]
    mbps: Option<f64>,

    /// TCP port to scan (repeatable)
    #[arg(short, long = "port", default_values_t = [25565])]
    ports: Vec<u16>,

    /// CIDR or single IP to include. Repeatable. Default: 0.0.0.0/0 minus bogons
    #[arg(long = "range")]
    ranges: Vec<String>,

    /// Extra CIDR to skip (repeatable). IANA special-purpose/bogons are skipped unless --include-reserved
    #[arg(long = "exclude")]
    excludes: Vec<String>,

    /// File of CIDRs to skip (# comments allowed)
    #[arg(long = "exclude-file")]
    exclude_files: Vec<PathBuf>,

    /// Also scan private/bogon/IANA special-purpose ranges
    #[arg(long)]
    include_reserved: bool,

    /// Write/resume cursor in this file
    #[arg(long, default_value = "mc-scan.state")]
    state: PathBuf,

    /// Ignore and do not write a state file
    #[arg(long)]
    no_state: bool,

    /// Ignore an existing state file and start this job from the beginning
    #[arg(long)]
    fresh: bool,

    /// Source IPv4 for SYN packets
    #[arg(long)]
    source_ip: Option<Ipv4Addr>,

    /// Source TCP port encoded in SYNs
    #[arg(long, default_value_t = DEFAULT_SRC_PORT)]
    source_port: u16,

    /// Connect + SLP timeout
    #[arg(long, default_value_t = 1500)]
    timeout_ms: u64,

    /// Concurrent TCP-connect workers (TCP mode only)
    #[arg(long, default_value_t = 16_384)]
    connect: usize,

    /// Concurrent SLP pings after SYN-ACK hits
    #[arg(long, default_value_t = 1024)]
    ping: usize,

    /// Only print servers with at least this many players
    #[arg(long, default_value_t = 1)]
    min_players: i32,

    /// Shuffle seed (default: from the clock)
    #[arg(long)]
    seed: Option<u64>,

    /// Skip the first N shuffled addresses (overrides the state file)
    #[arg(long, default_value_t = 0)]
    skip: u64,

    /// Wait this long after the last SYN has left the NIC for late replies
    #[arg(long, default_value_t = 12_000)]
    cooldown_ms: u64,

    /// Force TCP connect scan (no raw sockets)
    #[arg(long)]
    tcp: bool,

    /// No progress on stderr
    #[arg(short, long)]
    quiet: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    raise_nofile();

    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .max(4);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .thread_name("mc-scan")
        .build()
        .context("tokio runtime")?;

    let cfg = config_from_args(&args);
    if let Some(bind) = args.listen {
        rt.block_on(web::serve(bind, cfg))
    } else {
        let live = scan::Live::new(cfg.quiet, true, None);
        let opts = scan::prepare(cfg)?;
        rt.block_on(scan::run(opts, live))
    }
}

fn config_from_args(args: &Args) -> ScanConfig {
    ScanConfig {
        rate: args.rate,
        mbps: args.mbps,
        ports: args.ports.clone(),
        ranges: args.ranges.clone(),
        excludes: args.excludes.clone(),
        exclude_files: args.exclude_files.clone(),
        include_reserved: args.include_reserved,
        state: args.state.clone(),
        no_state: args.no_state,
        fresh: args.fresh,
        source_ip: args.source_ip,
        source_port: args.source_port,
        timeout_ms: args.timeout_ms,
        connect: args.connect,
        ping: args.ping,
        min_players: args.min_players,
        seed: args.seed,
        skip: args.skip,
        cooldown_ms: args.cooldown_ms,
        tcp: args.tcp,
        quiet: args.quiet,
        hits_file: std::path::PathBuf::from(scan::DEFAULT_HITS_FILE),
    }
}

fn raise_nofile() {
    // SAFETY: getrlimit/setrlimit on this process with a fully initialized rlimit.
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return;
        }
        let want = 1_048_576;
        let mut new = libc::rlimit {
            rlim_cur: want.min(lim.rlim_max.max(want)),
            rlim_max: lim.rlim_max.max(want),
        };
        if libc::setrlimit(libc::RLIMIT_NOFILE, &new) != 0 {
            new.rlim_max = lim.rlim_max;
            new.rlim_cur = lim.rlim_max;
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &new);
        }
    }
}
