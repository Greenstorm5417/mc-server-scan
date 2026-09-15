//! Tiny HTTP/1.1 server + HTMX UI. No extra crates; polling, not SSE.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::scan::{self, Live, Phase, ScanConfig, parse_lines, parse_ports};

struct App {
    live: Arc<Live>,
    defaults: ScanConfig,
    job: Mutex<Option<JoinHandle<()>>>,
    form: Mutex<FormState>,
}

#[derive(Clone)]
struct FormState {
    ranges: String,
    excludes: String,
    ports: String,
    min_players: String,
    rate: String,
    timeout_ms: String,
    connect: String,
    ping: String,
    include_reserved: bool,
    tcp: bool,
    fresh: bool,
}

impl FormState {
    fn from_cfg(cfg: &ScanConfig) -> Self {
        Self {
            ranges: cfg.ranges.join("\n"),
            excludes: cfg.excludes.join("\n"),
            ports: cfg
                .ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            min_players: cfg.min_players.to_string(),
            rate: cfg.rate.map(|r| r.to_string()).unwrap_or_default(),
            timeout_ms: cfg.timeout_ms.to_string(),
            connect: cfg.connect.to_string(),
            ping: cfg.ping.to_string(),
            include_reserved: cfg.include_reserved,
            tcp: cfg.tcp,
            fresh: cfg.fresh,
        }
    }
}

pub async fn serve(bind: String, defaults: ScanConfig) -> Result<()> {
    let addr = parse_bind(&bind).with_context(|| format!("listen address {bind}"))?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    let bound = listener.local_addr().unwrap_or(addr);
    eprintln!("mc-scan ui  http://{bound}");
    eprintln!("open that URL, name a CIDR, hit Scan. Ctrl-C stops the server.");

    let live = Live::new(true, true, Some(defaults.hits_file.clone()));
    let app = Arc::new(App {
        form: Mutex::new(FormState::from_cfg(&defaults)),
        live,
        defaults,
        job: Mutex::new(None),
    });

    loop {
        let (stream, _) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, app).await {
                eprintln!("http: {e}");
            }
        });
    }
}

fn parse_bind(s: &str) -> Result<SocketAddr> {
    let s = s.trim();
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(port) = s.parse::<u16>() {
        return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
    }
    if let Some(rest) = s.strip_prefix(':')
        && let Ok(port) = rest.parse::<u16>()
    {
        return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
    }
    bail!("expected HOST:PORT, :PORT, or PORT");
}

async fn handle_conn(mut stream: TcpStream, app: Arc<App>) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    let req = match tokio::time::timeout(Duration::from_secs(15), read_request(&mut stream)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            let _ = stream.write_all(&err_resp(400, &e.to_string())).await;
            return Ok(());
        }
        Err(_) => {
            let _ = stream.write_all(&err_resp(408, "timeout")).await;
            return Ok(());
        }
    };

    let htmx = req
        .headers
        .get("hx-request")
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let bytes = dispatch(&req, &app, htmx);
    stream.write_all(&bytes).await?;
    let _ = stream.flush().await;
    Ok(())
}

struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn read_request(stream: &mut TcpStream) -> io::Result<Request> {
    let mut buf = Vec::with_capacity(1024);
    loop {
        let mut tmp = [0u8; 2048];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 64 * 1024 {
            return Err(io::Error::other("headers too large"));
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("incomplete request"))?;
    let head = &buf[..split];
    let mut rest = buf[split + 4..].to_vec();
    let head = std::str::from_utf8(head).map_err(|_| io::Error::other("headers are not utf-8"))?;
    let mut lines = head.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let path = target.split('?').next().unwrap_or("/").to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let want = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if want > 64 * 1024 {
        return Err(io::Error::other("body too large"));
    }
    while rest.len() < want {
        let mut tmp = [0u8; 2048];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        rest.extend_from_slice(&tmp[..n]);
        if rest.len() > 64 * 1024 {
            return Err(io::Error::other("body too large"));
        }
    }
    rest.truncate(want);
    Ok(Request {
        method,
        path,
        headers,
        body: rest,
    })
}

fn dispatch(req: &Request, app: &App, htmx: bool) -> Vec<u8> {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => html(&page(app)),
        ("GET", "/live") => html(&live_block(app)),
        ("GET", "/hits") => html(&hits_block(app)),
        ("GET", "/hits.txt") => text(&app.live.all_hit_lines()),
        ("POST", "/start") => {
            let form = parse_form(&req.body);
            match start_scan(app, &form) {
                Ok(()) => {
                    if htmx {
                        html(&live_block(app))
                    } else {
                        redirect("/")
                    }
                }
                Err(e) => {
                    let msg = friendly_err(&e);
                    app.live.set_notice(msg);
                    if htmx {
                        html(&live_block(app))
                    } else {
                        html(&page(app))
                    }
                }
            }
        }
        ("POST", "/stop") => {
            app.live.request_stop();
            if htmx {
                html(&live_block(app))
            } else {
                redirect("/")
            }
        }
        _ => err_resp(404, "not found"),
    }
}

fn start_scan(app: &App, form: &HashMap<String, String>) -> Result<()> {
    let phase = app.live.phase();
    if matches!(phase, Phase::Running | Phase::Stopping) {
        bail!("a scan is already running");
    }
    let cfg = config_from_form(&app.defaults, form)?;
    {
        let mut g = app.form.lock().expect("form lock");
        *g = FormState::from_cfg(&cfg);
    }
    let opts = scan::prepare(cfg)?;
    let live = app.live.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = scan::run(opts, live.clone()).await {
            live.set_error(format!("{e:#}"));
        }
    });
    *app.job.lock().expect("job lock") = Some(handle);
    Ok(())
}

fn config_from_form(base: &ScanConfig, form: &HashMap<String, String>) -> Result<ScanConfig> {
    let mut cfg = base.clone();
    let ranges = parse_lines(form.get("ranges").map(String::as_str).unwrap_or(""));
    if ranges.is_empty() {
        bail!("name at least one CIDR or IP (the web UI will not scan all of IPv4 by default)");
    }
    cfg.ranges = ranges;
    cfg.excludes = parse_lines(form.get("excludes").map(String::as_str).unwrap_or(""));
    cfg.ports = parse_ports(form.get("ports").map(String::as_str).unwrap_or("25565"))?;
    cfg.min_players = form
        .get("min_players")
        .map(|s| s.parse())
        .transpose()
        .context("min players")?
        .unwrap_or(base.min_players);
    cfg.timeout_ms = form
        .get("timeout_ms")
        .map(|s| s.parse())
        .transpose()
        .context("timeout")?
        .unwrap_or(base.timeout_ms);
    cfg.connect = form
        .get("connect")
        .map(|s| s.parse())
        .transpose()
        .context("connect workers")?
        .unwrap_or(base.connect)
        .max(1);
    cfg.ping = form
        .get("ping")
        .map(|s| s.parse())
        .transpose()
        .context("ping workers")?
        .unwrap_or(base.ping)
        .max(1);
    let rate = form.get("rate").map(String::as_str).unwrap_or("").trim();
    cfg.rate = if rate.is_empty() {
        None
    } else {
        Some(rate.parse().context("rate")?)
    };
    cfg.include_reserved = form.get("include_reserved").is_some();
    cfg.tcp = form.get("tcp").is_some();
    cfg.fresh = form.get("fresh").is_some();
    Ok(cfg)
}

fn page(app: &App) -> String {
    let f = app.form.lock().expect("form lock").clone();
    let live = live_block(app);
    let hits = hits_block(app);
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mc-scan</title>
<script src="https://unpkg.com/htmx.org@2.0.4" defer></script>
<style>{css}</style>
</head>
<body>
<a class="skip" href="#ranges">Skip to range</a>
<div class="grain" aria-hidden="true"></div>
<main>
  <header>
    <p class="kicker">IPv4 · port 25565 · players online</p>
    <h1>mc-scan</h1>
    <p class="lede">Name a range. Hit scan. Populated Minecraft servers land in the table as they answer a status ping. SYN mode needs <code>CAP_NET_RAW</code>; without it this falls back to TCP connects.</p>
  </header>
  <noscript><p class="hint">JavaScript is off. Submit the form, then refresh the page to watch progress.</p></noscript>
  <form class="panel" method="post" action="/start"
        hx-post="/start" hx-target="#live" hx-swap="outerHTML">
    <div class="grid">
      <label class="span2">Range <span class="hint">one CIDR or IP per line. Required here.</span>
        <textarea id="ranges" name="ranges" rows="3" required placeholder="192.168.1.0/24" autofocus>{ranges}</textarea>
      </label>
      <label>Ports
        <input name="ports" value="{ports}" inputmode="numeric" autocomplete="off">
      </label>
      <label>Min players
        <input name="min_players" value="{min_players}" inputmode="numeric" autocomplete="off">
      </label>
      <label class="span2">Exclude <span class="hint">optional CIDRs to skip, one per line</span>
        <textarea name="excludes" rows="2">{excludes}</textarea>
      </label>
      <label>Rate <span class="hint">pps, blank = auto</span>
        <input name="rate" value="{rate}" inputmode="numeric" autocomplete="off" placeholder="auto">
      </label>
      <label>Timeout ms
        <input name="timeout_ms" value="{timeout_ms}" inputmode="numeric" autocomplete="off">
      </label>
      <label>TCP workers
        <input name="connect" value="{connect}" inputmode="numeric" autocomplete="off">
      </label>
      <label>Ping workers
        <input name="ping" value="{ping}" inputmode="numeric" autocomplete="off">
      </label>
    </div>
    <fieldset class="flags">
      <legend class="sr">Flags</legend>
      <label class="check"><input type="checkbox" name="include_reserved" {inc}> Include private / reserved (need this for 10/8, 192.168/16, …)</label>
      <label class="check"><input type="checkbox" name="tcp" {tcp}> Force TCP connect (skip raw SYN)</label>
      <label class="check"><input type="checkbox" name="fresh" {fresh}> Ignore saved cursor, start over</label>
    </fieldset>
    <div class="actions">
      <button type="submit">Scan</button>
      <button type="submit" formaction="/stop" formmethod="post"
              hx-post="/stop" hx-target="#live" hx-swap="outerHTML">Stop</button>
      <a class="text" href="/hits.txt">Download hits.txt</a>
    </div>
  </form>
  {live}
  {hits}
</main>
</body>
</html>
"##,
        css = CSS,
        ranges = esc(&f.ranges),
        ports = esc(&f.ports),
        min_players = esc(&f.min_players),
        excludes = esc(&f.excludes),
        rate = esc(&f.rate),
        timeout_ms = esc(&f.timeout_ms),
        connect = esc(&f.connect),
        ping = esc(&f.ping),
        inc = checked(f.include_reserved),
        tcp = checked(f.tcp),
        fresh = checked(f.fresh),
        live = live,
        hits = hits,
    )
}

fn live_block(app: &App) -> String {
    let live = &app.live;
    let phase = live.phase();
    let poll = "hx-get=\"/live\" hx-trigger=\"every 1s\" hx-swap=\"outerHTML\"";
    let done = live.stats.packets.load(Ordering::Relaxed);
    let open = live.stats.open.load(Ordering::Relaxed);
    let pinged = live.stats.pinged.load(Ordering::Relaxed);
    let populated = live.stats.live.load(Ordering::Relaxed);
    let total = live.total_pkts.load(Ordering::Relaxed);
    let addrs = live.total_addrs.load(Ordering::Relaxed);
    let pct = if total == 0 {
        if phase == Phase::Done { 100.0 } else { 0.0 }
    } else {
        (done as f64 / total as f64 * 100.0).clamp(0.0, 100.0)
    };
    let mode = live.mode();
    let mode = if mode.is_empty() { "—" } else { mode.as_str() };
    let progress = live.progress_line();
    let err = live.error();
    let phase_label = match phase {
        Phase::Idle => "idle",
        Phase::Running => "running",
        Phase::Stopping => "stopping",
        Phase::Done => "done",
    };
    let logs: String = live
        .snapshot_logs(12)
        .into_iter()
        .map(|l| format!("<li>{}</li>", esc(&l)))
        .collect();
    let err_html = err.as_deref().map(error_box).unwrap_or_default();
    let eta = progress
        .split("eta~")
        .nth(1)
        .unwrap_or("—")
        .to_string();
    format!(
        r##"<section id="live" class="panel" {poll} aria-live="polite">
  <div class="row">
    <h2>Status</h2>
    <p class="pill {phase_label}">{phase_label} · {mode}</p>
  </div>
  {err_html}
  <progress max="100" value="{pct:.3}" aria-label="scan progress">{pct:.1}%</progress>
  <dl class="stats">
    <div><dt>scanned</dt><dd>{done}</dd></div>
    <div><dt>of</dt><dd>{total}</dd></div>
    <div><dt>addrs</dt><dd>{addrs}</dd></div>
    <div><dt>open</dt><dd>{open}</dd></div>
    <div><dt>pinged</dt><dd>{pinged}</dd></div>
    <div><dt>populated</dt><dd>{populated}</dd></div>
    <div><dt>eta</dt><dd>{eta}</dd></div>
  </dl>
  <p class="progress-line">{progress}</p>
  <ol class="log">{logs}</ol>
</section>
"##,
        poll = poll,
        phase_label = phase_label,
        mode = esc(mode),
        err_html = err_html,
        pct = pct,
        done = done,
        total = total,
        addrs = addrs,
        open = open,
        pinged = pinged,
        populated = populated,
        eta = esc(&eta),
        progress = esc(&progress),
        logs = logs,
    )
}

fn hits_block(app: &App) -> String {
    let n = app.live.hit_count();
    let hits = app.live.snapshot_hits(400);
    let rows: String = if hits.is_empty() {
        r#"<tr><td colspan="5" class="empty">No populated servers yet. They show up here the moment a status ping comes back with players.</td></tr>"#.into()
    } else {
        hits.iter()
            .rev()
            .map(|h| {
                format!(
                    "<tr><td><code>{}:{}</code></td><td class=\"num\">{}/{}</td><td>{}</td><td>{}</td></tr>",
                    esc(&h.ip.to_string()),
                    h.port,
                    h.online,
                    h.max,
                    esc(h.version.as_deref().unwrap_or("")),
                    esc(h.motd.as_deref().unwrap_or("")),
                )
            })
            .collect()
    };
    format!(
        r##"<section class="panel" id="hits-wrap"
      hx-get="/hits" hx-trigger="every 1s" hx-swap="outerHTML">
  <div class="row">
    <h2>Populated</h2>
    <p class="pill">{n}</p>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>server</th><th>players</th><th>version</th><th>motd</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>
"##
    )
}

fn friendly_err(e: &anyhow::Error) -> String {
    let s = format!("{e:#}");
    if s.contains("include-reserved") {
        "that range is private or reserved. tick “include private / reserved” and scan again."
            .into()
    } else {
        s
    }
}

fn error_box(msg: &str) -> String {
    format!(r#"<p class="err" role="alert">{}</p>"#, esc(msg))
}

fn checked(on: bool) -> &'static str {
    if on { "checked" } else { "" }
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn parse_form(body: &[u8]) -> HashMap<String, String> {
    let s = String::from_utf8_lossy(body);
    let mut map = HashMap::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(percent_decode(k), percent_decode(v));
    }
    map
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16) {
                    Ok(c) => {
                        out.push(c);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn html(body: &str) -> Vec<u8> {
    resp("200 OK", "text/html; charset=utf-8", body.as_bytes())
}

fn text(body: &str) -> Vec<u8> {
    resp("200 OK", "text/plain; charset=utf-8", body.as_bytes())
}

fn redirect(to: &str) -> Vec<u8> {
    format!("HTTP/1.1 303 See Other\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

fn err_resp(code: u16, msg: &str) -> Vec<u8> {
    let status = match code {
        400 => "400 Bad Request",
        404 => "404 Not Found",
        408 => "408 Request Timeout",
        _ => "500 Internal Server Error",
    };
    let body = format!("{msg}\n");
    resp(status, "text/plain; charset=utf-8", body.as_bytes())
}

fn resp(status: &str, ctype: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

const CSS: &str = r#"
:root {
  --bg: #10140e;
  --bg-2: #181e14;
  --ink: #e4f0c8;
  --muted: #8ea06a;
  --line: #3a4a28;
  --accent: #c6e04a;
  --warn: #e0a14a;
  --hot: #7ee0c0;
  --err: #e07060;
  --font: "IBM Plex Mono", "iA Writer Mono", "Cascadia Mono", ui-monospace, monospace;
}
* { box-sizing: border-box; }
html { -webkit-font-smoothing: antialiased; }
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(1200px 500px at 10% -10%, #243018 0%, transparent 55%),
    var(--bg);
  color: var(--ink);
  font: 16px/1.5 var(--font);
}
.grain {
  pointer-events: none;
  position: fixed; inset: 0;
  background: repeating-linear-gradient(
    to bottom,
    transparent 0 2px,
    rgb(0 0 0 / 0.12) 2px 3px
  );
  z-index: 0;
}
.skip {
  position: absolute; left: -999px; top: 0;
}
.skip:focus { left: 1rem; top: 1rem; z-index: 2; background: var(--bg-2); padding: .4rem .6rem; }
main { position: relative; z-index: 1; max-width: 920px; margin: 0 auto; padding: 2.5rem 1.25rem 4rem; }
header { margin-bottom: 1.5rem; }
.kicker { color: var(--accent); letter-spacing: .14em; text-transform: uppercase; font-size: 12px; margin: 0 0 .4rem; }
h1 { font-size: 2.75rem; line-height: 1.05; letter-spacing: -.04em; margin: 0 0 .6rem; text-wrap: balance; }
h2 { font-size: 1rem; margin: 0; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
.lede { max-width: 62ch; color: var(--muted); text-wrap: pretty; margin: 0; }
.lede code { color: var(--hot); }
.panel {
  background: rgb(24 30 20 / 0.92);
  border: 1px solid var(--line);
  padding: 1.1rem 1.15rem 1.2rem;
  margin: 0 0 1rem;
}
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: .85rem 1rem; }
.span2 { grid-column: 1 / -1; }
label { display: flex; flex-direction: column; gap: .35rem; color: var(--muted); font-size: 13px; letter-spacing: .04em; text-transform: uppercase; }
.hint { text-transform: none; letter-spacing: 0; color: #6d7c52; font-size: 12px; }
input, textarea, button {
  font: inherit; color: var(--ink); background: #0c100a;
  border: 1px solid var(--line); padding: .55rem .65rem; border-radius: 0;
}
::placeholder { color: #5c6a45; opacity: 1; }
textarea { resize: vertical; min-height: 4.5rem; }
input:focus, textarea:focus, button:focus {
  outline: 2px solid var(--accent); outline-offset: 2px;
}
.flags { border: 0; padding: 1rem 0 0; margin: 0; display: flex; flex-direction: column; gap: .45rem; }
.check { flex-direction: row; align-items: center; gap: .55rem; text-transform: none; letter-spacing: 0; font-size: 14px; color: var(--ink); }
.check input { width: 1.05rem; height: 1.05rem; accent-color: var(--accent); }
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
.actions { display: flex; flex-wrap: wrap; gap: .6rem; align-items: center; margin-top: 1rem; }
button {
  background: var(--accent); color: #14180c; font-weight: 650; letter-spacing: .06em;
  text-transform: uppercase; padding: .65rem 1.1rem; cursor: pointer; border-color: var(--accent);
}
button:hover { filter: brightness(1.05); }
button:active { transform: translateY(1px); }
button[formaction] { background: transparent; color: var(--ink); border-color: var(--line); }
a.text { color: var(--hot); }
.row { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; margin-bottom: .8rem; }
.pill { margin: 0; font-size: 12px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
.pill.running, .pill.stopping { color: var(--warn); }
.pill.done { color: var(--hot); }
progress { width: 100%; height: .55rem; accent-color: var(--accent); background: #0c100a; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(7rem, 1fr)); gap: .6rem 1rem; margin: .9rem 0 .4rem; }
.stats div { margin: 0; }
dt { color: var(--muted); font-size: 11px; letter-spacing: .12em; text-transform: uppercase; }
dd { margin: 0; font-variant-numeric: tabular-nums; font-size: 1.15rem; }
.progress-line { color: var(--muted); font-size: 13px; min-height: 1.3em; font-variant-numeric: tabular-nums; }
.log { margin: .4rem 0 0; padding: 0; list-style: none; color: var(--muted); font-size: 13px; max-height: 9rem; overflow: auto; }
.log li { padding: .1rem 0; border-bottom: 1px solid rgb(58 74 40 / 0.4); }
.err { background: rgb(224 112 96 / 0.12); color: var(--err); border: 1px solid var(--err); padding: .6rem .75rem; margin: 0 0 1rem; }
.table-wrap { overflow: auto; max-height: 28rem; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th { text-align: left; color: var(--muted); font-weight: 500; font-size: 11px; letter-spacing: .1em; text-transform: uppercase; padding: .4rem .5rem; border-bottom: 1px solid var(--line); }
td { padding: .45rem .5rem; border-bottom: 1px solid rgb(58 74 40 / 0.45); vertical-align: top; }
td.num, .num { font-variant-numeric: tabular-nums; }
td.empty { color: var(--muted); }
code { font-family: inherit; color: var(--hot); }
@media (max-width: 640px) {
  h1 { font-size: 2rem; }
  .grid { grid-template-columns: 1fr; }
  .span2 { grid-column: auto; }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_form() {
        let m = parse_form(b"ranges=192.168.1.0%2F24&tcp=on");
        assert_eq!(m.get("ranges").unwrap(), "192.168.1.0/24");
        assert!(m.contains_key("tcp"));
    }

    #[test]
    fn plus_is_space() {
        assert_eq!(percent_decode("a+b"), "a b");
    }

    #[test]
    fn esc_stops_xss() {
        assert_eq!(esc("<script>"), "&lt;script&gt;");
    }

    #[test]
    fn bind_port_only() {
        assert_eq!(
            parse_bind("8080").unwrap(),
            SocketAddr::from(([0, 0, 0, 0], 8080))
        );
        assert_eq!(
            parse_bind("127.0.0.1:9").unwrap(),
            "127.0.0.1:9".parse().unwrap()
        );
    }

    #[test]
    fn form_requires_range() {
        let err = config_from_form(&ScanConfig::default(), &HashMap::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("CIDR"));
    }

    #[test]
    fn private_range_is_explained() {
        let mut form = HashMap::new();
        form.insert("ranges".into(), "127.0.0.1".into());
        form.insert("ports".into(), "25565".into());
        let cfg = config_from_form(&ScanConfig::default(), &form).unwrap();
        let Err(err) = crate::scan::prepare(cfg) else {
            panic!("expected prepare to fail");
        };
        assert!(friendly_err(&err).contains("private"));
    }

    #[tokio::test]
    async fn homepage_serves_htmx() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Arc::new(App {
            live: Live::new(true, false, None),
            defaults: ScanConfig::default(),
            job: Mutex::new(None),
            form: Mutex::new(FormState::from_cfg(&ScanConfig::default())),
        });
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_conn(stream, app).await.unwrap();
        });
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        c.read_to_end(&mut buf).await.unwrap();
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("200 OK"), "{s}");
        assert!(s.contains("htmx.org"));
        assert!(s.contains("name=\"ranges\""));
    }
}
