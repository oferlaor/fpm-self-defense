# fpm-self-defense

Lightweight server health monitor for Linux/Apache/PHP-FPM stacks. Runs every 3 minutes via cron, logs key metrics, sends email alerts on threshold breaches, and automatically enables/disables Cloudflare Under Attack Mode during load spikes.

## The problem

A DDoS or traffic spike hits your server. PHP-FPM has a fixed pool of worker processes (`pm.max_children`). Once every worker is busy, new requests queue up — and if the queue fills, the server starts refusing connections entirely. Memory climbs, load average spikes, swap kicks in, and the server becomes unresponsive or crashes. By the time you notice, the damage is done.

Traditional monitoring tools tell you *after* the fact. What you need is something that detects the attack early, fights back automatically, and wakes you up with enough context to understand what happened.

## How fpm-self-defense works

**Detection** — Every 3 minutes, the script samples PHP-FPM worker count, total FPM memory, system RAM, swap, load average, TCP connections, Apache workers, and MySQL threads. Thresholds are configurable per-server.

**Early warning** — FPM workers near capacity (default: 90% of `max_children`) for 3 consecutive rounds (~9 minutes) triggers an alert before the pool is exhausted. At 100% capacity it fires immediately.

**Active defense** — When load exceeds the high threshold, the script calls the Cloudflare API to enable [Under Attack Mode](https://developers.cloudflare.com/fundamentals/reference/under-attack-mode/), which challenges every visitor with a browser integrity check. This sheds most bot/attack traffic at the CDN edge before it ever reaches PHP-FPM, giving the server room to breathe.

**Situational awareness** — Alert emails include the top attacking IPs, URLs, user agents, and ASNs from Cloudflare Analytics over the last 5 minutes, so you can assess the attack without logging into anything.

**Auto-recovery** — Once load stays below the recovery threshold for 10+ consecutive minutes, Under Attack Mode is automatically disabled and a follow-up email confirms how long it was active.

## Features

- Tracks PHP-FPM workers, memory, system RAM, swap, load average, TCP connections, Apache, MySQL, and Sphinx
- Email alerts with cooldown (no alert floods)
- Cloudflare Under Attack Mode — auto-enabled on high load, auto-disabled after sustained recovery
- Alert emails include top IPs, URLs, user agents, and ASNs from CF Analytics (last 5 min)
- Rolling log with configurable retention

## Files

```
fpm-self-defense/
├── fpm-monitor.sh      # main script
├── .env                # site config & secrets (not committed)
├── .env.example        # template — copy this to .env
├── .gitignore
├── SKILL.md
└── README.md
```

Log files (written to `LOG_DIR` from `.env`):

| File | Purpose |
|------|---------|
| `server-monitor.log` | rolling metric log (one line per run) |
| `last-alert` | epoch timestamp of last alert sent (cooldown gate) |
| `fpm-mem-high-count` | consecutive rounds fpm memory has been high |
| `fpm-workers-high-count` | consecutive rounds fpm workers have been high |
| `cf-under-attack-active` | epoch timestamp CF UAM was enabled (absent = UAM off) |
| `low-load-since` | epoch timestamp load first dropped below recovery threshold |

## Setup

**1. Clone and configure**

```bash
git clone https://github.com/oferlaor/fpm-self-defense.git /opt/fpm-self-defense
cd /opt/fpm-self-defense
cp .env.example .env
# edit .env — fill in credentials and tune thresholds for your server
```

**2. Create the log directory**

```bash
mkdir -p /var/log/fpm-self-defense
# set LOG_DIR=/var/log/fpm-self-defense in .env
```

**3. Add to crontab**

```
*/3 * * * * /opt/fpm-self-defense/fpm-monitor.sh >/dev/null 2>&1
```

## Configuration

All tunable values live in `.env`. See `.env.example` for the full list with comments.

Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `FPM_POOL` | — | Name of your php-fpm pool (matches `php-fpm: pool <name>` in `ps`) |
| `FPM_MAX` | 40 | Must match `pm.max_children` in your php-fpm pool config |
| `FPM_WARN_PCT` | 90 | Alert when workers reach this % of `FPM_MAX`; at 100% fires immediately |
| `LOAD_HIGH_THRESHOLD` | 7.5 | Triggers alert + CF Under Attack Mode |
| `LOAD_LOW_THRESHOLD` | 1.0 | Load must stay below this for 10 min to disable CF UAM |
| `ALERT_COOLDOWN` | 1800 | Seconds between alert emails (30 min) |
| `MAX_LINES` | 240 | Log lines kept (12 h at 3-min intervals) |

## Alert logic

| Condition | Behaviour |
|-----------|-----------|
| FPM workers ≥ `FPM_MAX` | Alert immediately |
| FPM workers ≥ `FPM_WARN` for 3+ rounds (~9 min) | Alert |
| FPM memory > `FPM_MEM_THRESHOLD_MB` for 3+ rounds | Alert |
| Available memory < `MEM_AVAIL_THRESHOLD_MB` | Alert |
| Swap > `SWAP_THRESHOLD_MB` | Alert |
| Load > `LOAD_HIGH_THRESHOLD` | Alert + enable CF Under Attack Mode |
| TCP established > `TCP_ESTAB_THRESHOLD` | Alert |
| Apache workers > `HTTPD_THRESHOLD` | Alert |
| MySQL threads > `MYSQL_THRESHOLD` | Alert |
| Sphinx down | Alert |

## Cloudflare Under Attack Mode

Requires a CF API token with `Zone.Settings:Edit` permission and the zone ID from your CF dashboard.

When load exceeds `LOAD_HIGH_THRESHOLD`:
- CF security level is set to `under_attack` via API
- Alert email includes top IPs, URLs, user agents, and ASNs from the last 5 min
- UAM is automatically disabled once load stays below `LOAD_LOW_THRESHOLD` for 10+ consecutive minutes
- A follow-up email is sent on disable, including how long UAM was active

## Log format

Each line in `server-monitor.log`:

```
YYYY-MM-DD HH:MM:SS fpm=N fpm_mem=NMB mem_used=NMB mem_avail=NMB swap=NMB load=N N N tcp_estab=N tcp_tw=N tcp_total=N httpd=N mysql_threads=N sphinx=N
```

## Requirements

- bash, curl, bc, python3, sendmail (or compatible MTA)
- php-fpm, Apache (httpd), MySQL, Sphinx (optional — alerts if down)
- Cloudflare account with API token (for CF Under Attack Mode)
