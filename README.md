# fpm-self-defense

Lightweight server health monitor for Linux/Apache/PHP-FPM stacks. Runs every 3 minutes via cron, logs key metrics, sends email alerts on threshold breaches, and automatically enables/disables Cloudflare Under Attack Mode during load spikes.

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
