---
name: fpm-self-defense
description: Manage and troubleshoot the fpm-self-defense server health monitoring script. Use when asked about alerts, thresholds, Cloudflare Under Attack Mode, log files, cron setup, or any changes to fpm-self-defense configuration.
---

# fpm-self-defense

Server health monitor. Runs every 3 minutes via cron.

## Key files

| File | Purpose |
|------|---------|
| `fpm-monitor.sh` | Main script — logic only, no hardcoded values |
| `.env` | All config: credentials, thresholds, paths. Source of truth for tuning |
| `.env.example` | Public template with placeholder values |
| `SKILL.md` | This file |
| `README.md` | User-facing docs |

Log files live in `LOG_DIR` (set in `.env`):

- `server-monitor.log` — rolling 12-hour metric log
- `last-alert` — cooldown gate (epoch timestamp of last sent alert)
- `fpm-mem-high-count`, `fpm-workers-high-count` — consecutive-round counters
- `cf-under-attack-active` — present when CF UAM is active; contains epoch of activation
- `low-load-since` — epoch when load first dropped below recovery threshold

## How to make changes

**All tuning goes in `.env`** — never edit thresholds directly in the script.

To adjust FPM max workers, match it to `pm.max_children` in the php-fpm pool config, then update `FPM_MAX` in `.env`. `FPM_WARN` is computed automatically as `FPM_MAX * FPM_WARN_PCT / 100`.

## Alert flow

1. Script runs, gathers metrics, appends one line to `server-monitor.log`
2. Checks each metric against thresholds from `.env`
3. If any threshold breached AND `ALERT_COOLDOWN` has elapsed since last alert → sends email
4. If load is high → also calls CF API to enable Under Attack Mode
5. On every run while `cf-under-attack-active` exists → checks if load has been below `LOAD_LOW_THRESHOLD` for 10+ min; if so, disables UAM and sends follow-up email

## CF Under Attack Mode

Managed via CF API (`CF_TOKEN`, `CF_ZONE` in `.env`). Dashboard link is in `CF_DASH_URL`.

To manually disable UAM (e.g. false alarm):
```bash
rm "$LOG_DIR/cf-under-attack-active"
rm "$LOG_DIR/low-load-since"
```
Then call the CF API directly, or wait for the script to auto-disable it once load recovers.

## Cron entry

```
*/3 * * * * /path/to/fpm-self-defense/fpm-monitor.sh >/dev/null 2>&1
```

## Current thresholds (from .env)

| Metric | Threshold |
|--------|-----------|
| FPM workers (immediate) | ≥ 40 (`FPM_MAX`) |
| FPM workers (sustained) | ≥ 36 (`FPM_WARN`, 90% of max) for 3+ rounds |
| FPM memory | > 6500 MB for 3+ rounds |
| Available memory | < 1000 MB |
| Swap | > 1500 MB |
| Load (alert + CF UAM) | > 7.5 |
| Load (CF UAM recovery) | < 1.0 for 10+ min |
| TCP established | > 300 |
| Apache workers | > 200 |
| MySQL threads | > 200 |
