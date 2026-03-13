# SSH Login Monitoring System 🛡️

A real-time SSH brute force detection and monitoring dashboard built for Linux servers.

## Features
- Parses `/var/log/auth.log` for SSH login attempts
- Detects brute force attacks (3+ failed attempts from same IP)
- Auto-blocks attacker IPs via UFW firewall
- Fail2ban integration for 24/7 automatic protection
- Live web dashboard with auto-refresh every 5 seconds
- REST API backend built with Flask

## Project Structure
```
ssh-monitor/
├── log_parser.py      → Parses auth.log, extracts failed/success logins
├── brute_force.py     → Detects brute force attacks by IP
├── auto_blocker.py    → Blocks attacker IPs via UFW
├── app.py             → Flask REST API (5 endpoints)
└── dashboard.html     → Live web dashboard
```

## Tech Stack
- Python 3 + Flask
- Bash / Linux commands
- UFW Firewall
- Fail2ban
- HTML/CSS/JavaScript

## API Endpoints
| Endpoint | Description |
|---|---|
| `/api/status` | Server hostname and uptime |
| `/api/failed-logins` | All failed SSH attempts |
| `/api/brute-force` | Detected brute force attacks |
| `/api/blocked-ips` | UFW blocked IPs |
| `/api/stats` | Summary statistics |

## How to Run
```bash
# Install dependencies
pip install flask flask-cors

# Run the server
sudo python3 app.py

# Open dashboard
http://localhost:5000
```

## Real World Use
Used by SOC teams to monitor servers for intrusion attempts and brute force attacks.
# SSH-login-monitor
