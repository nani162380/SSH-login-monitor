import re

LOG_FILE = "/var/log/auth.log"

def parse_ssh_logs():
    failed_attempts = []
    successful_logins = []
    seen = set()

    failed_pattern = re.compile(
        r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'
    )
    success_pattern = re.compile(
        r'Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)'
    )

    with open(LOG_FILE, 'r') as f:
        for line in f:
            if line in seen:
                continue
            seen.add(line)

            timestamp = line[:32].strip()

            failed_match = failed_pattern.search(line)
            if failed_match:
                failed_attempts.append({
                    'timestamp': timestamp,
                    'username': failed_match.group(1),
                    'ip': failed_match.group(2),
                    'status': 'FAILED'
                })

            success_match = success_pattern.search(line)
            if success_match:
                successful_logins.append({
                    'timestamp': timestamp,
                    'username': success_match.group(1),
                    'ip': success_match.group(2),
                    'status': 'SUCCESS'
                })

    return failed_attempts, successful_logins


if __name__ == "__main__":
    failed, success = parse_ssh_logs()

    print(f"\n=== FAILED ATTEMPTS ({len(failed)}) ===")
    for attempt in failed[-10:]:
        print(f"[{attempt['timestamp']}] User: {attempt['username']} | IP: {attempt['ip']}")

    print(f"\n=== SUCCESSFUL LOGINS ({len(success)}) ===")
    for login in success[-10:]:
        print(f"[{login['timestamp']}] User: {login['username']} | IP: {login['ip']}")

    print(f"\nTotal Failed: {len(failed)} | Total Success: {len(success)}")
