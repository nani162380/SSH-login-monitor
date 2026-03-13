from collections import defaultdict
from log_parser import parse_ssh_logs

THRESHOLD = 3

def detect_brute_force():
    failed, success = parse_ssh_logs()

    # Group failed attempts by IP
    ip_data = defaultdict(list)
    for attempt in failed:
        ip_data[attempt['ip']].append(attempt)

    brute_force_ips = []
    normal_ips = []

    for ip, attempts in ip_data.items():
        if len(attempts) >= THRESHOLD:
            brute_force_ips.append({
                'ip': ip,
                'count': len(attempts),
                'usernames': list(set([a['username'] for a in attempts])),
                'first_seen': attempts[0]['timestamp'],
                'last_seen': attempts[-1]['timestamp']
            })
        else:
            normal_ips.append(ip)

    return brute_force_ips, normal_ips


if __name__ == "__main__":
    brute_ips, normal_ips = detect_brute_force()

    print("\n==============================")
    print(" Brute Force Detection Report")
    print("==============================")

    if brute_ips:
        for entry in brute_ips:
            print(f"\n🚨 BRUTE FORCE DETECTED")
            print(f"   IP Address : {entry['ip']}")
            print(f"   Attempts   : {entry['count']}")
            print(f"   Usernames  : {entry['usernames']}")
            print(f"   First Seen : {entry['first_seen']}")
            print(f"   Last Seen  : {entry['last_seen']}")
    else:
        print("\n✅ No brute force attacks detected")

    print(f"\n------------------------------")
    print(f"Total IPs scanned    : {len(brute_ips) + len(normal_ips)}")
    print(f"Brute force IPs      : {len(brute_ips)}")
    print(f"Normal failed logins : {len(normal_ips)}")
    print("==============================")
