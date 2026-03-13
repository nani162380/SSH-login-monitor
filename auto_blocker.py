import subprocess
from brute_force import detect_brute_force

WHITELIST = ['127.0.0.1']  # IPs to never block

def block_ip(ip):
    """Block an IP using UFW firewall"""
    result = subprocess.run(
        ['sudo', 'ufw', 'deny', 'from', ip, 'to', 'any'],
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        print(f"   ✅ Blocked: {ip}")
    else:
        print(f"   ❌ Failed to block {ip}: {result.stderr}")

def unblock_ip(ip):
    """Unblock an IP using UFW firewall"""
    result = subprocess.run(
        ['sudo', 'ufw', 'delete', 'deny', 'from', ip, 'to', 'any'],
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        print(f"   ✅ Unblocked: {ip}")
    else:
        print(f"   ❌ Failed to unblock {ip}: {result.stderr}")

def run_auto_blocker():
    brute_ips, _ = detect_brute_force()

    print("\n==============================")
    print("   Auto Blocker Running...")
    print("==============================")

    if not brute_ips:
        print("\n✅ No IPs to block")
        return

    blocked = []
    skipped = []

    for entry in brute_ips:
        ip = entry['ip']
        print(f"\n🚨 Attacker IP: {ip} | Attempts: {entry['count']}")

        if ip in WHITELIST:
            print(f"   ⚠️  Skipped (whitelisted): {ip}")
            skipped.append(ip)
        else:
            block_ip(ip)
            blocked.append(ip)

    print(f"\n------------------------------")
    print(f"Blocked  : {len(blocked)} IPs → {blocked}")
    print(f"Skipped  : {len(skipped)} IPs → {skipped}")
    print("==============================")


if __name__ == "__main__":
    run_auto_blocker()
