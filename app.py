from flask import Flask, jsonify, send_file
from flask_cors import CORS
import subprocess
import socket
from datetime import datetime
from log_parser import parse_ssh_logs
from brute_force import detect_brute_force

app = Flask(__name__)
CORS(app)

def get_uptime():
    result = subprocess.run(['uptime', '-p'], capture_output=True, text=True)
    return result.stdout.strip()

def get_blocked_ips():
    result = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True)
    blocked = []
    for line in result.stdout.splitlines():
        if 'DENY' in line:
            parts = line.split()
            if parts:
                blocked.append(parts[0])
    return blocked

@app.route('/')
def dashboard():
    return send_file('dashboard.html')

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        'status': 'online',
        'hostname': socket.gethostname(),
        'uptime': get_uptime(),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/api/failed-logins', methods=['GET'])
def failed_logins():
    failed, _ = parse_ssh_logs()
    return jsonify({
        'count': len(failed),
        'logins': failed[-20:]
    })

@app.route('/api/brute-force', methods=['GET'])
def brute_force():
    brute_ips, normal_ips = detect_brute_force()
    return jsonify({
        'brute_force_count': len(brute_ips),
        'normal_failed_count': len(normal_ips),
        'attacks': brute_ips
    })

@app.route('/api/blocked-ips', methods=['GET'])
def blocked_ips():
    ips = get_blocked_ips()
    return jsonify({
        'count': len(ips),
        'ips': ips
    })

@app.route('/api/stats', methods=['GET'])
def stats():
    failed, success = parse_ssh_logs()
    brute_ips, _ = detect_brute_force()
    blocked = get_blocked_ips()
    return jsonify({
        'total_failed_logins': len(failed),
        'total_successful_logins': len(success),
        'brute_force_attacks': len(brute_ips),
        'blocked_ips': len(blocked),
        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
