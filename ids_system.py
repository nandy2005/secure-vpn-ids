from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, send, conf
from flask import Flask, render_template_string, jsonify, request
from flask_socketio import SocketIO
from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading
import time
import random
import re
import argparse

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids_secret_key_2025'
socketio = SocketIO(app, cors_allowed_origins="*")

alerts = deque(maxlen=1000)
traffic_stats = {'total_packets': 0,'tcp_packets': 0,'udp_packets': 0,'icmp_packets': 0,'arp_packets': 0,'suspicious_packets': 0}

# Detection tracking
port_scan_tracker = defaultdict(lambda: {'ports': set(), 'last_seen': time.time()})
syn_flood_tracker = defaultdict(lambda: {'count': 0, 'last_reset': time.time()})
connection_tracker = defaultdict(int)
packet_rate_tracker = defaultdict(lambda: deque(maxlen=100))
ip_reputation = defaultdict(int)
brute_force_tracker = defaultdict(lambda: {'attempts': 0, 'last_reset': time.time()})

# Known attack patterns
suspicious_patterns = {
    'sql_injection': [r'union.*select', r'or.*1.*=.*1', r'drop.*table', r'exec.*xp_', r'information_schema'],
    'xss': [r'<script>', r'javascript:', r'onerror=', r'onload=', r'<iframe'],
    'command_injection': [r';.*cat.*/', r'\|.*ls', r'&&.*rm', r'`.*whoami', r'\$\(.*\)'],
    'directory_traversal': [r'\.\./', r'\.\.\\', r'\.\.%2f'],
    'xxe': [r'<!ENTITY', r'<!DOCTYPE'],
    'ldap_injection': [r'\*\)\(\|', r'\)\(cn=']
}

# Suspicious ports
suspicious_ports = {12345: 'NetBus', 31337: 'Back Orifice', 6667: 'IRC', 4444: 'Metasploit',5900: 'VNC'}

# Mode configuration
USE_SIMULATOR = False
CAPTURE_ACTIVE = False

class IntrusionDetector:
    def __init__(self):
        self.detection_enabled = True
        
    def detect_port_scan(self, src_ip, dst_port):
        #Detect port scanning attempts
        current_time = time.time()
        tracker = port_scan_tracker[src_ip]
        
        if current_time - tracker['last_seen'] > 30:
            tracker['ports'].clear()
        
        tracker['ports'].add(dst_port)
        tracker['last_seen'] = current_time
        
        if len(tracker['ports']) > 20:
            return True, len(tracker['ports'])
        return False, 0
    
    def detect_syn_flood(self, src_ip):
        #Detect SYN flood attacks
        current_time = time.time()
        tracker = syn_flood_tracker[src_ip]
        
        if current_time - tracker['last_reset'] > 5:
            tracker['count'] = 0
            tracker['last_reset'] = current_time
        
        tracker['count'] += 1
        
        if tracker['count'] > 200:
            return True, tracker['count']
        return False, 0
    
    def detect_ddos(self, src_ip):
        #Detect DDoS patterns
        current_time = time.time()
        packet_rate_tracker[src_ip].append(current_time)
        
        recent_packets = [t for t in packet_rate_tracker[src_ip] if current_time - t < 3]
        
        if len(recent_packets) > 100:
            return True, len(recent_packets)
        return False, 0
    
    def detect_brute_force(self, src_ip):
        #Detect brute force attempts
        current_time = time.time()
        tracker = brute_force_tracker[src_ip]
        
        if current_time - tracker['last_reset'] > 60:
            tracker['attempts'] = 0
            tracker['last_reset'] = current_time
        
        tracker['attempts'] += 1
        
        if tracker['attempts'] > 30:
            return True, tracker['attempts']
        return False, 0
    
    def detect_payload_attack(self, payload):
        #Detect attacks in packet payload
        if not payload:
            return False, None
        
        try:
            # Convert payload to string
            if isinstance(payload, bytes):
                try:
                    payload_str = payload.decode('utf-8', errors='ignore').lower()
                except:
                    return False, None
            else:
                payload_str = str(payload).lower()
            
            # Skip if payload is too short (likely not an attack)
            if len(payload_str) < 10:
                return False, None
            
            # Skip common legitimate patterns
            if any(x in payload_str for x in ['http/1.', 'http/2', 'mozilla/', 'chrome/', 'application/json', 'text/html']):
                # It's likely a normal HTTP request/response
                # Only flag if it has VERY suspicious patterns
                for attack_type, patterns in suspicious_patterns.items():
                    for pattern in patterns:
                        # Require stricter matching for HTTP traffic
                        match = re.search(pattern, payload_str, re.IGNORECASE)
                        if match:
                            # Additional validation - check context
                            context = payload_str[max(0, match.start()-20):min(len(payload_str), match.end()+20)]
                            
                            # Skip false positives
                            if attack_type == 'sql_injection':
                                # Must have SQL keywords AND special chars
                                if not (('union' in context and 'select' in context) or 
                                       ('drop' in context and 'table' in context) or
                                       ('exec' in context and 'xp_' in context)):
                                    continue
                            elif attack_type == 'xss':
                                # Must have script tags or event handlers
                                if not (('<script' in context) or 
                                       ('javascript:' in context) or
                                       ('onerror=' in context) or
                                       ('onload=' in context)):
                                    continue
                            
                            return True, attack_type
                return False, None
            
            # For non-HTTP traffic, use normal detection
            for attack_type, patterns in suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, payload_str, re.IGNORECASE):
                        return True, attack_type
        except:
            pass
        return False, None
    
    def detect_suspicious_port(self, port):
        #Check if port is known for malicious activity
        return port in suspicious_ports
    
    def detect_arp_spoofing(self, src_ip, src_mac):
        #Detect ARP spoofing attempts
        key = f"arp_{src_ip}"
        if key in connection_tracker:
            stored_mac = connection_tracker[key]
            if stored_mac != src_mac:
                return True
        connection_tracker[key] = src_mac
        return False

detector = IntrusionDetector()

def create_alert(severity, alert_type, message, src_ip=None, dst_ip=None, details=None):
    #Create and store an alert
    alert = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
        'severity': severity,
        'type': alert_type,
        'message': message,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'details': details or {}
    }
    alerts.append(alert)
    traffic_stats['suspicious_packets'] += 1
    
    if src_ip:
        ip_reputation[src_ip] += {'high': 10, 'medium': 5, 'low': 1}[severity]
    
    socketio.emit('new_alert', alert)
    return alert

def packet_handler(packet):
    #Main packet analysis function for Scapy
    try:
        traffic_stats['total_packets'] += 1
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # TCP Analysis
            if TCP in packet:
                traffic_stats['tcp_packets'] += 1
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                
                # Port Scan Detection - only for SYN without ACK
                if flags & 0x02 and not flags & 0x10:  # SYN without ACK
                    is_scan, port_count = detector.detect_port_scan(src_ip, dst_port)
                    if is_scan:
                        create_alert('high', 'Port Scan', 
                                    f'Port scan detected from {src_ip}',
                                    src_ip, dst_ip,
                                    {'ports_scanned': port_count})
                    
                    # SYN Flood Detection
                    is_flood, syn_count = detector.detect_syn_flood(src_ip)
                    if is_flood:
                        create_alert('high', 'SYN Flood',
                                    f'Possible SYN flood from {src_ip}',
                                    src_ip, dst_ip,
                                    {'syn_packets': syn_count})
                
                # Suspicious Port Check
                if detector.detect_suspicious_port(dst_port):
                    create_alert('medium', 'Suspicious Port',
                                f'Connection to suspicious port {dst_port} ({suspicious_ports[dst_port]})',
                                src_ip, dst_ip,
                                {'port': dst_port, 'service': suspicious_ports[dst_port]})
                
                # Payload Analysis
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    is_attack, attack_type = detector.detect_payload_attack(payload)
                    if is_attack:
                        create_alert('high', 'Payload Attack',
                                    f'{attack_type.upper().replace("_", " ")} attempt detected',
                                    src_ip, dst_ip,
                                    {'attack_type': attack_type})
            
            # UDP Analysis
            elif UDP in packet:
                traffic_stats['udp_packets'] += 1
            
            # ICMP Analysis
            elif ICMP in packet:
                traffic_stats['icmp_packets'] += 1
                is_ddos, rate = detector.detect_ddos(src_ip)
                if is_ddos:
                    create_alert('high', 'ICMP Flood',
                                f'ICMP flood detected from {src_ip}',
                                src_ip, dst_ip,
                                {'packet_rate': rate})
        
        # ARP Spoofing Detection
        elif ARP in packet:
            traffic_stats['arp_packets'] += 1
            if detector.detect_arp_spoofing(packet[ARP].psrc, packet[ARP].hwsrc):
                create_alert('high', 'ARP Spoofing',
                            f'Possible ARP spoofing detected',
                            packet[ARP].psrc, None,
                            {'mac': packet[ARP].hwsrc})
        
        # Emit traffic update
        if traffic_stats['total_packets'] % 100 == 0:
            socketio.emit('traffic_update', traffic_stats)
            
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_packet_capture():
    #Start capturing packets with Scapy
    global CAPTURE_ACTIVE
    CAPTURE_ACTIVE = True
    print("[+] Starting real-time packet capture...")
    print("[+] Monitoring all network interfaces...")
    try:
        # Capture on all interfaces
        sniff(prn=packet_handler, store=False)
    except Exception as e:
        print(f"[!] Packet capture error: {e}")
        print("[!] Make sure you're running with admin/sudo privileges")
        print("[!] On Windows, ensure Npcap is installed: https://npcap.com/")

# Traffic Generator for Testing (same as before)
class TrafficGenerator:
    def __init__(self):
        self.running = False
        self.attack_mode = None
        
    def generate_normal_traffic(self):
        #Generate normal traffic patterns
        src_ips = [f'192.168.1.{random.randint(10, 100)}' for _ in range(5)]
        dst_ips = ['192.168.1.1', '192.168.1.254']
        
        while self.running and self.attack_mode == 'normal':
            src_ip = random.choice(src_ips)
            dst_ip = random.choice(dst_ips)
            
            try:
                # Create normal TCP ACK packet
                packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(49152, 65535), 
                                                         dport=random.choice([80, 443]), 
                                                         flags='A')
                send(packet, verbose=0)
                time.sleep(random.uniform(0.05, 0.2))
            except Exception as e:
                print(f"[!] Error sending packet: {e}")
                break
    
    def generate_port_scan(self):
        #Simulate port scanning attack with Scapy
        attacker_ip = f'203.0.113.{random.randint(1, 254)}'
        target_ip = '192.168.1.1'
        
        create_alert('low', 'Attack Started', 
                    'Port scan attack simulation initiated',
                    attacker_ip, target_ip,
                    {'attack_type': 'port_scan'})
        
        print(f"[*] Launching port scan from {attacker_ip} to {target_ip}")
        
        ports = list(range(1, 1001))
        random.shuffle(ports)
        
        for port in ports[:100]:
            if not self.running or self.attack_mode != 'port_scan':
                break
            try:
                packet = IP(src=attacker_ip, dst=target_ip)/TCP(sport=random.randint(49152, 65535), dport=port, flags='S')
                send(packet, verbose=0)
                time.sleep(0.01)
            except:
                break
    
    def generate_syn_flood(self):
        #Simulate SYN flood attack with Scapy
        attacker_ip = f'198.51.100.{random.randint(1, 254)}'
        target_ip = '192.168.1.1'
        target_port = 80
        
        create_alert('low', 'Attack Started', 
                    'SYN flood attack simulation initiated',
                    attacker_ip, target_ip,
                    {'attack_type': 'syn_flood'})
        
        print(f"[*] Launching SYN flood from {attacker_ip} to {target_ip}:{target_port}")
        
        for i in range(300):
            if not self.running or self.attack_mode != 'syn_flood':
                break
            try:
                packet = IP(src=attacker_ip, dst=target_ip)/TCP(sport=random.randint(1024, 65535), 
                                                                 dport=target_port, 
                                                                 flags='S')
                send(packet, verbose=0)
                time.sleep(0.003)
            except:
                break
    
    def generate_ddos(self):
        #Simulate DDoS attack with Scapy
        attacker_ips = [f'203.0.113.{i}' for i in range(1, 21)]
        target_ip = '192.168.1.1'
        
        create_alert('low', 'Attack Started', 
                    'DDoS attack simulation initiated',
                    'Multiple IPs', target_ip,
                    {'attack_type': 'ddos', 'attacker_count': len(attacker_ips)})
        
        print(f"[*] Launching DDoS with {len(attacker_ips)} IPs to {target_ip}")
        
        for i in range(500):
            if not self.running or self.attack_mode != 'ddos':
                break
            try:
                attacker = random.choice(attacker_ips)
                packet = IP(src=attacker, dst=target_ip)/ICMP()
                send(packet, verbose=0)
                time.sleep(0.002)
            except:
                break
    
    def generate_sql_injection(self):
        #Simulate SQL injection attempts
        attacker_ip = f'198.18.0.{random.randint(1, 254)}'
        target_ip = '192.168.1.100'
        
        create_alert('low', 'Attack Started', 
                    'SQL injection attack simulation initiated',
                    attacker_ip, target_ip,
                    {'attack_type': 'sql_injection'})
        
        print(f"[*] Launching SQL injection from {attacker_ip} to {target_ip}")
        
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL, username, password FROM users--",
            "1; DROP TABLE users--",
            "' AND 1=1--",
            "admin'--",
            "' OR 1=1--"
        ]
        
        for i in range(20):
            if not self.running or self.attack_mode != 'sql_injection':
                break
            try:
                payload = f"GET /login?username=admin&password={random.choice(payloads)}"
                packet = IP(src=attacker_ip, dst=target_ip)/TCP(sport=random.randint(49152, 65535), 
                                                                 dport=80, 
                                                                 flags='PA')/Raw(load=payload)
                send(packet, verbose=0)
                time.sleep(random.uniform(0.1, 0.3))
            except:
                break
    
    def generate_xss(self):
        #Simulate XSS attempts
        attacker_ip = f'198.18.0.{random.randint(1, 254)}'
        target_ip = '192.168.1.100'
        
        create_alert('low', 'Attack Started', 
                    'XSS attack simulation initiated',
                    attacker_ip, target_ip,
                    {'attack_type': 'xss'})
        
        print(f"[*] Launching XSS from {attacker_ip} to {target_ip}")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<iframe src='javascript:alert(1)'>",
            "<body onload=alert('XSS')>"
        ]
        
        for i in range(15):
            if not self.running or self.attack_mode != 'xss':
                break
            try:
                payload = f"POST /comment HTTP/1.1\r\nContent: {random.choice(payloads)}"
                packet = IP(src=attacker_ip, dst=target_ip)/TCP(sport=random.randint(49152, 65535), 
                                                                 dport=80, 
                                                                 flags='PA')/Raw(load=payload)
                send(packet, verbose=0)
                time.sleep(random.uniform(0.1, 0.3))
            except:
                break
    
    def generate_arp_spoofing(self):
        #Simulate ARP spoofing attack
        attacker_mac = "00:11:22:33:44:55"
        victim_ip = "192.168.1.100"
        gateway_ip = "192.168.1.1"
        
        create_alert('low', 'Attack Started', 
                    'ARP spoofing attack simulation initiated',
                    victim_ip, gateway_ip,
                    {'attack_type': 'arp_spoofing'})
        
        print(f"[*] Launching ARP spoofing attack")
        
        for i in range(10):
            if not self.running or self.attack_mode != 'arp_spoofing':
                break
            try:
                # Send spoofed ARP reply
                packet = ARP(op=2, psrc=gateway_ip, hwsrc=attacker_mac, pdst=victim_ip)
                send(packet, verbose=0)
                time.sleep(0.5)
            except:
                break
    
    def start(self, mode='normal'):
        #Start traffic generation
        self.running = True
        self.attack_mode = mode
        
        attack_methods = {
            'normal': self.generate_normal_traffic,
            'port_scan': self.generate_port_scan,
            'syn_flood': self.generate_syn_flood,
            'ddos': self.generate_ddos,
            'sql_injection': self.generate_sql_injection,
            'xss': self.generate_xss,
            'arp_spoofing': self.generate_arp_spoofing
        }
        
        if mode in attack_methods:
            thread = threading.Thread(target=attack_methods[mode], daemon=True)
            thread.start()
    
    def stop(self):
        #Stop traffic generation
        self.running = False
        self.attack_mode = None

traffic_gen = TrafficGenerator()

# Dashboard HTML
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Network IDS - Scapy Edition</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #fff;
            padding: 20px;
        }
        .container { max-width: 1600px; margin: 0 auto; }
        h1 {
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .mode-badge {
            display: inline-block;
            background: rgba(68, 255, 68, 0.3);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.5em;
            margin-left: 15px;
            border: 2px solid rgba(68, 255, 68, 0.5);
        }
        .controls-section {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: 15px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            margin-bottom: 30px;
        }
        .controls-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 20px;
            border-radius: 15px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        .stat-label {
            font-size: 0.9em;
            opacity: 0.8;
            margin-bottom: 10px;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
        }
        .content-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 30px;
        }
        .alerts-section, .chart-container {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: 15px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .alerts-section {
            max-height: 600px;
            overflow-y: auto;
        }
        .alert-item {
            background: rgba(0, 0, 0, 0.2);
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 10px;
            border-left: 4px solid;
            animation: slideIn 0.3s ease;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        .alert-high { border-left-color: #ff4444; }
        .alert-medium { border-left-color: #ffaa00; }
        .alert-low { border-left-color: #44ff44; }
        .alert-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-weight: bold;
        }
        .alert-details {
            font-size: 0.9em;
            opacity: 0.9;
            line-height: 1.6;
        }
        button {
            background: rgba(255, 255, 255, 0.2);
            border: 2px solid rgba(255, 255, 255, 0.3);
            color: white;
            padding: 12px 20px;
            border-radius: 10px;
            cursor: pointer;
            font-size: 0.95em;
            transition: all 0.3s;
            width: 100%;
        }
        button:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: translateY(-2px);
        }
        button.danger {
            background: rgba(255, 68, 68, 0.3);
            border-color: rgba(255, 68, 68, 0.5);
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #44ff44;
            animation: pulse 2s infinite;
            margin-right: 8px;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        h2 {
            margin-bottom: 20px;
            display: flex;
            align-items: center;
        }
        @media (max-width: 1200px) {
            .content-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Advanced Network IDS <span class="mode-badge">Scapy Edition</span></h1>
        
        <div class="controls-section">
            <h2>🚀 Attack Simulator (Scapy Packet Injection)</h2>
            <div class="controls-grid">
                <button onclick="startAttack('normal')">▶️ Normal Traffic</button>
                <button onclick="startAttack('port_scan')">🔍 Port Scan</button>
                <button onclick="startAttack('syn_flood')">🌊 SYN Flood</button>
                <button onclick="startAttack('ddos')">💥 DDoS Attack</button>
                <button onclick="startAttack('sql_injection')">💉 SQL Injection</button>
                <button onclick="startAttack('xss')">🚨 XSS Attack</button>
                <button onclick="startAttack('arp_spoofing')">🎭 ARP Spoofing</button>
                <button class="danger" onclick="stopAttack()">⏹️ Stop Attack</button>
            </div>
            <div style="margin-top: 15px; text-align: center; opacity: 0.8;">
                <small>💡 Attacks use real Scapy packets. Also monitoring live network traffic!</small>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Packets</div>
                <div class="stat-value" id="total-packets">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">TCP Packets</div>
                <div class="stat-value" id="tcp-packets">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">UDP Packets</div>
                <div class="stat-value" id="udp-packets">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">ICMP Packets</div>
                <div class="stat-value" id="icmp-packets">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Threats Detected</div>
                <div class="stat-value" id="suspicious-packets" style="color: #ff4444;">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Active Alerts</div>
                <div class="stat-value" id="active-alerts">0</div>
            </div>
        </div>
        
        <div class="content-grid">
            <div class="chart-container">
                <h2>📊 Traffic Distribution</h2>
                <canvas id="trafficChart"></canvas>
            </div>
            
            <div class="alerts-section">
                <h2><span class="status-indicator"></span>Live Alerts</h2>
                <div style="text-align: center; margin-bottom: 15px;">
                    <button onclick="clearAlerts()" style="width: auto; padding: 8px 20px;">Clear Alerts</button>
                    <button onclick="exportAlerts()" style="width: auto; padding: 8px 20px;">Export JSON</button>
                </div>
                <div id="alerts-container">
                    <div style="text-align: center; opacity: 0.6; padding: 40px;">
                        Monitoring network... Launch an attack to test detection!
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        const socket = io();
        let alertsCount = 0;
        
        const ctx = document.getElementById('trafficChart').getContext('2d');
        const trafficChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'ARP', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.8)',
                        'rgba(54, 162, 235, 0.8)',
                        'rgba(255, 206, 86, 0.8)',
                        'rgba(75, 192, 192, 0.8)',
                        'rgba(153, 102, 255, 0.8)'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { 
                        labels: { color: 'white', font: { size: 14 } }
                    }
                }
            }
        });
        
        socket.on('new_alert', function(alert) {
            alertsCount++;
            const container = document.getElementById('alerts-container');
            
            if (alertsCount === 1) {
                container.innerHTML = '';
            }
            
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert-item alert-${alert.severity}`;
            alertDiv.innerHTML = `
                <div class="alert-header">
                    <span>${alert.type}</span>
                    <span>${alert.timestamp}</span>
                </div>
                <div class="alert-details">
                    <div><strong>Message:</strong> ${alert.message}</div>
                    ${alert.src_ip ? `<div><strong>Source:</strong> ${alert.src_ip}</div>` : ''}
                    ${alert.dst_ip ? `<div><strong>Target:</strong> ${alert.dst_ip}</div>` : ''}
                    ${Object.keys(alert.details).length > 0 ? 
                        `<div><strong>Details:</strong> ${JSON.stringify(alert.details)}</div>` : ''}
                </div>
            `;
            container.insertBefore(alertDiv, container.firstChild);
            
            document.getElementById('active-alerts').textContent = alertsCount;
        });
        
        socket.on('traffic_update', function(stats) {
            document.getElementById('total-packets').textContent = stats.total_packets.toLocaleString();
            document.getElementById('tcp-packets').textContent = stats.tcp_packets.toLocaleString();
            document.getElementById('udp-packets').textContent = stats.udp_packets.toLocaleString();
            document.getElementById('icmp-packets').textContent = stats.icmp_packets.toLocaleString();
            document.getElementById('suspicious-packets').textContent = stats.suspicious_packets.toLocaleString();
            
            const other = stats.total_packets - stats.tcp_packets - stats.udp_packets - 
                         stats.icmp_packets - stats.arp_packets;
            trafficChart.data.datasets[0].data = [
                stats.tcp_packets, stats.udp_packets, stats.icmp_packets, 
                stats.arp_packets, other
            ];
            trafficChart.update();
        });
        
        function startAttack(mode) {
            fetch('/start_attack', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({mode: mode})
            })
            .then(r => r.json())
            .then(data => {
                console.log('Attack started:', mode);
            });
        }
        
        function stopAttack() {
            fetch('/stop_attack', {method: 'POST'})
            .then(r => r.json())
            .then(data => {
                console.log('Attack stopped');
            });
        }
        
        function clearAlerts() {
            fetch('/clear_alerts', {method: 'POST'})
                .then(() => {
                    document.getElementById('alerts-container').innerHTML = 
                        '<div style="text-align: center; opacity: 0.6; padding: 40px;">Alerts cleared</div>';
                    alertsCount = 0;
                    document.getElementById('active-alerts').textContent = '0';
                });
        }
        
        function exportAlerts() {
            fetch('/get_alerts')
                .then(r => r.json())
                .then(data => {
                    const blob = new Blob([JSON.stringify(data, null, 2)], 
                                         {type: 'application/json'});
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `ids_alerts_${Date.now()}.json`;
                    a.click();
                });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route('/get_stats')
def get_stats():
    return jsonify(traffic_stats)

@app.route('/get_alerts')
def get_alerts():
    return jsonify(list(alerts))

@app.route('/clear_alerts', methods=['POST'])
def clear_alerts_route():
    alerts.clear()
    return jsonify({'status': 'success'})

@app.route('/start_attack', methods=['POST'])
def start_attack():
    """Start attack simulation"""
    data = request.get_json()
    mode = data.get('mode', 'normal')
    
    traffic_gen.stop()
    time.sleep(0.1)
    traffic_gen.start(mode)
    
    return jsonify({
        'status': 'success', 
        'message': f'Started {mode} simulation',
        'mode': mode
    })

@app.route('/stop_attack', methods=['POST'])
def stop_attack():
    """Stop attack simulation"""
    traffic_gen.stop()
    return jsonify({'status': 'success', 'message': 'Attack stopped'})

def run_flask():
    """Run Flask server"""
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Advanced Network IDS with Scapy')
    parser.add_argument('--simulate', action='store_true', 
                       help='Use simulator only (no real packet capture)')
    parser.add_argument('--interface', type=str, default=None,
                       help='Network interface to monitor (e.g., eth0, wlan0)')
    args = parser.parse_args()
    
    USE_SIMULATOR = args.simulate
    
    print("="*70)
    print(" Advanced Network Intrusion Detection System - Scapy Edition")
    print("="*70)
    
    if USE_SIMULATOR:
        print(f"\n[!] Running in SIMULATOR MODE (no real packet capture)")
    else:
        print(f"\n[+] Running in REAL CAPTURE MODE")
        print(f"    • Windows: Npcap installed (https://npcap.com/)")
        print(f"    • Linux/Mac: Run with sudo")
    
    print(f"\n[+] Dashboard: http://localhost:5000")
    print(f"\n[+] Detection Capabilities:")
    print(f"    -> Port Scanning Detection")
    print(f"    -> SYN Flood Attack Detection")
    print(f"    -> DDoS Attack Detection")
    print(f"    -> SQL Injection Detection")
    print(f"    -> XSS Attack Detection")
    print(f"    -> ARP Spoofing Detection")
    print(f"    -> Payload Analysis & Pattern Matching")
    print(f"    -> Suspicious Port Monitoring")
    print(f"\n[!] Press Ctrl+C to stop\n")
    print("="*70)
    
    # Start Flask in separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    # Small delay to ensure Flask starts
    time.sleep(2)
    
    # Start packet capture in main thread (unless simulator-only mode)
    if not USE_SIMULATOR:
        try:
            start_packet_capture()
        except KeyboardInterrupt:
            print("\n[!] Shutting down IDS...")
            traffic_gen.stop()
        except PermissionError:
            print("\n[!] ERROR: Insufficient privileges!")
            print("[!] Please run with administrator/root privileges:")
            print("[!]   Windows: Run as Administrator")
            print("[!]   Linux/Mac: sudo python ids_system.py")
        except Exception as e:
            print(f"\n[!] Error: {e}")
            print("[!] Make sure Npcap (Windows) is installed or run with sudo (Linux/Mac)")
            print("[!] Alternatively, run in simulator mode: python ids_system.py --simulate")
    else:
        print("\n[+] Simulator mode - Use dashboard to launch attacks")
        try:
            # Keep main thread alive
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] Shutting down IDS...")
            traffic_gen.stop()