from flask import Flask, render_template_string, jsonify
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter, deque
from datetime import datetime
import threading
import time
import socket
import numpy as np
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

# ========== GLOBAL DATA STORE ==========
packet_data = {
    'total': 0,
    'tcp': 0,
    'udp': 0,
    'icmp': 0,
    'other': 0,
    'anomalies': 0,
    'packets': deque(maxlen=100),  # Store last 100 packets
    'protocol_history': deque(maxlen=50),
    'top_sources': {},
    'top_destinations': {}
}

is_capturing = False
capture_thread = None
anomaly_model = None

# ========== HTML TEMPLATE ==========
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Net-Watch Live Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 {
            font-size: 28px;
            margin-bottom: 10px;
            color: #58a6ff;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .subtitle { color: #8b949e; margin-bottom: 25px; font-size: 14px; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        .stat-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 15px 20px;
            text-align: center;
        }
        .stat-card .number {
            font-size: 32px;
            font-weight: bold;
            color: #58a6ff;
        }
        .stat-card .label {
            font-size: 12px;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 5px;
        }
        .stat-card.anomaly .number { color: #f85149; }
        .stat-card.threat .number { color: #d29922; }

        .main-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
        }
        @media (max-width: 900px) {
            .main-grid { grid-template-columns: 1fr; }
        }

        .panel {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 15px;
        }
        .panel h2 {
            font-size: 16px;
            color: #8b949e;
            margin-bottom: 10px;
            border-bottom: 1px solid #30363d;
            padding-bottom: 8px;
        }

        .packet-list {
            max-height: 400px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        .packet-item {
            display: grid;
            grid-template-columns: 50px 80px 120px 120px 60px 60px 1fr;
            gap: 5px;
            padding: 4px 8px;
            border-bottom: 1px solid #21262d;
        }
        .packet-item:hover { background: #1c2128; }
        .packet-item .anomaly-badge {
            color: #f85149;
            font-weight: bold;
        }
        .packet-item .protocol-badge {
            padding: 0 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }
        .protocol-badge.tcp { color: #58a6ff; }
        .protocol-badge.udp { color: #3fb950; }
        .protocol-badge.icmp { color: #d29922; }
        .protocol-badge.other { color: #8b949e; }

        .top-list {
            list-style: none;
            font-size: 14px;
        }
        .top-list li {
            display: flex;
            justify-content: space-between;
            padding: 4px 0;
            border-bottom: 1px solid #21262d;
        }
        .top-list .count {
            color: #58a6ff;
            font-weight: bold;
        }

        .status-bar {
            margin-top: 20px;
            padding: 10px 15px;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            font-size: 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .status-dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-dot.active { background: #3fb950; }
        .status-dot.inactive { background: #8b949e; }

        .refresh-note {
            color: #8b949e;
            font-size: 12px;
            margin-top: 10px;
            text-align: right;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Net-Watch Live Dashboard</h1>
        <div class="subtitle">Real-time network traffic analysis • Auto-refreshes every 3 seconds</div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="number" id="total-packets">0</div>
                <div class="label">Total Packets</div>
            </div>
            <div class="stat-card">
                <div class="number" id="tcp-count">0</div>
                <div class="label">TCP</div>
            </div>
            <div class="stat-card">
                <div class="number" id="udp-count">0</div>
                <div class="label">UDP</div>
            </div>
            <div class="stat-card">
                <div class="number" id="icmp-count">0</div>
                <div class="label">ICMP</div>
            </div>
            <div class="stat-card anomaly">
                <div class="number" id="anomaly-count">0</div>
                <div class="label">⚠️ Anomalies</div>
            </div>
            <div class="stat-card threat">
                <div class="number" id="threat-score">0%</div>
                <div class="label">Threat Score</div>
            </div>
        </div>

        <div class="main-grid">
            <div class="panel">
                <h2>📋 Recent Packets <span style="color:#8b949e;font-weight:normal;font-size:12px;">(last 100)</span></h2>
                <div class="packet-list" id="packet-list">
                    <div style="color:#8b949e;text-align:center;padding:20px;">Waiting for packets...</div>
                </div>
            </div>

            <div>
                <div class="panel" style="margin-bottom:15px;">
                    <h2>📊 Top Sources</h2>
                    <ul class="top-list" id="top-sources">
                        <li style="color:#8b949e;text-align:center;padding:10px;">No data yet</li>
                    </ul>
                </div>
                <div class="panel">
                    <h2>🎯 Top Destinations</h2>
                    <ul class="top-list" id="top-destinations">
                        <li style="color:#8b949e;text-align:center;padding:10px;">No data yet</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="status-bar">
            <span>
                <span class="status-dot {{ 'active' if is_capturing else 'inactive' }}" id="status-dot"></span>
                <span id="status-text">{{ '🟢 Capturing' if is_capturing else '⏸️ Stopped' }}</span>
                <span style="color:#8b949e;margin-left:15px;">Interface: <strong>{{ interface or 'Not selected' }}</strong></span>
            </span>
            <span style="color:#8b949e;font-size:13px;">Updated: <span id="last-updated">Just now</span></span>
        </div>
        <div class="refresh-note">🔄 Auto-refreshes every 3 seconds</div>
    </div>

    <script>
        function fetchData() {
            fetch('/api/stats')
                .then(res => res.json())
                .then(data => {
                    // Update stats
                    document.getElementById('total-packets').textContent = data.total;
                    document.getElementById('tcp-count').textContent = data.tcp;
                    document.getElementById('udp-count').textContent = data.udp;
                    document.getElementById('icmp-count').textContent = data.icmp;
                    document.getElementById('anomaly-count').textContent = data.anomalies;
                    document.getElementById('threat-score').textContent = data.threat_score + '%';

                    // Update packet list
                    const list = document.getElementById('packet-list');
                    if (data.packets.length === 0) {
                        list.innerHTML = '<div style="color:#8b949e;text-align:center;padding:20px;">No packets captured yet</div>';
                    } else {
                        list.innerHTML = data.packets.map(p => `
                            <div class="packet-item">
                                <span>#${p.id}</span>
                                <span style="color:#8b949e;">${p.time}</span>
                                <span style="color:#58a6ff;">${p.src}</span>
                                <span style="color:#3fb950;">${p.dst}</span>
                                <span class="protocol-badge ${p.protocol.toLowerCase()}">${p.protocol}</span>
                                <span>${p.length}</span>
                                <span>${p.anomaly ? '<span class="anomaly-badge">⚠️</span>' : ''}</span>
                            </div>
                        `).join('');
                    }

                    // Update top sources
                    const srcList = document.getElementById('top-sources');
                    if (Object.keys(data.top_sources).length === 0) {
                        srcList.innerHTML = '<li style="color:#8b949e;text-align:center;padding:10px;">No data yet</li>';
                    } else {
                        srcList.innerHTML = Object.entries(data.top_sources)
                            .slice(0, 8)
                            .map(([ip, count]) => `<li><span>${ip}</span><span class="count">${count}</span></li>`)
                            .join('');
                    }

                    // Update top destinations
                    const dstList = document.getElementById('top-destinations');
                    if (Object.keys(data.top_destinations).length === 0) {
                        dstList.innerHTML = '<li style="color:#8b949e;text-align:center;padding:10px;">No data yet</li>';
                    } else {
                        dstList.innerHTML = Object.entries(data.top_destinations)
                            .slice(0, 8)
                            .map(([ip, count]) => `<li><span>${ip}</span><span class="count">${count}</span></li>`)
                            .join('');
                    }

                    // Update status
                    document.getElementById('status-dot').className = 'status-dot ' + (data.is_capturing ? 'active' : 'inactive');
                    document.getElementById('status-text').textContent = data.is_capturing ? '🟢 Capturing' : '⏸️ Stopped';
                    document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();
                })
                .catch(err => console.error('Error fetching data:', err));
        }

        // Fetch immediately and then every 3 seconds
        fetchData();
        setInterval(fetchData, 3000);
    </script>
</body>
</html>
"""

# ========== ANOMALY DETECTION MODEL ==========
def train_initial_model():
    """Train a simple Isolation Forest model for anomaly detection"""
    normal_data = []
    for _ in range(100):
        normal_data.append([
            np.random.randint(40, 1500),    # packet length
            np.random.randint(50, 128),     # TTL
            np.random.randint(40, 1500),    # IP length
            np.random.randint(1024, 65535), # source port
            np.random.choice([80, 443, 22, 53]),  # dest port
            np.random.randint(5000, 65000), # window size
        ])
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(normal_data)
    return model

anomaly_model = train_initial_model()

# ========== PACKET PROCESSING ==========
def extract_features(packet):
    """Extract numerical features from a packet for anomaly detection"""
    try:
        features = [
            len(packet),
            packet[IP].ttl if IP in packet else 64,
            packet[IP].len if IP in packet else len(packet),
        ]
        if TCP in packet:
            features.extend([
                packet[TCP].sport,
                packet[TCP].dport,
                packet[TCP].window,
            ])
        elif UDP in packet:
            features.extend([
                packet[UDP].sport,
                packet[UDP].dport,
                0,
            ])
        else:
            features.extend([0, 0, 0])
        return features
    except:
        return None

def packet_callback(packet):
    """Called by Scapy for each captured packet"""
    global packet_data, anomaly_model

    packet_info = {
        'id': packet_data['total'] + 1,
        'time': datetime.now().strftime("%H:%M:%S"),
        'src': 'N/A',
        'dst': 'N/A',
        'protocol': 'Other',
        'length': len(packet),
        'anomaly': False
    }

    if IP in packet:
        packet_info['src'] = packet[IP].src
        packet_info['dst'] = packet[IP].dst

        if TCP in packet:
            packet_info['protocol'] = 'TCP'
            packet_data['tcp'] += 1
        elif UDP in packet:
            packet_info['protocol'] = 'UDP'
            packet_data['udp'] += 1
        elif ICMP in packet:
            packet_info['protocol'] = 'ICMP'
            packet_data['icmp'] += 1
        else:
            packet_data['other'] += 1

    # Anomaly detection
    features = extract_features(packet)
    if features and len(features) == 7:
        try:
            pred = anomaly_model.predict([features])
            if pred[0] == -1:
                packet_info['anomaly'] = True
                packet_data['anomalies'] += 1
        except:
            pass

    # Update top sources/destinations
    if packet_info['src'] != 'N/A':
        packet_data['top_sources'][packet_info['src']] = packet_data['top_sources'].get(packet_info['src'], 0) + 1
    if packet_info['dst'] != 'N/A':
        packet_data['top_destinations'][packet_info['dst']] = packet_data['top_destinations'].get(packet_info['dst'], 0) + 1

    # Store packet
    packet_data['packets'].append(packet_info)
    packet_data['total'] += 1

    # Limit top lists
    if len(packet_data['top_sources']) > 20:
        packet_data['top_sources'] = dict(sorted(packet_data['top_sources'].items(), key=lambda x: x[1], reverse=True)[:15])
    if len(packet_data['top_destinations']) > 20:
        packet_data['top_destinations'] = dict(sorted(packet_data['top_destinations'].items(), key=lambda x: x[1], reverse=True)[:15])

# ========== CAPTURE THREAD ==========
def start_capture_loop(interface='eth0'):
    """Start packet capture in a background thread"""
    global is_capturing
    is_capturing = True
    try:
        sniff(iface=interface, prn=packet_callback, store=False, stop_filter=lambda x: not is_capturing)
    except Exception as e:
        print(f"Capture error: {e}")
        is_capturing = False

def stop_capture():
    global is_capturing
    is_capturing = False

# ========== FLASK ROUTES ==========
@app.route('/')
def index():
    """Serve the main dashboard HTML"""
    return render_template_string(
        HTML_TEMPLATE,
        is_capturing=is_capturing,
        interface=getattr(app, 'selected_interface', 'Not selected')
    )

@app.route('/api/stats')
def api_stats():
    """Return current statistics as JSON"""
    total = packet_data['total']
    threat_score = min(100, int((packet_data['anomalies'] / max(total, 1)) * 150))

    # Convert deque to list for JSON
    packets_list = list(packet_data['packets'])[::-1]  # Newest first

    return jsonify({
        'total': total,
        'tcp': packet_data['tcp'],
        'udp': packet_data['udp'],
        'icmp': packet_data['icmp'],
        'other': packet_data['other'],
        'anomalies': packet_data['anomalies'],
        'threat_score': threat_score,
        'packets': packets_list,
        'top_sources': dict(sorted(packet_data['top_sources'].items(), key=lambda x: x[1], reverse=True)[:8]),
        'top_destinations': dict(sorted(packet_data['top_destinations'].items(), key=lambda x: x[1], reverse=True)[:8]),
        'is_capturing': is_capturing
    })

@app.route('/api/start')
def api_start():
    """Start packet capture (admin-only in production)"""
    global capture_thread, is_capturing
    if not is_capturing:
        interface = app.selected_interface if hasattr(app, 'selected_interface') else 'eth0'
        capture_thread = threading.Thread(target=start_capture_loop, args=(interface,), daemon=True)
        capture_thread.start()
        return jsonify({'status': 'started', 'interface': interface})
    return jsonify({'status': 'already_running'})

@app.route('/api/stop')
def api_stop():
    """Stop packet capture"""
    stop_capture()
    return jsonify({'status': 'stopped'})

@app.route('/api/interface/<iface>')
def api_set_interface(iface):
    """Set the network interface to use"""
    app.selected_interface = iface
    return jsonify({'status': 'set', 'interface': iface})

# ========== MAIN ==========
if __name__ == '__main__':
    # Default interface - change this if needed
    app.selected_interface = 'eth0'  # Common on Linux, use 'Wi-Fi' or 'en0' on Mac
    
    # Start capture automatically on boot
    capture_thread = threading.Thread(target=start_capture_loop, args=(app.selected_interface,), daemon=True)
    capture_thread.start()
    
    # Run Flask
    app.run(debug=False, host='0.0.0.0', port=10000)
