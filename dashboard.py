"""
S3niffRade Dashboard Module
Provides a web-based dashboard for real-time visualization of network traffic and alerts
"""

import os
import json
import threading
import time
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

# Create Flask app and SocketIO instance
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*")

# Global reference to the analyzer
analyzer = None

# Dashboard data
dashboard_data = {
    "packets": [],
    "alerts": [],
    "stats": {
        "total_packets": 0,
        "protocols": {},
        "top_src_ips": [],
        "top_dst_ips": []
    }
}

# Dashboard update interval (seconds)
UPDATE_INTERVAL = 1.0

@app.route('/')
def index():
    """Render the main dashboard page"""
    return render_template('index.html')

@app.route('/api/data')
def get_data():
    """API endpoint to get current dashboard data"""
    global dashboard_data
    return jsonify(dashboard_data)

@app.route('/api/alerts')
def get_alerts():
    """API endpoint to get alerts"""
    global dashboard_data
    return jsonify(dashboard_data["alerts"])

@app.route('/api/packets')
def get_packets():
    """API endpoint to get recent packets"""
    global dashboard_data
    limit = request.args.get('limit', default=100, type=int)
    return jsonify(dashboard_data["packets"][-limit:])

@app.route('/api/stats')
def get_stats():
    """API endpoint to get statistics"""
    global dashboard_data
    return jsonify(dashboard_data["stats"])

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print("Client connected to dashboard")

def update_dashboard_data():
    """Update dashboard data from analyzer"""
    global analyzer, dashboard_data
    
    while True:
        if analyzer:
            # Update packets
            dashboard_data["packets"] = analyzer.dashboard_data["packets"]
            
            # Update alerts
            dashboard_data["alerts"] = analyzer.dashboard_data["alerts"]
            
            # Update statistics
            dashboard_data["stats"]["total_packets"] = analyzer.stats["total_packets"]
            dashboard_data["stats"]["protocols"] = analyzer.stats["protocols"]
            
            # Calculate top source IPs
            src_ips = analyzer.stats["src_ips"]
            dashboard_data["stats"]["top_src_ips"] = [
                {"ip": ip, "count": count}
                for ip, count in sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]
            ]
            
            # Calculate top destination IPs
            dst_ips = analyzer.stats["dst_ips"]
            dashboard_data["stats"]["top_dst_ips"] = [
                {"ip": ip, "count": count}
                for ip, count in sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:10]
            ]
            
            # Emit updates to connected clients
            socketio.emit('data_update', dashboard_data)
        
        time.sleep(UPDATE_INTERVAL)

def start_dashboard(packet_analyzer, host='127.0.0.1', port=5000):
    """Start the dashboard server"""
    global analyzer
    analyzer = packet_analyzer
    
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Create static directory if it doesn't exist
    os.makedirs('static', exist_ok=True)
    
    # Create HTML template
    create_html_template()
    
    # Create CSS file
    create_css_file()
    
    # Create JavaScript file
    create_js_file()
    
    # Start dashboard update thread
    threading.Thread(target=update_dashboard_data, daemon=True).start()
    
    # Start Flask server
    print(f"Starting dashboard on http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=False, use_reloader=False)

def create_html_template():
    """Create the HTML template for the dashboard"""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>S3niffRade - Network Packet Analyzer</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.socket.io/4.6.0/socket.io.min.js"></script>
</head>
<body>
    <header>
        <h1>S3niffRade</h1>
        <p>Network Packet Analyzer with Threat Detection</p>
    </header>
    
    <div class="dashboard">
        <div class="stats-container">
            <div class="stat-box">
                <h3>Packet Statistics</h3>
                <div class="stat-item">
                    <span>Total Packets:</span>
                    <span id="total-packets">0</span>
                </div>
                <div class="chart-container">
                    <canvas id="protocol-chart"></canvas>
                </div>
            </div>
            
            <div class="stat-box">
                <h3>Top Source IPs</h3>
                <div class="chart-container">
                    <canvas id="src-ip-chart"></canvas>
                </div>
            </div>
            
            <div class="stat-box">
                <h3>Top Destination IPs</h3>
                <div class="chart-container">
                    <canvas id="dst-ip-chart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="data-container">
            <div class="alerts-container">
                <h3>Security Alerts</h3>
                <div class="filter-bar">
                    <select id="alert-severity-filter">
                        <option value="all">All Severities</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                    <select id="alert-type-filter">
                        <option value="all">All Types</option>
                        <option value="ARP Spoofing">ARP Spoofing</option>
                        <option value="DNS Tunneling">DNS Tunneling</option>
                        <option value="Port Scanning">Port Scanning</option>
                    </select>
                    <input type="text" id="alert-search" placeholder="Search alerts...">
                </div>
                <div class="alerts-list" id="alerts-list">
                    <!-- Alerts will be populated here -->
                </div>
            </div>
            
            <div class="packets-container">
                <h3>Recent Packets</h3>
                <div class="filter-bar">
                    <select id="packet-protocol-filter">
                        <option value="all">All Protocols</option>
                        <option value="TCP">TCP</option>
                        <option value="UDP">UDP</option>
                        <option value="ICMP">ICMP</option>
                        <option value="DNS">DNS</option>
                        <option value="ARP">ARP</option>
                    </select>
                    <input type="text" id="packet-search" placeholder="Search packets...">
                </div>
                <div class="packets-list" id="packets-list">
                    <!-- Packets will be populated here -->
                </div>
            </div>
        </div>
    </div>
    
    <script src="{{ url_for('static', filename='dashboard.js') }}"></script>
</body>
</html>"""
    
    with open('templates/index.html', 'w') as f:
        f.write(html_content)

def create_css_file():
    """Create the CSS file for the dashboard"""
    css_content = """/* S3niffRade Dashboard Styles */

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

body {
    background-color: #f0f2f5;
    color: #333;
}

header {
    background-color: #2c3e50;
    color: white;
    padding: 1rem;
    text-align: center;
}

header h1 {
    margin-bottom: 0.5rem;
}

.dashboard {
    max-width: 1400px;
    margin: 1rem auto;
    padding: 1rem;
    display: grid;
    grid-template-columns: 1fr;
    gap: 1rem;
}

@media (min-width: 1200px) {
    .dashboard {
        grid-template-columns: 1fr 2fr;
    }
}

.stats-container {
    display: grid;
    grid-template-columns: 1fr;
    gap: 1rem;
}

.stat-box {
    background-color: white;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    padding: 1rem;
}

.stat-box h3 {
    margin-bottom: 1rem;
    color: #2c3e50;
    border-bottom: 1px solid #eee;
    padding-bottom: 0.5rem;
}

.stat-item {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.5rem;
}

.chart-container {
    height: 200px;
    margin-top: 1rem;
}

.data-container {
    display: grid;
    grid-template-columns: 1fr;
    gap: 1rem;
}

.alerts-container, .packets-container {
    background-color: white;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    padding: 1rem;
}

.alerts-container h3, .packets-container h3 {
    margin-bottom: 1rem;
    color: #2c3e50;
    border-bottom: 1px solid #eee;
    padding-bottom: 0.5rem;
}

.filter-bar {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
}

.filter-bar select, .filter-bar input {
    padding: 0.5rem;
    border: 1px solid #ddd;
    border-radius: 4px;
}

.filter-bar input {
    flex-grow: 1;
}

.alerts-list, .packets-list {
    max-height: 400px;
    overflow-y: auto;
}

.alert-item {
    padding: 0.75rem;
    border-left: 4px solid #e74c3c;
    background-color: #fef5f5;
    margin-bottom: 0.5rem;
    border-radius: 0 4px 4px 0;
}

.alert-item.medium {
    border-left-color: #f39c12;
    background-color: #fef9e7;
}

.alert-item.low {
    border-left-color: #3498db;
    background-color: #eaf2f8;
}

.alert-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.25rem;
    font-weight: bold;
}

.alert-time {
    font-size: 0.8rem;
    color: #777;
}

.alert-message {
    font-size: 0.9rem;
}

.packet-item {
    padding: 0.5rem;
    border-bottom: 1px solid #eee;
    display: grid;
    grid-template-columns: 100px 1fr 1fr 1fr;
    gap: 0.5rem;
    font-size: 0.9rem;
}

.packet-item:hover {
    background-color: #f9f9f9;
}

.packet-protocol {
    font-weight: bold;
}

.packet-protocol.TCP { color: #2980b9; }
.packet-protocol.UDP { color: #27ae60; }
.packet-protocol.ICMP { color: #8e44ad; }
.packet-protocol.DNS { color: #d35400; }
.packet-protocol.ARP { color: #c0392b; }

@media (max-width: 768px) {
    .packet-item {
        grid-template-columns: 1fr;
    }
}"""
    
    with open('static/style.css', 'w') as f:
        f.write(css_content)

def create_js_file():
    """Create the JavaScript file for the dashboard"""
    js_content = """// S3niffRade Dashboard JavaScript

// Initialize Socket.IO connection
const socket = io();

// Charts
let protocolChart = null;
let srcIpChart = null;
let dstIpChart = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    initCharts();
    setupFilters();
    
    // Connect to Socket.IO for real-time updates
    socket.on('data_update', function(data) {
        updateDashboard(data);
    });
    
    // Initial data load
    fetchInitialData();
});

function fetchInitialData() {
    fetch('/api/data')
        .then(response => response.json())
        .then(data => {
            updateDashboard(data);
        })
        .catch(error => {
            console.error('Error fetching dashboard data:', error);
        });
}

function initCharts() {
    // Protocol distribution chart
    const protocolCtx = document.getElementById('protocol-chart').getContext('2d');
    protocolChart = new Chart(protocolCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#3498db', // TCP
                    '#2ecc71', // UDP
                    '#9b59b6', // ICMP
                    '#e74c3c', // ARP
                    '#f39c12', // DNS
                    '#1abc9c', // Other
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                }
            }
        }
    });
    
    // Source IP chart
    const srcIpCtx = document.getElementById('src-ip-chart').getContext('2d');
    srcIpChart = new Chart(srcIpCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Packet Count',
                data: [],
                backgroundColor: '#3498db',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
    
    // Destination IP chart
    const dstIpCtx = document.getElementById('dst-ip-chart').getContext('2d');
    dstIpChart = new Chart(dstIpCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Packet Count',
                data: [],
                backgroundColor: '#2ecc71',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

function updateDashboard(data) {
    // Update total packets
    document.getElementById('total-packets').textContent = data.stats.total_packets;
    
    // Update protocol chart
    updateProtocolChart(data.stats.protocols);
    
    // Update source IP chart
    updateSrcIpChart(data.stats.top_src_ips);
    
    // Update destination IP chart
    updateDstIpChart(data.stats.top_dst_ips);
    
    // Update alerts list
    updateAlertsList(data.alerts);
    
    // Update packets list
    updatePacketsList(data.packets);
}

function updateProtocolChart(protocols) {
    const labels = Object.keys(protocols);
    const data = Object.values(protocols);
    
    protocolChart.data.labels = labels;
    protocolChart.data.datasets[0].data = data;
    protocolChart.update();
}

function updateSrcIpChart(srcIps) {
    const labels = srcIps.map(item => item.ip);
    const data = srcIps.map(item => item.count);
    
    srcIpChart.data.labels = labels;
    srcIpChart.data.datasets[0].data = data;
    srcIpChart.update();
}

function updateDstIpChart(dstIps) {
    const labels = dstIps.map(item => item.ip);
    const data = dstIps.map(item => item.count);
    
    dstIpChart.data.labels = labels;
    dstIpChart.data.datasets[0].data = data;
    dstIpChart.update();
}

function updateAlertsList(alerts) {
    const alertsList = document.getElementById('alerts-list');
    const severityFilter = document.getElementById('alert-severity-filter').value;
    const typeFilter = document.getElementById('alert-type-filter').value;
    const searchFilter = document.getElementById('alert-search').value.toLowerCase();
    
    // Clear current alerts
    alertsList.innerHTML = '';
    
    // Filter alerts
    const filteredAlerts = alerts.filter(alert => {
        const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter;
        const matchesType = typeFilter === 'all' || alert.type === typeFilter;
        const matchesSearch = !searchFilter || 
                             alert.message.toLowerCase().includes(searchFilter) ||
                             alert.type.toLowerCase().includes(searchFilter);
        
        return matchesSeverity && matchesType && matchesSearch;
    });
    
    // Add filtered alerts to the list (most recent first)
    filteredAlerts.slice().reverse().forEach(alert => {
        const alertItem = document.createElement('div');
        alertItem.className = `alert-item ${alert.severity}`;
        
        const alertHeader = document.createElement('div');
        alertHeader.className = 'alert-header';
        
        const alertType = document.createElement('span');
        alertType.textContent = alert.type;
        
        const alertTime = document.createElement('span');
        alertTime.className = 'alert-time';
        alertTime.textContent = alert.timestamp;
        
        alertHeader.appendChild(alertType);
        alertHeader.appendChild(alertTime);
        
        const alertMessage = document.createElement('div');
        alertMessage.className = 'alert-message';
        alertMessage.textContent = alert.message;
        
        alertItem.appendChild(alertHeader);
        alertItem.appendChild(alertMessage);
        
        alertsList.appendChild(alertItem);
    });
    
    // Show message if no alerts match filters
    if (filteredAlerts.length === 0) {
        const noAlerts = document.createElement('div');
        noAlerts.textContent = 'No alerts match the current filters';
        noAlerts.style.padding = '1rem';
        noAlerts.style.fontStyle = 'italic';
        noAlerts.style.color = '#777';
        alertsList.appendChild(noAlerts);
    }
}

function updatePacketsList(packets) {
    const packetsList = document.getElementById('packets-list');
    const protocolFilter = document.getElementById('packet-protocol-filter').value;
    const searchFilter = document.getElementById('packet-search').value.toLowerCase();
    
    // Clear current packets
    packetsList.innerHTML = '';
    
    // Filter packets
    const filteredPackets = packets.filter(packet => {
        const matchesProtocol = protocolFilter === 'all' || packet.protocol === protocolFilter;
        const matchesSearch = !searchFilter || 
                             packet.src.toLowerCase().includes(searchFilter) ||
                             packet.dst.toLowerCase().includes(searchFilter) ||
                             packet.info.toLowerCase().includes(searchFilter);
        
        return matchesProtocol && matchesSearch;
    });
    
    // Add filtered packets to the list (most recent first)
    filteredPackets.slice().reverse().slice(0, 100).forEach(packet => {
        const packetItem = document.createElement('div');
        packetItem.className = 'packet-item';
        
        const packetTime = document.createElement('div');
        packetTime.textContent = packet.timestamp;
        
        const packetProtocol = document.createElement('div');
        packetProtocol.className = `packet-protocol ${packet.protocol}`;
        packetProtocol.textContent = packet.protocol;
        
        const packetSrcDst = document.createElement('div');
        packetSrcDst.textContent = `${packet.src} → ${packet.dst}`;
        
        const packetInfo = document.createElement('div');
        packetInfo.textContent = packet.info;
        
        packetItem.appendChild(packetTime);
        packetItem.appendChild(packetProtocol);
        packetItem.appendChild(packetSrcDst);
        packetItem.appendChild(packetInfo);
        
        packetsList.appendChild(packetItem);
    });
    
    // Show message if no packets match filters
    if (filteredPackets.length === 0) {
        const noPackets = document.createElement('div');
        noPackets.textContent = 'No packets match the current filters';
        noPackets.style.padding = '1rem';
        noPackets.style.fontStyle = 'italic';
        noPackets.style.color = '#777';
        packetsList.appendChild(noPackets);
    }
}

function setupFilters() {
    // Alert filters
    document.getElementById('alert-severity-filter').addEventListener('change', function() {
        fetch('/api/alerts')
            .then(response => response.json())
            .then(alerts => {
                updateAlertsList(alerts);
            });
    });
    
    document.getElementById('alert-type-filter').addEventListener('change', function() {
        fetch('/api/alerts')
            .then(response => response.json())
            .then(alerts => {
                updateAlertsList(alerts);
            });
    });
    
    document.getElementById('alert-search').addEventListener('input', function() {
        fetch('/api/alerts')
            .then(response => response.json())
            .then(alerts => {
                updateAlertsList(alerts);
            });
    });
    
    // Packet filters
    document.getElementById('packet-protocol-filter').addEventListener('change', function() {
        fetch('/api/packets')
            .then(response => response.json())
            .then(packets => {
                updatePacketsList(packets);
            });
    });
    
    document.getElementById('packet-search').addEventListener('input', function() {
        fetch('/api/packets')
            .then(response => response.json())
            .then(packets => {
                updatePacketsList(packets);
            });
    });
}"""
    
    with open('static/dashboard.js', 'w') as f:
        f.write(js_content)