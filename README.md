# Net-Watch

A simple but powerful GUI tool to monitor and analyze network traffic in real-time. Built with Python, Tkinter, and Scapy.

## Features
- **Live Packet Capture**: Capture network traffic from any interface
- **Protocol Analysis**: Identify TCP, UDP, ICMP, and ARP traffic
- **Anomaly Detection**: Machine learning-based detection of suspicious traffic
- **Real-time Stats**: Live counters for packets, bytes, and protocols
- **Dark/Light Theme**: Toggle between dark and light modes
- **Packet Details**: Inspect individual packets with hex/ASCII view

## Installation

### 1. Install Python
Make sure you have Python 3.8 or higher installed.

### 2. Install Required Packages
Open terminal/command prompt and run:

```bash
pip install scapy matplotlib pandas numpy scikit-learn psutil
```

### 3. Run the Application
```bash
python network_analyzer.py
```

## Quick Start Guide

### Step 1: Select Network Interface
1. Click "Select Interface" button
2. Choose your network interface from the list (e.g., "Wi-Fi", "Ethernet")
3. Click "Select"

### Step 2: Start Capture
1. Click "▶ Start Capture" button
2. Watch packets appear in real-time

### Step 3: Analyze Traffic
- **View Packets**: See captured packets in the main list
- **Packet Details**: Click any packet to see detailed information
- **Statistics**: Monitor packet counts in the dashboard
- **Anomalies**: Look for ⚠️ marks next to suspicious packets

### Step 4: Stop & Export
1. Click "⏹ Stop Capture" when done
2. Use "Clear" button to reset
3. Data is automatically saved for this session

## Basic Troubleshooting

### "No interfaces found" error
- Run as administrator (Windows) or use sudo (Linux/Mac)
- Make sure you're connected to a network

### "Scapy not working"
On Windows, install Npcap (not WinPcap): https://npcap.com/

### App is slow
- Reduce captured packets using filters
- Close other network-intensive apps

## Common Use Cases
- **Network Troubleshooting**: See what's happening on your network
- **Security Monitoring**: Detect unusual traffic patterns
- **Learning Tool**: Understand how networks work
- **Application Debugging**: Monitor app network usage

## Tips
- Use filters to focus on specific IPs or ports
- Double-click packets for detailed view
- Toggle theme with the sun/moon button
- Start with small captures to learn the interface

## Legal Notice
Only capture traffic on networks you own or have permission to monitor. Respect privacy laws in your area.

## Need Help?
1. Check the troubleshooting section above
2. Make sure all packages are installed
3. Try running as administrator
4. Restart the application

---

**Simple Command to Run:**
```bash
python network_analyzer.py
```

That's it! Start analyzing your network traffic in minutes.
