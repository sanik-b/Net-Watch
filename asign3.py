import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime
import threading
import queue
import time
import socket
import psutil
import logging

import matplotlib
matplotlib.use('Agg')  # Use a non-interactive backend

import matplotlib.pyplot as plt
import numpy as np

# Disable interactive mode
plt.ioff()

# Create some data
x = np.linspace(0, 10, 100)
y = np.sin(x)

# Create a plot
plt.plot(x, y)
plt.title("Sine Wave")
plt.xlabel("X-axis")
plt.ylabel("Y-axis")

# Save the figure
plt.savefig("sine_wave.png")

class NetworkTrafficAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyzer")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        # Dark mode by default
        self.dark_mode = True
        self.set_theme()

        # Packet capture control
        self.capturing = False
        self.packet_queue = queue.Queue()
        self.anomaly_model = self.train_initial_model()
        self.network_profile = {}

        # Initialize packet data and counts
        self.packet_data = []
        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.anomaly_count = 0

        # Create GUI
        self.create_widgets()

        # Start packet processing thread
        self.processing_thread = threading.Thread(target=self.process_packets, daemon=True)
        self.processing_thread.start()

        # Update UI periodically
        self.update_ui()

        # Unique feature: Network behavior profiler
        self.profiler_thread = threading.Thread(target=self.run_behavior_profiler, daemon=True)
        self.profiler_thread.start()

    def set_theme(self):
        if self.dark_mode:
            self.bg_color = "#1e1e1e"
            self.fg_color = "#ffffff"
            self.accent_color = "#4a90e2"
            self.text_bg = "#2d2d2d"
            self.plot_bg = "#2d2d2d"
        else:
            self.bg_color = "#f5f5f5"
            self.fg_color = "#000000"
            self.accent_color = "#1f77b4"
            self.text_bg = "#ffffff"
            self.plot_bg = "#ffffff"

        self.root.configure(bg=self.bg_color)

    def create_widgets(self):
        # Create main container
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        self.header_frame = ttk.Frame(self.main_frame, padding="10")
        self.header_frame.pack(fill=tk.X)

        self.title_label = ttk.Label(
            self.header_frame,
            text="Network Packet Analyzer",
            font=("Helvetica", 20, "bold"),
            foreground=self.accent_color
        )
        self.title_label.pack(side=tk.LEFT)

        # Theme toggle
        self.theme_btn = ttk.Button(
            self.header_frame,
            text="☀️" if self.dark_mode else "🌙",
            command=self.toggle_theme,
            width=3
        )
        self.theme_btn.pack(side=tk.RIGHT, padx=5)

        # Interface selection
        self.interface_btn = ttk.Button(
            self.header_frame,
            text="Select Interface",
            command=self.select_interface
        )
        self.interface_btn.pack(side=tk.RIGHT, padx=5)

        # Control buttons
        self.control_frame = ttk.Frame(self.main_frame, padding="10")
        self.control_frame.pack(fill=tk.X)

        self.start_btn = ttk.Button(
            self.control_frame,
            text="Start Capture",
            command=self.start_capture,
            style="Accent.TButton"
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(
            self.control_frame,
            text="Stop Capture",
            command=self.stop_capture,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = ttk.Button(
            self.control_frame,
            text="Clear",
            command=self.clear_data
        )
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        # Stats display
        self.stats_frame = ttk.Frame(self.main_frame, padding="10")
        self.stats_frame.pack(fill=tk.X)

        stats_labels = ["Packets", "TCP", "UDP", "Anomalies", "Threat Score"]
        self.stats_vars = {}

        for label in stats_labels:
            frame = ttk.Frame(self.stats_frame)
            frame.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

            ttk.Label(frame, text=label, font=("Helvetica", 12)).pack()
            self.stats_vars[label] = tk.StringVar(value="0")
            ttk.Label(frame, textvariable=self.stats_vars[label], font=("Helvetica", 14, "bold")).pack()

        # Main content area
        self.content_frame = ttk.Frame(self.main_frame, padding="10")
        self.content_frame.pack(fill=tk.BOTH, expand=True)

        # Packet list and details
        self.packet_frame = ttk.Frame(self.content_frame)
        self.packet_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        # Packet list
        self.packet_list_frame = ttk.LabelFrame(self.packet_frame, text="Packet List", padding="10")
        self.packet_list_frame.pack(fill=tk.BOTH, expand=True)

        self.packet_columns = ("#", "Time", "Source", "Destination", "Protocol", "Length", "Anomaly")
        self.packet_tree = ttk.Treeview(
            self.packet_list_frame,
            columns=self.packet_columns,
            show="headings",
            selectmode="browse"
        )

        for col in self.packet_columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=80, anchor=tk.CENTER)

        self.packet_tree.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(self.packet_list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)

        self.packet_tree.bind("<<TreeviewSelect>>", self.show_packet_details)

        # Packet details
        self.details_frame = ttk.LabelFrame(self.packet_frame, text="Packet Details", padding="10")
        self.details_frame.pack(fill=tk.BOTH, pady=(10, 0))

        self.details_text = scrolledtext.ScrolledText(
            self.details_frame,
            wrap=tk.WORD,
            font=("Consolas", 12),
            bg=self.text_bg,
            fg=self.fg_color
        )
        self.details_text.pack(fill=tk.BOTH, expand=True)

        # Visualization and unique features frame
        self.vis_frame = ttk.Frame(self.content_frame, padding="10")
        self.vis_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False)

        # Traffic visualization
        self.plot_frame = ttk.LabelFrame(self.vis_frame, text="Traffic Analysis", padding="10")
        self.plot_frame.pack(fill=tk.BOTH, expand=True)

        self.fig, self.ax = plt.subplots(figsize=(4, 3), facecolor=self.plot_bg)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.plot_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Network Behavior Profile
        self.profile_frame = ttk.LabelFrame(self.vis_frame, text="Network Behavior Profile", padding="10")
        self.profile_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        self.profile_text = scrolledtext.ScrolledText(
            self.profile_frame,
            wrap=tk.WORD,
            height=10,
            font=("Consolas", 9),
            bg=self.text_bg,
            fg=self.fg_color
        )
        self.profile_text.pack(fill=tk.BOTH, expand=True)
        self.profile_text.insert(tk.END, "Building network profile...")

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(
            self.main_frame,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(fill=tk.X, pady=(10, 0))

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.set_theme()
        self.theme_btn.config(text="☀️" if self.dark_mode else "🌙")

        # Update text widget colors
        self.details_text.config(bg=self.text_bg, fg=self.fg_color)
        self.profile_text.config(bg=self.text_bg, fg=self.fg_color)

        # Redraw plots with new theme
        self.update_plots()

    def select_interface(self):
        interfaces = psutil.net_if_addrs()
        if not interfaces:
            messagebox.showerror("Error", "No network interfaces found!")
            return

        self.interface_window = tk.Toplevel(self.root)
        self.interface_window.title("Select Interface")
        self.interface_window.geometry("400x300")

        ttk.Label(self.interface_window, text="Available Network Interfaces:").pack(pady=10)

        self.interface_listbox = tk.Listbox(self.interface_window)
        self.interface_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        for iface in interfaces.keys():
            self.interface_listbox.insert(tk.END, iface)

        select_btn = ttk.Button(
            self.interface_window,
            text="Select",
            command=self.on_interface_selected
        )
        select_btn.pack(pady=10)

    def on_interface_selected(self):
        selection = self.interface_listbox.curselection()
        if selection:
            self.selected_interface = self.interface_listbox.get(selection[0])
            self.status_var.set(f"Selected interface: {self.selected_interface}")
            self.interface_window.destroy()

    def start_capture(self):
        if not hasattr(self, 'selected_interface'):
            messagebox.showerror("Error", "Please select a network interface first!")
            return

        self.capturing = True
        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.anomaly_count = 0
        self.packet_data = []

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        # Start packet capture in a separate thread
        self.capture_thread = threading.Thread(
            target=self.capture_packets,
            daemon=True
        )
        self.capture_thread.start()

        self.status_var.set(f"Capturing on {self.selected_interface}...")

    def stop_capture(self):
        self.capturing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Capture stopped")

    def clear_data(self):
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.packet_data = []
        self.update_stats()
        self.status_var.set("Data cleared")

    def capture_packets(self):
        sniff(
            iface=self.selected_interface,
            prn=self.process_packet,
            stop_filter=lambda x: not self.capturing
        )

    def process_packet(self, packet):
        packet_info = {
            'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'src': '',
            'dst': '',
            'protocol': '',
            'length': len(packet),
            'anomaly': 0,
            'raw': packet
        }

        if IP in packet:
            packet_info['src'] = packet[IP].src
            packet_info['dst'] = packet[IP].dst
            packet_info['protocol'] = packet[IP].proto

            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                self.tcp_count += 1
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                self.udp_count += 1

        self.packet_queue.put(packet_info)
        self.packet_count += 1

    def process_packets(self):
        while True:
            try:
                packet_info = self.packet_queue.get(timeout=0.1)

                features = self.extract_features(packet_info)

                if features:
                    anomaly_score = self.anomaly_model.predict([features])[0]
                    packet_info['anomaly'] = anomaly_score
                    if anomaly_score == 1:
                        self.anomaly_count += 1

                self.packet_data.append(packet_info)

            except queue.Empty:
                continue

    def extract_features(self, packet_info):
        if not IP in packet_info['raw']:
            return None

        features = [
            len(packet_info['raw']),
            packet_info['raw'][IP].ttl,
            packet_info['raw'][IP].len,
        ]

        if TCP in packet_info['raw']:
            features.extend([
                packet_info['raw'][TCP].sport,
                packet_info['raw'][TCP].dport,
                packet_info['raw'][TCP].window,
                packet_info['raw'][TCP].flags.value
            ])
        elif UDP in packet_info['raw']:
            features.extend([
                packet_info['raw'][UDP].sport,
                packet_info['raw'][UDP].dport,
                0,
                0
            ])
        else:
            features.extend([0, 0, 0, 0])

        return features

    def train_initial_model(self):
        normal_data = []
        for _ in range(100):
            normal_data.append([
                np.random.randint(40, 1500),
                np.random.randint(50, 128),
                np.random.randint(40, 1500),
                np.random.randint(1024, 65535),
                np.random.choice([80, 443, 22, 53]),
                np.random.randint(5000, 65000),
                np.random.randint(0, 255)
            ])

        model = IsolationForest(contamination='auto', random_state=42)
        model.fit(normal_data)
        return model

    def update_model(self):
        if len(self.packet_data) < 50:
            return

        features = []
        for packet in self.packet_data[-100:]:
            feat = self.extract_features(packet)
            if feat:
                features.append(feat)

        if len(features) < 50:
            return

        self.anomaly_model.fit(features)

    def update_ui(self):
        if self.packet_data and len(self.packet_tree.get_children()) < len(self.packet_data):
            for i in range(len(self.packet_tree.get_children()), len(self.packet_data)):
                packet = self.packet_data[i]

                anomaly_text = ""
                if packet['anomaly'] == 1:
                    anomaly_text = "⚠️ Anomaly"

                self.packet_tree.insert("", tk.END, values=(
                    i + 1,
                    packet['timestamp'],
                    packet['src'],
                    packet['dst'],
                    packet['protocol'],
                    packet['length'],
                    anomaly_text
                ))

        self.update_stats()
        self.update_plots()
        self.update_network_profile()

        self.root.after(1000, self.update_ui)

    def update_stats(self):
        self.stats_vars["Packets"].set(str(self.packet_count))
        self.stats_vars["TCP"].set(str(self.tcp_count))
        self.stats_vars["UDP"].set(str(self.udp_count))
        self.stats_vars["Anomalies"].set(str(self.anomaly_count))

        threat_score = 0
        if self.packet_count > 0:
            threat_score = min(100, int((self.anomaly_count / self.packet_count) * 200))
        self.stats_vars["Threat Score"].set(f"{threat_score}/100")

    def update_plots(self):
        self.ax.clear()

        if not self.packet_data:
            self.ax.text(0.5, 0.5, "No data to display",
                         ha='center', va='center', fontsize=12)
            self.canvas.draw()
            return

        protocols = [p['protocol'] for p in self.packet_data if 'protocol' in p]
        anomalies = [1 if p['anomaly'] == -1 else 0 for p in self.packet_data]

        protocol_counts = pd.Series(protocols).value_counts()
        protocol_counts.plot(kind='bar', ax=self.ax, color=self.accent_color)

        self.ax.set_title("Protocol Distribution", pad=10)
        self.ax.set_facecolor(self.plot_bg)
        self.fig.set_facecolor(self.plot_bg)
        self.ax.tick_params(colors=self.fg_color)

        for spine in self.ax.spines.values():
            spine.set_color(self.fg_color)

        self.ax.xaxis.label.set_color(self.fg_color)
        self.ax.yaxis.label.set_color(self.fg_color)
        self.ax.title.set_color(self.fg_color)

        self.canvas.draw()

    def show_packet_details(self, event):
        selected = self.packet_tree.focus()
        if not selected:
            return

        item = self.packet_tree.item(selected)
        packet_idx = int(item['values'][0]) - 1

        if packet_idx < 0 or packet_idx >= len(self.packet_data):
            return

        packet = self.packet_data[packet_idx]['raw']

        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, packet.show(dump=True))

    def run_behavior_profiler(self):
        while True:
            if self.packet_data:
                self.analyze_network_behavior()
            time.sleep(30)

    def analyze_network_behavior(self):
        if not self.packet_data:
            return

        now = datetime.now()
        recent_packets = [
            p for p in self.packet_data
            if (now - datetime.strptime(p['timestamp'], "%H:%M:%S.%f")).total_seconds() < 300
        ]

        if not recent_packets:
            return

        protocols = [p['protocol'] for p in recent_packets if 'protocol' in p]
        src_ips = [p['src'] for p in recent_packets if 'src' in p]
        dst_ips = [p['dst'] for p in recent_packets if 'dst' in p]

        protocol_counts = pd.Series(protocols).value_counts().to_dict()
        src_counts = pd.Series(src_ips).value_counts().head(5).to_dict()
        dst_counts = pd.Series(dst_ips).value_counts().head(5).to_dict()

        self.network_profile = {
            'protocol_dist': protocol_counts,
            'top_sources': src_counts,
            'top_destinations': dst_counts,
            'avg_packet_size': np.mean([p['length'] for p in recent_packets]),
            'anomaly_rate': np.mean([1 if p['anomaly'] == -1 else 0 for p in recent_packets])
        }

    def update_network_profile(self):
        if not self.network_profile:
            return

        self.profile_text.delete(1.0, tk.END)

        self.profile_text.insert(tk.END, "=== Network Behavior Profile ===\n\n")
        self.profile_text.insert(tk.END, "Protocol Distribution:\n")
        for proto, count in self.network_profile['protocol_dist'].items():
            self.profile_text.insert(tk.END, f"  {proto}: {count} packets\n")

        self.profile_text.insert(tk.END, "\nTop Sources:\n")
        for ip, count in self.network_profile['top_sources'].items():
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"
            self.profile_text.insert(tk.END, f"  {ip} ({hostname}): {count} packets\n")

        self.profile_text.insert(tk.END, "\nTop Destinations:\n")
        for ip, count in self.network_profile['top_destinations'].items():
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"
            self.profile_text.insert(tk.END, f"  {ip} ({hostname}): {count} packets\n")

        self.profile_text.insert(tk.END, f"\nAverage Packet Size: {self.network_profile['avg_packet_size']:.2f} bytes\n")
        self.profile_text.insert(tk.END, f"Anomaly Rate: {self.network_profile['anomaly_rate']*100:.2f}%\n")

        # Add behavioral insights
        self.profile_text.insert(tk.END, "\nBehavioral Insights:\n")
        if self.network_profile['anomaly_rate'] > 0.1:
            self.profile_text.insert(tk.END, "⚠️ High anomaly rate detected!\n")

        if 'TCP' in self.network_profile['protocol_dist'] and self.network_profile['protocol_dist']['TCP'] / sum(self.network_profile['protocol_dist'].values()) > 0.8:
            self.profile_text.insert(tk.END, "🔹 Network is predominantly TCP traffic\n")

        if 'UDP' in self.network_profile['protocol_dist'] and self.network_profile['protocol_dist']['UDP'] / sum(self.network_profile['protocol_dist'].values()) > 0.5:
            self.profile_text.insert(tk.END, "🔹 Significant UDP traffic detected\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkTrafficAnalyzer(root)
    root.mainloop()