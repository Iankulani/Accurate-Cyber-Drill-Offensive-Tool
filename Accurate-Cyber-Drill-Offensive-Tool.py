"""
ACCURATE CYBER DRILL TOOL 
Author: Ian Carter Kulani
Version: 0.0.0
"""

import sys
import os
import time
import json
import logging
from typing import Dict, List, Set, Tuple, Optional, Any
from pathlib import Path
from datetime import datetime
import threading
import queue

# Core imports from original tool
import socket
import subprocess
import requests
import random
import platform
import psutil
import getpass
import hashlib
import sqlite3
import ipaddress
import re
import shutil

# GUI imports
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, scrolledtext
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("GUI features unavailable - tkinter not installed")

try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# Security imports
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

# Configuration
CONFIG_FILE = "cyber_security_config.json"
DATABASE_FILE = "network_data.db"
REPORT_DIR = "reports"
THEMES = {
    "dark": {
        "bg": "#121212",
        "fg": "#00ff00",
        "text_bg": "#222222",
        "text_fg": "#ffffff",
        "button_bg": "#333333",
        "button_fg": "#00ff00",
        "highlight": "#006600"
    },
    "light": {
        "bg": "#f0f0f0",
        "fg": "#000000",
        "text_bg": "#ffffff",
        "text_fg": "#000000",
        "button_bg": "#e0e0e0",
        "button_fg": "#000000",
        "highlight": "#a0a0a0"
    }
}

class TracerouteTool:
    """Enhanced interactive traceroute tool"""
    
    @staticmethod
    def is_ipv4_or_ipv6(address: str) -> bool:
        """Check if input is valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_hostname(name: str) -> bool:
        """Check if input is valid hostname"""
        if name.endswith('.'):
            name = name[:-1]
        HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
        return bool(HOSTNAME_RE.match(name))

    @staticmethod
    def choose_traceroute_cmd(target: str) -> List[str]:
        """Return appropriate traceroute command for the system"""
        system = platform.system()

        if system == 'Windows':
            return ['tracert', '-d', target]

        # On Unix-like systems
        if shutil.which('traceroute'):
            return ['traceroute', '-n', '-q', '1', '-w', '2', target]
        if shutil.which('tracepath'):
            return ['tracepath', target]
        if shutil.which('ping'):
            return ['ping', '-c', '4', target]

        raise EnvironmentError('No traceroute utilities found')

    @staticmethod
    def stream_subprocess(cmd: List[str]) -> Tuple[int, str]:
        """Run subprocess and capture output"""
        output_lines = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

            if proc.stdout:
                for line in proc.stdout:
                    cleaned_line = line.rstrip()
                    output_lines.append(cleaned_line)
                    print(cleaned_line)

            proc.wait()
            return proc.returncode, '\n'.join(output_lines)
        except KeyboardInterrupt:
            print('\n[+] User cancelled traceroute...')
            try:
                proc.terminate()
            except Exception:
                pass
            return -1, '\n'.join(output_lines)
        except Exception as e:
            error_msg = f'[!] Error: {e}'
            print(error_msg)
            output_lines.append(error_msg)
            return -2, '\n'.join(output_lines)

    def interactive_traceroute(self, target: str = None) -> str:
        """Run interactive traceroute with validation"""
        if not target:
            target = self.prompt_target()
            if not target:
                return "Traceroute cancelled."

        if not (self.is_ipv4_or_ipv6(target) or self.is_valid_hostname(target)):
            return f"❌ Invalid IP address or hostname: {target}"

        try:
            cmd = self.choose_traceroute_cmd(target)
        except EnvironmentError as e:
            return f"❌ Traceroute error: {e}"

        print(f'Running: {" ".join(cmd)}\n')
        
        start_time = time.time()
        returncode, output = self.stream_subprocess(cmd)
        execution_time = time.time() - start_time

        result = f"🛣️ <b>Traceroute to {target}</b>\n\n"
        result += f"Command: <code>{' '.join(cmd)}</code>\n"
        result += f"Execution time: {execution_time:.2f}s\n"
        result += f"Return code: {returncode}\n\n"
        
        if len(output) > 3000:
            result += f"<code>{output[-3000:]}</code>"
        else:
            result += f"<code>{output}</code>"

        return result

    def prompt_target(self) -> Optional[str]:
        """Prompt user for target"""
        while True:
            user_input = input('Enter target IP/hostname (or "quit"): ').strip()
            if not user_input:
                print('Please enter a value.')
                continue
            if user_input.lower() in ('q', 'quit', 'exit'):
                return None

            if self.is_ipv4_or_ipv6(user_input) or self.is_valid_hostname(user_input):
                return user_input
            else:
                print('Invalid IP/hostname. Examples: 8.8.8.8, example.com')

class DatabaseManager:
    """Manage SQLite database for network data"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Original tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT 1
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # New tables for IDS
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS intrusion_detection (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                packet_count INTEGER,
                description TEXT,
                action_taken TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                packets_processed INTEGER,
                packet_rate REAL,
                tcp_count INTEGER,
                udp_count INTEGER,
                icmp_count INTEGER,
                threat_count INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS session_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_name TEXT NOT NULL,
                data_type TEXT NOT NULL,
                data TEXT,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_command(self, command: str, source: str = 'local', success: bool = True):
        """Log command to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO command_history (command, source, success) VALUES (?, ?, ?)',
            (command, source, success)
        )
        conn.commit()
        conn.close()
    
    def log_intrusion(self, source_ip: str, threat_type: str, severity: str, 
                     packet_count: int = 0, description: str = "", action: str = "logged"):
        """Log intrusion detection event"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO intrusion_detection 
               (source_ip, threat_type, severity, packet_count, description, action_taken) 
               VALUES (?, ?, ?, ?, ?, ?)''',
            (source_ip, threat_type, severity, packet_count, description, action)
        )
        conn.commit()
        conn.close()
    
    def log_network_stats(self, stats: Dict[str, Any]):
        """Log network statistics"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO network_stats 
               (packets_processed, packet_rate, tcp_count, udp_count, icmp_count, threat_count)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (stats.get('packets_processed', 0),
             stats.get('packet_rate', 0),
             stats.get('tcp_count', 0),
             stats.get('udp_count', 0),
             stats.get('icmp_count', 0),
             stats.get('threat_count', 0))
        )
        conn.commit()
        conn.close()
    
    def get_recent_intrusions(self, limit: int = 50) -> List[Tuple]:
        """Get recent intrusion detection events"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''SELECT timestamp, source_ip, threat_type, severity, description 
               FROM intrusion_detection 
               ORDER BY timestamp DESC LIMIT ?''',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_threat_stats(self, hours: int = 24) -> Dict[str, int]:
        """Get threat statistics for specified period"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT threat_type, COUNT(*) as count 
            FROM intrusion_detection 
            WHERE timestamp > datetime('now', ?)
            GROUP BY threat_type
        ''', (f'-{hours} hours',))
        
        results = cursor.fetchall()
        conn.close()
        
        stats = {}
        for threat_type, count in results:
            stats[threat_type] = count
        
        return stats

class ThreatDetector:
    """Advanced threat detection system"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.ip_stats = {}
        self.port_stats = {}
        self.syn_flood_stats = {}
        self.detection_thresholds = {
            'DOS': 1000,  # packets per second
            'PortScan': 50,  # unique ports in 60 seconds
            'SYNFlood': 500,  # SYN packets without ACK
            'UDPFlood': 1000,  # UDP packets per second
            'ICMPFlood': 500,  # ICMP packets per second
            'BruteForce': 100  # failed connection attempts
        }
        
    def analyze_packet(self, packet):
        """Analyze packet for threats"""
        threats = []
        
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            # Initialize stats for IP
            if ip_src not in self.ip_stats:
                self.ip_stats[ip_src] = {
                    'packet_count': 0,
                    'last_seen': time.time(),
                    'ports_accessed': set(),
                    'packet_times': [],
                    'syn_count': 0
                }
            
            ip_stat = self.ip_stats[ip_src]
            ip_stat['packet_count'] += 1
            ip_stat['last_seen'] = time.time()
            ip_stat['packet_times'].append(time.time())
            
            # Keep only last minute of packet times
            cutoff = time.time() - 60
            ip_stat['packet_times'] = [t for t in ip_stat['packet_times'] if t > cutoff]
            
            # Protocol-specific analysis
            if TCP in packet:
                threats.extend(self._analyze_tcp(packet, ip_src))
            elif UDP in packet:
                threats.extend(self._analyze_udp(packet, ip_src))
            elif ICMP in packet:
                threats.extend(self._analyze_icmp(packet, ip_src))
            
            # General threat detection
            threats.extend(self._detect_dos(ip_src))
            threats.extend(self._detect_port_scan(ip_src))
        
        return threats
    
    def _analyze_tcp(self, packet, ip_src):
        """Analyze TCP packets"""
        threats = []
        tcp = packet[TCP]
        
        # Track ports accessed
        self.ip_stats[ip_src]['ports_accessed'].add(tcp.dport)
        
        # SYN flood detection
        if tcp.flags & 0x02:  # SYN flag
            self.ip_stats[ip_src]['syn_count'] += 1
            
            if ip_src not in self.syn_flood_stats:
                self.syn_flood_stats[ip_src] = {'syn_count': 0, 'start_time': time.time()}
            
            self.syn_flood_stats[ip_src]['syn_count'] += 1
            
            # Check for SYN flood
            syn_stats = self.syn_flood_stats[ip_src]
            elapsed = time.time() - syn_stats['start_time']
            if elapsed > 0:
                syn_rate = syn_stats['syn_count'] / elapsed
                if syn_rate > self.detection_thresholds['SYNFlood']:
                    threats.append({
                        'type': 'SYNFlood',
                        'source': ip_src,
                        'severity': 'high',
                        'rate': syn_rate
                    })
        
        return threats
    
    def _analyze_udp(self, packet, ip_src):
        """Analyze UDP packets"""
        threats = []
        udp = packet[UDP]
        
        # Track UDP packet rate
        udp_rate = len([t for t in self.ip_stats[ip_src]['packet_times'] 
                       if time.time() - t < 1])
        
        if udp_rate > self.detection_thresholds['UDPFlood']:
            threats.append({
                'type': 'UDPFlood',
                'source': ip_src,
                'severity': 'medium',
                'rate': udp_rate
            })
        
        return threats
    
    def _analyze_icmp(self, packet, ip_src):
        """Analyze ICMP packets"""
        threats = []
        
        # Track ICMP packet rate
        icmp_rate = len([t for t in self.ip_stats[ip_src]['packet_times'] 
                        if time.time() - t < 1])
        
        if icmp_rate > self.detection_thresholds['ICMPFlood']:
            threats.append({
                'type': 'ICMPFlood',
                'source': ip_src,
                'severity': 'medium',
                'rate': icmp_rate
            })
        
        return threats
    
    def _detect_dos(self, ip_src):
        """Detect DOS attacks"""
        threats = []
        
        ip_stat = self.ip_stats[ip_src]
        if len(ip_stat['packet_times']) > 0:
            time_window = ip_stat['packet_times'][-1] - ip_stat['packet_times'][0]
            if time_window > 0:
                packet_rate = len(ip_stat['packet_times']) / time_window
                if packet_rate > self.detection_thresholds['DOS']:
                    threats.append({
                        'type': 'DOS',
                        'source': ip_src,
                        'severity': 'high',
                        'rate': packet_rate
                    })
        
        return threats
    
    def _detect_port_scan(self, ip_src):
        """Detect port scanning"""
        threats = []
        
        ip_stat = self.ip_stats[ip_src]
        unique_ports = len(ip_stat['ports_accessed'])
        
        if unique_ports > self.detection_thresholds['PortScan']:
            threats.append({
                'type': 'PortScan',
                'source': ip_src,
                'severity': 'medium',
                'ports': unique_ports
            })
        
        return threats
    
    def clear_old_stats(self, max_age: int = 300):
        """Clear statistics older than max_age seconds"""
        cutoff = time.time() - max_age
        ips_to_remove = []
        
        for ip, stats in self.ip_stats.items():
            if stats['last_seen'] < cutoff:
                ips_to_remove.append(ip)
        
        for ip in ips_to_remove:
            del self.ip_stats[ip]
            
        # Clean SYN flood stats
        syn_ips_to_remove = []
        for ip, stats in self.syn_flood_stats.items():
            if stats['start_time'] < cutoff:
                syn_ips_to_remove.append(ip)
        
        for ip in syn_ips_to_remove:
            del self.syn_flood_stats[ip]

class NetworkMonitor:
    """Network monitoring with threat detection"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.threat_detector = ThreatDetector(db_manager)
        self.is_monitoring = False
        self.sniffer_thread = None
        self.packet_queue = queue.Queue()
        self.target_ip = None
        self.packet_count = 0
        self.start_time = None
        self.stats = {
            'tcp_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'threat_count': 0
        }
    
    def start_monitoring(self, target_ip: str = None):
        """Start network monitoring"""
        if self.is_monitoring:
            return False
        
        self.target_ip = target_ip
        self.is_monitoring = True
        self.packet_count = 0
        self.start_time = time.time()
        self.stats = {'tcp_count': 0, 'udp_count': 0, 'icmp_count': 0, 'threat_count': 0}
        
        # Start packet capture thread
        self.sniffer_thread = threading.Thread(
            target=self._packet_capture_loop,
            daemon=True
        )
        self.sniffer_thread.start()
        
        # Start packet processing thread
        self.processor_thread = threading.Thread(
            target=self._packet_processing_loop,
            daemon=True
        )
        self.processor_thread.start()
        
        # Start stats logging thread
        self.stats_thread = threading.Thread(
            target=self._stats_logging_loop,
            daemon=True
        )
        self.stats_thread.start()
        
        return True
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=2)
        if self.processor_thread and self.processor_thread.is_alive():
            self.processor_thread.join(timeout=2)
        if self.stats_thread and self.stats_thread.is_alive():
            self.stats_thread.join(timeout=2)
    
    def _packet_capture_loop(self):
        """Capture packets from network"""
        try:
            filter_str = f"host {self.target_ip}" if self.target_ip else ""
            sniff(
                filter=filter_str,
                prn=lambda p: self.packet_queue.put(p),
                store=0,
                stop_filter=lambda _: not self.is_monitoring
            )
        except Exception as e:
            print(f"Packet capture error: {e}")
    
    def _packet_processing_loop(self):
        """Process captured packets for threats"""
        while self.is_monitoring or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                self.packet_count += 1
                
                # Update protocol stats
                if TCP in packet:
                    self.stats['tcp_count'] += 1
                elif UDP in packet:
                    self.stats['udp_count'] += 1
                elif ICMP in packet:
                    self.stats['icmp_count'] += 1
                
                # Detect threats
                threats = self.threat_detector.analyze_packet(packet)
                if threats:
                    self.stats['threat_count'] += len(threats)
                    for threat in threats:
                        self.db_manager.log_intrusion(
                            source_ip=threat['source'],
                            threat_type=threat['type'],
                            severity=threat['severity'],
                            description=f"Rate: {threat.get('rate', 'N/A')}"
                        )
                
                # Clean old stats periodically
                if self.packet_count % 1000 == 0:
                    self.threat_detector.clear_old_stats()
                    
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Packet processing error: {e}")
    
    def _stats_logging_loop(self):
        """Periodically log network statistics"""
        while self.is_monitoring:
            time.sleep(60)  # Log every minute
            
            uptime = time.time() - self.start_time
            if uptime > 0:
                stats = {
                    'packets_processed': self.packet_count,
                    'packet_rate': self.packet_count / uptime,
                    'tcp_count': self.stats['tcp_count'],
                    'udp_count': self.stats['udp_count'],
                    'icmp_count': self.stats['icmp_count'],
                    'threat_count': self.stats['threat_count']
                }
                self.db_manager.log_network_stats(stats)
    
    def get_current_stats(self) -> Dict[str, Any]:
        """Get current monitoring statistics"""
        uptime = time.time() - self.start_time if self.start_time else 0
        packet_rate = self.packet_count / uptime if uptime > 0 else 0
        
        return {
            'is_monitoring': self.is_monitoring,
            'target_ip': self.target_ip,
            'packets_processed': self.packet_count,
            'uptime': uptime,
            'packet_rate': packet_rate,
            'tcp_packets': self.stats['tcp_count'],
            'udp_packets': self.stats['udp_count'],
            'icmp_packets': self.stats['icmp_count'],
            'threats_detected': self.stats['threat_count']
        }

class NetworkScanner:
    """Network scanning capabilities"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.traceroute_tool = TracerouteTool()
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
    
    def ping_ip(self, ip: str) -> str:
        """Simple ping that works reliably"""
        try:
            if os.name == 'nt':  # Windows
                cmd = ['ping', '-n', '4', ip]
            else:  # Linux/Mac
                cmd = ['ping', '-c', '4', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"Ping timeout for {ip}"
        except Exception as e:
            return f"Ping error: {str(e)}"
    
    def traceroute(self, target: str) -> str:
        """Perform enhanced traceroute"""
        return self.traceroute_tool.interactive_traceroute(target)
    
    def port_scan(self, ip: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Perform port scan"""
        if self.nm:
            try:
                self.nm.scan(ip, ports, arguments='-T4')
                open_ports = []
                
                if ip in self.nm.all_hosts():
                    for proto in self.nm[ip].all_protocols():
                        lport = self.nm[ip][proto].keys()
                        for port in lport:
                            if self.nm[ip][proto][port]['state'] == 'open':
                                open_ports.append({
                                    'port': port,
                                    'state': self.nm[ip][proto][port]['state'],
                                    'service': self.nm[ip][proto][port].get('name', 'unknown')
                                })
                
                # Log to database
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO scan_results (ip_address, scan_type, open_ports, services) VALUES (?, ?, ?, ?)',
                    (ip, 'nmap', json.dumps([p['port'] for p in open_ports]), 
                     json.dumps([p['service'] for p in open_ports]))
                )
                conn.commit()
                conn.close()
                
                return {
                    'success': True,
                    'target': ip,
                    'open_ports': open_ports,
                    'scan_time': datetime.now().isoformat()
                }
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            return {'success': False, 'error': 'Nmap not available'}
    
    def get_ip_location(self, ip: str) -> str:
        """Get IP location using ip-api.com"""
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return json.dumps({
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A'),
                        'timezone': data.get('timezone', 'N/A')
                    }, indent=2)
                else:
                    return f"Location error: {data.get('message', 'Unknown error')}"
            else:
                return f"Location error: HTTP {response.status_code}"
        except Exception as e:
            return f"Location error: {str(e)}"
    
    def vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """Perform vulnerability scan"""
        if not self.nm:
            return {'success': False, 'error': 'Nmap not available'}
        
        try:
            self.nm.scan(target, arguments='--script vuln')
            
            vulns = []
            if target in self.nm.all_hosts():
                for script in self.nm[target].get('scripts', []):
                    if 'vuln' in script.lower():
                        vulns.append(script)
            
            return {
                'success': True,
                'target': target,
                'vulnerabilities': vulns,
                'scan_time': datetime.now().isoformat()
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

class NetworkTrafficGenerator:
    """Network traffic generation capabilities"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.running = False
        self.current_thread = None
    
    def generate_tcp_traffic(self, target_ip: str, port: int, packet_count: int, delay: float) -> str:
        """Generate TCP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for TCP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                packet = IP(src=src_ip, dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=port)
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO traffic_logs (traffic_type, target, packets_sent, duration) VALUES (?, ?, ?, ?)',
                ('TCP Flood', f"{target_ip}:{port}", packets_sent, duration)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} TCP packets to {target_ip}:{port} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ TCP traffic error: {str(e)}"
    
    def generate_udp_traffic(self, target_ip: str, port: int, packet_count: int, delay: float) -> str:
        """Generate UDP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for UDP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                payload = random._urandom(random.randint(64, 512))
                packet = IP(src=src_ip, dst=target_ip)/UDP(sport=random.randint(1024, 65535), dport=port)/payload
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO traffic_logs (traffic_type, target, packets_sent, duration) VALUES (?, ?, ?, ?)',
                ('UDP Flood', f"{target_ip}:{port}", packets_sent, duration)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} UDP packets to {target_ip}:{port} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ UDP traffic error: {str(e)}"
    
    def generate_icmp_traffic(self, target_ip: str, packet_count: int, delay: float) -> str:
        """Generate ICMP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for ICMP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                packet = IP(dst=target_ip)/ICMP()
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO traffic_logs (traffic_type, target, packets_sent, duration) VALUES (?, ?, ?, ?)',
                ('ICMP Flood', target_ip, packets_sent, duration)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} ICMP packets to {target_ip} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ ICMP traffic error: {str(e)}"
    
    def stop_traffic(self):
        """Stop all traffic generation"""
        self.running = False
        if self.current_thread and self.current_thread.is_alive():
            self.current_thread.join(timeout=2)

class TerminalEmulator:
    """Command-line terminal emulator with security commands"""
    
    def __init__(self, network_scanner: NetworkScanner, network_monitor: NetworkMonitor):
        self.scanner = network_scanner
        self.monitor = network_monitor
        self.commands = {
            'help': self.cmd_help,
            'start monitoring': self.cmd_start_monitoring,
            'stop monitoring': self.cmd_stop_monitoring,
            'status': self.cmd_status,
            'scan': self.cmd_scan,
            'ping': self.cmd_ping,
            'traceroute': self.cmd_traceroute,
            'vulnscan': self.cmd_vulnscan,
            'ifconfig': self.cmd_ifconfig,
            'netstat': self.cmd_netstat,
            'whois': self.cmd_whois,
            'dns': self.cmd_dns,
            'threats': self.cmd_threats,
            'stats': self.cmd_stats,
            'clear': self.cmd_clear,
            'exit': self.cmd_exit
        }
    
    def execute(self, command: str) -> str:
        """Execute terminal command"""
        parts = command.strip().split()
        if not parts:
            return ""
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        # Find matching command
        matched_cmd = None
        for available_cmd in self.commands:
            if cmd in available_cmd.split():
                matched_cmd = available_cmd
                break
        
        if not matched_cmd:
            return f"Command not found: {cmd}\nType 'help' for available commands"
        
        try:
            return self.commands[matched_cmd](args)
        except Exception as e:
            return f"Error executing command: {str(e)}"
    
    def cmd_help(self, args):
        help_text = """Available Commands:
  help                    - Show this help message
  start monitoring [ip]   - Start network monitoring (optional IP)
  stop monitoring         - Stop network monitoring
  status                  - Show system and monitoring status
  scan <ip> [ports]       - Port scan IP (default: 1-1000)
  ping <ip/hostname>      - Ping target
  traceroute <target>     - Traceroute to target
  vulnscan <target>       - Vulnerability scan
  ifconfig                - Network interface information
  netstat                 - Network connections
  whois <domain>          - WHOIS lookup
  dns <domain>           - DNS lookup
  threats                 - Show recent threats
  stats                   - Show network statistics
  clear                   - Clear screen
  exit                    - Exit terminal
"""
        return help_text
    
    def cmd_start_monitoring(self, args):
        target_ip = args[0] if args else None
        if self.monitor.start_monitoring(target_ip):
            return f"Started monitoring {target_ip if target_ip else 'all traffic'}"
        else:
            return "Monitoring is already active"
    
    def cmd_stop_monitoring(self, args):
        self.monitor.stop_monitoring()
        return "Stopped network monitoring"
    
    def cmd_status(self, args):
        stats = self.monitor.get_current_stats()
        system_info = f"""
System Status:
  OS: {platform.system()} {platform.release()}
  CPU: {psutil.cpu_percent()}%
  Memory: {psutil.virtual_memory().percent}%
  Disk: {psutil.disk_usage('/').percent}%

Monitoring Status:
  Active: {'Yes' if stats['is_monitoring'] else 'No'}
  Target: {stats['target_ip'] or 'All traffic'}
  Packets: {stats['packets_processed']}
  Packet Rate: {stats['packet_rate']:.2f}/s
  Threats Detected: {stats['threats_detected']}
"""
        return system_info
    
    def cmd_scan(self, args):
        if not args:
            return "Usage: scan <ip> [ports]"
        
        ip = args[0]
        ports = args[1] if len(args) > 1 else "1-1000"
        
        result = self.scanner.port_scan(ip, ports)
        if result['success']:
            open_ports = result.get('open_ports', [])
            response = f"Scan Results for {ip}:\n"
            response += f"Open Ports: {len(open_ports)}\n\n"
            for port in open_ports[:20]:  # Show first 20 ports
                response += f"  Port {port['port']}: {port['service']}\n"
            if len(open_ports) > 20:
                response += f"\n  ... and {len(open_ports) - 20} more ports"
            return response
        else:
            return f"Scan error: {result.get('error', 'Unknown')}"
    
    def cmd_ping(self, args):
        if not args:
            return "Usage: ping <ip/hostname>"
        return self.scanner.ping_ip(args[0])
    
    def cmd_traceroute(self, args):
        if not args:
            return "Usage: traceroute <target>"
        return self.scanner.traceroute(args[0])
    
    def cmd_vulnscan(self, args):
        if not args:
            return "Usage: vulnscan <target>"
        
        result = self.scanner.vulnerability_scan(args[0])
        if result['success']:
            vulns = result.get('vulnerabilities', [])
            response = f"Vulnerability Scan for {args[0]}:\n"
            response += f"Vulnerabilities found: {len(vulns)}\n\n"
            for vuln in vulns[:10]:  # Show first 10 vulnerabilities
                response += f"  • {vuln}\n"
            return response
        else:
            return f"Scan error: {result.get('error', 'Unknown')}"
    
    def cmd_ifconfig(self, args):
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            else:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return str(e)
    
    def cmd_netstat(self, args):
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
            else:
                result = subprocess.run(['netstat', '-tulpn'], capture_output=True, text=True)
            return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return str(e)
    
    def cmd_whois(self, args):
        if not args:
            return "Usage: whois <domain>"
        
        try:
            result = subprocess.run(['whois', args[0]], capture_output=True, text=True, timeout=30)
            return result.stdout[:1000] + "..." if len(result.stdout) > 1000 else result.stdout
        except Exception as e:
            return str(e)
    
    def cmd_dns(self, args):
        if not args:
            return "Usage: dns <domain>"
        
        try:
            ip = socket.gethostbyname(args[0])
            return f"{args[0]} → {ip}"
        except Exception as e:
            return str(e)
    
    def cmd_threats(self, args):
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(
            '''SELECT timestamp, source_ip, threat_type, severity 
               FROM intrusion_detection 
               ORDER BY timestamp DESC LIMIT 10'''
        )
        results = cursor.fetchall()
        conn.close()
        
        if not results:
            return "No threats detected"
        
        response = "Recent Threats:\n"
        for timestamp, source_ip, threat_type, severity in results:
            response += f"  {timestamp} - {source_ip} - {threat_type} ({severity})\n"
        return response
    
    def cmd_stats(self, args):
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Get threat stats
        cursor.execute('''
            SELECT threat_type, COUNT(*) as count 
            FROM intrusion_detection 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY threat_type
        ''')
        threat_stats = cursor.fetchall()
        
        # Get packet stats
        cursor.execute('''
            SELECT SUM(packets_processed), AVG(packet_rate)
            FROM network_stats 
            WHERE timestamp > datetime('now', '-1 hour')
        ''')
        packet_stats = cursor.fetchone()
        
        conn.close()
        
        response = "Network Statistics (Last 24 hours):\n\n"
        response += "Threat Types:\n"
        for threat_type, count in threat_stats:
            response += f"  {threat_type}: {count}\n"
        
        if packet_stats and packet_stats[0]:
            response += f"\nTotal Packets: {packet_stats[0]:,}\n"
            response += f"Average Rate: {packet_stats[1]:.2f} packets/s\n"
        
        return response
    
    def cmd_clear(self, args):
        os.system('cls' if os.name == 'nt' else 'clear')
        return ""
    
    def cmd_exit(self, args):
        return "EXIT"

class TrafficGeneratorGUI:
    """GUI for network traffic generation"""
    
    def __init__(self, root, traffic_generator: NetworkTrafficGenerator):
        self.root = root
        self.traffic_generator = traffic_generator
        self.setup_gui()
    
    def setup_gui(self):
        """Setup the GUI interface"""
        self.root.title("Accurate Cyber Defense - Traffic Generator")
        self.root.geometry("700x500")
        self.root.resizable(True, True)
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Target configuration
        ttk.Label(main_frame, text="Target IP/Hostname:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.target_entry = ttk.Entry(main_frame, width=30)
        self.target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        ttk.Label(main_frame, text="Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.port_entry = ttk.Entry(main_frame, width=10)
        self.port_entry.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        self.port_entry.insert(0, "80")
        
        # Traffic type
        ttk.Label(main_frame, text="Traffic Type:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.traffic_type = ttk.Combobox(main_frame, values=["TCP", "UDP", "ICMP"], width=15)
        self.traffic_type.grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)
        self.traffic_type.current(0)
        
        # Packet configuration
        ttk.Label(main_frame, text="Packet Count:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.packet_count = ttk.Entry(main_frame, width=10)
        self.packet_count.grid(row=3, column=1, sticky=tk.W, pady=5, padx=5)
        self.packet_count.insert(0, "100")
        
        ttk.Label(main_frame, text="Delay (ms):").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.delay_entry = ttk.Entry(main_frame, width=10)
        self.delay_entry.grid(row=4, column=1, sticky=tk.W, pady=5, padx=5)
        self.delay_entry.insert(0, "10")
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start Traffic", command=self.start_traffic)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Traffic", command=self.stop_traffic, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Output console
        ttk.Label(main_frame, text="Output:").grid(row=7, column=0, sticky=tk.W, pady=5)
        self.output_text = scrolledtext.ScrolledText(main_frame, width=80, height=15)
        self.output_text.grid(row=8, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(8, weight=1)
    
    def log_output(self, message: str):
        """Add message to output console"""
        self.output_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {message}\n")
        self.output_text.see(tk.END)
        self.root.update()
    
    def start_traffic(self):
        """Start traffic generation"""
        target = self.target_entry.get().strip()
        traffic_type = self.traffic_type.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target IP/hostname")
            return
        
        try:
            packet_count = int(self.packet_count.get())
            delay = float(self.delay_entry.get()) / 1000  # Convert to seconds
        except ValueError:
            messagebox.showerror("Error", "Invalid numeric values")
            return
        
        self.traffic_generator.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        self.log_output(f"Starting {traffic_type} traffic to {target}...")
        
        # Start traffic in separate thread
        def traffic_thread():
            try:
                if traffic_type == "TCP":
                    port = int(self.port_entry.get())
                    result = self.traffic_generator.generate_tcp_traffic(target, port, packet_count, delay)
                elif traffic_type == "UDP":
                    port = int(self.port_entry.get())
                    result = self.traffic_generator.generate_udp_traffic(target, port, packet_count, delay)
                elif traffic_type == "ICMP":
                    result = self.traffic_generator.generate_icmp_traffic(target, packet_count, delay)
                else:
                    result = "❌ Unknown traffic type"
                
                self.log_output(result)
                
            except Exception as e:
                self.log_output(f"❌ Error: {str(e)}")
            finally:
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
                self.traffic_generator.running = False
        
        thread = threading.Thread(target=traffic_thread, daemon=True)
        thread.start()
    
    def stop_traffic(self):
        """Stop traffic generation"""
        self.traffic_generator.stop_traffic()
        self.log_output("Stopping traffic generation...")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

class CyberSecurityDashboard:
    """Main GUI dashboard for cyber security monitoring"""
    
    def __init__(self, root, db_manager: DatabaseManager, 
                 network_monitor: NetworkMonitor, network_scanner: NetworkScanner):
        self.root = root
        self.db_manager = db_manager
        self.monitor = network_monitor
        self.scanner = network_scanner
        self.current_theme = "dark"
        
        self.setup_gui()
        self.update_interval = 2000  # ms
        self.update_dashboard()
    
    def setup_gui(self):
        """Setup the main dashboard GUI"""
        self.root.title("Accurate Cyber Defense - Network Intrusion Detection System")
        self.root.geometry("1200x800")
        
        # Create menu
        self.create_menu()
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_threat_dashboard_tab()
        self.create_network_monitor_tab()
        self.create_scanner_tab()
        self.create_terminal_tab()
        self.create_reports_tab()
        
        # Apply theme
        self.apply_theme()
    
    def create_menu(self):
        """Create application menu"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Load Session", command=self.load_session)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Switch Theme", command=self.switch_theme)
        view_menu.add_command(label="Threat Dashboard", 
                             command=lambda: self.notebook.select(0))
        view_menu.add_command(label="Network Monitor",
                             command=lambda: self.notebook.select(1))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Traffic Generator", command=self.open_traffic_generator)
        tools_menu.add_command(label="Port Scanner", command=self.open_port_scanner)
        tools_menu.add_command(label="Vulnerability Scanner", command=self.open_vulnerability_scanner)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        self.root.config(menu=menubar)
    
    def create_threat_dashboard_tab(self):
        """Create threat dashboard tab"""
        self.threat_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.threat_tab, text="Threat Dashboard")
        
        # Monitoring controls
        monitor_frame = ttk.LabelFrame(self.threat_tab, text="Network Monitoring")
        monitor_frame.pack(fill=tk.X, padx=10, pady=5)
        
        control_frame = ttk.Frame(monitor_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Target IP (optional):").pack(side=tk.LEFT, padx=5)
        self.monitor_ip_entry = ttk.Entry(control_frame, width=20)
        self.monitor_ip_entry.pack(side=tk.LEFT, padx=5)
        
        self.start_monitor_btn = ttk.Button(control_frame, text="Start Monitoring", 
                                           command=self.start_monitoring)
        self.start_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_monitor_btn = ttk.Button(control_frame, text="Stop Monitoring",
                                          command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        # Current threats display
        threats_frame = ttk.LabelFrame(self.threat_tab, text="Current Threats")
        threats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview for threats
        columns = ('Time', 'Source IP', 'Threat Type', 'Severity', 'Description')
        self.threats_tree = ttk.Treeview(threats_frame, columns=columns, show='headings')
        
        for col in columns:
            self.threats_tree.heading(col, text=col)
            self.threats_tree.column(col, width=150)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(threats_frame, orient=tk.VERTICAL, command=self.threats_tree.yview)
        self.threats_tree.configure(yscrollcommand=scrollbar.set)
        
        self.threats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Threat statistics
        stats_frame = ttk.LabelFrame(self.threat_tab, text="Threat Statistics")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=8)
        self.stats_text.pack(fill=tk.X, padx=5, pady=5)
    
    def create_network_monitor_tab(self):
        """Create network monitor tab"""
        self.monitor_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.monitor_tab, text="Network Monitor")
        
        # Real-time stats
        stats_frame = ttk.LabelFrame(self.monitor_tab, text="Real-time Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create stats display
        self.stats_labels = {}
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        stats_info = [
            ("Packets Processed:", "packets"),
            ("Packet Rate:", "rate"),
            ("TCP Packets:", "tcp"),
            ("UDP Packets:", "udp"),
            ("ICMP Packets:", "icmp"),
            ("Threats Detected:", "threats"),
            ("Monitoring Time:", "uptime")
        ]
        
        for i, (label_text, key) in enumerate(stats_info):
            row = i % 4
            col = i // 4
            
            frame = ttk.Frame(stats_grid)
            frame.grid(row=row, column=col, sticky=tk.W, padx=20, pady=10)
            
            ttk.Label(frame, text=label_text, font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
            self.stats_labels[key] = ttk.Label(frame, text="0", font=('Arial', 10))
            self.stats_labels[key].pack(side=tk.LEFT, padx=5)
        
        # Packet log
        log_frame = ttk.LabelFrame(self.monitor_tab, text="Packet Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.packet_log = scrolledtext.ScrolledText(log_frame, height=10)
        self.packet_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_scanner_tab(self):
        """Create network scanner tab"""
        self.scanner_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_tab, text="Network Scanner")
        
        # Scanner controls
        control_frame = ttk.LabelFrame(self.scanner_tab, text="Scanner Controls")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Target input
        target_frame = ttk.Frame(control_frame)
        target_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(target_frame, text="Target:").pack(side=tk.LEFT, padx=5)
        self.scan_target_entry = ttk.Entry(target_frame, width=30)
        self.scan_target_entry.pack(side=tk.LEFT, padx=5)
        
        # Port range
        port_frame = ttk.Frame(control_frame)
        port_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(port_frame, text="Ports:").pack(side=tk.LEFT, padx=5)
        self.port_range_entry = ttk.Entry(port_frame, width=15)
        self.port_range_entry.pack(side=tk.LEFT, padx=5)
        self.port_range_entry.insert(0, "1-1000")
        
        # Scan buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Ping", command=self.run_ping).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Port Scan", command=self.run_port_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Traceroute", command=self.run_traceroute).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Vulnerability Scan", command=self.run_vuln_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Get Location", command=self.get_ip_location).pack(side=tk.LEFT, padx=5)
        
        # Results display
        results_frame = ttk.LabelFrame(self.scanner_tab, text="Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.scan_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.scan_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_terminal_tab(self):
        """Create terminal emulator tab"""
        self.terminal_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.terminal_tab, text="Terminal")
        
        # Terminal output
        self.terminal_output = scrolledtext.ScrolledText(self.terminal_tab, wrap=tk.WORD, state='disabled')
        self.terminal_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Terminal input
        input_frame = ttk.Frame(self.terminal_tab)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text=">").pack(side=tk.LEFT, padx=5)
        self.terminal_input = ttk.Entry(input_frame)
        self.terminal_input.pack(fill=tk.X, expand=True, padx=5)
        self.terminal_input.bind('<Return>', self.execute_terminal_command)
        
        # Help button
        ttk.Button(input_frame, text="Help", command=self.show_terminal_help).pack(side=tk.RIGHT, padx=5)
    
    def create_reports_tab(self):
        """Create reports tab"""
        self.reports_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.reports_tab, text="Reports")
        
        # Report controls
        control_frame = ttk.LabelFrame(self.reports_tab, text="Report Generation")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(padx=5, pady=10)
        
        ttk.Button(button_frame, text="Generate Threat Report", 
                  command=self.generate_threat_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Generate Network Report",
                  command=self.generate_network_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Generate Full Report",
                  command=self.generate_full_report).pack(side=tk.LEFT, padx=5)
        
        # Reports display
        reports_frame = ttk.LabelFrame(self.reports_tab, text="Generated Reports")
        reports_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.reports_display = scrolledtext.ScrolledText(reports_frame, wrap=tk.WORD)
        self.reports_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def apply_theme(self):
        """Apply current theme to GUI"""
        theme = THEMES[self.current_theme]
        
        # Configure ttk styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('TFrame', background=theme['bg'])
        style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe.Label', background=theme['bg'], foreground=theme['fg'])
        
        # Configure text widgets
        text_widgets = [self.stats_text, self.packet_log, self.scan_results, 
                       self.terminal_output, self.reports_display]
        
        for widget in text_widgets:
            widget.configure(
                background=theme['text_bg'],
                foreground=theme['text_fg'],
                insertbackground=theme['fg']
            )
    
    def switch_theme(self):
        """Switch between dark and light themes"""
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.apply_theme()
    
    def start_monitoring(self):
        """Start network monitoring"""
        target_ip = self.monitor_ip_entry.get().strip()
        if target_ip and not self.validate_ip(target_ip):
            messagebox.showerror("Error", "Invalid IP address")
            return
        
        if self.monitor.start_monitoring(target_ip):
            self.start_monitor_btn.config(state=tk.DISABLED)
            self.stop_monitor_btn.config(state=tk.NORMAL)
            self.log_message(f"Started monitoring {target_ip if target_ip else 'all traffic'}")
        else:
            messagebox.showwarning("Warning", "Monitoring is already active")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitor.stop_monitoring()
        self.start_monitor_btn.config(state=tk.NORMAL)
        self.stop_monitor_btn.config(state=tk.DISABLED)
        self.log_message("Stopped network monitoring")
    
    def run_ping(self):
        """Run ping command"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Pinging {target}...\n")
        self.scan_results.see(tk.END)
        
        def do_ping():
            result = self.scanner.ping_ip(target)
            self.scan_results.insert(tk.END, result + "\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=do_ping, daemon=True).start()
    
    def run_port_scan(self):
        """Run port scan"""
        target = self.scan_target_entry.get().strip()
        ports = self.port_range_entry.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        if not self.validate_ip(target):
            messagebox.showerror("Error", "Invalid IP address")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Scanning {target} ports {ports}...\n")
        self.scan_results.see(tk.END)
        
        def do_scan():
            result = self.scanner.port_scan(target, ports)
            if result['success']:
                open_ports = result.get('open_ports', [])
                self.scan_results.insert(tk.END, f"\nScan completed. Open ports: {len(open_ports)}\n")
                for port in open_ports:
                    self.scan_results.insert(tk.END, 
                        f"Port {port['port']}: {port['service']}\n")
            else:
                self.scan_results.insert(tk.END, f"Error: {result.get('error', 'Unknown')}\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=do_scan, daemon=True).start()
    
    def run_traceroute(self):
        """Run traceroute"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Traceroute to {target}...\n")
        self.scan_results.see(tk.END)
        
        def do_trace():
            result = self.scanner.traceroute(target)
            self.scan_results.insert(tk.END, result + "\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=do_trace, daemon=True).start()
    
    def run_vuln_scan(self):
        """Run vulnerability scan"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        if not NMAP_AVAILABLE:
            messagebox.showerror("Error", "Nmap not available")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Running vulnerability scan on {target}...\n")
        self.scan_results.see(tk.END)
        
        def do_vuln_scan():
            result = self.scanner.vulnerability_scan(target)
            if result['success']:
                vulns = result.get('vulnerabilities', [])
                self.scan_results.insert(tk.END, f"\nVulnerabilities found: {len(vulns)}\n")
                for vuln in vulns:
                    self.scan_results.insert(tk.END, f"• {vuln}\n")
            else:
                self.scan_results.insert(tk.END, f"Error: {result.get('error', 'Unknown')}\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=do_vuln_scan, daemon=True).start()
    
    def get_ip_location(self):
        """Get IP location"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Getting location for {target}...\n")
        self.scan_results.see(tk.END)
        
        def do_location():
            result = self.scanner.get_ip_location(target)
            self.scan_results.insert(tk.END, result + "\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=do_location, daemon=True).start()
    
    def execute_terminal_command(self, event=None):
        """Execute terminal command"""
        command = self.terminal_input.get()
        self.terminal_input.delete(0, tk.END)
        
        if not command:
            return
        
        # Create terminal emulator
        terminal = TerminalEmulator(self.scanner, self.monitor)
        
        # Display command
        self.terminal_output.config(state='normal')
        self.terminal_output.insert(tk.END, f"> {command}\n")
        
        # Execute command
        result = terminal.execute(command)
        if result:  # Don't show empty results
            self.terminal_output.insert(tk.END, f"{result}\n")
        
        self.terminal_output.see(tk.END)
        self.terminal_output.config(state='disabled')
        
        # Handle exit command
        if command.lower() == 'exit':
            self.root.after(1000, self.root.quit)
    
    def show_terminal_help(self):
        """Show terminal help"""
        terminal = TerminalEmulator(self.scanner, self.monitor)
        help_text = terminal.cmd_help([])
        
        self.terminal_output.config(state='normal')
        self.terminal_output.insert(tk.END, help_text + "\n")
        self.terminal_output.see(tk.END)
        self.terminal_output.config(state='disabled')
    
    def generate_threat_report(self):
        """Generate threat report"""
        threats = self.db_manager.get_recent_intrusions(100)
        
        report = "THREAT REPORT\n"
        report += "=" * 50 + "\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Total Threats: {len(threats)}\n\n"
        
        # Threat statistics
        threat_stats = self.db_manager.get_threat_stats(24)
        report += "Threat Statistics (Last 24 hours):\n"
        for threat_type, count in threat_stats.items():
            report += f"  {threat_type}: {count}\n"
        
        report += "\nRecent Threats:\n"
        for timestamp, source_ip, threat_type, severity, description in threats:
            report += f"{timestamp} - {source_ip} - {threat_type} ({severity})\n"
            if description:
                report += f"  {description}\n"
        
        self.reports_display.delete(1.0, tk.END)
        self.reports_display.insert(tk.END, report)
        
        # Save to file
        filename = f"threat_report_{int(time.time())}.txt"
        os.makedirs(REPORT_DIR, exist_ok=True)
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(report)
        
        self.log_message(f"Threat report saved to {filename}")
    
    def generate_network_report(self):
        """Generate network report"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Get network stats
        cursor.execute('''
            SELECT timestamp, packets_processed, packet_rate, threat_count
            FROM network_stats 
            WHERE timestamp > datetime('now', '-24 hours')
            ORDER BY timestamp
        ''')
        stats = cursor.fetchall()
        
        report = "NETWORK REPORT\n"
        report += "=" * 50 + "\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        if stats:
            total_packets = sum(row[1] for row in stats)
            avg_rate = sum(row[2] for row in stats) / len(stats) if stats else 0
            total_threats = sum(row[3] for row in stats)
            
            report += f"Total Packets (24h): {total_packets:,}\n"
            report += f"Average Packet Rate: {avg_rate:.2f}/s\n"
            report += f"Total Threats (24h): {total_threats}\n"
        
        conn.close()
        
        self.reports_display.delete(1.0, tk.END)
        self.reports_display.insert(tk.END, report)
        
        # Save to file
        filename = f"network_report_{int(time.time())}.txt"
        os.makedirs(REPORT_DIR, exist_ok=True)
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(report)
        
        self.log_message(f"Network report saved to {filename}")
    
    def generate_full_report(self):
        """Generate full comprehensive report"""
        self.generate_threat_report()
        threat_report = self.reports_display.get(1.0, tk.END)
        
        self.generate_network_report()
        network_report = self.reports_display.get(1.0, tk.END)
        
        full_report = "FULL SECURITY REPORT\n"
        full_report += "=" * 60 + "\n\n"
        full_report += network_report + "\n"
        full_report += threat_report
        
        self.reports_display.delete(1.0, tk.END)
        self.reports_display.insert(tk.END, full_report)
        
        # Save to file
        filename = f"full_report_{int(time.time())}.txt"
        os.makedirs(REPORT_DIR, exist_ok=True)
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(full_report)
        
        self.log_message(f"Full report saved to {filename}")
    
    def update_dashboard(self):
        """Update dashboard with current information"""
        # Update threat list
        self.update_threat_list()
        
        # Update statistics
        self.update_statistics()
        
        # Update network stats
        self.update_network_stats()
        
        # Schedule next update
        self.root.after(self.update_interval, self.update_dashboard)
    
    def update_threat_list(self):
        """Update the threat list display"""
        # Clear current items
        for item in self.threats_tree.get_children():
            self.threats_tree.delete(item)
        
        # Get recent threats
        threats = self.db_manager.get_recent_intrusions(20)
        
        # Add threats to treeview
        for timestamp, source_ip, threat_type, severity, description in threats:
            self.threats_tree.insert('', 'end', values=(
                timestamp,
                source_ip,
                threat_type,
                severity,
                description[:50] + "..." if len(description) > 50 else description
            ))
    
    def update_statistics(self):
        """Update threat statistics"""
        threat_stats = self.db_manager.get_threat_stats(1)  # Last hour
        
        stats_text = "Threat Statistics (Last Hour):\n"
        stats_text += "-" * 30 + "\n"
        
        if threat_stats:
            for threat_type, count in threat_stats.items():
                stats_text += f"{threat_type}: {count}\n"
        else:
            stats_text += "No threats detected\n"
        
        # Add monitoring status
        stats = self.monitor.get_current_stats()
        stats_text += f"\nMonitoring Status: {'Active' if stats['is_monitoring'] else 'Inactive'}\n"
        if stats['is_monitoring']:
            stats_text += f"Target: {stats['target_ip'] or 'All traffic'}\n"
            stats_text += f"Threats Detected: {stats['threats_detected']}\n"
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats_text)
    
    def update_network_stats(self):
        """Update network statistics display"""
        stats = self.monitor.get_current_stats()
        
        # Update labels
        self.stats_labels['packets'].config(text=f"{stats['packets_processed']:,}")
        self.stats_labels['rate'].config(text=f"{stats['packet_rate']:.2f}/s")
        self.stats_labels['tcp'].config(text=f"{stats['tcp_packets']:,}")
        self.stats_labels['udp'].config(text=f"{stats['udp_packets']:,}")
        self.stats_labels['icmp'].config(text=f"{stats['icmp_packets']:,}")
        self.stats_labels['threats'].config(text=f"{stats['threats_detected']:,}")
        
        # Format uptime
        if stats['uptime'] > 0:
            hours = int(stats['uptime'] // 3600)
            minutes = int((stats['uptime'] % 3600) // 60)
            seconds = int(stats['uptime'] % 60)
            uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        else:
            uptime_str = "00:00:00"
        
        self.stats_labels['uptime'].config(text=uptime_str)
    
    def log_message(self, message: str):
        """Log message to packet log"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.packet_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.packet_log.see(tk.END)
    
    def new_session(self):
        """Create new session"""
        if messagebox.askyesno("New Session", "Start a new monitoring session?"):
            self.monitor.stop_monitoring()
            self.monitor_ip_entry.delete(0, tk.END)
            self.log_message("New session started")
    
    def save_session(self):
        """Save current session"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                session_data = {
                    'target_ip': self.monitor_ip_entry.get(),
                    'scan_target': self.scan_target_entry.get(),
                    'port_range': self.port_range_entry.get(),
                    'timestamp': datetime.now().isoformat()
                }
                
                with open(file_path, 'w') as f:
                    json.dump(session_data, f, indent=4)
                
                self.log_message(f"Session saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save session: {str(e)}")
    
    def load_session(self):
        """Load saved session"""
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    session_data = json.load(f)
                
                self.monitor_ip_entry.delete(0, tk.END)
                self.monitor_ip_entry.insert(0, session_data.get('target_ip', ''))
                
                self.scan_target_entry.delete(0, tk.END)
                self.scan_target_entry.insert(0, session_data.get('scan_target', ''))
                
                self.port_range_entry.delete(0, tk.END)
                self.port_range_entry.insert(0, session_data.get('port_range', '1-1000'))
                
                self.log_message(f"Session loaded from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load session: {str(e)}")
    
    def open_traffic_generator(self):
        """Open traffic generator window"""
        if not GUI_AVAILABLE:
            messagebox.showerror("Error", "GUI features not available")
            return
        
        traffic_window = tk.Toplevel(self.root)
        traffic_window.title("Traffic Generator")
        
        # Create traffic generator instance
        from cyber_tool import NetworkTrafficGenerator
        traffic_gen = NetworkTrafficGenerator(self.db_manager)
        TrafficGeneratorGUI(traffic_window, traffic_gen)
    
    def open_port_scanner(self):
        """Open port scanner"""
        self.notebook.select(self.scanner_tab)
    
    def open_vulnerability_scanner(self):
        """Open vulnerability scanner"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target in the Scanner tab")
            self.notebook.select(self.scanner_tab)
            return
        
        self.run_vuln_scan()
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

class CyberSecurityMonitor:
    """Main monitor class for CLI mode"""
    
    def __init__(self):
        self.monitored_ips = set()
        self.monitoring_active = False
        self.telegram_token = None
        self.telegram_chat_id = None
        self.db_manager = DatabaseManager()
        self.scanner = NetworkScanner(self.db_manager)
        self.traceroute_tool = TracerouteTool()
        self.traffic_generator = NetworkTrafficGenerator(self.db_manager)
        self.network_monitor = NetworkMonitor(self.db_manager)
        self.setup_logging()
        self.load_config()
    
    def setup_logging(self):
        """Setup logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler('cybersecurity.log'), logging.StreamHandler(sys.stdout)]
        )
    
    def load_config(self):
        """Load configuration"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.telegram_token = config.get('telegram_token')
                    self.telegram_chat_id = config.get('telegram_chat_id')
                    self.monitored_ips = set(config.get('monitored_ips', []))
        except Exception as e: 
            logging.error(f"Config load error: {e}")
    
    def save_config(self):
        """Save configuration"""
        try:
            config = {
                'telegram_token': self.telegram_token,
                'telegram_chat_id': self.telegram_chat_id,
                'monitored_ips': list(self.monitored_ips)
            }
            with open(CONFIG_FILE, 'w') as f: 
                json.dump(config, f, indent=4)
        except Exception as e: 
            logging.error(f"Config save error: {e}")

def print_banner():
    """Print banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                                                                      ║
    ║          🛡️  ACCURATE CYBER DRILL OFFENSIVE TOOL        🛡️          ║
    ║                                                                      ║
    ║      Network Monitoring • Intrusion Detection • Traffic Generation   ║
    ║         Security Analysis • Threat Detection • Vulnerability Scan    ║
    ║                                                                      ║
    ║   Version: 1.0.0                  Author: Ian Carter Kulani          ║
    ║   Community: https://github.com/Accurate-Cyber-Defense               ║
    ║                                                                      ║
    ║   Features:                                                          ║
    ║   • Real-time Network Monitoring      • Advanced Threat Detection    ║
    ║   • Port & Vulnerability Scanning     • Traffic Generation Tools     ║
    ║   • Intrusion Detection System        • Comprehensive Reporting      ║
    ║   • CLI & GUI Interfaces              • Database Logging             ║
    ║                                                                      ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def cli_mode():
    """Run in CLI mode"""
    monitor = CyberSecurityMonitor()
    terminal = TerminalEmulator(monitor.scanner, monitor.network_monitor)
    
    print_banner()
    print("\n🔧 CLI Mode Activated")
    print("Type 'help' for available commands")
    print("Type 'gui' to switch to GUI mode")
    print("Type 'exit' to quit\n")
    
    while True:
        try:
            command = input("cyberdefense> ").strip()
            if not command:
                continue
            
            if command.lower() == 'exit':
                print("👋 Exiting...")
                monitor.network_monitor.stop_monitoring()
                monitor.traffic_generator.stop_traffic()
                break
            
            elif command.lower() == 'gui':
                print("🚀 Switching to GUI mode...")
                return 'gui'
            
            elif command.lower() == 'menu':
                print_banner()
                print("\nAvailable modes:")
                print("  1. CLI Mode (current)")
                print("  2. GUI Mode")
                print("  3. Exit")
                
                choice = input("\nSelect mode (1-3): ").strip()
                if choice == '2':
                    return 'gui'
                elif choice == '3':
                    print("👋 Exiting...")
                    monitor.network_monitor.stop_monitoring()
                    monitor.traffic_generator.stop_traffic()
                    break
            
            else:
                result = terminal.execute(command)
                if result == "EXIT":
                    print("👋 Exiting...")
                    monitor.network_monitor.stop_monitoring()
                    monitor.traffic_generator.stop_traffic()
                    break
                elif result:
                    print(result)
        
        except KeyboardInterrupt:
            print("\n👋 Exiting...")
            monitor.network_monitor.stop_monitoring()
            monitor.traffic_generator.stop_traffic()
            break
        except Exception as e:
            print(f"❌ Error: {e}")

def gui_mode():
    """Run in GUI mode"""
    if not GUI_AVAILABLE:
        print("❌ GUI mode requires tkinter. Please install it or use CLI mode.")
        print("On Ubuntu/Debian: sudo apt-get install python3-tk")
        print("On Fedora/RHEL: sudo dnf install python3-tkinter")
        print("On macOS: brew install python-tk")
        print("On Windows: Usually included with Python")
        return 'cli'
    
    # Initialize components
    db_manager = DatabaseManager()
    network_monitor = NetworkMonitor(db_manager)
    network_scanner = NetworkScanner(db_manager)
    
    # Create main window
    root = tk.Tk()
    root.title("Accurate Cyber Defense - Unified Security Platform")
    root.geometry("1200x800")
    
    try:
        app = CyberSecurityDashboard(root, db_manager, network_monitor, network_scanner)
        
        # Handle window close
        def on_closing():
            network_monitor.stop_monitoring()
            root.quit()
            root.destroy()
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        root.mainloop()
        
        return 'menu'
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start GUI: {str(e)}")
        print(f"GUI Error: {e}")
        return 'cli'

def main():
    """Main entry point"""
    print_banner()
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == '--cli':
            mode = 'cli'
        elif sys.argv[1] == '--gui':
            mode = 'gui'
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Usage: python cyber_tool.py [--cli|--gui]")
            mode = 'menu'
    else:
        # Interactive mode selection
        print("\nSelect mode:")
        print("  1. CLI Mode (Command Line Interface)")
        print("  2. GUI Mode (Graphical User Interface)")
        print("  3. Exit")
        
        while True:
            choice = input("\nSelect mode (1-3): ").strip()
            if choice == '1':
                mode = 'cli'
                break
            elif choice == '2':
                mode = 'gui'
                break
            elif choice == '3':
                print("👋 Thank you for using Accurate Cyber Defense!")
                return
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
    
    # Run selected mode
    while True:
        if mode == 'cli':
            mode = cli_mode()
        elif mode == 'gui':
            mode = gui_mode()
        elif mode == 'menu':
            print("\nSelect mode:")
            print("  1. CLI Mode (Command Line Interface)")
            print("  2. GUI Mode (Graphical User Interface)")
            print("  3. Exit")
            
            choice = input("\nSelect mode (1-3): ").strip()
            if choice == '1':
                mode = 'cli'
            elif choice == '2':
                mode = 'gui'
            elif choice == '3':
                print("👋 Thank you for using Accurate Cyber Defense!")
                break
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
        else:
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Thank you for using Accurate Cyber Defense!")
    except Exception as e:
        print(f"❌ Application error: {e}")
        logging.exception("Application crash")