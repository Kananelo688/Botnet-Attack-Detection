#!/usr/bin/env python3
"""

brief: Simulates remote sensor in an Iot Network that recieves packects from the IoT devices and performs some processing.

decscription:
    Runs on server (the victim). Listens on both TCP and UDP ports to capture all attack traffic types from the CICDDoSIOT2024 dataset:

    This provides GROUND-TRUTH measurements essential for:
      1. Computing Mitigation Effectiveness (how much attack traffic POX blocked)
      2. Validating ML model detections
      3. Time-series analysis of attack patterns

LOG OUTPUT:
    logs/victim_traffic.csv - One line per 5-second reporting interval with:
      - timestamp, src_ip, protocol (TCP/UDP/ICMP), packet_count,
        rate_pps, total_packets, label (NORMAL/ATTACK)

USAGE (auto-started by topology.py on server):
    python3 victim_server.py [--port_udp 9999] [--port_tcp 80] [--interval 5]

DESIGN NOTES:
    - Uses threading: one listener per protocol, plus one reporter thread
    - Thread-safe counters with locks to avoid race conditions
    - Separate thresholds per protocol because attack intensity varies:
      * TCP (SYN/ACK): ~40 pkt/s indicates attack
      * UDP: ~35 pkt/s indicates attack
      * ICMP: ~200 pkt/s indicates attack (ICMP echo floods are very high rate)
    - CSV format enables offline analysis with pandas/ML models
"""

import socket
import threading
import time
import csv
import os
import argparse
import psutil
from collections import defaultdict


REPORT_INTERVAL = 5  # seconds between rate computation and CSV logging

# Protocol-specific thresholds (packets per second from single source)
# These values are calibrated from CICDDoSIOT2024 dataset:
ATTACK_THRESHOLDS = {
    'TCP': 40,      # SYN flood, ACK flood, HTTP flood
    'UDP': 35,      # UDP flood
    'ICMP': 200,    # ICMP flood, ICMP fragmentation (very high rate)
}

LOG_DIR = '/home/chabeli/SDN_IoT/sdn-iot/logs'
os.makedirs(LOG_DIR, exist_ok=True)


# Structure: {protocol: {src_ip: count}}
# Reset every REPORT_INTERVAL by reporter thread
interval_counts = {
    'TCP': defaultdict(int),
    'UDP': defaultdict(int),
    'ICMP': defaultdict(int),
}

# Cumulative totals (never reset)
total_counts = {
    'TCP': defaultdict(int),
    'UDP': defaultdict(int),
    'ICMP': defaultdict(int),
}

# Lock protects both dicts during updates
counts_lock = threading.Lock()


# ============================================================================
# UDP LISTENER — Captures UDP packets (normal sensors + UDP flood attacks)
# ============================================================================

def udp_listener(port: int):
    """
    Listen for UDP packets and tally per-source.
    Runs in daemon thread.

    Args:
        port: UDP port to bind (typically 9999 for sensor traffic)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))
    sock.settimeout(1.0)  # 1s timeout prevents blocking shutdown
    print(f'[VictimServer] UDP Listener started on port {port}')

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            src = addr[0]

            # Atomic increment: must hold lock
            with counts_lock:
                interval_counts['UDP'][src] += 1
                total_counts['UDP'][src] += 1

        except socket.timeout:
            # Timeout is normal when no traffic — just loop
            continue
        except Exception as e:
            print(f'[VictimServer] UDP listener error: {e}')
            break

    sock.close()


# ============================================================================
# TCP LISTENER — Captures TCP packets (SYN flood, ACK flood, HTTP flood)
# ============================================================================

def tcp_listener(port: int):
    """
    Listen for TCP connections and tally per-source.
    Runs in daemon thread.

    Note: This is a passive listener that accepts connections.
    For spoofed TCP floods (ACK with random IPs), we'd need raw sockets.
    This implementation handles legitimate TCP attempts but is primarily
    monitoring for HTTP floods and TCP three-way handshakes.

    Args:
        port: TCP port to bind (typically 80 for HTTP, or 9999)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(100)  # backlog: accept up to 100 pending connections
    sock.settimeout(1.0)
    print(f'[VictimServer] TCP Listener started on port {port}')

    while True:
        try:
            conn, addr = sock.accept()
            src = addr[0]

            # Count the connection attempt
            with counts_lock:
                interval_counts['TCP'][src] += 1
                total_counts['TCP'][src] += 1

            # Close immediately (don't waste resources)
            conn.close()

        except socket.timeout:
            continue
        except Exception as e:
            print(f'[VictimServer] TCP listener error: {e}')
            break

    sock.close()


# ============================================================================
# ICMP LISTENER — Captures ICMP packets (Echo floods, fragmentation attacks)
# ============================================================================

def icmp_listener():
    """
    Listen for ICMP packets using raw sockets.
    Requires elevated privileges (running under sudo).
    Captures both ICMP Echo (ping) and fragmented ICMP floods.

    Runs in daemon thread.
    """
    try:
        # Raw socket to capture ICMP
        sock = socket.socket(socket.AF_INET, socket.IPPROTO_ICMP)
        sock.bind(('0.0.0.0', 0))
        sock.settimeout(1.0)
        print('[VictimServer] ICMP Listener started (raw socket)')

        while True:
            try:
                # Receive raw ICMP packet
                data, addr = sock.recvfrom(4096)
                src = addr[0]

                # Count ICMP packet from this source
                with counts_lock:
                    interval_counts['ICMP'][src] += 1
                    total_counts['ICMP'][src] += 1

            except socket.timeout:
                continue
            except Exception as e:
                print(f'[VictimServer] ICMP listener error: {e}')
                break

        sock.close()

    except PermissionError:
        print('[VictimServer] ⚠️  ICMP listener requires root privileges.')
        print('              Run with: sudo python3 victim_server.py')


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='IoT Botnet Victim Server (Multi-Protocol Listener)'
    )
    parser.add_argument('--port_udp', default=9999, type=int,
                        help='UDP port for sensor traffic & UDP floods')
    parser.add_argument('--port_tcp', default=80, type=int,
                        help='TCP port for HTTP floods & SYN/ACK attacks')
    parser.add_argument('--interval', default=REPORT_INTERVAL, type=float,
                        help='Report interval in seconds')
    args = parser.parse_args()

    csv_path = os.path.join(LOG_DIR, 'victim_traffic.csv')
    cpu_log_path = os.path.expanduser('~/SDN_IoT/sdn-iot/sim_results/victim_cpu_utilization.csv')
    os.makedirs(os.path.dirname(cpu_log_path), exist_ok=True)

    print('=' * 70)
    print('  VICTIM SERVER STARTING...')
    print('=' * 70)
    print(f'  UDP Port: {args.port_udp} (sensors + UDP floods)')
    print(f'  TCP Port: {args.port_tcp} (HTTP floods + SYN/ACK)')
    print(f'  Report Interval: {args.interval}s')
    print('=' * 70)
    print()

    # Start listener threads (daemon mode = exit when main thread exits)
    t_udp = threading.Thread(
        target=udp_listener, args=(args.port_udp,), daemon=True
    )
    t_udp.start()

    t_tcp = threading.Thread(
        target=tcp_listener, args=(args.port_tcp,), daemon=True
    )
    t_tcp.start()

    t_icmp = threading.Thread(
        target=icmp_listener, daemon=True
    )
    t_icmp.start()

    while True:
        try:
            pass # Main thread just keeps running to allow daemon threads to operate
        except KeyboardInterrupt:
            print('\n[VictimServer] Shutting down.')
