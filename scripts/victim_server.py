#!/usr/bin/env python3
"""
FILE: victim_server.py (UPDATED FOR MULTI-ATTACK DETECTION)
PROJECT: ML-Assisted Detection of IoT Botnet DDoS Attacks: An Ensemble Learning Approach
AUTHOR: Kananelo Chabeli
DATE: 2024 - Updated 2026

DESCRIPTION:
    Runs on server (the victim). Listens on both TCP and UDP ports to capture
    all attack traffic types from the CICDDoSIOT2024 dataset:
      - TCP attacks: SYN floods, ACK floods, HTTP floods
      - UDP attacks: UDP floods
      - ICMP attacks: ICMP floods, ICMP fragmentation

    Separates traffic by protocol, applies per-protocol thresholds (since attack
    signatures differ by type), and logs per-source metrics to CSV for post-analysis.

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

# ============================================================================
# CONSTANTS — Attack Detection Thresholds
# ============================================================================

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

# ============================================================================
# SHARED STATE — Per-Protocol Packet Counters
# ============================================================================

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
# REPORTER — Log results every REPORT_INTERVAL seconds
# ============================================================================

def reporter(interval: float, csv_path: str, cpu_log_path: str):
    """
    Main reporting loop: wake every `interval` seconds, compute rates,
    log to CSV, log CPU utilization, and print summary.

    Runs in main thread.

    Args:
        interval: seconds between reports (typically 5)
        csv_path: where to write traffic CSV log file
        cpu_log_path: where to write CPU utilization log file
    """
    # Open CSV file and write header
    f = open(csv_path, 'w', newline='')
    writer = csv.writer(f)
    writer.writerow([
        'timestamp', 'src_ip', 'protocol', 'interval_pkts',
        'rate_pps', 'total_pkts', 'label', 'threshold_pps'
    ])
    f.flush()

    # Open CPU log file and write header
    cpu_f = open(cpu_log_path, 'w', newline='')
    cpu_writer = csv.writer(cpu_f)
    cpu_writer.writerow(['timestamp', 'cpu_percent'])
    cpu_f.flush()

    # Get process object for CPU monitoring
    proc = psutil.Process(os.getpid())

    print(f'[VictimServer] Reporter writing traffic to {csv_path}')
    print(f'[VictimServer] Reporter writing CPU to {cpu_log_path}')
    print(f'[VictimServer] Report interval: {interval}s')
    print()

    while True:
        time.sleep(interval)
        now = time.strftime('%Y-%m-%d %H:%M:%S')
        now_ts = int(time.time())

        # Log CPU utilization
        try:
            cpu_percent = proc.cpu_percent(interval=0.1)
            cpu_writer.writerow([now_ts, round(cpu_percent, 2)])
            cpu_f.flush()
        except Exception as e:
            print(f'[VictimServer] Error reading CPU: {e}')

        # Atomic snapshot + reset interval counters
        with counts_lock:
            snapshots = {
                'TCP': dict(interval_counts['TCP']),
                'UDP': dict(interval_counts['UDP']),
                'ICMP': dict(interval_counts['ICMP']),
            }
            # Reset for next interval
            interval_counts['TCP'].clear()
            interval_counts['UDP'].clear()
            interval_counts['ICMP'].clear()

        # Check if any traffic at all
        total_traffic = sum(
            sum(snapshots[proto].values()) for proto in ['TCP', 'UDP', 'ICMP']
        )
        if total_traffic == 0:
            print(f'[{now}] No traffic in last {interval}s')
            continue

        # ────────────────────────────────────────────────────────────────
        # Print summary header
        # ────────────────────────────────────────────────────────────────
        print(f'\n[{now}] ────── VICTIM TRAFFIC REPORT ──────')

        # ────────────────────────────────────────────────────────────────
        # Process each protocol separately
        # ────────────────────────────────────────────────────────────────
        for protocol in ['TCP', 'UDP', 'ICMP']:
            snapshot = snapshots[protocol]
            if not snapshot:
                continue

            protocol_total_rate = sum(v for v in snapshot.values()) / interval
            threshold = ATTACK_THRESHOLDS[protocol]

            print(f'\n  {protocol} Traffic ({len(snapshot)} source(s)): '
                  f'{protocol_total_rate:.1f} pkt/s | Threshold: {threshold} pkt/s')
            print(f'  {"-" * 60}')

            # Sort by packet count (descending) for visibility
            for src, count in sorted(snapshot.items(),
                                     key=lambda x: x[1], reverse=True):
                rate = count / interval
                total = total_counts[protocol][src]

                # Label: ATTACK if exceeds threshold, else NORMAL
                label = 'ATTACK' if rate > threshold else 'NORMAL'
                icon = '⚠️ ' if label == 'ATTACK' else '✅'

                print(f'    {icon} {src:15s}  {rate:7.1f} pkt/s  '
                      f'[Δ={count:5d}  total={total:6d}]  [{label}]')

                # Write to CSV
                writer.writerow([
                    now, src, protocol, count, round(rate, 2),
                    total, label, threshold
                ])

        print(f'  {"=" * 60}\n')
        f.flush()

    f.close()


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
    print('  VICTIM SERVER (Multi-Protocol Attack Detection)')
    print('=' * 70)
    print(f'  UDP Port: {args.port_udp} (sensors + UDP floods)')
    print(f'  TCP Port: {args.port_tcp} (HTTP floods + SYN/ACK)')
    print(f'  Report Interval: {args.interval}s')
    print(f'  CSV Log: {csv_path}')
    print(f'  CPU Log: {cpu_log_path}')
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

    # Reporter runs in main thread (blocking)
    try:
        reporter(args.interval, csv_path, cpu_log_path)
    except KeyboardInterrupt:
        print('\n[VictimServer] Shutting down.')
