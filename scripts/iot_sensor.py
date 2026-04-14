#!/usr/bin/env python3
"""
    
brief: Simulates a normal IoT sensor device sending periodic UDP packets to the victim server.

decscription: Generates the BASELINE normal traffic of a typical IoT sensor. 
            This data is modeled by UDP packet sent to the  victim server every few seconds.
            Each packet contains a small JSON payload with a sensor reading (e.g. temperature, humidity, motion) and a timestamp.

            Runs on Mininet hosts which emulate IoT devices.  Each host sends one small JSON UDP packet every
            INTERVAL seconds, mimicking temperature / humidity / motion sensors.
A
            Packet payload (JSON, ~60 bytes):
                {"src": "h1", "sensor": "temperature", "value": 23.4, "ts": ...}

    USAGE (inside Mininet or directly):
    python3 iot_sensor.py --src N1 --dst 192.168.3.1
    python3 iot_sensor.py --src N2 --dst 192.168.3.1 --interval 3

    ARGUMENTS:
    --src       Logical host name (used in payload, e.g. N1)
    --dst       Victim server IP  (default 192.168.3.1 as seen from Mininet hosts)
    --port      UDP destination port (default 9999) 
    --interval  Seconds between packets (default 2.0)

@author:  Kananelo Chabeli
@date:    2024-03-25
"""

import socket
import time
from datetime import datetime
import json
import random
import argparse


# Sensor types that IoT devices might report
SENSOR_TYPES = ['temperature', 'humidity', 'motion', 'light', 'door_status']


def make_reading(src_name: str) -> dict:
    """
    Generate a fake-but-plausible IoT sensor reading.

    Args:
        src_name: logical name of this sensor host (e.g. 'h1')

    Returns:
        dict with sensor type, measured value, source, and Unix timestamp
    """
    sensor = random.choice(SENSOR_TYPES)

    if sensor == 'temperature':
        value = round(random.uniform(18.0, 30.0), 1)
    elif sensor == 'humidity':
        value = round(random.uniform(30.0, 80.0), 1)
    elif sensor == 'motion':
        value = random.choice([0, 1])          # binary: motion detected or not
    elif sensor == 'light':
        value = round(random.uniform(0, 1000), 1)
    else:  # door_status
        value = random.choice(['open', 'closed'])

    return {
        'src':    src_name,
        'sensor': sensor,
        'value':  value,
        'ts':     round(time.time(), 3)
    }


def run_sensor(src: str, dst: str, port: int, interval: float = 2):
    """
    Main loop: send periodic UDP sensor packets.

    Args:
        src      : logical name (used in payload)
        dst      : victim server IP
        port     : UDP destination port
        interval : seconds between packets
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f'[IoT Sensor {src}] Sending to {dst}:{port} every {interval}s')

    pkt_count = 0
    try:
        while True:
            reading = make_reading(src)
            payload = json.dumps(reading).encode('utf-8')
            sock.sendto(payload, (dst, port))
            pkt_count += 1

            # Heartbeat log every 10 packets
            if pkt_count % 10 == 0:
                print(f'[{src}] {pkt_count} pkts sent | '
                      f'last: {reading["sensor"]}={reading["value"]}')
            print(f'[IoT Sensor {src}] {datetime.now()} Sending data: {payload}...')
            time.sleep(interval)

    except KeyboardInterrupt:
        print(f'\n[{src}] Stopped after {pkt_count} packets.')
    finally:
        sock.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='IoT Sensor Traffic Simulator')
    parser.add_argument('--src',      default='N1')
    parser.add_argument('--dst',      default='192.168.1.11')
    parser.add_argument('--port',     default=9999, type=int)
    parser.add_argument('--interval', default=2.0, type=float)
    args = parser.parse_args()

    run_sensor(args.src, args.dst, args.port, args.interval)
