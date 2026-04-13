#!/usr/bin/env python3
"""
FILE: topology.py
PROJECT: ML-Assisted Detection of  IoT Botnet DDoS Attacks: An Ensemble Learning Approach
DESCRIPTION:
    Builds the Mininet emulated IoT network and connects it to the POX
    SDN controller.

    IMPORTANT — OpenFlow version:
        POX only supports OpenFlow 1.0 (wire protocol 0x01).
        The switch is therefore configured with protocols='OpenFlow10'.
        This is different from the Ryu version which used OpenFlow 1.3.

    Topology:
        N1–N10  : IoT Sensor Nodes/Devices(192.168.1.1 – 192.168.1.10)
        Server     : Victim server (192.168.1.11)
        N10     : C&C attacker node (192.168.1.10), this node will send trigger signals to the 
        botnet hosts to start the attack.
        s1, s2, s3     : Open vSwitch, managed by remote POX controller
     five nodes (N1-N5) connect to s1, while other five nodes (N6-N10) connects to s2. switches s1 and s2, connect to s3 which then 
     The victim server. 
    POX listens on 127.0.0.1:6633 by default, so the RemoteController is configured to connect there.

USAGE:
    Open Two terminal windows:
    In the first terminal, start the POX controller:
        cd ~/pox
        2. Run the topology script in the second terminal:
            sudo python3 topology.py

REQUIREMENTS:
    sudo apt install mininet openvswitch-switch hping3
    git clone https://github.com/noxrepo/pox ~/pox
    # Copy ext/threshold_detector.py and ext/entropy_detector.py into ~/pox/ext/

AUTHOR: Kananelo Chabeli
"""

import argparse
from datetime import datetime
import json

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink
import time
import os

# ============================================================================
# Paths — Use absolute paths so Mininet hosts can find files
# ============================================================================

BASE_DIR = '/home/chabeli/SDN_IoT/sdn-iot'
SRC_DIR = os.path.join(BASE_DIR, 'src')
LOG_DIR = os.path.join(BASE_DIR, 'logs')
PTYHON = '/home/chabeli/.pyenv/shims/python3'
SYN_FILENAME = '/home/chabeli/SDN_IoT/sdn-iot/syn.txt'
ATTACK_DETAILS_FILE_CONTROLLER = '/home/chabeli/SDN_IoT/sdn-iot/sim_results/attack_details_controller.json'
ATTACK_DETAILS_FILE_CNC_TRIGGER = '/home/chabeli/SDN_IoT/sdn-iot/sim_results/attack_details_cnc_trigger.json'

# ---------------------------------------------------------------------------
# Topology Definition
# ---------------------------------------------------------------------------

class IoTBotnetTopo(Topo):
    """
    Mininet topology modelling IoT LAN for botnet attack simulation.
    Topology:
        N1–N10  : IoT Sensor Nodes/Devices(
        Server     : Victim server
        attacker     : C&C attacker node, this node will send trigger signals to the bot
    """

    def build(self, max_bw=50):
        """
        Args:
            bw (int): Link bandwidth cap in Mbps for IoT hosts (default 10).
                      Simulates resource-constrained IoT device uplinks.
        """

        # ----------------------------------------------------------------
        # Single Open vSwitch — OpenFlow 1.0 for POX compatibility
        # ----------------------------------------------------------------
        switch_1 = self.addSwitch(
            's1',
            cls=OVSSwitch,
            protocols='OpenFlow10'   # POX only supports OF 1.0
        )

        switch_2 = self.addSwitch(
            's2',
            cls=OVSSwitch,
            protocols='OpenFlow10'   # POX only supports OF 1.0
        )

        switch_3 = self.addSwitch(
            's3',
            cls=OVSSwitch,
            protocols='OpenFlow10'   # POX only supports OF 1.0
        )

        # ----------------------------------------------------------------
        # IoT device hosts N1–N10 — connect to s1 and s2 with limited bandwidth
        # Simulate smart sensors / cameras on a home/industrial IoT LAN.
        # ----------------------------------------------------------------
        for i in range(0, 10):
            host = self.addHost(
                f'N{i+1}',
                ip=f'192.168.1.{i + 1}/24'
            )
            if i<5 ==0:
                self.addLink(host, switch_1, cls=TCLink, bw=10)
            else:
                self.addLink(host, switch_2, cls=TCLink, bw=10)
        
        self.addLink(switch_1, switch_3, cls=TCLink, bw=10)
        self.addLink(switch_2, switch_3, cls=TCLink, bw=10)

        # ----------------------------------------------------------------
        # Victim server — receives both normal sensor data and flood
        # ----------------------------------------------------------------
        victim = self.addHost(
            'server',
            ip='192.168.1.11/24',
        )
        self.addLink(victim, switch_3, cls=TCLink, bw=10)

        # ----------------------------------------------------------------
        # C&C attacker node N11 — sends trigger signals to botnet hosts
        # ----------------------------------------------------------------
        cnc = self.addHost(
            'attacker',
            ip='192.168.1.12/24',
        )
        self.addLink(cnc, switch_2, cls=TCLink, bw=10)


# ---------------------------------------------------------------------------
# Network Runner
# ---------------------------------------------------------------------------

def run_network(mode = 'SIMULATION'):
    """
    Start the Mininet network, launch background IoT traffic, then open CLI.
    """
    with open(SYN_FILENAME, 'w') as syn_file:
        syn_file.write(mode+'\n')
        syn_file.write("BENIGN")
    
    os.makedirs(LOG_DIR, exist_ok=True)

    setLogLevel('info')

    info('\n*** Building IoT Botnet Simulation Topology (POX / OpenFlow 1.0)\n')
    topo = IoTBotnetTopo()

    # Remote controller = POX running on localhost:6633
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633),
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=False,
        waitConnected=True
    )

    info('*** Starting network\n')
    net.start()

    # Force OF 1.0 on the switch (belt-and-suspenders; Mininet may reset it)
    net.get('s1').cmd('ovs-vsctl set bridge s1 protocols=OpenFlow10')
    net.get('s2').cmd('ovs-vsctl set bridge s2 protocols=OpenFlow10')
    net.get('s3').cmd('ovs-vsctl set bridge s3 protocols=OpenFlow10')

    info('\n*** Verifying connectivity (pingAll)\n')
    net.pingAll()
   
    time.sleep(3)

    info('\n*** Starting victim server on server\n')
    remote_server = net.get('server')
    victim_server_script = os.path.join(SRC_DIR, 'victim_server.py')
    remote_server.cmd(f'python3 {victim_server_script} > {LOG_DIR}/victim_server_stdout.log 2>&1 &')

    info('\n*** Preparing Simulation Result Datafile')
    data = {
        'BENIGN': {
            'flow_count': 0,
            'positives': 0,
            'negatives': 0,
        },
        'ACK_FRAGMENTATION': {
            'flow_count': 0,
            'positives': 0,
            'negatives': 0,
        },
        'ICMP_FLOOD': {
            'flow_count': 0,
            'positives': 0,
            'negatives': 0,
        },
        'UDP_FLOOD': {
            'flow_count': 0,
            'positives': 0,
            'negatives': 0,
        },
        'ICMP_FRAGMENTATION': {
            'flow_count': 0,
            'positives': 0,
            'negatives': 0,
        },
    }
    with open(ATTACK_DETAILS_FILE_CONTROLLER, 'w') as f:
        json.dump(data, f, indent=4)
    
    data = {
        'BENIGN': {
            'start_time': datetime.now().isoformat(),
            'end_time': None,
        },
        'ACK_FRAGMENTATION': {
            'start_time': None,
            'end_time': None,
        },
        'ICMP_FLOOD': {
            'start_time': None,
            'end_time': None,
        },
        'UDP_FLOOD': {
            'start_time': None,
            'end_time': None,
        },
        'ICMP_FRAGMENTATION': {
            'start_time': None,
            'end_time': None,
        },
    }

    with open(ATTACK_DETAILS_FILE_CNC_TRIGGER, 'w') as f:
        json.dump(data, f, indent=4)

    # ----------------------------------------------------------------
    # Start normal IoT sensor traffic from n1–n10 → server
    # Each host sends a small UDP packet every 2 seconds (baseline traffic)
    # ----------------------------------------------------------------

    info('\n*** Starting normal IoT sensor traffic n1–n10 → server\n')
    iot_sensor_script = os.path.join(SRC_DIR, 'iot_sensor.py')
    for i in range(1, 11):
        h = net.get(f'N{i}')
        h.cmd(
            f'python3 {iot_sensor_script} --src N{i} --dst 192.168.1.11 --interval 2 > ' +
            f'{LOG_DIR}/sensor_N{i}.log 2>&1 &'
        )
        time.sleep(0.2)   # stagger starts to avoid artificial burst at t=0

    info('\n*** Network ready. Normal baseline traffic is running.\n')
    info('*** To launch the attack, from Mininet CLI:\n')
    info(f'*** mininet> attacker python3 {os.path.join(SRC_DIR, "cnc_trigger.py")} --recruit --botnet N1-N10 --attack SYN_FLOOD --duration 60\n')
    info('***   or: attacker python3 cnc_trigger.py --attack ACK_FRAGMENTATION --duration 30\n\n')

    CLI(net)

    # Cleanup
    info('\n*** Cleaning up background processes\n')
    for i in range(1, 11):
        net.get(f'N{i}').cmd('kill %1 2>/dev/null; kill %2 2>/dev/null')
    net.get('server').cmd('kill %1 2>/dev/null; kill %2 2>/dev/null')
    net.get('attacker').cmd('kill %1 2>/dev/null; kill %2 2>/dev/null')
    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run Mininet topology for IoT botnet DDoS attack simulation.')
    parser.add_argument('--mode', choices=['SIMULATION', 'DATASET'], default='SIMULATION',
                        help='Set to SIMULATION to run with live traffic. Set to DATASET to generate logs for offline dataset creation (default: SIMULATION).')
    args = parser.parse_args()
    run_network(mode=args.mode)
