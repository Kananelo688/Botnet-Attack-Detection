#!/usr/bin/env python3
"""
FILE: controller.py
PROJECT: ML-Assisted Detection of IoT Botnet DDoS Attacks
AUTHOR: Kananelo Chabeli

DESCRIPTION:
    Main POX SDN controller. Wires together the learning switch, ML-based
    DDoS detector, mitigation manager, and structured logger into a single
    coherent OpenFlow 1.0 controller.

    POLLING STRATEGY:
        Every POLL_INTERVAL seconds the controller sends ofp_stats_request
        to ALL connected switches. Each switch replies with its flow table
        stats. The controller aggregates stats per source IP across switches,
        passes them to DDoSDetector, and acts on any DetectionResult
        where is_attack=True.

    LEARNING SWITCH:
        Implements standard MAC-learning switch behaviour for normal traffic.
        Flow rules are installed at priority 100. Block rules are at
        priority 200 — ensuring attack traffic is dropped BEFORE the
        forwarding rule is ever evaluated.

    USAGE:
        cd ~/pox
        ./pox.py log.level --DEBUG controller

    MININET CLI COMMANDS (after network starts):
        mininet> attacker python3 src/cnc_trigger.py --attack ICMP_FLOOD --duration 60
        mininet> attacker python3 src/cnc_trigger.py --attack SYN_FLOOD  --duration 60

REQUIREMENTS:
    ~/pox/ext/artefacts/   — all model artefacts from Jupyter notebook
    ~/pox/ext/ddos_detection.py
    ~/pox/ext/mitigation.py
    ~/pox/ext/flow_logger.py
"""

import os
import sys
import time
import threading
import json
import psutil
import csv

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.recoco import Timer

# Add ext/ to path so POX can find our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flow_logger    import FlowLogger
from ddos_detection import DDoSDetector
from mitigation     import MitigationManager

log = core.getLogger()
SYN_FILE = '/home/chabeli/SDN_IoT/sdn-iot/syn.txt' #file contains one line: BENIGN or ATTACK, 
ATTACK_DETAILS_FILE = '/home/chabeli/SDN_IoT/sdn-iot/sim_results/attack_details.json' 


#used to tell controller which traffic is under consideration. 
# This is a hack to let the controller know which attack type the 
# C&C is triggering in each test run, 
# since we don't have a direct comms channel between the C&C and controller.
#  The DDoSDetector can read this file to get the current attack type for 
# more accurate detection and logging.

POLL_INTERVAL   = 10           # seconds between flow stats requests
ARTEFACT_DIR    = os.path.expanduser('~/pox/ext/artefacts')
LOG_DIR         = os.path.expanduser('~/SDN_IoT/sdn-iot/logs')

# Topology constants — must match topology.py
SERVER_IP       = '192.168.1.11'
ATTACKER_IP     = '192.168.1.12'

# Known IoT sensor IPs (unrecruited nodes — registered as safe at startup)
# These are allowed through even if the RF gives a non-benign prediction
# with low confidence, because they are known normal traffic sources.
# The controller will dynamically update this if recruitment is detected.
IOT_NODE_IPS = [f'192.168.1.{i}' for i in range(1, 11)]  # N1–N10

# Forwarding rule parameters
FORWARD_PRIORITY = 100
FORWARD_IDLE_TO  = 30
FORWARD_HARD_TO  = 0

# ============================================================================
# SwitchController — one instance per connected switch
# ============================================================================

class SwitchController(object):
    """
    Handles all OpenFlow events for a single connected switch.
    Implements MAC-learning forwarding + hooks for detection/mitigation.
    One instance is created per switch connection by IoTDDoSController.
    """

    def __init__(self, connection, dpid, parent):
        """
        Args:
            connection : POX connection object for this switch
            dpid       : datapath ID string
            parent     : IoTDDoSController (shared detector/mitigator/logger)
        """
        self.connection = connection
        self.dpid       = dpid
        self.parent     = parent

        # MAC → port table for this switch
        self.mac_to_port = {}

        # Register event listeners
        connection.addListeners(self)

        log.info(f'[{dpidToStr(dpid)}] Switch connected.')
        self.parent.logger.log_event(
            f'SWITCH_CONNECTED  dpid={dpidToStr(dpid)}'
        )


    # PacketIn handler: learning switch + TCP flag extraction for DDoS detection

    def _handle_PacketIn(self, event):
        """
        Handle PacketIn events — the switch sends these when it has no
        matching flow rule for an incoming packet.

        Responsibilities:
            1. Update MAC learning table
            2. Extract TCP flags for the DDoS detector's flag counters
            3. Forward packet (flood or directed)
            4. Install forwarding rule if destination MAC is known
        """
        try:
            packet = event.parsed
        except Exception:
            log.warning(f'[{dpidToStr(self.dpid)}] Malformed packet — ignoring.')
            return          # drop malformed/unparseable packets silently

        in_port   = event.port

        if not packet.parsed:
            log.warning(f'[{dpidToStr(self.dpid)}] Unparseable packet — ignoring.')
            return

        # MAC learning 
        self.mac_to_port[packet.src] = in_port

        # TCP flag extraction for DDoS detector
        ip_pkt = packet.find('ipv4')
        if ip_pkt:
            src_ip = str(ip_pkt.srcip)
            dst_ip = str(ip_pkt.dstip)

            # Skip flag update for server and attacker
            if src_ip not in (SERVER_IP,):
                tcp_pkt = packet.find('tcp')
                if tcp_pkt:
                    self.parent.detector.update_tcp_flags(
                        src_ip = src_ip,
                        dst_ip = dst_ip,
                        syn = int(bool(tcp_pkt.SYN)),
                        ack = int(bool(tcp_pkt.ACK)),
                        fin = int(bool(tcp_pkt.FIN)),
                        rst = int(bool(tcp_pkt.RST)),
                        psh = int(bool(tcp_pkt.PSH)),
                        urg = int(bool(tcp_pkt.URG)),
                    )

                # Track all seen hosts
                self.parent.mitigator.mark_seen(src_ip)

        # Determine output port
        if packet.dst in self.mac_to_port:
            out_port = self.mac_to_port[packet.dst]
        else:
            out_port = of.OFPP_FLOOD

        # Send packet out 
        self._send_packet(event, out_port)

        # Install flow rule if destination is known 
        if out_port != of.OFPP_FLOOD:
            self._install_forward_rule(packet, in_port, out_port)

    def _send_packet(self, event, out_port):
        """Send a packet_out message for the given event."""
        msg         = of.ofp_packet_out()
        msg.data    = event.ofp
        action      = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def _install_forward_rule(self, packet, in_port, out_port):
        """Install a low-priority forwarding flow rule."""
        msg               = of.ofp_flow_mod()
        msg.match         = of.ofp_match.from_packet(packet, in_port)
        msg.priority      = FORWARD_PRIORITY
        msg.idle_timeout  = FORWARD_IDLE_TO
        msg.hard_timeout  = FORWARD_HARD_TO
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    # FlowStatsReply 
    def _handle_FlowStatsReceived(self, event):
        """
        Handle flow stats reply from this switch.

        For each flow entry that has a source IP:
            1. Pass stats to DDoSDetector.inspect_flow().
            2. Log reconstructed features via FlowLogger.
            3. If is_attack → trigger MitigationManager.block_host().
            4. Log detection result.
        """
        stats = event.stats
        log.warning(f'🔔 [STATS] {dpidToStr(self.dpid)} received flow stats reply with {len(stats) if stats else 0} entries')
        
        if not stats:
            log.debug(f'[{dpidToStr(self.dpid)}] No flow stats in reply.')
            return


        log.info(f'[{dpidToStr(self.dpid)}] Processing {len(stats)} flow entries...')
        src_stats = {}
        for flow in stats:
            # Only inspect IPv4 flows with a source IP match
            if not hasattr(flow.match, 'nw_src') or flow.match.nw_src is None:
                continue
            if flow.match.dl_type != 0x0800:
                continue

            src_ip = str(flow.match.nw_src)
            dst_ip = str(flow.match.nw_dst) if flow.match.nw_dst else SERVER_IP

            print(f'[FLOW] Found flow: {src_ip}→{dst_ip} pkts={flow.packet_count} bytes={flow.byte_count}')

            # Skip server and attacker node flows( traffic is generally from  IoT nodes to the server)
            if src_ip in (SERVER_IP,):
                print(f'[FLOW] Skipping {src_ip} (server)')
                continue

            # Aggregate if same src seen in multiple rules
            if src_ip not in src_stats:
                src_stats[src_ip] = {
                    'dst_ip'       : dst_ip,
                    'packet_count' : 0,
                    'byte_count'   : 0,
                    'duration_sec' : 0,
                }
            src_stats[src_ip]['packet_count'] += flow.packet_count
            src_stats[src_ip]['byte_count']   += flow.byte_count
            src_stats[src_ip]['duration_sec']  = max(
                src_stats[src_ip]['duration_sec'], flow.duration_sec
            )

        print(f'[DETECTION] Aggregated {len(src_stats)} unique source IPs: {list(src_stats.keys())}')
        
        #For each attack interval, load the syn.txt to see what attack and execution scenarion is 
        try:
            with open(os.path.expanduser(SYN_FILE), 'r') as f:
                lines = f.read().splitlines()
                if len(lines) >= 2:
                    scenario = lines[0].strip()
                    attack_type = lines[1].strip()
                    log.info(f'[SYN] Loaded scenario from {SYN_FILE}: {scenario} | {attack_type}')
                else:
                    log.warning(f'[SYN] {SYN_FILE} does not contain enough lines. Expected at least 2.')
        except Exception as e:
            log.error(f'[SYN] Failed to read {SYN_FILE}: {e}')

        #For each attack interval, load the attack_details.json to get the attack start time for logging.
        try:
            with open(ATTACK_DETAILS_FILE, 'r') as f:
                attack_details = json.load(f)
                log.info(f'[ATTACK_DETAILS] Loaded attack details from {ATTACK_DETAILS_FILE}')
        except Exception as e:
            log.error(f'[ATTACK_DETAILS] Failed to read {ATTACK_DETAILS_FILE}: {e}')
            attack_details = None
        # Run detection for each source IP 
        for src_ip, st in src_stats.items():
            print(f'[DETECTION] Calling inspect_flow for {src_ip} with {st["packet_count"]} packets')
            log.debug(f'[{dpidToStr(self.dpid)}] Inspecting {src_ip}: {st["packet_count"]} pkts')
            result = self.parent.detector.inspect_flow(
                src_ip        = src_ip,
                dst_ip        = st['dst_ip'],
                packet_count  = st['packet_count'],
                byte_count    = st['byte_count'],
                duration_sec  = st['duration_sec'],
                poll_interval = POLL_INTERVAL,
                scenario      = scenario if scenario in ('DATASET', 'SIMULATION') else None,
                traffic_type  = attack_type if attack_type in ('BENIGN', 'ACK_FRAGMENTATION', 'ICMP_FLOOD', 'ICMP_FRAGMENTATION','SYN_FLOOD') else None,
            )

            
            if result is None:
                log.debug(f'[{dpidToStr(self.dpid)}] inspect_flow returned None for {src_ip}')
                continue
            
            if result.insufficient_data:
                log.info(
                    f'[{dpidToStr(self.dpid)}] ⏱️  Insufficient data for {src_ip}: '
                    f'{result.flow_packets} packets (threshold: 3 packets)'
                )
                continue
            #Log detection result.

            # Log flow stats 
            feat_dict = self.parent.detector.get_flow_feature_dict(
                src_ip, st['dst_ip'], POLL_INTERVAL)
            
            if feat_dict:
                self.parent.logger.log_flow_stats(
                    src_ip          = src_ip,
                    poll_interval   = POLL_INTERVAL,
                    of_packet_count = st['packet_count'],
                    of_byte_count   = st['byte_count'],
                    of_duration_sec = st['duration_sec'],
                    reconstructed   = feat_dict,
                )

            # Log detection result 
            self.parent.logger.log_detection(
                src_ip           = src_ip,
                predicted_label  = result.predicted_label,
                confidence       = result.confidence,
                is_attack        = result.is_attack,
                proba_vector     = result.proba_vector,
                class_names      = result.class_names,
                flow_packets     = result.flow_packets,
                flow_bytes       = result.flow_bytes,
                flow_duration    = result.flow_duration,
            )
            #Do no metigation for then the controller runs in DATASET generation mode, 
            # since in this mode we want to collect data for all traffic types without blocking any of them.
            if scenario == 'DATASET':
                log.info(f'[{dpidToStr(self.dpid)}] Running in DATASET generation mode — skipping mitigation for {src_ip}.')
                continue
            
            if attack_details and attack_type in attack_details:
                attack_details[attack_type]['flow_count'] += 1
                if result.predicted_label == attack_type:
                    attack_details[attack_type]['positives'] += 1
                else:
                    attack_details[attack_type]['negatives'] += 1
                with open(ATTACK_DETAILS_FILE, 'w') as f:
                    json.dump(attack_details, f, indent=4)

            if result.is_attack:
                log.warning(
                    f'[{dpidToStr(self.dpid)}] 🚨 ATTACK  '
                    f'src={src_ip}  label={result.predicted_label}  '
                    f'conf={result.confidence:.2%}'
                )
                self.parent.mitigator.block_host(
                    src_ip             = src_ip,
                    trigger_label      = result.predicted_label,
                    trigger_confidence = result.confidence,
                )
            else:
                log.debug(
                    f'[{dpidToStr(self.dpid)}] ✅ Benign  '
                    f'src={src_ip}  label={result.predicted_label}  '
                    f'conf={result.confidence:.2%}'
                )

    # ConnectionDown
    def _handle_ConnectionDown(self, event):
        """Handle switch disconnect."""
        log.warning(f'[{dpidToStr(self.dpid)}] Switch disconnected.')
        self.parent.logger.log_warning(
            f'SWITCH_DISCONNECTED  dpid={dpidToStr(self.dpid)}'
        )
        if self.dpid in self.parent.connections:
            del self.parent.connections[self.dpid]


# ============================================================================
# IoTDDoSController — top-level POX component
# ============================================================================

class IoTDDoSController(object):
    """
    Top-level POX component. Manages all switch connections and owns the
    shared DDoSDetector, MitigationManager, and FlowLogger instances.

    Registered with POX via launch() at the bottom of this file.
    """

    def __init__(self):
        # Shared connections dict — passed to MitigationManager by reference
        self.connections: dict = {}   # dpid → Connection

        # Initialise shared components: logger, detector, mitigator
        try:
            self.logger    = FlowLogger(log_dir=LOG_DIR)
            log.info('[INIT] ✅ FlowLogger initialised successfully')
        except Exception as e:
            log.error(f'[INIT] ❌ FlowLogger FAILED: {e}')
            raise
        
        try:
            self.detector  = DDoSDetector(artefact_dir=ARTEFACT_DIR)
            log.info('[INIT] ✅ DDoSDetector initialised successfully')
        except Exception as e:
            log.error(f'[INIT] ❌ DDoSDetector FAILED: {e}')
            raise
        
        try:
            self.mitigator = MitigationManager(
                logger      = self.logger,
                connections = self.connections,
            )
            log.info('[INIT] ✅ MitigationManager initialised successfully')
        except Exception as e:
            log.error(f'[INIT] ❌ MitigationManager FAILED: {e}')
            raise

        # ── CPU logging setup
        cpu_log_path = os.path.expanduser('~/SDN_IoT/sdn-iot/sim_results/controller_cpu_utilization.csv')
        os.makedirs(os.path.dirname(cpu_log_path), exist_ok=True)
        self.cpu_log_file = open(cpu_log_path, 'w', newline='')
        self.cpu_writer = csv.writer(self.cpu_log_file)
        self.cpu_writer.writerow(['timestamp', 'cpu_percent'])
        self.cpu_log_file.flush()
        self.cpu_process = psutil.Process(os.getpid())
        log.info(f'[CPU Logger] Logging to {cpu_log_path}')

        # Register known safe IoT nodes
        # These are the unrecruited sensor nodes — never block them
        # The controller will unregister a node from safe set if it is
        # detected launching an attack (recruited by C&C)
        for ip in IOT_NODE_IPS:
            self.mitigator.register_safe_host(ip)

        self.logger.log_event(
            f'IoTDDoSController started | '
            f'poll_interval={POLL_INTERVAL}s | '
            f'artefacts={ARTEFACT_DIR} | '
            f'logs={LOG_DIR}'
        )

        # Listen for new switch connections 
        core.openflow.addListeners(self)

        # Start polling timer 
        # POX's Timer runs in the cooperative scheduler — no threading needed
        Timer(POLL_INTERVAL, self._poll_all_switches, recurring=True)

        log.info('='*60)
        log.info('  IoTDDoSController READY')
        log.info(f'  Poll interval   : {POLL_INTERVAL}s')
        log.info(f'  Artefacts       : {ARTEFACT_DIR}')
        log.info(f'  Logs            : {LOG_DIR}')
        log.info(f'  Safe IoT nodes  : {IOT_NODE_IPS}')
        log.info('='*60)

    # Switch connection
    def _handle_ConnectionUp(self, event):
        """
        Called by POX when a new switch connects.
        Creates a SwitchController for the new switch and stores connection.
        """
        dpid = event.dpid
        self.connections[dpid] = event.connection
        # SwitchController registers itself as a listener on the connection
        SwitchController(event.connection, dpid, self)
        log.info(f'New switch registered: dpid={dpidToStr(dpid)}')

    # ── Polling ───────────────────────────────────────────────────────────────

    def _poll_all_switches(self):
        """
        Send ofp_stats_request to every connected switch.
        Called every POLL_INTERVAL seconds by the POX Timer.
        Replies are handled by SwitchController._handle_FlowStatsReply().
        Also logs CPU utilization at each polling interval.
        """
        # Log CPU utilization at each poll interval
        try:
            cpu_percent = self.cpu_process.cpu_percent(interval=0.1)
            now_ts = int(time.time())
            self.cpu_writer.writerow([now_ts, round(cpu_percent, 2)])
            self.cpu_log_file.flush()
        except Exception as e:
            log.error(f'[CPU Logger] Error reading CPU: {e}')

        if not self.connections:
            log.debug('[Poll] No switches connected — skipping.')
            return

        log.info(f'[Poll] Requesting flow stats from {len(self.connections)} switch(es)...')

        for dpid, conn in list(self.connections.items()):
            try:
                # ofp_stats_request with OFPST_FLOW type
                req      = of.ofp_stats_request()
                req.type = of.OFPST_FLOW
                req.body = of.ofp_flow_stats_request()
                conn.send(req)
            except Exception as e:
                log.error(f'[Poll] Failed to send stats request to {dpidToStr(dpid)}: {e}')
                self.logger.log_error(
                    f'POLL_FAILED  dpid={dpidToStr(dpid)}  error={e}'
                )

        # Expire old flow records periodically
        self.detector.expire_old_flows()

    # Dynamic safe/unsafe reclassification 

    def reclassify_as_attacker(self, src_ip: str):
        """
        Remove a previously safe IoT node from the safe set once it has
        been confirmed as a recruited botnet node.
        Called automatically when block_host() detects a safe-registered IP.

        This is a deliberate design choice: we initially give IoT nodes
        the benefit of the doubt, but once the RF flags them with high
        confidence we remove their safe status for the duration of the run.

        Args:
            src_ip: IP address to reclassify as attacker
        """
        if src_ip in self.mitigator._safe_hosts:
            self.mitigator._safe_hosts.discard(src_ip)
            log.warning(f'[RECLASSIFY] {src_ip} removed from safe set — now treated as attacker.')
            self.logger.log_warning(f'RECLASSIFIED_AS_ATTACKER  src={src_ip}')

    # Graceful shutdown

    def _handle_GoingDownEvent(self, event):
        """Clean up block rules and close logs on controller shutdown."""
        log.info('[Shutdown] Removing all block rules...')
        self.mitigator.unblock_all()
        self.logger.log_event('CONTROLLER_SHUTDOWN — all block rules removed.')
        # Close CPU log file
        try:
            self.cpu_log_file.close()
            log.info('[Shutdown] CPU log file closed.')
        except Exception as e:
            log.error(f'[Shutdown] Error closing CPU log: {e}')
        log.info('[Shutdown] Done.')


# ============================================================================
# POX entry point
# ============================================================================

def launch():
    """
    POX calls this function when the component is loaded.
    Registers IoTDDoSController with the POX core and waits for switches.

    Run with:
        cd ~/pox
        ./pox.py log.level --DEBUG controller
    """
    # Verify artefacts exist before binding to the OpenFlow port
    manifest_path = os.path.join(ARTEFACT_DIR, 'artefact_manifest.json')
    if not os.path.exists(manifest_path):
        raise FileNotFoundError(
            f'\n[controller] ❌ Artefact manifest not found at {manifest_path}\n'
            f'             Run the artefact-saving cell in Jupyter and copy files to:\n'
            f'             {ARTEFACT_DIR}\n'
        )

    # Verify log dir is writable
    os.makedirs(LOG_DIR, exist_ok=True)

    # Instantiate and register the controller
    controller = IoTDDoSController()
    core.register('IoTDDoSController', controller)

    log.info('[launch] IoTDDoSController registered with POX core.')
    log.info(f'[launch] Waiting for switches on port 6633...')
