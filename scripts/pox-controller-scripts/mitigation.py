#!/usr/bin/env python3
"""
FILE: mitigation.py
PROJECT: ML-Assisted Detection of IoT Botnet DDoS Attacks
AUTHOR: Kananelo Chabeli

DESCRIPTION:
    Mitigation module responsible for installing and removing OpenFlow DROP
    rules on behalf of the POX controller. Decoupled from the controller so
    rule logic can be changed without touching POX event-handling code.

    RESPONSIBILITIES:
        1. Install high-priority DROP rules on the switch for detected
           attacker source IPs (blocking recruited botnet nodes)
        2. Track all currently blocked IPs with timestamps and expiry
        3. Allow explicitly safe IPs (unrecruited IoT sensors) through
           by installing low-priority ALLOW rules — preventing the
           controller from accidentally blocking normal sensor traffic
        4. Provide unblock capability for post-attack recovery
        5. Log all mitigation actions via FlowLogger

    BLOCKING STRATEGY:
        - Block rules are installed on ALL switches (s1, s2, s3) so that
          attack traffic is dropped as close to the source as possible.
        - Block rules match on source IP only (nw_src) — this blocks all
          protocols from the offending host, not just the attack protocol.
        - Priority 200 for block rules > priority 100 for normal forwarding
          rules installed by the controller's learning switch logic.
        - idle_timeout=300s: rule expires after 5min of inactivity
        - hard_timeout=600s: rule expires after 10min regardless

    ALLOW STRATEGY:
        - Safe (unrecruited) IoT nodes get a priority-50 ALLOW rule
          installed at startup. This runs BELOW normal forwarding rules
          and serves as an explicit record + fallback.

USAGE:
    from mitigation import MitigationManager
    mitigator = MitigationManager(logger, connections)
    mitigator.block_host(src_ip, trigger_label, trigger_confidence)
    mitigator.unblock_host(src_ip)
    mitigator.is_blocked(src_ip)  → bool
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

# POX OpenFlow imports — available when running inside POX
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.core import core

log = core.getLogger('mitigation')

# ============================================================================
# CONSTANTS
# ============================================================================

BLOCK_PRIORITY    = 200   # higher than normal forwarding rules
ALLOW_PRIORITY    = 50    # lower than normal rules — just an explicit entry
BLOCK_IDLE_TO     = 300   # block rule idle timeout (seconds)
BLOCK_HARD_TO     = 600   # block rule hard timeout (seconds)

# IoT node IP range — used to identify sensor traffic vs external
IOT_SUBNET        = '192.168.1.'

# Server IP — never block
SERVER_IP         = '192.168.1.11'
ATTACKER_IP       = '192.168.1.12'   # C&C node — block immediately on attack

# ============================================================================
# BlockRecord — tracks one blocked host
# ============================================================================

@dataclass
class BlockRecord:
    """Metadata for one blocked source IP."""
    src_ip             : str
    blocked_at         : float = field(default_factory=time.time)
    trigger_label      : str   = ''
    trigger_confidence : float = 0.0
    block_count        : int   = 1    # incremented on repeated detections


# ============================================================================
# MitigationManager
# ============================================================================

class MitigationManager:
    """
    Manages OpenFlow-based blocking and allowing of hosts detected by the
    RF DDoS detector. Maintains the blocked set and exposes block/unblock
    operations to the controller.
    """

    def __init__(self, logger, connections: dict):
        """
        Args:
            logger      : FlowLogger instance for logging all actions
            connections : dict mapping dpid → POX Connection object.
                          Managed by the controller and passed by reference
                          so MitigationManager always has current connections.
        """
        self.logger      = logger
        self.connections = connections   # {dpid: connection}

        # Blocked hosts registry: src_ip → BlockRecord
        self._blocked: Dict[str, BlockRecord] = {}

        # Explicitly safe hosts (unrecruited sensors) — never block these
        self._safe_hosts: Set[str] = set()

        # IPs that have been seen at least once (for FP tracking)
        self._seen_hosts: Set[str] = set()

        log.info('MitigationManager initialised.')
        log.info(f'  Block priority  : {BLOCK_PRIORITY}')
        log.info(f'  Block idle_to   : {BLOCK_IDLE_TO}s')
        log.info(f'  Block hard_to   : {BLOCK_HARD_TO}s')
        log.info(f'  Protected IPs   : {SERVER_IP}, {ATTACKER_IP}')

    # Public API 

    def register_safe_host(self, src_ip: str):
        """
        Mark an IP as a safe, unrecruited IoT sensor.
        This host will never be blocked by the mitigation manager.

        Called by the controller during network initialisation for all
        IoT nodes that are not part of the botnet.

        Args:
            src_ip: IP address of the safe host
        """
        self._safe_hosts.add(src_ip)
        log.debug(f'Safe host registered: {src_ip}')

    def mark_seen(self, src_ip: str):
        """Record that a host has been seen — used for FP analysis."""
        self._seen_hosts.add(src_ip)

    def is_blocked(self, src_ip: str) -> bool:
        """Return True if a block rule has been installed for this IP."""
        return src_ip in self._blocked

    def is_safe(self, src_ip: str) -> bool:
        """Return True if this IP is registered as a safe host."""
        return src_ip in self._safe_hosts

    def get_blocked_hosts(self) -> List[str]:
        """Return list of currently blocked IPs."""
        return list(self._blocked.keys())

    def get_block_record(self, src_ip: str) -> Optional[BlockRecord]:
        """Return BlockRecord for a blocked IP, or None."""
        return self._blocked.get(src_ip)

    def block_host(
        self,
        src_ip: str,
        trigger_label: str = '',
        trigger_confidence: float = 0.0,
    ) -> bool:
        """
        Install DROP rules for src_ip on all connected switches.
        Does nothing if the IP is protected (server / safe host).

        Args:
            src_ip             : source IP to block
            trigger_label      : attack label that triggered this block
            trigger_confidence : RF confidence that triggered this block

        Returns:
            True if block was installed, False if skipped (protected IP)
        """
        # Safety checks 
        if src_ip == SERVER_IP:
            log.warning(f'BLOCK REFUSED — server IP {src_ip} is protected.')
            return False

        if src_ip in self._safe_hosts:
            log.warning(
                f'BLOCK REFUSED — {src_ip} is registered as a safe IoT sensor. '
                f'(False positive suppressed)'
            )
            self.logger.log_warning(
                f'FP_SUPPRESSED  src={src_ip}  label={trigger_label}  '
                f'conf={trigger_confidence:.4f}'
            )
            return False

        # Already blocked — just increment counter and update confidence/label if needed
        if src_ip in self._blocked:
            self._blocked[src_ip].block_count += 1
            if trigger_confidence > self._blocked[src_ip].trigger_confidence:
                self._blocked[src_ip].trigger_confidence = trigger_confidence
                self._blocked[src_ip].trigger_label = trigger_label
            log.debug(
                f'[BLOCK] {src_ip} already blocked '
                f'(count={self._blocked[src_ip].block_count})'
            )
            return True

        # Install DROP rule on every connected switch 
        installed_on = []
        for dpid, conn in self.connections.items():
            success = self._install_drop_rule(
                conn, src_ip, dpid, trigger_label, trigger_confidence
            )
            if success:
                installed_on.append(dpid)

        if not installed_on:
            log.error(f'[BLOCK] Failed to install block rule for {src_ip} — no connections.')
            self.logger.log_error(f'BLOCK_FAILED  src={src_ip}  reason=no_connections')
            return False

        # Update blocked registry 
        self._blocked[src_ip] = BlockRecord(
            src_ip             = src_ip,
            trigger_label      = trigger_label,
            trigger_confidence = trigger_confidence,
        )

        log.warning(
            f'🚫 BLOCKED: {src_ip} | {trigger_label} ({trigger_confidence:.2%}) '
            f'| switches: {installed_on}'
        )
        self.logger.log_event(
            f'BLOCK_INSTALLED  src={src_ip}  label={trigger_label}  '
            f'conf={trigger_confidence:.4f}  switches={installed_on}',
            level='WARNING'
        )

        return True

    def unblock_host(self, src_ip: str) -> bool:
        """
        Remove DROP rules for src_ip from all connected switches.
        Used for post-attack recovery or manual override from CLI.

        Args:
            src_ip: IP address to unblock

        Returns:
            True if unblock was successful, False if host was not blocked
        """
        if src_ip not in self._blocked:
            log.info(f'[UNBLOCK] {src_ip} is not currently blocked.')
            return False

        rec = self._blocked[src_ip]

        # Install flow_mod with OFPFC_DELETE to remove the rule
        for dpid, conn in self.connections.items():
            self._remove_drop_rule(conn, src_ip, dpid)

        del self._blocked[src_ip]

        log.info(f'✅ UNBLOCKED: {src_ip}')
        for dpid, conn in self.connections.items():
            self.logger.log_mitigation(
                action             = 'UNBLOCK',
                src_ip             = src_ip,
                dpid               = dpid,
                rule_priority      = BLOCK_PRIORITY,
                idle_timeout       = 0,
                hard_timeout       = 0,
                trigger_label      = rec.trigger_label,
                trigger_confidence = rec.trigger_confidence,
            )
        return True

    def unblock_all(self):
        """Unblock all currently blocked hosts. Called on controller shutdown."""
        blocked_copy = list(self._blocked.keys())
        log.info(f'[UNBLOCK ALL] Removing {len(blocked_copy)} block rules...')
        for src_ip in blocked_copy:
            self.unblock_host(src_ip)
        log.info('[UNBLOCK ALL] Done.')

    def print_status(self):
        """Print current mitigation state to stdout — useful from Mininet CLI."""
        print(f'\n{"="*55}')
        print(f'  MITIGATION STATUS')
        print(f'{"="*55}')
        print(f'  Blocked hosts    : {len(self._blocked)}')
        print(f'  Safe hosts       : {len(self._safe_hosts)}')
        print(f'  Seen hosts       : {len(self._seen_hosts)}')
        if self._blocked:
            print(f'\n  {"Source IP":<18}  {"Label":<25}  {"Conf":>6}  {"Count":>5}  {"Age(s)":>7}')
            print(f'  {"-"*70}')
            now = time.time()
            for ip, rec in sorted(self._blocked.items()):
                age = now - rec.blocked_at
                print(
                    f'  {ip:<18}  {rec.trigger_label:<25}  '
                    f'{rec.trigger_confidence:>6.2%}  {rec.block_count:>5}  {age:>7.1f}'
                )
        print(f'{"="*55}\n')

    # Private OpenFlow helpers 

    def _install_drop_rule(
        self,
        conn,
        src_ip: str,
        dpid,
        trigger_label: str,
        trigger_confidence: float,
    ) -> bool:
        """
        Send ofp_flow_mod DROP message to one switch connection.

        Rule: match nw_src=src_ip, dl_type=0x0800 (IPv4)
              action=[] (empty = DROP)
              priority=200, idle_timeout=300, hard_timeout=600

        Returns True on success.
        """
        try:
            msg               = of.ofp_flow_mod()
            msg.command       = of.OFPFC_ADD
            msg.priority      = BLOCK_PRIORITY
            msg.idle_timeout  = BLOCK_IDLE_TO
            msg.hard_timeout  = BLOCK_HARD_TO
            msg.match.dl_type = 0x0800          # IPv4
            msg.match.nw_src  = IPAddr(src_ip)
            # Empty action list = DROP (no actions = no forwarding)
            conn.send(msg)

            # Log to CSV
            self.logger.log_mitigation(
                action             = 'BLOCK',
                src_ip             = src_ip,
                dpid               = dpid,
                rule_priority      = BLOCK_PRIORITY,
                idle_timeout       = BLOCK_IDLE_TO,
                hard_timeout       = BLOCK_HARD_TO,
                trigger_label      = trigger_label,
                trigger_confidence = trigger_confidence,
            )
            return True

        except Exception as e:
            log.error(f'[BLOCK] Failed to send flow_mod to switch {dpid}: {e}')
            self.logger.log_error(
                f'BLOCK_FLOW_MOD_FAILED  src={src_ip}  dpid={dpid}  error={e}'
            )
            return False

    def _remove_drop_rule(self, conn, src_ip: str, dpid):
        """
        Send OFPFC_DELETE flow_mod to remove the block rule for src_ip.

        Args:
            conn   : POX switch connection
            src_ip : IP whose block rule to remove
            dpid   : switch datapath ID (for logging)
        """
        try:
            msg               = of.ofp_flow_mod()
            msg.command       = of.OFPFC_DELETE
            msg.priority      = BLOCK_PRIORITY
            msg.match.dl_type = 0x0800
            msg.match.nw_src  = IPAddr(src_ip)
            conn.send(msg)

        except Exception as e:
            log.error(f'[UNBLOCK] Failed to remove flow_mod on {dpid}: {e}')
            self.logger.log_error(
                f'UNBLOCK_FLOW_MOD_FAILED  src={src_ip}  dpid={dpid}  error={e}'
            )
