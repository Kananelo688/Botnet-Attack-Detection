#!/usr/bin/env python3
"""
FILE: ddos_detection.py
PROJECT: ML-Assisted Detection of IoT Botnet DDoS Attacks
AUTHOR: Kananelo Chabeli

DESCRIPTION:
    RF-based DDoS detection module. Decoupled from POX so it can be
    unit-tested independently and swapped for another model later.

    RESPONSIBILITIES:
        1. Load all model artefacts from ~/pox/ext/artefacts/
        2. Maintain a per-flow state table that accumulates OpenFlow stats
           across polling windows and reconstructs CICFlowMeter-compatible
           feature vectors
        3. Run the RF model on each source IP's feature vector
        4. Return a DetectionResult for every source IP seen in stats

    FEATURE RECONSTRUCTION STRATEGY:
        OpenFlow 1.0 flow stats give us only:
            - packet_count, byte_count, duration_sec, duration_nsec
        We reconstruct the full feature vector by:
            (a) Deriving rate features from counts / duration
            (b) Tracking per-interval deltas across polling windows
            (c) Maintaining running statistics (mean, std) from deltas
            (d) Zeroing out features we genuinely cannot reconstruct —
                the RF is robust to this because near-zero-variance features
                were dropped in preprocessing and rate features dominate
                the top-20 importances

    DESIGN NOTES:
        - FlowStateTable is the only stateful component — one entry per
          (src_ip, dst_ip, protocol) tuple, cleaned up after FLOW_EXPIRY_S
        - DetectionResult is a plain dataclass — easy to log, pickle, test
        - All artefact paths are resolved relative to ARTEFACT_DIR constant
          so the module works regardless of where POX is invoked from

USAGE:
    from ddos_detection import DDoSDetector
    detector = DDoSDetector(artefact_dir='/home/user/pox/ext/artefacts')
    result   = detector.inspect_flow(src_ip, dst_ip, proto, of_stats)
    if result.is_attack:
        # trigger mitigation
"""

import os
import time
import joblib
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import csv
# ============================================================================
# CONSTANTS
# ============================================================================

ARTEFACT_DIR    = os.path.expanduser('~/pox/ext/artefacts')


# A flow entry expires if no packets seen for this many seconds
FLOW_EXPIRY_S   = 120

# Minimum packets required in a window before we attempt prediction.
# Below this threshold the feature vector is too sparse to be reliable.
MIN_PACKETS     = 3

DATASET_DIR = '/home/chabeli/SDN_IoT/Dataset/Custom-Dataset'  # Directory to save generated dataset CSV files
# ============================================================================
# DetectionResult — returned for every inspected source IP
# ============================================================================

@dataclass
class DetectionResult:
    """
    Encapsulates a single RF prediction for one source IP's flow.
    Passed from DDoSDetector back to the controller and then to the logger.
    """
    src_ip            : str
    dst_ip            : str
    predicted_label   : str
    confidence        : float
    is_attack         : bool
    proba_vector      : List[float]
    class_names       : List[str]
    flow_packets      : int   = 0
    flow_bytes        : int   = 0
    flow_duration     : float = 0.0
    insufficient_data : bool  = False   # True if MIN_PACKETS not met


# ============================================================================
# FlowRecord — per-flow accumulated state
# ============================================================================

@dataclass
class FlowRecord:
    """
    Tracks accumulated OpenFlow statistics for one (src, dst, proto) flow.
    Updated every polling interval; used to reconstruct feature vectors.
    """
    src_ip            : str
    dst_ip            : str

    # Cumulative OpenFlow counters (from switch)
    total_packets     : int   = 0
    total_bytes       : int   = 0
    duration_sec      : int   = 0

    # Per-interval deltas — list of (delta_packets, delta_bytes) per poll
    delta_packets_list: List[int]   = field(default_factory=list)
    delta_bytes_list  : List[int]   = field(default_factory=list)
    delta_time_list   : List[float] = field(default_factory=list)

    # TCP flag accumulators (incremented when we see PacketIn events)
    syn_count         : int   = 0
    ack_count         : int   = 0
    fin_count         : int   = 0
    rst_count         : int   = 0
    psh_count         : int   = 0
    urg_count         : int   = 0

    # Timestamps
    first_seen        : float = field(default_factory=time.time)
    last_seen         : float = field(default_factory=time.time)
    last_poll_packets : int   = 0
    last_poll_bytes   : int   = 0


# ============================================================================
# DDoSDetector
# ============================================================================

class DDoSDetector:
    """
    Loads the pre-trained Random Forest model and artefacts, maintains a
    per-flow state table, reconstructs CICFlowMeter features from OpenFlow
    stats, and runs predictions for each source IP on demand.
    """

    def __init__(self, artefact_dir: str = ARTEFACT_DIR):
        """
        Load all model artefacts. Raises FileNotFoundError if any are missing.

        Args:
            artefact_dir: path to directory containing all .pkl artefacts
        """
        self.artefact_dir = artefact_dir
        self._load_artefacts()

        # Flow state table: key = (src_ip, dst_ip) → FlowRecord
        self._flows: Dict[Tuple[str, str], FlowRecord] = {}
        self._flow_lock_flag = False   # simple re-entrancy guard (POX is single-threaded)

        print(f'[DDoSDetector] Initialised.')
        print(f'[DDoSDetector] Model features  : {len(self.selected_features)}')
        print(f'[DDoSDetector] Classes         : {list(self.class_names)}')
        print(f'[DDoSDetector] Benign index    : {self.benign_idx}')
        print(f'[DDoSDetector] Threshold       : {self.threshold}')

    #Artefact loading 

    def _load_artefacts(self):
        """Load all required artefacts from disk."""
        def _load(filename):
            path = os.path.join(self.artefact_dir, filename)
            if not os.path.exists(path):
                raise FileNotFoundError(
                    f'[DDoSDetector] Missing artefact: {path}\n'
                    f'               Run the artefact-saving cell in Jupyter first.'
                )
            return joblib.load(path)

        print(f'[DDoSDetector] Loading artefacts from {self.artefact_dir}...')

        self.model             = _load('best_model_rf.pkl')
        self.label_encoder     = _load('label_encoder.pkl')
        self.selected_features = _load('selected_features.pkl')
        self.class_names       = list(self.label_encoder.classes_)
        self.reverse_mapping   = _load('reverse_mapping.pkl')
        self.benign_idx        = int(_load('benign_class_idx.pkl'))
        self.threshold         = float(_load('confidence_threshold.pkl'))
        self.zero_vector       = _load('zero_feature_vector.pkl').copy()

        print(f'[DDoSDetector] ✅ All artefacts loaded successfully.')

    #Flow state management 
    def update_flow(
        self,
        src_ip: str,
        dst_ip: str,
        packet_count: int,
        byte_count: int,
        duration_sec: int,
        poll_interval: float,
    ):
        """
        Update the flow state table with new OpenFlow stats for one entry.
        Called by the controller every polling cycle for each flow stat reply.

        Args:
            src_ip        : source IP of the flow
            dst_ip        : destination IP of the flow
            packet_count  : cumulative packet count from switch
            byte_count    : cumulative byte count from switch
            duration_sec  : flow duration in seconds from switch
            poll_interval : polling interval in seconds (T)
        """
        key = (src_ip, dst_ip)
        now = time.time()
        
        is_new = key not in self._flows

        if is_new:
            print(f'[DDoSDetector.update_flow] 🆕 NEW FLOW: {src_ip}→{dst_ip}')
            self._flows[key] = FlowRecord(src_ip=src_ip, dst_ip=dst_ip)
        else:
            print(f'[DDoSDetector.update_flow] 🔄 UPDATE: {src_ip}→{dst_ip}')

        rec = self._flows[key]

        # Compute deltas from last poll
        old_pkts = rec.total_packets
        delta_pkts  = max(0, packet_count - rec.last_poll_packets)
        delta_bytes = max(0, byte_count   - rec.last_poll_bytes)
        delta_time  = now - rec.last_seen if rec.last_seen else poll_interval

        rec.total_packets     = packet_count
        rec.total_bytes       = byte_count
        rec.duration_sec      = duration_sec
        rec.last_poll_packets = packet_count
        rec.last_poll_bytes   = byte_count
        rec.last_seen         = now
        
        print(f'[DDoSDetector.update_flow]   Packets: {old_pkts}→{packet_count} (delta={delta_pkts})')

        # Accumulate delta lists for running statistics
        if delta_pkts > 0:
            rec.delta_packets_list.append(delta_pkts)
            rec.delta_bytes_list.append(delta_bytes)
            rec.delta_time_list.append(delta_time)

        # Keep lists bounded (last 50 intervals)
        MAX_HISTORY = 50
        if len(rec.delta_packets_list) > MAX_HISTORY:
            rec.delta_packets_list = rec.delta_packets_list[-MAX_HISTORY:]
            rec.delta_bytes_list   = rec.delta_bytes_list[-MAX_HISTORY:]
            rec.delta_time_list    = rec.delta_time_list[-MAX_HISTORY:]

    def update_tcp_flags(
        self,
        src_ip: str,
        dst_ip: str,
        syn: int = 0, ack: int = 0, fin: int = 0,
        rst: int = 0, psh: int = 0, urg: int = 0,
    ):
        """
        Increment TCP flag counters for a flow from PacketIn events.
        Called by the controller's _handle_PacketIn for every TCP packet
        that triggers a PacketIn (before a flow rule is installed).

        Args:
            src_ip / dst_ip : flow identifier
            syn/ack/fin/rst/psh/urg : flag increment values (0 or 1)
        """
        key = (src_ip, dst_ip)
        if key not in self._flows:
            self._flows[key] = FlowRecord(src_ip=src_ip, dst_ip=dst_ip)
        rec = self._flows[key]
        rec.syn_count += syn
        rec.ack_count += ack
        rec.fin_count += fin
        rec.rst_count += rst
        rec.psh_count += psh
        rec.urg_count += urg

    def expire_old_flows(self):
        """
        Remove flow records not updated within FLOW_EXPIRY_S seconds.
        Called by the controller periodically to prevent memory growth.
        """
        now     = time.time()
        expired = [
            k for k, v in self._flows.items()
            if (now - v.last_seen) > FLOW_EXPIRY_S
        ]
        for k in expired:
            del self._flows[k]
        if expired:
            print(f'[DDoSDetector] Expired {len(expired)} stale flow records.')

    # Feature reconstruction 
    def _reconstruct_features(self, rec: FlowRecord, 
                              poll_interval: float,
                              traffic_type: Optional[str] = None,
                              ) -> Tuple[np.ndarray, dict]:
        """
        Reconstruct a CICFlowMeter-compatible feature vector from a FlowRecord.

        Returns:
            feature_array : numpy array aligned to selected_features order
            feature_dict  : human-readable dict for logging
            dump_filename(str, optional): if provided, dumps the feature_dict to this csv file for dataset generation purposes. ( columns used in the same order as FEATURE_KEYS )
        """
        duration    = max(rec.duration_sec, 1e-6)
        pkt_list    = rec.delta_packets_list
        byte_list   = rec.delta_bytes_list
        time_list   = rec.delta_time_list
        total_pkts  = rec.total_packets
        total_bytes = rec.total_bytes

        # Rate feature
        flow_bytes_s    = total_bytes  / duration
        flow_packets_s  = total_pkts   / duration

        fwd_packets_s   = flow_packets_s   # simplified: all traffic is fwd from src
        fwd_bytes       = total_bytes
        fwd_packet_len_mean = (total_bytes / total_pkts) if total_pkts > 0 else 0.0

        # IAT features (inter-arrival time between polling intervals)
        if len(time_list) > 1:
            iat_arr          = np.array(time_list)
            flow_iat_mean    = float(np.mean(iat_arr))
            flow_iat_std     = float(np.std(iat_arr))
            flow_iat_max     = float(np.max(iat_arr))
            flow_iat_min     = float(np.min(iat_arr))
        else:
            flow_iat_mean = poll_interval
            flow_iat_std  = 0.0
            flow_iat_max  = poll_interval
            flow_iat_min  = poll_interval

        #Packet length features (from byte/packet delta ratios)
        if len(byte_list) > 1 and len(pkt_list) > 1:
            pkt_means = [
                b / p if p > 0 else 0.0
                for b, p in zip(byte_list, pkt_list)
            ]
            pkt_arr              = np.array(pkt_means)
            packet_length_mean   = float(np.mean(pkt_arr))
            packet_length_std    = float(np.std(pkt_arr))
            packet_length_max    = float(np.max(pkt_arr))
            packet_length_min    = float(np.min(pkt_arr))
            packet_length_var    = float(np.var(pkt_arr))
            avg_packet_size      = packet_length_mean
        else:
            packet_length_mean   = fwd_packet_len_mean
            packet_length_std    = 0.0
            packet_length_max    = fwd_packet_len_mean
            packet_length_min    = fwd_packet_len_mean
            packet_length_var    = 0.0
            avg_packet_size      = fwd_packet_len_mean

        # Flag features 
        syn_flag_count = rec.syn_count
        ack_flag_count = rec.ack_count
        fin_flag_count = rec.fin_count
        rst_flag_count = rec.rst_count
        psh_flag_count = rec.psh_count
        urg_flag_count = rec.urg_count

        # Subflow / init window approximations
        # OpenFlow doesn't provide these directly — approximate from totals
        subflow_fwd_packets = total_pkts
        subflow_fwd_bytes   = total_bytes
        subflow_bwd_packets = 0
        subflow_bwd_bytes   = 0
        fwd_init_win_bytes  = min(total_bytes, 65535)
        bwd_init_win_bytes  = 0

        # Build feature dict keyed by CICFlowMeter column names 
        feature_dict = {
            # Flow duration
            'Flow Duration'                     : duration * 1e6,  # microseconds

            # Packet counts
            'Total Fwd Packets'                 : total_pkts,
            'Total Backward Packets'            : 0,
            'Total Length of Fwd Packets'       : fwd_bytes,
            'Total Length of Bwd Packets'       : 0,

            # Forward packet lengths
            'Fwd Packet Length Max'             : packet_length_max,
            'Fwd Packet Length Min'             : packet_length_min,
            'Fwd Packet Length Mean'            : fwd_packet_len_mean,
            'Fwd Packet Length Std'             : packet_length_std,

            # Backward packet lengths
            'Bwd Packet Length Max'             : 0,
            'Bwd Packet Length Min'             : 0,
            'Bwd Packet Length Mean'            : 0,
            'Bwd Packet Length Std'             : 0,

            # Rate features
            'Flow Bytes/s'                      : flow_bytes_s,
            'Flow Packets/s'                    : flow_packets_s,

            # Flow IAT
            'Flow IAT Mean'                     : flow_iat_mean,
            'Flow IAT Std'                      : flow_iat_std,
            'Flow IAT Max'                      : flow_iat_max,
            'Flow IAT Min'                      : flow_iat_min,

            # Fwd IAT
            'Fwd IAT Total'                     : duration,
            'Fwd IAT Mean'                      : flow_iat_mean,
            'Fwd IAT Std'                       : flow_iat_std,
            'Fwd IAT Max'                       : flow_iat_max,
            'Fwd IAT Min'                       : flow_iat_min,

            # Bwd IAT
            'Bwd IAT Total'                     : 0,
            'Bwd IAT Mean'                      : 0,
            'Bwd IAT Std'                       : 0,
            'Bwd IAT Max'                       : 0,
            'Bwd IAT Min'                       : 0,

            # TCP Flags
            'Fwd PSH Flags'                     : psh_flag_count,
            'Bwd PSH Flags'                     : 0,
            'Fwd URG Flags'                     : urg_flag_count,
            'Bwd URG Flags'                     : 0,
            'FIN Flag Count'                    : fin_flag_count,
            'SYN Flag Count'                    : syn_flag_count,
            'RST Flag Count'                    : rst_flag_count,
            'PSH Flag Count'                    : psh_flag_count,
            'ACK Flag Count'                    : ack_flag_count,
            'URG Flag Count'                    : urg_flag_count,
            'CWR Flag Count'                    : 0,
            'ECE Flag Count'                    : 0,

            # Header lengths
            'Fwd Header Length'                 : total_pkts * 20,  # 20 byte IP header approx
            'Bwd Header Length'                 : 0,

            # Directional packet rates
            'Fwd Packets/s'                     : fwd_packets_s,
            'Bwd Packets/s'                     : 0,

            # Packet length stats
            'Packet Length Min'                 : packet_length_min,
            'Packet Length Max'                 : packet_length_max,
            'Packet Length Mean'                : packet_length_mean,
            'Packet Length Std'                 : packet_length_std,
            'Packet Length Variance'            : packet_length_var,

            # Ratios and averages
            'Down/Up Ratio'                     : 0,
            'Average Packet Size'               : avg_packet_size,
            'Avg Fwd Segment Size'              : fwd_packet_len_mean,
            'Avg Bwd Segment Size'              : 0,

            # Bulk features
            'Fwd Avg Bytes/Bulk'                : 0,
            'Fwd Avg Packets/Bulk'              : 0,
            'Fwd Avg Bulk Rate'                 : 0,
            'Bwd Avg Bytes/Bulk'                : 0,
            'Bwd Avg Packets/Bulk'              : 0,
            'Bwd Avg Bulk Rate'                 : 0,

            # Subflow
            'Subflow Fwd Packets'               : subflow_fwd_packets,
            'Subflow Fwd Bytes'                 : subflow_fwd_bytes,
            'Subflow Bwd Packets'               : subflow_bwd_packets,
            'Subflow Bwd Bytes'                 : subflow_bwd_bytes,

            # Init window
            'Init_Win_bytes_forward'            : fwd_init_win_bytes,
            'Init_Win_bytes_backward'           : bwd_init_win_bytes,
            'act_data_pkt_fwd'                  : total_pkts,
            'min_seg_size_forward'              : packet_length_min,

            # Active/Idle
            'Active Mean'                       : duration,
            'Active Std'                        : 0,
            'Active Max'                        : duration,
            'Active Min'                        : duration,
            'Idle Mean'                         : 0,
            'Idle Std'                          : 0,
            'Idle Max'                          : 0,
            'Idle Min'                          : 0,
        }
        
        #Save the data in the given filename (if run for dataset generation purposes)
        if traffic_type:
            dump_filename = os.path.join(DATASET_DIR, f'{traffic_type}.csv')
            print(f'[DDoSDetector] Running in {traffic_type} data generation mode. Dumping features to CSV...')
            feature_dict['Label'] = traffic_type  # Add label for dataset generation

            #open file in append mode, write header only if file is new, then write the feature dict as a row
            if os.path.exists(dump_filename):
                with open(dump_filename, 'a', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=feature_dict.keys())
                    writer.writerow(feature_dict)
            else:
                with open(dump_filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=feature_dict.keys())
                    writer.writeheader()
                    writer.writerow(feature_dict)
        
        # Align to selected_features order 
        vector = np.array(
            [feature_dict.get(f, 0.0) for f in self.selected_features],
            dtype=np.float32
        )

        # Replace any NaN/inf that might arise from zero-duration edge cases
        vector = np.nan_to_num(vector, nan=0.0, posinf=0.0, neginf=0.0)

        return vector, feature_dict

    # Main inspection API
    def inspect_flow(
        self,
        src_ip: str,
        dst_ip: str,
        packet_count: int,
        byte_count: int,
        duration_sec: int,
        poll_interval: float,
        scenario = None,
        traffic_type = None,
    ) -> Optional[DetectionResult]:
        """
        Update flow state and run RF prediction for one (src_ip, dst_ip) flow.
        Called by the controller for each flow stat entry every T seconds.

        Returns:
            DetectionResult if enough data to classify, None otherwise.
        """
        print(f'[DDoSDetector.inspect_flow] Called: {src_ip}→{dst_ip} pkts={packet_count}')
        
        # Update state
        self.update_flow(
            src_ip, dst_ip, packet_count, byte_count, duration_sec, poll_interval
        )

        key = (src_ip, dst_ip)
        rec = self._flows.get(key)
        if rec is None:
            print(f'[DDoSDetector.inspect_flow] ❌ No record found after update')
            return None

        print(f'[DDoSDetector.inspect_flow] Flow {src_ip}: total_packets={rec.total_packets} (MIN_PACKETS={MIN_PACKETS})')
        
        # Require minimum packet count before predicting
        if rec.total_packets < MIN_PACKETS:
            print(f'[DDoSDetector.inspect_flow] ⏱️  Insufficient - {rec.total_packets} < {MIN_PACKETS}')
            return DetectionResult(
                src_ip           = src_ip,
                dst_ip           = dst_ip,
                predicted_label  = 'UNKNOWN',
                confidence       = 0.0,
                is_attack        = False,
                proba_vector     = [0.0] * len(self.class_names),
                class_names      = self.class_names,
                flow_packets     = rec.total_packets,
                flow_bytes       = rec.total_bytes,
                flow_duration    = rec.duration_sec,
                insufficient_data = True,
            )

        print(f'[DDoSDetector.inspect_flow] ✅ {src_ip}: Reconstructing features...')
        
        # Reconstruct features
        feature_vector, _ = self._reconstruct_features(rec, poll_interval, traffic_type = traffic_type if scenario == 'DATASET' else None)

        print(f'[DDoSDetector.inspect_flow] Running RF prediction for {src_ip}...')
        
        # RF prediction
        proba       = self.model.predict_proba(feature_vector.reshape(1, -1))[0]
        pred_idx    = int(np.argmax(proba))
        confidence  = float(proba[pred_idx])
        label       = self.class_names[pred_idx]

        # Attack decision: non-benign AND confidence meets threshold
        is_attack = (pred_idx != self.benign_idx) and (confidence >= self.threshold)
        
        print(f'[DDoSDetector.inspect_flow] Result for {src_ip}: label={label} conf={confidence:.2%} is_attack={is_attack}')
        print(f'[DDoSDetector.inspect_flow]   pred_idx={pred_idx} benign_idx={self.benign_idx} threshold={self.threshold:.2%}')
        print(f'[DDoSDetector.inspect_flow]   Full proba: {proba}')
        
        if not is_attack and pred_idx != self.benign_idx:
            # Log near-misses (detected as attack but confidence too low)
            print(f'[DDoSDetector] ⚠️  NEAR-MISS {src_ip}: {label} ({confidence:.2%}) < threshold {self.threshold:.2%}')

        return DetectionResult(
            src_ip           = src_ip,
            dst_ip           = dst_ip,
            predicted_label  = label,
            confidence       = confidence,
            is_attack        = is_attack,
            proba_vector     = proba.tolist(),
            class_names      = self.class_names,
            flow_packets     = rec.total_packets,
            flow_bytes       = rec.total_bytes,
            flow_duration    = float(rec.duration_sec),
        )

    def inspect_all_flows(self, poll_interval: float) -> List[DetectionResult]:
        """
        Run inspect_flow for every flow currently in the state table.
        Called by the controller after each stats reply batch is processed.

        Returns:
            List of DetectionResult (one per tracked flow).
        """
        results = []
        for (src_ip, dst_ip), rec in list(self._flows.items()):
            result = self.inspect_flow(
                src_ip        = src_ip,
                dst_ip        = dst_ip,
                packet_count  = rec.total_packets,
                byte_count    = rec.total_bytes,
                duration_sec  = rec.duration_sec,
                poll_interval = poll_interval,
            )
            if result is not None:
                results.append(result)
        return results

    def get_flow_feature_dict(
        self, src_ip: str, dst_ip: str, poll_interval: float
    ) -> Optional[dict]:
        """
        Return the reconstructed feature dict for a flow — used by the
        logger to write flow_stats.csv without re-computing features.
        """
        key = (src_ip, dst_ip)
        rec = self._flows.get(key)
        if rec is None:
            return None
        _, feature_dict = self._reconstruct_features(rec, poll_interval)
        return feature_dict


if __name__ == '__main__':
    print('[DDoSDetector] This module is not meant to be run standalone. It is imported and used by the POX controller.')