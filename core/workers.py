import queue
import pandas as pd
import joblib
import numpy as np
import time
from scapy.all import sniff, wrpcap, rdpcap
from sklearn.ensemble import IsolationForest
from PyQt5.QtCore import QThread, pyqtSignal
from collections import defaultdict
from core.feature_extractor import extract_features
from core.rule_analyzer import analyze_anomaly

class SnifferThread(QThread):
    def __init__(self, packet_queue, interface=None):
        super().__init__()
        self.packet_queue = packet_queue
        self.interface = interface
        self.running = False

    def run(self):
        self.running = True
        sniff(iface=self.interface, prn=self.packet_queue.put, stop_filter=lambda p: not self.running)

    def stop(self):
        self.running = False

class ProcessingWorker(QThread):
    update_ui = pyqtSignal(dict, list)
    stats_updated = pyqtSignal(dict)

    def __init__(self, packet_queue, detection_engine, beacon_detector, geoip_manager, db_manager):
        super().__init__()
        self.packet_queue = packet_queue
        self.detection_engine = detection_engine
        self.beacon_detector = beacon_detector
        self.geoip_manager = geoip_manager
        self.db_manager = db_manager
        self.running = False

    def run(self):
        self.running = True
        packet_count = 0
        attack_count = 0
        protocol_counter = defaultdict(int)
        last_stats_update = time.time()
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=1)
                if packet is None: continue
                packet_count += 1
                proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
                if packet.haslayer("IP"):
                    protocol_num = packet["IP"].proto
                    if protocol_num in proto_map:
                        protocol_counter[proto_map[protocol_num]] += 1
                numerical_features, log_features = extract_features(packet)
                if numerical_features:
                    log_features['pkt_len'] = len(packet)
                    is_beacon = self.beacon_detector.process_packet(log_features)
                    is_anomaly = self.detection_engine.predict(numerical_features)
                    if is_anomaly or is_beacon:
                        attack_count += 1
                        attack_type, threat_level = analyze_anomaly(log_features, is_beacon_ml=is_beacon)
                        log_features['description'] = attack_type
                        log_features['severity'] = threat_level
                        source_ip = log_features.get('src_ip')
                        if source_ip:
                            location_data = self.geoip_manager.get_location(source_ip)
                            if location_data:
                                log_features['location'] = location_data
                        self.db_manager.log_alert(log_features)
                        recent_logs = self.db_manager.get_all_logs(limit=5)
                        self.update_ui.emit(log_features, recent_logs)
                current_time = time.time()
                if current_time - last_stats_update > 1:
                    stats = {
                        'packet_count': packet_count, 'attack_count': attack_count,
                        'protocols': dict(protocol_counter)
                    }
                    self.stats_updated.emit(stats)
                    packet_count = 0
                    attack_count = 0
                    protocol_counter.clear()
                    last_stats_update = current_time
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error in processing worker: {e}")

    def stop(self):
        self.running = False
        self.packet_queue.put(None)

class CaptureWorker(QThread):
    finished = pyqtSignal(str)
    progress = pyqtSignal(str)
    
    def __init__(self, duration_sec=60, packet_count=1000, output_file="normal_traffic.pcap"):
        super().__init__()
        self.duration_sec = duration_sec
        self.packet_count = packet_count
        self.output_file = output_file
        self.running = False

    def run(self):
        self.running = True
        self.progress.emit(f"Starting traffic capture for {self.duration_sec} seconds...")
        self.progress.emit("Please perform your normal network activities now.")
        
        packets = sniff(count=self.packet_count, timeout=self.duration_sec, stop_filter=lambda p: not self.running)
        
        if not self.running:
            self.progress.emit("Capture cancelled by user.")
            self.finished.emit("")
            return

        wrpcap(self.output_file, packets, append=True)
        
        self.progress.emit(f"Capture complete! {len(packets)} packets have been ADDED to '{self.output_file}'.")
        self.finished.emit(self.output_file)

    def stop(self):
        self.running = False


class TrainerWorker(QThread):
    finished = pyqtSignal()
    progress = pyqtSignal(str)
    
    def __init__(self, pcap_file):
        super().__init__()
        self.pcap_file = pcap_file

    def run(self):
        try:
            self.progress.emit(f"Starting model training from '{self.pcap_file}'...")
            self.progress.emit("Loading packets (this may take a moment for large files)...")
            packets = rdpcap(self.pcap_file)

            # --- STAGE 1: Train Packet-Level Anomaly Model ---
            self.progress.emit("\n--- Stage 1: Training Packet Anomaly Model ---")
            self.progress.emit("Extracting features from individual packets...")
            packet_feature_list = []
            for packet in packets:
                numerical_features, _ = extract_features(packet)
                if numerical_features:
                    packet_feature_list.append(numerical_features)
            
            if not packet_feature_list:
                self.progress.emit("Error: No valid packet features found. Aborting.")
                self.finished.emit()
                return
            
            X_train_packets = pd.DataFrame(packet_feature_list)
            self.progress.emit(f"Extracted features from {len(X_train_packets)} packets.")
            
            self.progress.emit("Training IsolationForest model for packet anomalies...")
            packet_model = IsolationForest(contamination='auto', random_state=42, n_jobs=-1)
            packet_model.fit(X_train_packets)
            joblib.dump(packet_model, 'models/anomaly_detector.joblib')
            self.progress.emit("Packet Anomaly Model saved successfully.")

            # --- STAGE 2: Train Flow-Based Beacon Model ---
            self.progress.emit("\n--- Stage 2: Training Beacon Detection Model ---")
            self.progress.emit("Processing packets into network flows...")
            flows = defaultdict(lambda: {'timestamps': [], 'sizes': []})
            for packet in packets:
                timestamp = float(packet.time)
                _, log_features = extract_features(packet)
                if log_features:
                    src_ip = log_features.get('src_ip')
                    dst_ip = log_features.get('dst_ip')
                    dst_port = log_features.get('dst_port')
                    pkt_len = len(packet)
                    if all([src_ip, dst_ip, dst_port]):
                        flow_key = (src_ip, dst_ip, dst_port)
                        flows[flow_key]['timestamps'].append(timestamp)
                        flows[flow_key]['sizes'].append(pkt_len)

            self.progress.emit(f"Processed {len(packets)} packets into {len(flows)} flows.")
            
            self.progress.emit("Extracting statistical features from flows...")
            flow_features_list = []
            for _, flow_data in flows.items():
                if len(flow_data['timestamps']) >= 5:
                    timestamps = np.array(sorted(flow_data['timestamps']))
                    sizes = np.array(flow_data['sizes'])
                    inter_arrival_times = np.diff(timestamps)
                    if len(inter_arrival_times) < 2: continue
                    features = {
                        'std_dev_iat': np.std(inter_arrival_times), 'mean_iat': np.mean(inter_arrival_times),
                        'std_dev_size': np.std(sizes), 'mean_size': np.mean(sizes),
                        'packet_count': len(timestamps)
                    }
                    flow_features_list.append(features)

            if not flow_features_list:
                self.progress.emit("Warning: Not enough substantial flows to train a beacon model. Skipping.")
            else:
                X_train_flows = pd.DataFrame(flow_features_list)
                self.progress.emit(f"Training IsolationForest model for beacon detection on {len(X_train_flows)} flows...")
                beacon_model = IsolationForest(contamination='auto', random_state=42, n_jobs=-1)
                beacon_model.fit(X_train_flows)
                joblib.dump(beacon_model, 'models/beacon_detector.joblib')
                self.progress.emit("Beacon Detection Model saved successfully.")

            self.progress.emit("\nSUCCESS! All models have been retrained.")
            self.finished.emit()

        except Exception as e:
            self.progress.emit(f"An error occurred during training: {e}")
            self.finished.emit()