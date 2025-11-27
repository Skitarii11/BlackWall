import pandas as pd
import joblib
import numpy as np
from scapy.all import sniff, wrpcap, rdpcap
from sklearn.ensemble import IsolationForest
from PyQt5.QtCore import QThread, pyqtSignal
from collections import defaultdict
from core.feature_extractor import extract_features

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
        
        # Sniff packets
        packets = sniff(count=self.packet_count, timeout=self.duration_sec, stop_filter=lambda p: not self.running)
        
        if not self.running:
            self.progress.emit("Capture cancelled by user.")
            self.finished.emit("")
            return

        # Save the captured packets
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
                if len(flow_data['timestamps']) >= 5: # Min packets for training a flow
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