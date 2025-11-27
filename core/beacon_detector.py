import time
import numpy as np
import pandas as pd
import joblib
from collections import defaultdict, deque

# This will store a deque of (timestamp, packet_size) for each flow
FLOW_MEMORY_SECONDS = 120
MIN_PACKETS_FOR_ANALYSIS = 10

class BeaconDetector:
    def __init__(self, model_path='models/beacon_detector.joblib'):
        try:
            self.model = joblib.load(model_path)
            # These are the feature names the model was trained on
            self.feature_columns = [
                'std_dev_iat', 'mean_iat', 'std_dev_size', 'mean_size', 'packet_count'
            ]
            print("Beacon detection model loaded successfully.")
        except FileNotFoundError:
            self.model = None
            print(f"Warning: Beacon detection model not found at {model_path}. Feature disabled.")
        
        self.active_flows = defaultdict(lambda: {'timestamps': deque(), 'sizes': deque()})

    def process_packet(self, packet_features):
        """Adds a packet to its flow and checks if the flow should be analyzed."""
        if self.model is None:
            return None # Do nothing if model isn't loaded

        src_ip = packet_features.get('src_ip')
        dst_ip = packet_features.get('dst_ip')
        dst_port = packet_features.get('dst_port')
        pkt_len = packet_features.get('pkt_len')

        if not all([src_ip, dst_ip, dst_port, pkt_len]):
            return None

        flow_key = (src_ip, dst_ip, dst_port)
        current_time = time.time()
        
        # Add packet info to its flow
        flow_data = self.active_flows[flow_key]
        flow_data['timestamps'].append(current_time)
        flow_data['sizes'].append(pkt_len)

        # Clean up old packets from this flow's memory
        while flow_data['timestamps'] and current_time - flow_data['timestamps'][0] > FLOW_MEMORY_SECONDS:
            flow_data['timestamps'].popleft()
            flow_data['sizes'].popleft()
        
        # Analyze if we have enough data points
        if len(flow_data['timestamps']) >= MIN_PACKETS_FOR_ANALYSIS:
            return self.analyze_flow(flow_key)
        
        return None

    def analyze_flow(self, flow_key):
        """Extracts features from a flow and predicts if it's a beacon."""
        flow_data = self.active_flows[flow_key]
        
        # 1. Feature Extraction
        timestamps = np.array(flow_data['timestamps'])
        sizes = np.array(flow_data['sizes'])
        
        inter_arrival_times = np.diff(timestamps)
        
        # Avoid division by zero if there's only one packet somehow
        if len(inter_arrival_times) < 2:
            return None

        features = {
            'std_dev_iat': np.std(inter_arrival_times),
            'mean_iat': np.mean(inter_arrival_times),
            'std_dev_size': np.std(sizes),
            'mean_size': np.mean(sizes),
            'packet_count': len(timestamps)
        }
        
        # 2. Prediction
        df = pd.DataFrame([features])
        df = df[self.feature_columns] # Ensure correct column order

        prediction = self.model.predict(df)
        is_beacon = (prediction[0] == -1) # IsolationForest: -1 means anomaly (beacon)

        if is_beacon:
            # Clear the flow to prevent repeated alerts for the same beaconing activity
            self.active_flows.pop(flow_key, None)
            return True
            
        return False