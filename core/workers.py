import pandas as pd
import joblib
from scapy.all import sniff, wrpcap, rdpcap
from sklearn.ensemble import IsolationForest
from PyQt5.QtCore import QThread, pyqtSignal

# Import the feature extractor from our project
from core.feature_extractor import extract_features

class CaptureWorker(QThread):
    """
    Worker thread to capture network traffic and save it to a pcap file.
    """
    # Signals: finished with file path, progress update (string)
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
            self.finished.emit("") # Emit empty string on cancellation
            return

        # Save the captured packets
        wrpcap(self.output_file, packets, append=True)
        
        self.progress.emit(f"Capture complete! {len(packets)} packets have been ADDED to '{self.output_file}'.")
        self.finished.emit(self.output_file)

    def stop(self):
        self.running = False


class TrainerWorker(QThread):
    """
    Worker thread to train the ML model from a pcap file.
    """
    finished = pyqtSignal(str)
    progress = pyqtSignal(str)
    
    def __init__(self, pcap_file, model_output_path="models/anomaly_detector.joblib"):
        super().__init__()
        self.pcap_file = pcap_file
        self.model_output_path = model_output_path

    def run(self):
        try:
            self.progress.emit(f"Starting model training from '{self.pcap_file}'...")
            
            # --- 1. Load Data ---
            self.progress.emit("Loading packets...")
            packets = rdpcap(self.pcap_file)

            # --- 2. Feature Extraction ---
            self.progress.emit("Extracting features from packets...")
            feature_list = []
            for packet in packets:
                numerical_features, _ = extract_features(packet)
                if numerical_features:
                    feature_list.append(numerical_features)
            
            if not feature_list:
                self.progress.emit("Error: No valid features found in pcap file. Training aborted.")
                self.finished.emit("")
                return
            
            X_train = pd.DataFrame(feature_list)
            self.progress.emit(f"Extracted features from {len(X_train)} packets.")

            # --- 3. Model Training ---
            self.progress.emit("Training the IsolationForest model... (This may take a moment)")
            model = IsolationForest(contamination='auto', random_state=42, n_jobs=-1)
            model.fit(X_train)
            
            # --- 4. Save the Model ---
            self.progress.emit("Saving the new model...")
            joblib.dump(model, self.model_output_path)
            
            self.progress.emit(f"SUCCESS! New model saved to '{self.model_output_path}'.")
            self.finished.emit(self.model_output_path)
        except Exception as e:
            self.progress.emit(f"An error occurred during training: {e}")
            self.finished.emit("")