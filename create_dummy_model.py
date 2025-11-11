import joblib
import numpy as np
import pandas as pd # <--- ADD THIS IMPORT
from sklearn.ensemble import IsolationForest
import os

print("Creating a dummy ML model for Blackwall...")

# --- NEW: Define feature names. MUST match the order in feature_extractor.py ---
feature_names = ['protocol', 'pkt_len', 'src_port', 'dst_port']

# Create a dummy dataset of "normal" traffic
raw_data = np.array([
    [6, 64, 12345, 80],    # TCP, small packet, random port to HTTP
    [17, 128, 54321, 53],   # UDP, medium packet, random port to DNS
    [6, 60, 443, 67890],   # TCP, small packet, HTTPS to random port
    [17, 256, 10000, 20000] # UDP, larger packet
])

# --- NEW: Convert the numpy array to a pandas DataFrame with column names ---
X_train = pd.DataFrame(raw_data, columns=feature_names)
print("Training data with feature names:")
print(X_train)
print("-" * 30)


# The IsolationForest is an anomaly detection algorithm
model = IsolationForest(contamination='auto', random_state=42)
# The model will now learn the feature names during fit
model.fit(X_train)

# Ensure the 'models' directory exists
if not os.path.exists('models'):
    os.makedirs('models')

# Save the trained model to the file our application expects
model_path = 'models/anomaly_detector.joblib'
joblib.dump(model, model_path)

print(f"Dummy model with feature names saved successfully to '{model_path}'!")
print("You can now run the main Blackwall application without the warning.")