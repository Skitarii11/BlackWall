import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import os

print("Creating a dummy ML model for Blackwall...")

feature_names = ['protocol', 'pkt_len', 'src_port', 'dst_port']

raw_data = np.array([
    [6, 64, 12345, 80],
    [17, 128, 54321, 53],
    [6, 60, 443, 67890],
    [17, 256, 10000, 20000]
])

X_train = pd.DataFrame(raw_data, columns=feature_names)
print("Training data with feature names:")
print(X_train)
print("-" * 30)


model = IsolationForest(contamination='auto', random_state=42)
model.fit(X_train)

if not os.path.exists('models'):
    os.makedirs('models')

model_path = 'models/anomaly_detector.joblib'
joblib.dump(model, model_path)

print(f"Dummy model with feature names saved successfully to '{model_path}'!")
print("You can now run the main Blackwall application without the warning.")