import joblib
import pandas as pd
import numpy as np

class DetectionEngine:
    def __init__(self, model_path):
        try:
            self.model = joblib.load(model_path)
            self.feature_columns = ['protocol', 'pkt_len', 'src_port', 'dst_port']
            print("ML model loaded successfully.")
        except FileNotFoundError:
            self.model = None
            print(f"Error: Model file not found at {model_path}")

    def predict(self, numerical_features):
        if self.model is None or numerical_features is None:
            return 0
        df = pd.DataFrame([numerical_features])
        df = df[self.feature_columns]

        prediction = self.model.predict(df)
        
        is_anomaly = 1 if prediction[0] == -1 else 0
        return is_anomaly