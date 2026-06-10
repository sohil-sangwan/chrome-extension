import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from skl2onnx import __max_supported_opset__
from skl2onnx import to_onnx

# 1. Create a quick mock training dataset based on your feature extractor layout
# Features: [url_length, dot_count, is_https, domain_entropy, is_risky_tld, contains_scam_keyword]
X = np.array([
    [42, 4, 1, 1.92, 0, 0], # Safe site example (IRCTC clone baseline)
    [31, 3, 1, 2.94, 0, 0], # Safe site example (SBI baseline)
    [53, 3, 0, 3.58, 1, 1], # Phishing example
    [45, 2, 0, 3.24, 1, 1], # Phishing example
    [60, 5, 0, 4.10, 1, 1]  # Phishing example
], dtype=np.float32)

y = np.array([0, 0, 1, 1, 1]) # 0 = Safe, 1 = Phishing

print("[*] Training the baseline ByteShield RandomForest Classifier...")
# 2. Train a baseline classifier model
model = RandomForestClassifier(n_estimators=10, random_state=42)
model.fit(X, y)

print("[*] Converting Python model to ONNX format...")
# 3. Convert the scikit-learn model to ONNX format
# We specify the input data shape: 1 row at a time, containing 6 numerical features
initial_type = X[0:1] 
onnx_model = to_onnx(model, initial_type, target_opset=__max_supported_opset__)

# 4. Save the compiled model file to disk
output_model_path = "byteshield_model.onnx"
with open(output_model_path, "wb") as f:
    f.write(onnx_model.SerializeToString())

print(f"[+] SUCCESS! Model compiled and saved as: '{output_model_path}'")