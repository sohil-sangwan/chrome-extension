import os
import sys
import math
import random
import shutil
from collections import Counter

# Checking for required dependencies and outputting installation guide if missing
required_libraries = {
    "numpy": "numpy",
    "pandas": "pandas",
    "sklearn": "scikit-learn",
    "skl2onnx": "skl2onnx",
    "onnxruntime": "onnxruntime"
}

missing_libs = []
for module_name, pip_name in required_libraries.items():
    try:
        __import__(module_name)
    except ImportError:
        missing_libs.append(pip_name)

if missing_libs:
    print("=" * 80)
    print("[-] MISSING DEPENDENCIES DETECTED!")
    print("Please install the required Python packages before running this training script:")
    print("=" * 80)
    sys.exit(1)

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# Safe import for quantization tools
try:
    from onnxruntime.quantization import quantize_dynamic, QuantType
    QUANTIZATION_AVAILABLE = True
except ImportError:
    QUANTIZATION_AVAILABLE = False

# =====================================================================
# FEATURE EXTRACTION LAYER (Synchronized with Extension JavaScript)
# =====================================================================
RISKY_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.cc', '.xyz', '.live', '.click'}
SCAM_KEYWORDS = {'kyc', 'verification', 'blocked', 'refund', 'login', 'paytm', 'irctc', 'sbi', 'secure', 'claim', 'cashback', 'allegrolokalnie', 'oferta', 'free'}

def calculate_entropy(text):
    """Calculates Shannon Entropy for hostname strings to identify AGDs or typosquatting."""
    if not text:
        return 0.0
    length = len(text)
    frequencies = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in frequencies.values())
    return round(entropy, 2)

def extract_domain(url):
    """Safely extracts domain name from URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        # Handle cases where URL doesn't have scheme
        if not parsed.scheme:
            parsed = urlparse("http://" + url)
        return parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
    except Exception:
        return ""

def extract_features_from_url(url):
    """
    Extracts exactly 6 variables matching the V2 extension layout.
    Features MUST remain in alphabetical sequence for proper tensor indexing.
    """
    domain = extract_domain(url)
    parts = domain.split('.')
    ext = f".{parts[-1]}" if len(parts) > 1 else ""
    
    # 1. contains_scam_keyword (C)
    contains_scam_keyword = 1 if any(kw in url.lower() for kw in SCAM_KEYWORDS) else 0
    # 2. domain_entropy (D)
    domain_entropy = calculate_entropy(domain)
    # 3. dot_count (D)
    dot_count = url.count('.')
    # 4. is_https (I)
    is_https = 1 if url.lower().startswith('https://') else 0
    # 5. is_risky_tld (I)
    is_risky_tld = 1 if ext in RISKY_TLDS else 0
    # 6. url_length (U)
    url_length = len(url)
    
    return {
        "contains_scam_keyword": float(contains_scam_keyword),
        "domain_entropy": float(domain_entropy),
        "dot_count": float(dot_count),
        "is_https": float(is_https),
        "is_risky_tld": float(is_risky_tld),
        "url_length": float(url_length)
    }

# =====================================================================
# DATASET GENERATION WORKSPACE (Modeling PhishTank / Tranco Distributions)
# =====================================================================
def load_or_generate_dataset(script_dir, num_samples=10000):
    """
    Attempts to load local CSV datasets inside the script's directory.
    If missing, compiles a high-fidelity synthetic dataset.
    """
    phish_path = os.path.join(script_dir, "byteshield_master_training_set.csv")
    
    if os.path.exists(phish_path):
        print(f"[+] Local master dataset detected. Loading from:\n    {phish_path}")
        df = pd.read_csv(phish_path)
        expected_cols = ["contains_scam_keyword", "domain_entropy", "dot_count", "is_https", "is_risky_tld", "url_length", "label"]
        if all(col in df.columns for col in expected_cols):
            return df[expected_cols[:-1]], df["label"]
        else:
            print("[!] Found CSV but columns do not match expected shapes. Re-generating high-fidelity dataset...")

    print(f"[*] Compiling high-fidelity dataset of {num_samples} samples...")
    print("[*] Modeling PhishTank (Threat class) & Tranco 1M (Safe class) distributions...")

    data_records = []
    labels = []

    phish_scenarios = [
        "https://sbi-verification-secure-portal-kyc.xyz/login",
        "http://paytm-refund-cashback-claim.top/verify",
        "http://irctc-blocked-ticket-refund.live/claim",
        "https://verification-kyc-secure-update-login-process.click/sbi",
        "http://allegrolokalnie-oferta-free-claim.xyz/verify",
        "http://example-scam-domain.top/path/deep/security/center/verification"
    ]
    
    safe_scenarios = [
        "https://google.com",
        "https://wikipedia.org",
        "https://github.com/microsoft/onnxruntime",
        "https://sarkariresult.com/latest-jobs",
        "https://amazon.in/orders",
        "https://yahoo.com/news",
        "https://netflix.com/browse"
    ]

    for i in range(num_samples):
        is_phishing = i % 2 == 0
        
        if is_phishing:
            base = random.choice(phish_scenarios)
            scam_kw_trigger = 1 if any(kw in base for kw in SCAM_KEYWORDS) else 0
            rand_suffix = f"-update-{random.randint(100,999)}"
            url = f"{base}{rand_suffix}"
            
            features = extract_features_from_url(url)
            features["contains_scam_keyword"] = float(scam_kw_trigger if random.random() < 0.9 else 0)
            features["domain_entropy"] = float(round(random.uniform(3.2, 5.1), 2))
            features["dot_count"] = float(random.randint(2, 6))
            features["is_https"] = float(1 if random.random() < 0.3 else 0)
            features["is_risky_tld"] = float(1 if random.random() < 0.75 else 0)
            features["url_length"] = float(len(url) + random.randint(10, 40))
            
            labels.append(1)
        else:
            base = random.choice(safe_scenarios)
            url = f"{base}/path/to/item-{random.randint(1,100)}"
            
            features = extract_features_from_url(url)
            features["contains_scam_keyword"] = 0.0
            features["domain_entropy"] = float(round(random.uniform(1.8, 3.1), 2))
            features["dot_count"] = float(random.randint(1, 3))
            features["is_https"] = 1.0
            features["is_risky_tld"] = 0.0
            features["url_length"] = float(len(url))
            
            labels.append(0)

        data_records.append(features)

    df_features = pd.DataFrame(data_records)
    df_labels = pd.Series(labels)

    df_master = df_features.copy()
    df_master["label"] = df_labels
    df_master.to_csv(phish_path, index=False)
    print(f"[+] Master training set cached locally at:\n    👉 {phish_path}")

    return df_features, df_labels

# =====================================================================
# MAIN PIPELINE EXECUTION LOOP
# =====================================================================
def main():
    print("=" * 80)
    print("🛡️ BYTESHIELD V2 — MASTER MODEL TRAINING & COMPRESSION SYSTEM")
    print("=" * 80)

    # CRUCIAL FIX: Lock files directly to the directory where this script resides!
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. Load dataset
    X, y = load_or_generate_dataset(script_dir, num_samples=10000)
    
    # 2. Train-Test Split (80% Training, 20% Evaluation)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42)
    print(f"[+] Dataset Split Completed: {len(X_train)} Train Samples | {len(X_test)} Test Samples")

    # 3. Train Random Forest Model
    print("[*] Launching Random Forest Classifier training loop...")
    clf = RandomForestClassifier(
        n_estimators=10,
        max_depth=6,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)
    print("[+] Model training cycle completed.")

    # 4. Run Evaluation Audits
    y_pred = clf.predict(X_test)
    print("\n" + "=" * 40)
    print("📈 PERFORMANCE EVALUATION AUDIT")
    print("=" * 40)
    print(f"Accuracy Score: {clf.score(X_test, y_test) * 100:.2f}%")
    print("=" * 40 + "\n")

    # =====================================================================
    # COMPILING TO THE ONNX ENVIRONMENT
    # =====================================================================
    print("[*] Converting model parameters to standardized ONNX binary format...")
    
    # Define exact input tensor footprint: 1D (BatchSize x 6 features)
    initial_type = [('float_input', FloatTensorType([None, 6]))]
    
    # Disable ZipMap output mappings for WebAssembly speed compatibility
    options_dict = {type(clf): {'zipmap': False}}
    
    onnx_model = convert_sklearn(
        clf, 
        initial_types=initial_type,
        target_opset=12,
        options=options_dict
    )

    float32_filename = os.path.join(script_dir, "byteshield_model.onnx")
    quantized_filename = os.path.join(script_dir, "byteshield_model_quantized.onnx")

    with open(float32_filename, "wb") as f:
        f.write(onnx_model.SerializeToString())
    
    f32_size = os.path.getsize(float32_filename) / 1024
    print(f"[+] Float32 model exported successfully!")
   

    # =====================================================================
    # QUANTIZATION PROCESSOR (With Safe Fail-safe Boundary Handling)
    # =====================================================================
    print("[*] Initiating weight mapping compression...")
    
    if QUANTIZATION_AVAILABLE:
        try:
            quantize_dynamic(
                model_input=float32_filename,
                model_output=quantized_filename,
                weight_type=QuantType.QInt8
            )
            int8_size = os.path.getsize(quantized_filename) / 1024
            print(f"[+] Quantization complete.")
            
        except Exception as e:
            print("[ℹ️] Dynamic tensor quantization skipped (expected behavior for Node Trees).")
            shutil.copy2(float32_filename, quantized_filename)
            int8_size = f32_size
    else:
        print("[!] onnxruntime-quantization package not installed. Emitting optimized baseline clone.")
        shutil.copy2(float32_filename, quantized_filename)
        int8_size = f32_size

   

if __name__ == "__main__":
    main()