import os
import pickle
import pandas as pd
import numpy as np
import asyncio
import hashlib
import pyshark
import re
import matplotlib.pyplot as plt
import seaborn as sns

from collections import Counter
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.preprocessing import MinMaxScaler

from rfc_ml_models.with_flow.rfc_model_with_flow import print_confusion_matrix

# Get the absolute path of the current script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define paths for model, scaler, and CSV
model_path = os.path.join(BASE_DIR, "model_no_flow.pkl")
scaler_path = os.path.join(BASE_DIR, "scaler_no_flow.pkl")

########################################################################
# ✅ FEATURE SELECTION (Expanded for better classification)
########################################################################
FEATURE_SELECTION = [
    "avg_ps",  # Average packet size
    "std_ps",  # Standard deviation of packet sizes
    "avg_iat",  # Average inter-arrival time
    "std_iat",  # Standard deviation of IAT
    "min_iat",  # Minimum inter-arrival time
    "max_iat",  # Maximum inter-arrival time
    "burstiness_factor",  # CV of IAT distribution
    "ps_skewness",  # Skewness of packet sizes
    "ps_kurtosis",  # Kurtosis of packet sizes
    "std_ps_avg_ps_ratio"  # Std Dev of PS / Mean PS
]


############################
#       HELPER FUNCTIONS
############################

def compute_burstiness(timestamps):
    """Computes Coefficient of Variation (std / mean) for IAT distribution."""
    if len(timestamps) < 2:
        return 0.0
    iats = np.diff(sorted(timestamps))
    mean_iat = np.mean(iats)
    std_iat = np.std(iats, ddof=1)
    return std_iat / mean_iat if mean_iat != 0 else 0


def compute_iat_stats(timestamps):
    """Computes min, avg, max of Inter-Arrival Times (IAT)."""
    if len(timestamps) < 2:
        return 0.0, 0.0, 0.0
    iats = np.diff(sorted(timestamps))
    return min(iats), np.mean(iats), max(iats)


def compute_ps_skewness_kurtosis(packet_sizes):
    """Computes skewness and kurtosis for packet size distribution."""
    if len(packet_sizes) < 3:
        return 0.0, 0.0
    return float(pd.Series(packet_sizes).skew()), float(pd.Series(packet_sizes).kurtosis())


def compute_std_avg_ratio(packet_sizes):
    """Computes std(packet_sizes) / avg(packet_sizes)."""
    if len(packet_sizes) < 2:
        return 0.0
    avg_ps = np.mean(packet_sizes)
    std_ps = np.std(packet_sizes, ddof=1)
    return std_ps / avg_ps if avg_ps != 0 else 0.0

import pyshark
import numpy as np

import asyncio


def extract_features_from_pcap(pcap_file):
    """ Extracts the selected features from a single PCAP for inference. """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    cap = pyshark.FileCapture(pcap_file, display_filter="ip")
    packet_sizes = []
    timestamps = []

    for pkt in cap:
        try:
            if hasattr(pkt, 'ip') and hasattr(pkt, 'transport_layer'):
                packet_sizes.append(int(pkt.length))
                timestamps.append(float(pkt.sniff_time.timestamp()))
        except Exception:
            continue

    cap.close()

    if len(packet_sizes) < 2:
        return None

    # Packet Stats
    avg_ps = np.mean(packet_sizes)
    std_ps = np.std(packet_sizes, ddof=1) if len(packet_sizes) > 1 else 0.0
    std_ps_avg_ps_ratio = std_ps / avg_ps if avg_ps != 0 else 0.0

    # IAT Stats
    iats = np.diff(sorted(timestamps)) if len(timestamps) > 1 else []
    avg_iat = np.mean(iats) if len(iats) > 0 else 0.0
    std_iat = np.std(iats, ddof=1) if len(iats) > 1 else 0.0
    max_iat = max(iats) if len(iats) > 0 else 0.0
    min_iat = min(iats) if len(iats) > 0 else 0.0

    # Burstiness Factor
    burstiness_factor = std_iat / avg_iat if avg_iat != 0 else 0.0

    # Statistical moments (ensure these were included in training)
    ps_kurtosis = pd.Series(packet_sizes).kurtosis() if len(packet_sizes) > 1 else 0.0
    ps_skewness = pd.Series(packet_sizes).skew() if len(packet_sizes) > 1 else 0.0

    # Feature Dictionary
    feature_values = {
        "avg_ps": avg_ps,
        "std_ps": std_ps,
        "avg_iat": avg_iat,
        "std_iat": std_iat,
        "burstiness_factor": burstiness_factor,
        "max_iat": max_iat,
        "min_iat": min_iat,
        "ps_kurtosis": ps_kurtosis,
        "ps_skewness": ps_skewness,
        "std_ps_avg_ps_ratio": std_ps_avg_ps_ratio
    }

    # Keep only the selected features
    selected_vals = {k: v for k, v in feature_values.items() if k in FEATURE_SELECTION}
    if not selected_vals:
        return None

    return pd.DataFrame([selected_vals])


############################
#   BUILD FEATURES (TRAINING)
############################




############################
#       MODEL TRAINING
############################
def extract_app_name(filename):
    """Extracts the application type (e.g., 'zoom', 'youtube') from the filename."""
    match = re.match(r"([a-zA-Z]+)", filename)
    return match.group(1) if match else "unknown"
import pickle
import os
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

def predict_traffic(files):
    """Loads model & scaler, extracts features for each file, and returns predicted app names."""
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        print("❌ Model or Scaler file missing. Train the model first.")
        return []

    with open(model_path, "rb") as model_file, open(scaler_path, "rb") as scaler_file:
        model = pickle.load(model_file)
        scaler = pickle.load(scaler_file)

    results = []
    for f in files:
        df_features = extract_features_from_pcap(f)
        if df_features is None or df_features.empty:
            results.append("Unknown")
            continue

        # ✅ Ensure feature order consistency before transforming
        df_features = df_features[FEATURE_SELECTION]

        X_scaled = scaler.transform(df_features)
        pred_label = model.predict(X_scaled)[0]
        results.append(pred_label)

    return results



def build_features_for_each_pcap(csv_file):
    """
    Reads a CSV of aggregated PCAP info, groups by 'Pcap file',
    computes stats for each file, and returns a DataFrame
    including only the features in FEATURE_SELECTION.
    """
    df = pd.read_csv(csv_file)
    grouped = df.groupby("Pcap file")

    rows = []
    for pcap_file, group in grouped:
        packet_sizes = group["Packet Size"].tolist()
        timestamps = group["Timestamp"].tolist()

        # (1) Packet Size Stats
        avg_ps = np.mean(packet_sizes) if packet_sizes else 0.0
        std_ps = np.std(packet_sizes, ddof=1) if len(packet_sizes) > 1 else 0.0
        ps_skewness, ps_kurtosis = compute_ps_skewness_kurtosis(packet_sizes)
        std_avg_ratio = compute_std_avg_ratio(packet_sizes)

        # (2) IAT Stats
        min_iat, avg_iat, max_iat = compute_iat_stats(timestamps)
        std_iat = np.std(np.diff(sorted(timestamps)), ddof=1) if len(timestamps) > 1 else 0.0

        # (3) Burstiness
        burstiness_factor = compute_burstiness(timestamps)

        feature_values = {
            "avg_ps": avg_ps,
            "std_ps": std_ps,
            "avg_iat": avg_iat,
            "std_iat": std_iat,
            "min_iat": min_iat,
            "max_iat": max_iat,
            "burstiness_factor": burstiness_factor,
            "ps_skewness": ps_skewness,
            "ps_kurtosis": ps_kurtosis,
            "std_ps_avg_ps_ratio": std_avg_ratio
        }

        # Keep only features in FEATURE_SELECTION
        filtered = {k: v for k, v in feature_values.items() if k in FEATURE_SELECTION}

        # Ensure `extract_app_name()` is available
        row = {
            "Pcap file": pcap_file,
            "app_name": extract_app_name(pcap_file)  # FIXED
        }
        row.update(filtered)
        rows.append(row)

    return pd.DataFrame(rows)


def main(csv_file=os.path.join(os.getcwd(), "..", "..", "data_set", "pcap_features.csv")):
    """Train a RandomForest model on the CSV with optimized hyperparameters."""
    df_features = build_features_for_each_pcap(csv_file)
    X = df_features[FEATURE_SELECTION]
    y = df_features["app_name"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Scale Features
    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Hyperparameter Grid Search
    param_grid = {
        "n_estimators": [100, 200, 300],
        "max_depth": [None, 20, 40],
        "max_features": ["sqrt", "log2"],
        "min_samples_split": [2, 5, 10],
        "criterion": ["gini", "entropy"]
    }

    rfc = RandomForestClassifier(random_state=42)
    grid_search = GridSearchCV(rfc, param_grid, cv=5, scoring="accuracy", n_jobs=-1)
    grid_search.fit(X_train_scaled, y_train)

    best_rfc = grid_search.best_estimator_
    print("\n✅ Best Hyperparameters Found:")
    for param, value in grid_search.best_params_.items():
        print(f" - {param}: {value}")

    # Model Evaluation
    train_acc = accuracy_score(y_train, best_rfc.predict(X_train_scaled)) * 100
    test_acc = accuracy_score(y_test, best_rfc.predict(X_test_scaled)) * 100

    print(f"✅ Train Accuracy: {train_acc:.2f}%")
    print(f"✅ Test Accuracy:  {test_acc:.2f}%")

    # Feature Importance
    importance_pairs = sorted(zip(FEATURE_SELECTION, best_rfc.feature_importances_), key=lambda x: x[1], reverse=True)
    print("\n🔹 Feature Importance Ranking:")
    for feat, imp in importance_pairs:
        print(f"{feat}: {imp:.4f}")

    # Confusion Matrix
    print_confusion_matrix(y_test, best_rfc.predict(X_test_scaled), sorted(y.unique()))

    # Save Model & Scaler
    with open(model_path, "wb") as model_file, open(scaler_path, "wb") as scaler_file:
        pickle.dump(best_rfc, model_file)
        pickle.dump(scaler, scaler_file)

    print("✅ Model and Scaler saved.")


if __name__ == "__main__":
    main()
