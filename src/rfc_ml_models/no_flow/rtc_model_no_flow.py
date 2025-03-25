import re
import os
import pickle
import pandas as pd
import numpy as np
import asyncio
import pyshark
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import MinMaxScaler
from src.rfc_ml_models.with_flow.rfc_model_with_flow import print_confusion_matrix

# Get the absolute path of the current script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define paths for model, scaler, etc.
model_path = os.path.join(BASE_DIR, "model_no_flow.pkl")
scaler_path = os.path.join(BASE_DIR, "scaler_no_flow.pkl")

########################################################################
# ✨ EXPANDED FEATURE SELECTION FOR BETTER CLASSIFICATION
########################################################################
FEATURE_SELECTION = [ "flow_duration",              # (1) Flow duration
    "avg_ps",
    "avg_iat",
    "std_ps",
    "std_iat",

]

############################
#       HELPER FUNCTIONS
############################

def compute_burstiness(timestamps):
    """Coefficient of Variation (std / mean) for Inter-Arrival Times."""
    if len(timestamps) < 2:
        return 0.0
    iats = np.diff(sorted(timestamps))
    mean_iat = np.mean(iats)
    std_iat = np.std(iats, ddof=1)
    return std_iat / mean_iat if mean_iat != 0 else 0.0

def compute_iat_stats(timestamps):
    """Returns (min, avg, max) of IAT."""
    if len(timestamps) < 2:
        return (0.0, 0.0, 0.0)
    iats = np.diff(sorted(timestamps))
    return (np.min(iats), np.mean(iats), np.max(iats))

def compute_ps_skewness_kurtosis(packet_sizes):
    """Skew and kurtosis of packet-size distribution."""
    if len(packet_sizes) < 3:
        return (0.0, 0.0)
    s = pd.Series(packet_sizes)
    return (float(s.skew()), float(s.kurtosis()))

def compute_estimated_direction_ratio(packet_sizes):
    """
    Heuristic ratio of 'large' to 'small' packets.
    Large => likely inbound, small => likely outbound.
    """
    if len(packet_sizes) < 2:
        return 0.5
    large_packets = sum(1 for p in packet_sizes if p > 1000)
    small_packets = sum(1 for p in packet_sizes if p <= 300)
    denom = (large_packets + small_packets)
    if denom == 0:
        return 0.5
    return large_packets / denom

############################
#   FEATURE EXTRACTION (INFERENCE)
############################

def extract_features_from_pcap(pcap_file):
    """Extracts relevant features from a PCAP file for *inference*."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    cap = pyshark.FileCapture(pcap_file, display_filter="ip")

    packet_sizes = []
    timestamps = []

    for pkt in cap:
        try:
            if hasattr(pkt, "ip") and hasattr(pkt, "transport_layer"):
                packet_sizes.append(int(pkt.length))
                timestamps.append(float(pkt.sniff_time.timestamp()))
        except:
            continue

    cap.close()

    if len(packet_sizes) < 2:
        return None

    # Basic stats
    total_packets = len(packet_sizes)
    total_bytes = np.sum(packet_sizes)
    flow_start = np.min(timestamps)
    flow_end = np.max(timestamps)
    flow_duration = flow_end - flow_start if flow_end > flow_start else 0.0

    # Packet size stats
    avg_ps = np.mean(packet_sizes)
    std_ps = np.std(packet_sizes, ddof=1) if total_packets > 1 else 0.0
    skew_ps, kurt_ps = compute_ps_skewness_kurtosis(packet_sizes)

    # IAT stats
    iats = np.diff(sorted(timestamps)) if total_packets > 1 else []
    avg_iat = np.mean(iats) if len(iats) else 0.0
    std_iat = np.std(iats, ddof=1) if len(iats) > 1 else 0.0
    burstiness_factor = compute_burstiness(timestamps)

    # Packet Rate
    packets_per_second = total_packets / flow_duration if flow_duration > 0 else 0.0

    # Direction ratio
    direction_ratio = compute_estimated_direction_ratio(packet_sizes)

    # Collect & filter for final
    all_features = {
        "flow_duration": flow_duration,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "avg_ps": avg_ps,
        "std_ps": std_ps,
        "skew_ps": skew_ps,
        "kurt_ps": kurt_ps,
        "avg_iat": avg_iat,
        "std_iat": std_iat,
        "burstiness_factor": burstiness_factor,
        "packets_per_second": packets_per_second,
        "direction_ratio": direction_ratio,
    }
    selected = {k: v for k, v in all_features.items() if k in FEATURE_SELECTION}

    if not selected:
        return None

    return pd.DataFrame([selected])

############################
#   FEATURE BUILDING (TRAINING)
############################

def extract_app_name(filename):
    """Extracts the app name from the PCAP filename (e.g. 'zoom' from 'zoom1.pcap')."""
    match = re.match(r"([a-zA-Z]+)", filename)
    return match.group(1) if match else "unknown"

def build_features_for_each_pcap(csv_file):
    """
    Reads a CSV of aggregated PCAP info,
    computes per-PCAP stats, returns a DataFrame ready for training.
    """
    df = pd.read_csv(csv_file)
    grouped = df.groupby("Pcap file")

    rows = []
    for pcap_file, group in grouped:
        packet_sizes = group["Packet Size"].tolist()
        timestamps = group["Timestamp"].tolist()

        # Skip if insufficient data
        if len(packet_sizes) < 2:
            continue

        total_packets = len(packet_sizes)
        total_bytes = np.sum(packet_sizes)
        flow_start = np.min(timestamps)
        flow_end = np.max(timestamps)
        flow_duration = flow_end - flow_start if flow_end > flow_start else 0.0

        # Packet sizes
        avg_ps = np.mean(packet_sizes)
        std_ps = np.std(packet_sizes, ddof=1) if total_packets > 1 else 0.0
        skew_ps, kurt_ps = compute_ps_skewness_kurtosis(packet_sizes)

        # IAT stats
        iats = np.diff(sorted(timestamps)) if total_packets > 1 else []
        avg_iat = np.mean(iats) if len(iats) else 0.0
        std_iat = np.std(iats, ddof=1) if len(iats) > 1 else 0.0
        burstiness_factor = compute_burstiness(timestamps)

        # Packets per second
        packets_per_second = total_packets / flow_duration if flow_duration > 0 else 0.0

        # Direction ratio
        direction_ratio = compute_estimated_direction_ratio(packet_sizes)

        all_features = {
            "flow_duration": flow_duration,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "avg_ps": avg_ps,
            "std_ps": std_ps,
            "skew_ps": skew_ps,
            "kurt_ps": kurt_ps,
            "avg_iat": avg_iat,
            "std_iat": std_iat,
            "burstiness_factor": burstiness_factor,
            "packets_per_second": packets_per_second,
            "direction_ratio": direction_ratio,
        }

        # Keep only what we want
        selected = {k: v for k, v in all_features.items() if k in FEATURE_SELECTION}

        row = {
            "Pcap file": pcap_file,
            "app_name": extract_app_name(pcap_file)
        }
        row.update(selected)
        rows.append(row)

    return pd.DataFrame(rows)

############################
#       MODEL TRAINING
############################

def predict_traffic(files):
    """Loads model & scaler, extracts features, returns predicted app names."""
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

        df_features = df_features[FEATURE_SELECTION]
        X_scaled = scaler.transform(df_features)
        pred_label = model.predict(X_scaled)[0]
        results.append(pred_label)

    return results

def main(csv_file=os.path.join(os.getcwd(), "..", "..", "training_set", "pcap_features.csv")):
    """Train a RandomForest model with an expanded feature set + class weighting."""
    df_features = build_features_for_each_pcap(csv_file)
    if df_features.empty:
        print("❌ No valid data to train on.")
        return

    X = df_features[FEATURE_SELECTION]
    y = df_features["app_name"]

    # Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale
    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Define a hyperparameter grid
    param_grid = {
        "n_estimators": [100, 200, 300],
        "max_depth": [None, 20, 40],
        "max_features": ["sqrt", "log2"],
    }

    # Include class_weight to fix potential misclassification for smaller classes
    rfc = RandomForestClassifier(random_state=42, class_weight="balanced_subsample")

    grid_search = GridSearchCV(
        rfc,
        param_grid,
        cv=5,
        scoring="accuracy",
        n_jobs=-1
    )
    grid_search.fit(X_train_scaled, y_train)

    best_rfc = grid_search.best_estimator_
    print("\n✅ Best Hyperparameters Found:")
    for param, value in grid_search.best_params_.items():
        print(f" - {param}: {value}")

    # Evaluate
    train_acc = accuracy_score(y_train, best_rfc.predict(X_train_scaled)) * 100
    test_acc = accuracy_score(y_test, best_rfc.predict(X_test_scaled)) * 100

    print(f"✅ Train Accuracy: {train_acc:.2f}%")
    print(f"✅ Test Accuracy:  {test_acc:.2f}%")

    # Feature Importance
    importance_pairs = sorted(
        zip(FEATURE_SELECTION, best_rfc.feature_importances_),
        key=lambda x: x[1],
        reverse=True
    )
    print("\n🔹 Feature Importance Ranking:")
    for feat, imp in importance_pairs:
        print(f"{feat}: {imp:.4f}")

    # Confusion Matrix
    print_confusion_matrix(y_test, best_rfc.predict(X_test_scaled), sorted(y.unique()))

    # Save
    with open(model_path, "wb") as model_file, open(scaler_path, "wb") as scaler_file:
        pickle.dump(best_rfc, model_file)
        pickle.dump(scaler, scaler_file)

    print("✅ Model and Scaler saved.")

if __name__ == "__main__":
    main()
