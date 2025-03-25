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

from collections import Counter, defaultdict
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.preprocessing import MinMaxScaler

# Get the absolute path of the current script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define paths for model, scaler, and CSV
model_path = os.path.join(BASE_DIR, "model_with_flow.pkl")
scaler_path = os.path.join(BASE_DIR, "scaler_with_flow.pkl")

# --------------------------------------------------------------------
FEATURE_SELECTION = [
    # Packet stats
    "std_ps",
    # Flow-based features
    "flow_count",
    # Newly added flow-based packet size stats
    "std_of_flow_pkt_size_std"
]

# --------------------------------------------------------------------

############################
#       HELPER FUNCTIONS
############################

def compute_ratio_large_small(ratio_large, ratio_small, epsilon=1e-6):
    """Computes the ratio between large and small packet ratios."""
    return ratio_large / (ratio_small + epsilon)

def print_confusion_matrix(y_true, y_pred, class_labels):
    """Prints and plots the confusion matrix for classification results."""
    cm = confusion_matrix(y_true, y_pred, labels=class_labels)

    print("\nConfusion Matrix:")
    cm_df = pd.DataFrame(cm, index=class_labels, columns=class_labels)
    print(cm_df)

    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=class_labels, yticklabels=class_labels)
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.title("Confusion Matrix")
    # plt.show()

def extract_app_name(filename):
    """Extract the application type (e.g., 'zoom', 'youtube') from the filename."""
    match = re.match(r"([a-zA-Z]+)", filename)
    return match.group(1) if match else "unknown"

def compute_iat_stats(timestamps):
    """Computes min, avg, max of Inter-Arrival Times (IAT)."""
    if len(timestamps) < 2:
        return 0, 0, 0
    iats = np.diff(sorted(timestamps))
    return min(iats), np.mean(iats), max(iats)

def compute_burstiness(timestamps):
    """
    Coefficient of Variation for the IAT distribution => (std / mean).
    If there's < 2 timestamps, returns 0.
    """
    if len(timestamps) < 2:
        return 0
    iats = np.diff(sorted(timestamps))
    mean_iat = np.mean(iats)
    std_iat = np.std(iats, ddof=1)
    return std_iat / mean_iat if mean_iat != 0 else 0

############################
#     ADVANCED FEATURES
############################

def compute_packet_entropy(packet_sizes, bins=10):
    """Computes Shannon entropy of packet sizes by binning them."""
    if len(packet_sizes) < 2:
        return 0.0
    hist, _ = np.histogram(packet_sizes, bins=bins, density=True)
    hist = hist[hist > 0]  # remove zero-prob bins
    if len(hist) == 0:
        return 0.0
    return -np.sum(hist * np.log2(hist))

def compute_ratio_small(packet_sizes, threshold=300):
    """Ratio of packets < threshold / total packets."""
    if not packet_sizes:
        return 0.0
    return sum(size < threshold for size in packet_sizes) / len(packet_sizes)

def compute_ratio_large(packet_sizes, threshold=1000):
    """Ratio of packets > threshold / total packets."""
    if not packet_sizes:
        return 0.0
    return sum(size > threshold for size in packet_sizes) / len(packet_sizes)

def compute_median_iat(timestamps):
    """Median of the IAT distribution."""
    if len(timestamps) < 2:
        return 0.0
    iats = np.diff(sorted(timestamps))
    return float(np.median(iats))

def compute_iqr_iat(timestamps):
    """Interquartile range of IAT: Q3 - Q1."""
    if len(timestamps) < 2:
        return 0.0
    iats = np.diff(sorted(timestamps))
    q1 = np.percentile(iats, 25)
    q3 = np.percentile(iats, 75)
    return float(q3 - q1)

############################
#  BUILD FEATURES (TRAINING)
############################

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
        flows_numeric = group["Flow Hash Numeric"].tolist()

        # (1) Flow-wise packet size tracking
        flow_pkt_sizes = defaultdict(list)
        for idx, row_ in group.iterrows():
            fhash = row_["Flow Hash Numeric"]
            flow_pkt_sizes[fhash].append(row_["Packet Size"])

        # Compute standard deviation of packet sizes per flow
        flow_pkt_std = [np.std(sizes, ddof=1) if len(sizes) > 1 else 0.0 for sizes in flow_pkt_sizes.values()]
        avg_flow_pkt_size_std = np.mean(flow_pkt_std) if flow_pkt_std else 0.0
        max_flow_pkt_size_std = np.max(flow_pkt_std) if flow_pkt_std else 0.0
        std_of_flow_pkt_size_std = np.std(flow_pkt_std, ddof=1) if len(flow_pkt_std) > 1 else 0.0

        # (2) Flow-based stats
        flow_counter = Counter(flows_numeric)
        flow_count = len(set(flows_numeric))
        max_flows = max(flow_counter.values()) if flow_counter else 0
        flow_ratio = max_flows / flow_count if flow_count > 0 else 0
        packets_per_flow = np.mean(list(flow_counter.values())) if flow_counter else 0

        # Combine all
        feature_values = {
            # Packet stats
            "avg_ps": np.mean(packet_sizes) if packet_sizes else 0.0,
            "std_ps": np.std(packet_sizes, ddof=1) if len(packet_sizes) > 1 else 0.0,
            # IAT stats
            "avg_iat": np.mean(timestamps) if timestamps else 0.0,
            "max_iat": max(timestamps) if timestamps else 0.0,
            "std_iat": np.std(timestamps, ddof=1) if len(timestamps) > 1 else 0.0,
            # Flow-based
            "flow_count": flow_count,
            "max_flows": max_flows,
            "flow_ratio": flow_ratio,
            "packets_per_flow": packets_per_flow,
            # Newly added flow-based packet size stats
            "avg_flow_pkt_size_std": avg_flow_pkt_size_std,
            "max_flow_pkt_size_std": max_flow_pkt_size_std,
            "std_of_flow_pkt_size_std": std_of_flow_pkt_size_std
        }

        # Filter down to selected features
        filtered_features = {k: v for k, v in feature_values.items() if k in FEATURE_SELECTION}

        app_name = extract_app_name(pcap_file)
        row = {"Pcap file": pcap_file, "app_name": app_name}
        row.update(filtered_features)
        rows.append(row)

    return pd.DataFrame(rows)


def main(csv_file=os.path.join(os.getcwd(), "data_set", "pcap_features.csv")):
    """
    Train a RandomForest model on the CSV, then save the trained model & scaler.
    """

    df_features = build_features_for_each_pcap(csv_file)

    X = df_features[FEATURE_SELECTION]
    y = df_features["app_name"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    param_grid = {
        "n_estimators": [50, 100, 200],
        "max_depth": [None, 10, 20],
        "max_features": ["sqrt", "log2", None]
    }
    rfc = RandomForestClassifier(random_state=42)
    grid_search = GridSearchCV(rfc, param_grid, cv=3, scoring="accuracy", n_jobs=-1)
    grid_search.fit(X_train_scaled, y_train)

    best_rfc = grid_search.best_estimator_
    y_pred = best_rfc.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred) * 100
    best_rfc = grid_search.best_estimator_
    print("\n✅ Best Hyperparameters Found:")
    for param, value in grid_search.best_params_.items():
        print(f" - {param}: {value}")

    print(f"✅ Model Accuracy: {accuracy:.2f}%")
    train_accuracy = accuracy_score(y_train, best_rfc.predict(X_train_scaled)) * 100
    print(f"✅ Train Accuracy: {train_accuracy:.2f}%")

    # Test accuracy
    accuracy = accuracy_score(y_test, best_rfc.predict(X_test_scaled)) * 100
    print(f"✅ Test Accuracy: {accuracy:.2f}%")

    # Print Feature Importances (Sorted)
    feature_importance = best_rfc.feature_importances_
    sorted_features = list(sorted(zip(FEATURE_SELECTION, feature_importance), key=lambda x: x[1], reverse=True))

    print("\n🔹 Feature Importance Ranking (Sorted):")
    for feature, importance in sorted_features:
        print(f"{feature}: {importance:.4f}")

    # Confusion Matrix
    class_labels = sorted(y.unique())
    print_confusion_matrix(y_test, y_pred, class_labels)


    # Save model & scaler (uncomment if you want to persist)
    with open(model_path, "wb") as model_file, open(scaler_path, "wb") as scaler_file:
        pickle.dump(best_rfc, model_file)
        pickle.dump(scaler, scaler_file)
    print("✅ Model and Scaler saved.")


def extract_features_from_pcap(pcap_file):
    """Extracts advanced + flow-based features from a PCAP file using Pyshark inside a new event loop."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    cap = pyshark.FileCapture(pcap_file, display_filter="ip")
    packet_sizes = []
    timestamps = []
    flow_hashes = []

    # Flow-wise packet size tracking
    flow_pkt_sizes = defaultdict(list)

    for pkt in cap:
        try:
            if not hasattr(pkt, 'ip') or not hasattr(pkt, 'transport_layer'):
                continue

            size = int(pkt.length)
            t_ = float(pkt.sniff_time.timestamp())
            packet_sizes.append(size)
            timestamps.append(t_)

            # Flow hashing
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            src_port = pkt[pkt.transport_layer].srcport
            dst_port = pkt[pkt.transport_layer].dstport
            flow_tuple = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}"

            flow_hash_hex = hashlib.md5(flow_tuple.encode()).hexdigest()
            flow_hash_decimal = int(flow_hash_hex, 16) % 10**10
            flow_hashes.append(flow_hash_decimal)

            # Track packet sizes per flow
            flow_pkt_sizes[flow_hash_decimal].append(size)

        except Exception:
            continue

    cap.close()

    if len(packet_sizes) < 2 or not flow_hashes:
        return None

    # Compute standard deviation of packet sizes per flow
    flow_pkt_std = [np.std(sizes, ddof=1) if len(sizes) > 1 else 0.0 for sizes in flow_pkt_sizes.values()]
    avg_flow_pkt_size_std = np.mean(flow_pkt_std) if flow_pkt_std else 0.0
    max_flow_pkt_size_std = np.max(flow_pkt_std) if flow_pkt_std else 0.0
    std_of_flow_pkt_size_std = np.std(flow_pkt_std, ddof=1) if len(flow_pkt_std) > 1 else 0.0

    # Flow-based stats
    flow_counter = Counter(flow_hashes)
    flow_count = len(set(flow_hashes))
    max_flows = max(flow_counter.values(), default=0)
    flow_ratio = max_flows / flow_count if flow_count > 0 else 0
    packets_per_flow = np.mean(list(flow_counter.values())) if flow_counter else 0

    feature_values = {
        # Packet stats
        "avg_ps": np.mean(packet_sizes) if packet_sizes else 0.0,
        "std_ps": np.std(packet_sizes, ddof=1) if len(packet_sizes) > 1 else 0.0,
        # IAT stats
        "avg_iat": np.mean(timestamps) if timestamps else 0.0,
        "max_iat": max(timestamps) if timestamps else 0.0,
        "std_iat": np.std(timestamps, ddof=1) if len(timestamps) > 1 else 0.0,
        # Flow-based
        "flow_count": flow_count,
        "max_flows": max_flows,
        "flow_ratio": flow_ratio,
        "packets_per_flow": packets_per_flow,
        # Newly added flow-based packet size stats
        "avg_flow_pkt_size_std": avg_flow_pkt_size_std,
        "max_flow_pkt_size_std": max_flow_pkt_size_std,
        "std_of_flow_pkt_size_std": std_of_flow_pkt_size_std
    }

    # Filter to only FEATURE_SELECTION
    selected_values = {k: v for k, v in feature_values.items() if k in FEATURE_SELECTION}
    df = pd.DataFrame([selected_values])
    return df if not df.empty else None



def predict_traffic(files):
    """Loads model & scaler, extracts features for each file, and returns predicted app_names."""
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        print("❌ Model or Scaler file missing. Train the model first.")
        return []

    with open(model_path, "rb") as model_file, open(scaler_path, "rb") as scaler_file:
        model = pickle.load(model_file)
        scaler = pickle.load(scaler_file)

    results = []
    for file in files:
        df_features = extract_features_from_pcap(file)
        if df_features is None or df_features.empty:
            results.append("Unknown")
            continue

        # Scale & Predict
        X_scaled = scaler.transform(df_features)
        predicted_label = model.predict(X_scaled)[0]
        results.append(predicted_label)

    return results


############################
#       SCRIPT ENTRY
############################

if __name__ == "__main__":
    csv_file = os.path.join(os.getcwd(), "..", "..", "data_set", "pcap_features.csv")
    main(csv_file)
