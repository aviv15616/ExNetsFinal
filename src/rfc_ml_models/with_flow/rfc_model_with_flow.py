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

# Get the absolute path of the current script directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define paths for saving/loading the model, scaler, and also for CSV operations
model_path = os.path.join(BASE_DIR, "model_with_flow.pkl")
scaler_path = os.path.join(BASE_DIR, "scaler_with_flow.pkl")

# --------------------------------------------------------------------
# FEATURE SELECTION: list of features to be used in the model
# --------------------------------------------------------------------
FEATURE_SELECTION = [
    "cv_iat",                     # Coefficient of Variation for Inter-Arrival Times
    "std_ps",                     # Standard deviation of packet sizes
    # Flow-based features:
    "flow_count",                 # Number of unique flows in the PCAP
    # Newly added flow-based packet size statistics:
    "std_of_flow_pkt_size_std"    # Standard deviation of per-flow packet size standard deviations
]

############################
#       HELPER FUNCTIONS
############################

def compute_ratio_large_small(ratio_large, ratio_small, epsilon=1e-6):
    """
    Computes the ratio between large and small packet ratios.
    Adds a small epsilon to avoid division by zero.
    :param ratio_large: Ratio of large packets.
    :param ratio_small: Ratio of small packets.
    :param epsilon: Small constant to avoid division by zero.
    :return: The computed ratio.
    """
    return ratio_large / (ratio_small + epsilon)

def print_confusion_matrix(y_true, y_pred, class_labels):
    """
    Prints and plots the confusion matrix for classification results.
    :param y_true: Array-like of true class labels.
    :param y_pred: Array-like of predicted class labels.
    :param class_labels: List of class label names to index the matrix.
    """
    cm = confusion_matrix(y_true, y_pred, labels=class_labels)

    print("\nConfusion Matrix:")
    cm_df = pd.DataFrame(cm, index=class_labels, columns=class_labels)
    print(cm_df)

    # Plot confusion matrix as a heatmap using seaborn for better aesthetics
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=class_labels, yticklabels=class_labels)
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.title("Confusion Matrix")
    # plt.show()  # Uncomment to display the plot interactively

def extract_app_name(filename):
    """
    Extract the application type (e.g., 'zoom', 'youtube') from the filename.
    :param filename: Filename of the PCAP.
    :return: Extracted application name or "unknown" if not found.
    """
    match = re.match(r"([a-zA-Z]+)", filename)
    return match.group(1) if match else "unknown"

def compute_iat_stats(timestamps):
    """
    Computes minimum, average, and maximum of Inter-Arrival Times (IAT).
    :param timestamps: List of packet timestamps.
    :return: Tuple (min_iat, avg_iat, max_iat) or (0,0,0) if insufficient data.
    """
    if len(timestamps) < 2:
        return 0, 0, 0
    iats = np.diff(sorted(timestamps))
    return min(iats), np.mean(iats), max(iats)

def compute_burstiness(timestamps):
    """
    Computes the burstiness of packet arrivals, defined as the coefficient of variation
    (std / mean) of the IAT distribution.
    :param timestamps: List of packet timestamps.
    :return: Burstiness value or 0 if insufficient data.
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
    """
    Computes Shannon entropy of packet sizes by binning them.
    :param packet_sizes: List of packet sizes.
    :param bins: Number of bins for histogram.
    :return: Shannon entropy value.
    """
    if len(packet_sizes) < 2:
        return 0.0
    hist, _ = np.histogram(packet_sizes, bins=bins, density=True)
    hist = hist[hist > 0]  # Remove bins with zero probability
    if len(hist) == 0:
        return 0.0
    return -np.sum(hist * np.log2(hist))

def compute_ratio_small(packet_sizes, threshold=300):
    """
    Computes the ratio of packets with size less than a threshold.
    :param packet_sizes: List of packet sizes.
    :param threshold: Size threshold.
    :return: Ratio of packets below the threshold.
    """
    if not packet_sizes:
        return 0.0
    return sum(size < threshold for size in packet_sizes) / len(packet_sizes)

def compute_ratio_large(packet_sizes, threshold=1000):
    """
    Computes the ratio of packets with size greater than a threshold.
    :param packet_sizes: List of packet sizes.
    :param threshold: Size threshold.
    :return: Ratio of packets above the threshold.
    """
    if not packet_sizes:
        return 0.0
    return sum(size > threshold for size in packet_sizes) / len(packet_sizes)

def compute_median_iat(timestamps):
    """
    Computes the median of the IAT distribution.
    :param timestamps: List of packet timestamps.
    :return: Median IAT.
    """
    if len(timestamps) < 2:
        return 0.0
    iats = np.diff(sorted(timestamps))
    return float(np.median(iats))

def compute_iqr_iat(timestamps):
    """
    Computes the interquartile range (IQR) of IAT, defined as Q3 - Q1.
    :param timestamps: List of packet timestamps.
    :return: IQR of IAT.
    """
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
    Reads a CSV of aggregated PCAP information, groups data by 'Pcap file',
    computes statistics for each PCAP file, and returns a DataFrame containing
    only the features specified in FEATURE_SELECTION.
    :param csv_file: Path to the CSV file with aggregated PCAP data.
    :return: pandas DataFrame with derived features for each PCAP.
    """
    df = pd.read_csv(csv_file)
    grouped = df.groupby("Pcap file")

    rows = []
    for pcap_file, group in grouped:
        packet_sizes = group["Packet Size"].tolist()
        timestamps = group["Timestamp"].tolist()
        flows_numeric = group["Flow Hash Numeric"].tolist()

        # (1) Flow-wise packet size tracking: group packet sizes by their flow hash
        flow_pkt_sizes = defaultdict(list)
        for idx, row_ in group.iterrows():
            fhash = row_["Flow Hash Numeric"]
            flow_pkt_sizes[fhash].append(row_["Packet Size"])

        # Compute standard deviation of packet sizes per flow
        flow_pkt_std = [np.std(sizes, ddof=1) if len(sizes) > 1 else 0.0 for sizes in flow_pkt_sizes.values()]
        avg_flow_pkt_size_std = np.mean(flow_pkt_std) if flow_pkt_std else 0.0
        max_flow_pkt_size_std = np.max(flow_pkt_std) if flow_pkt_std else 0.0
        std_of_flow_pkt_size_std = np.std(flow_pkt_std, ddof=1) if len(flow_pkt_std) > 1 else 0.0

        # (2) Flow-based statistics: count flows, compute flow ratios, etc.
        flow_counter = Counter(flows_numeric)
        flow_count = len(set(flows_numeric))
        max_flows = max(flow_counter.values()) if flow_counter else 0
        flow_ratio = max_flows / flow_count if flow_count > 0 else 0
        packets_per_flow = np.mean(list(flow_counter.values())) if flow_counter else 0

        # Compute inter-arrival time (IAT) statistics
        iats = np.diff(sorted(timestamps)) if len(timestamps) > 1 else [0.0]
        mean_iat = np.mean(iats)
        std_iat = np.std(iats, ddof=1)

        cv_iat = std_iat / mean_iat if mean_iat != 0 else 0.0

        # Combine computed features into a dictionary
        feature_values = {
            # Packet statistics
            "avg_iat": np.mean(timestamps) if timestamps else 0.0,
            "avg_ps": np.mean(packet_sizes) if packet_sizes else 0.0,
            "cv_iat": cv_iat,
            "std_ps": np.std(packet_sizes, ddof=1) if len(packet_sizes) > 1 else 0.0,
            # IAT statistics (these keys may be used in extended feature sets)
            "max_iat": max(timestamps) if timestamps else 0.0,
            "std_iat": np.std(timestamps, ddof=1) if len(timestamps) > 1 else 0.0,
            # Flow-based features
            "flow_count": flow_count,
            "max_flows": max_flows,
            "flow_ratio": flow_ratio,
            "packets_per_flow": packets_per_flow,
            # Newly added flow-based packet size statistics
            "avg_flow_pkt_size_std": avg_flow_pkt_size_std,
            "max_flow_pkt_size_std": max_flow_pkt_size_std,
            "std_of_flow_pkt_size_std": std_of_flow_pkt_size_std
        }

        # Filter down to only the features specified in FEATURE_SELECTION
        filtered_features = {k: v for k, v in feature_values.items() if k in FEATURE_SELECTION}

        # Extract the application name from the PCAP file name
        app_name = extract_app_name(pcap_file)
        row = {"Pcap file": pcap_file, "app_name": app_name}
        row.update(filtered_features)
        rows.append(row)

    return pd.DataFrame(rows)

def main(csv_file=os.path.join(os.getcwd(), "training_set", "pcap_features.csv")):
    """
    Trains a RandomForest model using features built from the CSV file of PCAP data.
    Splits the data, scales features, performs hyperparameter tuning, evaluates the model,
    prints feature importances and confusion matrix, and saves the model and scaler.
    :param csv_file: Path to the CSV file containing training data.
    """
    df_features = build_features_for_each_pcap(csv_file)

    X = df_features[FEATURE_SELECTION]
    y = df_features["app_name"]

    # Split the dataset into training and testing sets (80/20 split, stratified by app_name)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale features to a [0, 1] range using MinMaxScaler
    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Define hyperparameter grid for RandomForest and perform GridSearchCV
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
    print("\n✅ Best Hyperparameters Found:")
    for param, value in grid_search.best_params_.items():
        print(f" - {param}: {value}")

    print(f"✅ Model Accuracy: {accuracy:.2f}%")
    train_accuracy = accuracy_score(y_train, best_rfc.predict(X_train_scaled)) * 100
    print(f"✅ Train Accuracy: {train_accuracy:.2f}%")
    test_accuracy = accuracy_score(y_test, best_rfc.predict(X_test_scaled)) * 100
    print(f"✅ Test Accuracy: {test_accuracy:.2f}%")

    # Print sorted feature importances
    feature_importance = best_rfc.feature_importances_
    sorted_features = list(sorted(zip(FEATURE_SELECTION, feature_importance), key=lambda x: x[1], reverse=True))

    print("\n🔹 Feature Importance Ranking (Sorted):")
    for feature, importance in sorted_features:
        print(f"{feature}: {importance:.4f}")

    # Print and plot the confusion matrix
    class_labels = sorted(y.unique())
    print_confusion_matrix(y_test, y_pred, class_labels)

    # Save the trained model and scaler using pickle
    with open(model_path, "wb") as model_file, open(scaler_path, "wb") as scaler_file:
        pickle.dump(best_rfc, model_file)
        pickle.dump(scaler, scaler_file)
    print("✅ Model and Scaler saved.")

def extract_features_from_pcap(pcap_file):
    """
    Extracts advanced, flow-based features from a PCAP file.
    Opens the PCAP with Pyshark, extracts packet sizes, timestamps, and computes flow hashes.
    :param pcap_file: Path to the PCAP file.
    :return: A pandas DataFrame with the selected features or None if insufficient data.
    """
    try:
        # Try to get the current running loop; if none, create a new one
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    # Open the PCAP file filtering for IP packets
    cap = pyshark.FileCapture(pcap_file, display_filter="ip")
    packet_sizes = []
    timestamps = []
    flow_hashes = []

    # For tracking packet sizes per flow
    flow_pkt_sizes = defaultdict(list)

    for pkt in cap:
        try:
            if not hasattr(pkt, 'ip') or not hasattr(pkt, 'transport_layer'):
                continue

            size = int(pkt.length)
            t_ = float(pkt.sniff_time.timestamp())
            packet_sizes.append(size)
            timestamps.append(t_)

            # Generate a flow hash using source/destination IP and ports
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            src_port = pkt[pkt.transport_layer].srcport
            dst_port = pkt[pkt.transport_layer].dstport
            flow_tuple = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}"
            flow_hash_hex = hashlib.md5(flow_tuple.encode()).hexdigest()
            flow_hash_decimal = int(flow_hash_hex, 16) % 10**10
            flow_hashes.append(flow_hash_decimal)

            # Record packet size for the corresponding flow
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

    # Compute IAT statistics
    iats = np.diff(sorted(timestamps)) if len(timestamps) > 1 else [0.0]
    mean_iat = np.mean(iats)
    std_iat = np.std(iats, ddof=1)
    cv_iat = std_iat / mean_iat if mean_iat != 0 else 0.0

    # Compute flow-based statistics
    flow_counter = Counter(flow_hashes)
    flow_count = len(set(flow_hashes))
    max_flows = max(flow_counter.values(), default=0)
    flow_ratio = max_flows / flow_count if flow_count > 0 else 0
    packets_per_flow = np.mean(list(flow_counter.values())) if flow_counter else 0

    # Gather all computed features
    feature_values = {
        # Packet statistics
        "avg_iat": np.mean(timestamps) if timestamps else 0.0,
        "avg_ps": np.mean(packet_sizes) if packet_sizes else 0.0,
        # IAT and packet size variability statistics
        "max_iat": max(timestamps) if timestamps else 0.0,
        "std_iat": np.std(timestamps, ddof=1) if len(timestamps) > 1 else 0.0,
        "cv_iat": cv_iat,
        "std_ps": np.std(packet_sizes, ddof=1) if len(packet_sizes) > 1 else 0.0,
        # Flow-based features
        "flow_count": flow_count,
        "max_flows": max_flows,
        "flow_ratio": flow_ratio,
        "packets_per_flow": packets_per_flow,
        # Newly added flow-based packet size statistics
        "avg_flow_pkt_size_std": avg_flow_pkt_size_std,
        "max_flow_pkt_size_std": max_flow_pkt_size_std,
        "std_of_flow_pkt_size_std": std_of_flow_pkt_size_std
    }

    # Filter the computed features to only those specified in FEATURE_SELECTION
    selected_values = {k: v for k, v in feature_values.items() if k in FEATURE_SELECTION}
    df = pd.DataFrame([selected_values])
    return df if not df.empty else None

def predict_traffic(files):
    """
    Loads the trained model and scaler, extracts advanced flow-based features from each PCAP file,
    scales the features, and returns predicted application names.
    :param files: List of PCAP file paths.
    :return: List of predicted labels (or "Unknown" if features extraction fails).
    """
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

        # Scale the extracted features and predict the label
        X_scaled = scaler.transform(df_features)
        predicted_label = model.predict(X_scaled)[0]
        results.append(predicted_label)

    return results

############################
#       SCRIPT ENTRY
############################

if __name__ == "__main__":
    # Define the CSV file path for training data, assumed to be located two directories up in "training_set"
    csv_file = os.path.join(os.getcwd(), "..", "..", "training_set", "pcap_features.csv")
    main(csv_file)
