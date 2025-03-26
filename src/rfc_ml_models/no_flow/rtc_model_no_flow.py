import os
import re
import pickle
import asyncio
import pyshark
import numpy as np
import pandas as pd

import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.preprocessing import MinMaxScaler

############################
#    CONFUSION MATRIX
############################
def print_confusion_matrix(y_true, y_pred, class_labels):
    """Displays confusion matrix + classification report."""
    cm = confusion_matrix(y_true, y_pred, labels=class_labels)
    print("\nConfusion Matrix:")
    print(pd.DataFrame(cm, index=class_labels, columns=class_labels))

    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, labels=class_labels))

    # Simple Heatmap with matplotlib
    plt.figure(figsize=(8, 6))
    plt.imshow(cm, cmap="Blues", interpolation="nearest")
    plt.colorbar()
    tick_marks = np.arange(len(class_labels))
    plt.xticks(tick_marks, class_labels, rotation=45)
    plt.yticks(tick_marks, class_labels)
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.title("Confusion Matrix")
    for i in range(len(class_labels)):
        for j in range(len(class_labels)):
            plt.text(j, i, cm[i, j], ha="center", va="center", color="red")
    plt.tight_layout()
    # plt.show()

############################
#  Paths for model & scaler
############################
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "model_no_flow.pkl")
scaler_path = os.path.join(BASE_DIR, "scaler_no_flow.pkl")

########################################################################
#  FEATURE SELECTION
#    (Derived *only* from sizes & timestamps)
########################################################################
FEATURE_SELECTION = [
    "avg_iat",
    "std_ps",
    "avg_ps"

]

############################
#       HELPER FUNCTIONS
############################
def compute_cv_iat(timestamps):
    """
    Coefficient of Variation for IAT = std(iat) / mean(iat).
    """
    if len(timestamps) < 2:
        return 0.0
    iats = np.diff(sorted(timestamps))
    mean_iat = np.mean(iats)
    std_iat = np.std(iats, ddof=1)
    return (std_iat / mean_iat) if mean_iat != 0 else 0.0

def compute_cv_ps(packet_sizes):
    """
    Coefficient of Variation for packet sizes = std_ps / avg_ps.
    """
    if len(packet_sizes) < 2:
        return 0.0
    mean_ps = np.mean(packet_sizes)
    std_ps = np.std(packet_sizes, ddof=1)
    return (std_ps / mean_ps) if mean_ps != 0 else 0.0

############################
#  FEATURE EXTRACTION (INFERENCE)
############################
def extract_features_from_pcap(pcap_file):
    """Extracts features from a single PCAP file for inference."""
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

    # Sort timestamps to compute overall duration
    sorted_ts = sorted(timestamps)
    flow_start = sorted_ts[0]
    flow_end   = sorted_ts[-1]
    duration   = flow_end - flow_start if flow_end > flow_start else 0.0

    # Packet-size stats
    avg_ps = np.mean(packet_sizes)
    std_ps = np.std(packet_sizes, ddof=1)
    cv_ps = compute_cv_ps(packet_sizes)

    # Inter-Arrival Times (IAT)
    iats = np.diff(sorted_ts)
    avg_iat = np.mean(iats) if len(iats) else 0.0
    std_iat = np.std(iats, ddof=1) if len(iats) > 1 else 0.0
    cv_iat = compute_cv_iat(timestamps)

    # Packets per second
    total_packets = len(packet_sizes)
    packets_per_second = total_packets / duration if duration > 0 else 0.0

    # Gather all possible features
    all_features = {
        "avg_ps": avg_ps,
        "std_ps": std_ps,
        "cv_ps": cv_ps,
        "avg_iat": avg_iat,
        "std_iat": std_iat,
        "cv_iat": cv_iat,
        "packets_per_second": packets_per_second,
    }

    # Only keep the features we specified
    selected = {k: v for k, v in all_features.items() if k in FEATURE_SELECTION}
    if not selected:
        return None

    return pd.DataFrame([selected])

############################
#  HELPER FOR TRAINING
############################
def extract_app_name(filename):
    """Extracts app name from the PCAP filename (e.g. 'zoom' from 'zoom1.pcap')."""
    match = re.match(r"([a-zA-Z]+)", filename)
    return match.group(1) if match else "unknown"

def build_features_for_each_pcap(csv_file):
    """
    Reads a CSV (with "Pcap file", "Packet Size", "Timestamp"),
    groups by "Pcap file", and computes stats. Each group corresponds
    to one PCAP's data. We then form a single row of derived features.
    """
    df = pd.read_csv(csv_file)
    grouped = df.groupby("Pcap file")

    rows = []
    for pcap_file, group in grouped:
        packet_sizes = group["Packet Size"].tolist()
        timestamps = group["Timestamp"].tolist()
        if len(packet_sizes) < 2:
            continue

        sorted_ts = sorted(timestamps)
        flow_start = sorted_ts[0]
        flow_end   = sorted_ts[-1]
        duration   = flow_end - flow_start if flow_end > flow_start else 0.0

        # Stats
        avg_ps = np.mean(packet_sizes)
        std_ps = np.std(packet_sizes, ddof=1)
        cv_ps = compute_cv_ps(packet_sizes)

        iats = np.diff(sorted_ts)
        avg_iat = np.mean(iats) if len(iats) else 0.0
        std_iat = np.std(iats, ddof=1) if len(iats) > 1 else 0.0
        cv_iat = compute_cv_iat(timestamps)

        packets_per_second = (len(packet_sizes)/duration) if duration > 0 else 0.0

        all_features = {
            "avg_ps": avg_ps,
            "std_ps": std_ps,
            "cv_ps": cv_ps,
            "avg_iat": avg_iat,
            "std_iat": std_iat,
            "cv_iat": cv_iat,
            "packets_per_second": packets_per_second,
        }

        selected = {k: v for k, v in all_features.items() if k in FEATURE_SELECTION}

        row_dict = {
            "Pcap file": pcap_file,
            "app_name": extract_app_name(pcap_file),
        }
        row_dict.update(selected)
        rows.append(row_dict)

    return pd.DataFrame(rows)

############################
#    MODEL TRAINING
############################
def predict_traffic(files):
    """Loads model & scaler; extracts features from each PCAP; returns predicted labels."""
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

        X = df_features[FEATURE_SELECTION]
        X_scaled = scaler.transform(X)
        pred_label = model.predict(X_scaled)[0]
        results.append(pred_label)

    return results

def main(csv_file=os.path.join(os.getcwd(), "..", "..", "training_set", "pcap_features.csv")):
    """
    Reads CSV, computes features (derived strictly from packet sizes & timestamps),
    and trains a RandomForest model.
    """
    df_features = build_features_for_each_pcap(csv_file)
    if df_features.empty:
        print("❌ No valid data to train on.")
        return

    X = df_features[FEATURE_SELECTION]
    y = df_features["app_name"]

    # Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale features
    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # RandomForest + GridSearch
    param_grid = {
        "n_estimators": [100, 200],
        "max_depth": [None, 20],
        "max_features": ["sqrt", "log2"]
    }
    rfc = RandomForestClassifier(random_state=42, class_weight="balanced_subsample")
    grid_search = GridSearchCV(
        rfc, param_grid, cv=3, scoring="accuracy", n_jobs=-1
    )
    grid_search.fit(X_train_scaled, y_train)

    best_rfc = grid_search.best_estimator_
    print("\n✅ Best Hyperparameters Found:")
    for param, value in grid_search.best_params_.items():
        print(f" - {param}: {value}")

    # Accuracy
    train_acc = accuracy_score(y_train, best_rfc.predict(X_train_scaled)) * 100
    test_acc = accuracy_score(y_test, best_rfc.predict(X_test_scaled)) * 100
    print(f"✅ Train Accuracy: {train_acc:.2f}%")
    print(f"✅ Test Accuracy:  {test_acc:.2f}%")

    # Feature importances
    feats_and_importance = sorted(
        zip(FEATURE_SELECTION, best_rfc.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    print("\n🔹 Feature Importance Ranking:")
    for feat, imp in feats_and_importance:
        print(f"{feat}: {imp:.4f}")

    # Confusion Matrix
    unique_labels = sorted(y.unique())
    y_pred = best_rfc.predict(X_test_scaled)
    print_confusion_matrix(y_test, y_pred, unique_labels)

    # Save model + scaler
    with open(model_path, "wb") as mf, open(scaler_path, "wb") as sf:
        pickle.dump(best_rfc, mf)
        pickle.dump(scaler, sf)
    print("✅ Model and Scaler saved.")

if __name__ == "__main__":
    main()
