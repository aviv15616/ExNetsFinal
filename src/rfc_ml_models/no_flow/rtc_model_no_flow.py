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
    """
    Displays the confusion matrix and classification report.
    :param y_true: List or array of true labels.
    :param y_pred: List or array of predicted labels.
    :param class_labels: List of class label names to use as index for the matrix.
    """
    # Compute confusion matrix using sklearn's function with specified label order
    cm = confusion_matrix(y_true, y_pred, labels=class_labels)
    print("\nConfusion Matrix:")
    # Print the confusion matrix as a DataFrame for better formatting
    print(pd.DataFrame(cm, index=class_labels, columns=class_labels))

    print("\nClassification Report:")
    # Print detailed classification report including precision, recall, f1-score, etc.
    print(classification_report(y_true, y_pred, labels=class_labels))

    # Plot a simple heatmap of the confusion matrix using matplotlib
    plt.figure(figsize=(8, 6))
    plt.imshow(cm, cmap="Blues", interpolation="nearest")
    plt.colorbar()
    tick_marks = np.arange(len(class_labels))
    plt.xticks(tick_marks, class_labels, rotation=45)
    plt.yticks(tick_marks, class_labels)
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.title("Confusion Matrix")
    # Annotate each cell with the corresponding count
    for i in range(len(class_labels)):
        for j in range(len(class_labels)):
            plt.text(j, i, cm[i, j], ha="center", va="center", color="red")
    plt.tight_layout()
    # plt.show()  # Uncomment this line to display the plot interactively

############################
#  Paths for model & scaler
############################
# Determine the base directory (directory of the current file)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Build full paths to the model and scaler pickle files in the same directory as this script
model_path = os.path.join(BASE_DIR, "model_no_flow.pkl")
scaler_path = os.path.join(BASE_DIR, "scaler_no_flow.pkl")

########################################################################
#  FEATURE SELECTION
#    (Derived *only* from sizes & timestamps)
########################################################################
# List of features to be used for model training and prediction (derived from packet sizes and timestamps)
FEATURE_SELECTION = [
    "avg_iat",  # Average Inter-Arrival Time
    "std_ps",   # Standard deviation of packet sizes
    "avg_ps"    # Average packet size
]

############################
#       HELPER FUNCTIONS
############################
def compute_cv_iat(timestamps):
    """
    Computes the Coefficient of Variation for Inter-Arrival Times (IAT).
    Formula: CV = standard deviation(iat) / mean(iat)
    :param timestamps: List of packet timestamps.
    :return: Coefficient of variation for the IAT, or 0.0 if not computable.
    """
    if len(timestamps) < 2:
        return 0.0
    # Compute differences between consecutive sorted timestamps
    iats = np.diff(sorted(timestamps))
    mean_iat = np.mean(iats)
    std_iat = np.std(iats, ddof=1)
    return (std_iat / mean_iat) if mean_iat != 0 else 0.0

def compute_cv_ps(packet_sizes):
    """
    Computes the Coefficient of Variation for packet sizes.
    Formula: CV = standard deviation(packet_sizes) / average(packet_sizes)
    :param packet_sizes: List of packet sizes.
    :return: Coefficient of variation for packet sizes, or 0.0 if not computable.
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
    """
    Extracts features from a single PCAP file for inference.
    Processes the PCAP file to extract packet sizes and timestamps, then computes derived statistics.
    :param pcap_file: Path to the PCAP file.
    :return: A pandas DataFrame containing the selected features, or None if insufficient data.
    """
    # Create and set a new asyncio event loop for processing
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # Open the PCAP file using pyshark with a display filter to capture only IP packets
    cap = pyshark.FileCapture(pcap_file, display_filter="ip")

    packet_sizes = []  # List to store packet sizes
    timestamps = []    # List to store packet timestamps

    # Iterate over each packet in the capture
    for pkt in cap:
        try:
            # If packet contains IP layer and a transport layer, record its size and timestamp
            if hasattr(pkt, "ip") and hasattr(pkt, "transport_layer"):
                packet_sizes.append(int(pkt.length))
                timestamps.append(float(pkt.sniff_time.timestamp()))
        except:
            continue  # Skip packets that raise any error
    cap.close()

    if len(packet_sizes) < 2:
        return None  # Not enough data to compute features

    # Sort timestamps to compute overall flow duration
    sorted_ts = sorted(timestamps)
    flow_start = sorted_ts[0]
    flow_end   = sorted_ts[-1]
    duration   = flow_end - flow_start if flow_end > flow_start else 0.0

    # Compute packet size statistics
    avg_ps = np.mean(packet_sizes)
    std_ps = np.std(packet_sizes, ddof=1)
    cv_ps = compute_cv_ps(packet_sizes)

    # Compute inter-arrival times (IAT)
    iats = np.diff(sorted_ts)
    avg_iat = np.mean(iats) if len(iats) else 0.0
    std_iat = np.std(iats, ddof=1) if len(iats) > 1 else 0.0
    cv_iat = compute_cv_iat(timestamps)

    # Compute packets per second metric
    total_packets = len(packet_sizes)
    packets_per_second = total_packets / duration if duration > 0 else 0.0

    # Combine all computed features into a dictionary
    all_features = {
        "avg_ps": avg_ps,
        "std_ps": std_ps,
        "cv_ps": cv_ps,
        "avg_iat": avg_iat,
        "std_iat": std_iat,
        "cv_iat": cv_iat,
        "packets_per_second": packets_per_second,
    }

    # Only select the features specified in FEATURE_SELECTION
    selected = {k: v for k, v in all_features.items() if k in FEATURE_SELECTION}
    if not selected:
        return None

    # Return the selected features as a single-row DataFrame
    return pd.DataFrame([selected])

############################
#  HELPER FOR TRAINING
############################
def extract_app_name(filename):
    """
    Extracts the application name from the PCAP filename.
    For example, 'zoom1.pcap' returns 'zoom'.
    :param filename: The PCAP filename.
    :return: The extracted app name or 'unknown' if not found.
    """
    match = re.match(r"([a-zA-Z]+)", filename)
    return match.group(1) if match else "unknown"

def build_features_for_each_pcap(csv_file):
    """
    Reads a CSV file (with columns "Pcap file", "Packet Size", "Timestamp"),
    groups data by "Pcap file", computes statistical features for each group,
    and forms a single row of derived features per PCAP.
    :param csv_file: Path to the CSV file containing raw packet data.
    :return: A pandas DataFrame with derived features for each PCAP.
    """
    df = pd.read_csv(csv_file)
    grouped = df.groupby("Pcap file")

    rows = []
    for pcap_file, group in grouped:
        packet_sizes = group["Packet Size"].tolist()
        timestamps = group["Timestamp"].tolist()
        if len(packet_sizes) < 2:
            continue  # Skip groups with insufficient data

        sorted_ts = sorted(timestamps)
        flow_start = sorted_ts[0]
        flow_end   = sorted_ts[-1]
        duration   = flow_end - flow_start if flow_end > flow_start else 0.0

        # Compute packet size statistics
        avg_ps = np.mean(packet_sizes)
        std_ps = np.std(packet_sizes, ddof=1)
        cv_ps = compute_cv_ps(packet_sizes)

        # Compute inter-arrival times (IAT) statistics
        iats = np.diff(sorted_ts)
        avg_iat = np.mean(iats) if len(iats) else 0.0
        std_iat = np.std(iats, ddof=1) if len(iats) > 1 else 0.0
        cv_iat = compute_cv_iat(timestamps)

        # Compute packets per second metric
        packets_per_second = (len(packet_sizes) / duration) if duration > 0 else 0.0

        # Gather all computed features
        all_features = {
            "avg_ps": avg_ps,
            "std_ps": std_ps,
            "cv_ps": cv_ps,
            "avg_iat": avg_iat,
            "std_iat": std_iat,
            "cv_iat": cv_iat,
            "packets_per_second": packets_per_second,
        }

        # Select only features defined in FEATURE_SELECTION
        selected = {k: v for k, v in all_features.items() if k in FEATURE_SELECTION}

        # Create a row dictionary with the PCAP filename and the extracted app name
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
    """
    Loads the trained model and scaler from disk; extracts features from each provided PCAP file;
    scales the features; and returns the predicted application labels.
    :param files: List of PCAP file paths to predict.
    :return: List of predicted labels (or "Unknown" if features cannot be extracted).
    """
    # Check that both the model and scaler files exist
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        print("❌ Model or Scaler file missing. Train the model first.")
        return []

    # Load the model and scaler using pickle
    with open(model_path, "rb") as model_file, open(scaler_path, "rb") as scaler_file:
        model = pickle.load(model_file)
        scaler = pickle.load(scaler_file)

    results = []
    # Process each file individually
    for f in files:
        df_features = extract_features_from_pcap(f)
        if df_features is None or df_features.empty:
            results.append("Unknown")
            continue

        # Select the features used during training
        X = df_features[FEATURE_SELECTION]
        # Scale features using the loaded scaler
        X_scaled = scaler.transform(X)
        # Predict the label using the loaded model
        pred_label = model.predict(X_scaled)[0]
        results.append(pred_label)

    return results

def main(csv_file=os.path.join(os.getcwd(), "..", "..", "training_set", "pcap_features.csv")):
    """
    Main function for training a RandomForest model.
    Reads a CSV file with raw PCAP packet data, computes derived features,
    splits the data into training and test sets, performs hyperparameter tuning,
    evaluates the model, displays feature importance and confusion matrix,
    and finally saves the trained model and scaler.
    :param csv_file: Path to the CSV file containing training data.
    """
    df_features = build_features_for_each_pcap(csv_file)
    if df_features.empty:
        print("❌ No valid data to train on.")
        return

    # Define feature matrix X and target vector y
    X = df_features[FEATURE_SELECTION]
    y = df_features["app_name"]

    # Split the dataset into training and testing sets (80/20 split, stratified by class)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale features to the range [0, 1] using MinMaxScaler
    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Set up hyperparameter grid for RandomForest and perform GridSearchCV for tuning
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

    # Retrieve the best estimator found during grid search
    best_rfc = grid_search.best_estimator_
    print("\n✅ Best Hyperparameters Found:")
    for param, value in grid_search.best_params_.items():
        print(f" - {param}: {value}")

    # Calculate and print training and testing accuracy
    train_acc = accuracy_score(y_train, best_rfc.predict(X_train_scaled)) * 100
    test_acc = accuracy_score(y_test, best_rfc.predict(X_test_scaled)) * 100
    print(f"✅ Train Accuracy: {train_acc:.2f}%")
    print(f"✅ Test Accuracy:  {test_acc:.2f}%")

    # Compute and display feature importances from the trained model
    feats_and_importance = sorted(
        zip(FEATURE_SELECTION, best_rfc.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    print("\n🔹 Feature Importance Ranking:")
    for feat, imp in feats_and_importance:
        print(f"{feat}: {imp:.4f}")

    # Generate and display confusion matrix for test set predictions
    unique_labels = sorted(y.unique())
    y_pred = best_rfc.predict(X_test_scaled)
    print_confusion_matrix(y_test, y_pred, unique_labels)

    # Save the trained model and scaler to disk using pickle
    with open(model_path, "wb") as mf, open(scaler_path, "wb") as sf:
        pickle.dump(best_rfc, mf)
        pickle.dump(scaler, sf)
    print("✅ Model and Scaler saved.")

if __name__ == "__main__":
    main()
