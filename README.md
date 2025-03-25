# PCAP Analyzer – Communication Networks Final Project

## 📌 Overview
This project provides tools to analyze network traffic captured in PCAP files and employs Machine Learning (ML) models to classify encrypted internet traffic. It focuses on extracting critical traffic features, visualizing them, and predicting the application generating the traffic.

## 🚀 Features

### Main Functionalities:
- **PCAP File Analysis:**
  - Accepts `.pcap` and `.pcapng` files.
  - Extracts features including:
    - Flow size (total packets per flow)
    - Flow volume (total bytes per flow)
    - Average packet size
    - Packet sizes and distribution
    - Packet timestamps and inter-arrival times (IAT)
    - Flow duration
    - Flow directionality (forward vs. backward packet counts)
    - TCP flags distribution (SYN, ACK, RST, PSH, FIN)
    - IP protocols usage
    - HTTP packet count (HTTP/1, HTTP/2, HTTP/3)

- **Visualization:** Interactive graphical representation of extracted features, including:
  - Average Packet Size (Bar Chart)
  - Average Inter-Arrival Time (IAT) (Bar Chart)
  - Packet Size Distribution (Histogram)
  - IAT Distribution (Histogram)
  - Flow Volume per Second (Line Graph)
  - Flow Size vs. Volume (Scatter Plot)
  - Flow Size per PCAP (Bar Chart)
  - Flow Volume per PCAP (Bar Chart)
  - Flow Direction (Forward vs. Backward packets per PCAP) (Bar Chart)
  - IP Protocols Distribution (Bar Chart)
  - TCP Flags Distribution (Bar Chart)
  - HTTP Distribution (Bar Chart)

- **Traffic Classification:** Application prediction using Random Forest ML models:
  - **Flow-based Model:** Features include flow size, flow volume, packet inter-arrival times, and flow directionality ratios.
  - **No-Flow Model:** Uses general features like packet sizes, packet timestamps, and packet throughput.

- **Interactive GUI:** Built with Tkinter, enabling easy interaction for loading PCAP files, viewing detailed data frames, graphical visualizations, and executing ML predictions.

## 🛠️ Installation

### Requirements
- Python 3.8+
- Dependencies: `pyshark`, `scikit-learn`, `matplotlib`, `pandas`, `numpy`, `seaborn`, `tkinter`

### Steps
1. Clone repository:
   ```sh
   git clone <repository_url>
   ```
2. Navigate to directory:
   ```sh
   cd <repository_name>
   ```
3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## 🎯 Detailed GUI Usage

### Buttons & Functions:
- **Load PCAPs:** Select `.pcap` or `.pcapng` files to load and process.
- **Show DataFrame:** Displays extracted data in a structured, interactive table format with detailed column descriptions.
- **Show Graphs:** Opens visualization window with various selectable interactive graphs listed above.
- **Predict without Flow:** Runs ML classification using packet sizes and timestamps.
- **Predict with Flow:** Runs ML classification using flow-based features.

## 📊 Machine Learning Models

### Model Features:
- **Scenario 1 (Flow-Based):** Attacker obtains packet sizes, timestamps, and hashes of the 4-tuple flowID.
  - Features: Flow size, flow volume, packet inter-arrival times, flow directionality ratio.

- **Scenario 2 (No-Flow):** Attacker obtains only packet sizes and timestamps.
  - Features: Average packet size, average IAT, packet throughput.

## 📍 Authors:
- Aviv Neeman (owner of this github account)
- Noa Shalom
- Gil Aharon
- Amnon Pozailov

## 📌 Links:
- Training set for the ML models, consisting 20 10~30 seconds pcap recordings of each traffic type (chrome,edge,youtube,spotify,zoom)
- 7 recordings of each traffic type (all 3 minute long to ensure a valid comparison) + sslkey file to allow HTTP analysis.
[Drive link](https://drive.google.com/drive/folders/1_HTYFmh8jFF9BU6gwGZcF5H-YbXrWvgu?usp=drive_link)
