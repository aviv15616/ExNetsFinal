# PCAP Analyzer – Communication Networks Final Project

## 📌 Overview
This project provides tools to analyze network traffic captured in PCAP files and employs Machine Learning (ML) models to classify encrypted internet traffic. It focuses on extracting critical traffic features for app usage classification, visualizing them, and predicting the application generating the traffic among Chrome, Edge, Spotify, YouTube, and Zoom.

## 🚀 Features

### Main Functionalities

**PCAP File Analysis:**

- **Load PCAP Files:**
  - Supports `.pcap` and `.pcapng` formats.
  - Activates "Show Dataframe" and "Show Graphs" buttons upon loading.

- **Show Dataframe:**
  - Extracts and displays features such as:
    - Flow size (total packets per flow)
    - Flow volume (total bytes per flow)
    - Average packet size
    - Packet size distributions
    - Packet timestamps and Inter-Arrival Times (IAT)
    - Flow duration
    - Flow directionality (forward vs. backward packet counts)
    - TCP flags distribution (SYN, ACK, RST, PSH, FIN)
    - IP protocols usage
    - HTTP packet counts (HTTP/1, HTTP/2, HTTP/3)

- **Show Graphs:**
  - Provides interactive visualizations of extracted features:
    - Average Packet Size (Bar Chart)
    - Average Inter-Arrival Time (Bar Chart)
    - Packet Size Distribution (Histogram)
    - Inter-Arrival Time Distribution (Histogram)
    - Flow Volume per Second (Line Graph)
    - Flow Size vs. Volume (Scatter Plot)
    - Flow Size per PCAP (Bar Chart)
    - Flow Volume per PCAP (Bar Chart)
    - Flow Directionality (Forward vs. Backward packets per PCAP, Bar Chart)
    - IP Protocols Distribution (Bar Chart)
    - TCP Flags Distribution (Bar Chart)
    - HTTP Distribution (Bar Chart)

- **ML Prediction:**
- in order to see accuracy results file must be naned <appname><number> as the validation is based on existence of the label claasified in the filename
  - **Predict without Flow:** Classifies traffic using packet sizes and timestamps.
  - **Predict with Flow:** Classifies traffic using packet sizes, timestamps, and anonymous flow-based features.

## 🛠️ Installation

### Requirements
- Python 3.8+
- Dependencies: `pyshark`, `scikit-learn`, `matplotlib`, `pandas`, `numpy`, `seaborn`, `tkinter`

### How to run
if running on linux, recommended to run in full screen for full compatability

1. Clone the repository:
   ```sh
   git clone https://github.com/aviv15616/ExNetsFinal.git
   ```
2. Navigate to the project directory:
   ```sh
   cd ExNetsFinal
   ```
3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
4. Run main.py
5. Enjoy!

## 📊 Machine Learning Models

### Model Features

- **Scenario 1 (Packet sizes, timestamps and Flow-Based):**
  - Attacker obtains packet sizes, timestamps, and hashes of the 4-tuple flow ID.
  - Features used for classification: Coefficient of variance of Inter Arrival Times, Standard deviation of Packet Sizes,
    Count of Unique Flows and the Standard Deviation of the Standard Deviations of Packet Sizes across Different Flows

- **Scenario 2 (Only Packet sizes and timestamps):**
  - Attacker obtains only packet sizes and timestamps.
  - Features used for classification: Average Inter arrival times, Average Packet size, Standard deviation of packet sizes.
    
## 🔥Special Features
  - All the visual representation of the data updates dynamically upon loading of pcaps (dataframe,graphs and predictions).
  - All graphs have check/radio buttons to ensure comfortable comparison of the different traffics.

## 🔥Troubleshooting
  - Given the dynamic nature of the gui, sometimes restarting the main py, will make the program run smoother due to delayed callback etc..
 


## 📍 Authors
- Aviv Neeman (GitHub owner) – [anksilae@gmail.com](mailto:anksilae@gmail.com)
- Noa Shalom
- Gil Aharon
- Amnon Pozailov

## 📌 Dataset Links
- **Training Set:**
  - 25 PCAP files (10–30 seconds each) per traffic type (Chrome, Edge, YouTube, Spotify, Zoom). Only 15 per type were used for training.
- **Visual Analysis Set:**
  - 7 PCAP recordings per traffic type (each 3 minutes long for robust analysis) including SSL key files for HTTP analysis.

[🔗 Access via Google Drive](https://drive.google.com/drive/folders/1_HTYFmh8jFF9BU6gwGZcF5H-YbXrWvgu?usp=drive_link)

