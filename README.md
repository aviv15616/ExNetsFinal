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

## 📂 Project Structure
```
.
├── README.md
├── src/
│   ├── main.py
│   ├── pcap_gui.py
│   ├── data_frame.py
│   ├── graph.py
│   ├── pcap_processor.py
│   ├── rfc_model_with_flow.py
│   ├── rtc_model_no_flow.py
│   └── models/
│       ├── flow_based_model.pkl
│       └── no_flow_model.pkl
└── res/
    ├── result_figures/
    └── example_results.csv
```

- **`models/`:** Contains serialized (`.pkl`) Random Forest ML models.
- **`res/`:** Generated results and figures storage.

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

## 📝 Reports and Analysis
Contains detailed analyses:

1. **Network Performance Factors:**
   - Discusses TCP protocol performance factors, network conditions impacting data transfer, and methods for troubleshooting common TCP-related issues.

2. **Academic Papers Analysis:**
   - *FlowPic: Encrypted Internet Traffic Classification*
   - *Early Traffic Classification with Encrypted ClientHello*
   - *Analyzing HTTPS Traffic to Identify OS, Browser, and Application*

3. **Visualization Analysis:**
   - Detailed examination of traffic characteristics for Chrome, Edge, Spotify, YouTube, and Zoom.
   - Conclusions highlight patterns unique to each application, facilitating better classification accuracy.

4. **ML RFC Model Implementation:**
   - Explains implementation details of Random Forest classifiers for traffic classification.
   - Discusses feature selection rationale for each scenario.
   - Analyzes attacker capabilities in passive traffic classification, effectiveness of encryption obfuscation, and recommended mitigation strategies to enhance privacy.

## 📈 Results and Conclusions
Results provide information on:
- Network performance affecting data transfer (TCP-focused).
- Analyses and insights from visualizing recorded traffic sessions.
- ML classification accuracy (presented through confusion matrices).
- Effectiveness and limitations of automated encrypted traffic classification.
- Recommendations for enhancing traffic privacy and security.

## 🚧 Troubleshooting
- Verify all dependencies are installed.
- Use filtered or reasonably sized PCAP files to ensure stable analysis.
- GUI must be run from project root.

## 📍 Authors
- [List team members here with GitHub/LinkedIn links]

## 📌 Submission
- **GitHub Repository:** Includes all relevant project files.
- **LinkedIn:** Linked project profiles.
- **Moodle Submission:**
  - GitHub link
  - Filtered `.pcap` files
  - PCAP parsing Python scripts

---

🌟 Contact project team for further assistance or questions.
