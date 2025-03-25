
# PCAP Analyzer – Communication Networks Final Project

## 📌 Overview
This project provides tools to analyze network traffic captured in PCAP files and utilizes Machine Learning (ML) models to classify encrypted internet traffic. The analysis focuses on extracting critical traffic features, visualizing them, and predicting the application generating the traffic.

## 🚀 Features

### Main Functionalities:
- **PCAP File Analysis:** Extract key features from PCAP files (packet sizes, inter-arrival times, TCP/IP header data, HTTP packet counts, etc.).
- **Visualization:** Graphically present various traffic characteristics using interactive graphs:
  - Average packet size
  - Inter-packet arrival time distribution
  - Flow volume and size
  - TCP flags and IP protocols distributions
- **Traffic Classification:** Predict the source application (e.g., Chrome, Edge, Spotify, YouTube, Zoom) using Random Forest ML models:
  - Model with Flow-based features
  - Model without Flow-based features
- **Interactive GUI:** Easy-to-use graphical interface to load PCAPs, visualize data, and run predictions.

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
│   └── rtc_model_no_flow.py
└── res/
    ├── result_figures/
    └── example_results.csv
```

- **`src/`:** Contains the Python scripts for processing PCAP files, GUI application, and ML predictions.
- **`res/`:** Holds generated results and figures.

## 🛠️ Installation

### Requirements
- Python 3.8 or newer
- `pyshark`, `scikit-learn`, `matplotlib`, `pandas`, `numpy`, `seaborn`, `tkinter`

### Steps
1. Clone the repository:
   ```sh
   git clone <your_repository_url>
   ```
2. Navigate to the directory:
   ```sh
   cd your_repository_name
   ```
3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## 🎯 Usage
- Run the GUI application:
  ```sh
  python src/main.py
  ```
- Load PCAP files through the interface.
- Use built-in functionalities to visualize and analyze network traffic.

## 📊 Machine Learning Models
### With Flow-Based Features
- Utilizes advanced features such as flow size, flow volume, packet inter-arrival time variations.
- Features include standard deviations of packet sizes per flow, average flow packet size, and flow directionality ratios.

### Without Flow-Based Features
- Focuses on general statistics like average packet size, burstiness of inter-arrival times, and packet throughput.
- Does not require flow-specific information, making it useful for simpler scenarios.

## 🖥️ Visualization Tools
- Interactive bar charts, histograms, scatter plots, and distribution graphs.
- Dynamic UI elements for selecting and viewing specific PCAP data characteristics.

## 📝 Reports and Analysis
- Includes analysis of TCP/IP behaviors (e.g., flow control mechanisms, routing impacts).
- Comparative visualization of apps' traffic characteristics, highlighting differences and similarities.

## 🔒 Security and Privacy Analysis
- Evaluates the ability of attackers to identify apps/sites from encrypted or anonymized traffic.
- Provides mitigation recommendations for potential privacy leaks.

## 📈 Results and Conclusions
- Confusion matrices and classification accuracy clearly presented.
- Visual summaries facilitate interpretation of model performance.

## 📚 Papers Reviewed
- Detailed analyses provided for:
  - *FlowPic: Encrypted Internet Traffic Classification*
  - *Early Traffic Classification with Encrypted ClientHello*
  - *Analyzing HTTPS Traffic to Identify OS, Browser, and Application*

## 🚧 Troubleshooting
- Ensure all dependencies are installed.
- PCAP files should not be too large; consider filtering.
- GUI application must be run from the project root directory.

## 📍 Authors
- List of team members and links to GitHub and LinkedIn profiles.

## 📌 Submission
- **GitHub repository:** Contains all project-related files.
- **LinkedIn:** Project linked in profiles.
- **Moodle submission:**
  - Link to GitHub repo
  - Filtered `.pcap` files (or cloud links)
  - Python scripts for parsing PCAP files

---

🌟 For further questions or support, contact the project team.
