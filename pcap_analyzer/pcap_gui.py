import tkinter as tk
from tkinter import filedialog, messagebox, ttk, Toplevel, Label
import os
import threading
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, accuracy_score
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from data_frame import DataFrameWindow
from pcap_processor import PcapProcessor
from graph import Graph

# Import your two model prediction functions
from rfc_ml_models.no_flow.rtc_model_no_flow import predict_traffic as predict_no_flow
from rfc_ml_models.with_flow.rfc_model_with_flow import predict_traffic as predict_with_flow


class PcapGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PCAP Analyzer")
        self.root.geometry("400x450")

        self.processor = PcapProcessor(sample_mode=False)
        self.data_window = None
        self.graph_window = None

        # -- Main Buttons --
        self.load_button = tk.Button(root, text="Load PCAPs", command=self.load_pcaps)
        self.load_button.pack(pady=10)

        self.show_button = tk.Button(root, text="Show DataFrame", command=self.show_dataframe)
        self.show_button.pack(pady=10)

        self.graph_button = tk.Button(root, text="Show Graphs", command=self.show_graphs)
        self.graph_button.pack(pady=10)

        # Separate buttons for each prediction type
        self.predict_no_flow_button = tk.Button(root, text="Predict without Flow", command=self.predict_pcaps_no_flow)
        self.predict_no_flow_button.pack(pady=10)

        self.predict_with_flow_button = tk.Button(root, text="Predict with Flow", command=self.predict_pcaps_with_flow)
        self.predict_with_flow_button.pack(pady=10)

    # -------------------------------
    #  PCAP LOADING
    # -------------------------------
    def load_pcaps(self):
        """
        Opens file dialog to select PCAP files and processes them in a separate thread.
        """
        files = filedialog.askopenfilenames(
            filetypes=[("PCAP Files", "*.pcap;*.pcapng"), ("All Files", "*.*")],
            title="Select PCAP files"
        )
        if files:
            threading.Thread(target=self.process_pcaps_thread, args=(files,), daemon=True).start()

    def process_pcaps_thread(self, files):
        """
        Processes multiple PCAP files in a separate thread and updates UI dynamically.
        """
        total_files = len(files)
        processed_files = 0
        successfully_uploaded = 0

        for file in files:
            processed_files += 1
            self.root.after(
                0,
                lambda cnt=processed_files: self.root.title(f"Processing PCAPs ({cnt}/{total_files})")
            )

            success = self.processor.process_pcap(file)
            if success:
                successfully_uploaded += 1

            if self.data_window:
                self.root.after(0, lambda: self.data_window.update_data(self.processor.pcap_data))

        self.root.after(0, lambda: self.root.title("PCAP Processing - Complete"))

        if successfully_uploaded > 0:
            self.root.after(0, lambda: messagebox.showinfo("Success", "PCAPs loaded successfully!"))
        elif processed_files > 0 and successfully_uploaded == 0:
            self.root.after(0, lambda: messagebox.showinfo("No New Files", "No new PCAPs loaded."))

    # -------------------------------
    #  PREDICT BUTTON HANDLERS
    # -------------------------------
    def predict_pcaps_no_flow(self):
        """Predict using the no-flow model."""
        self.open_prediction_window(predict_no_flow, "PCAP Predictions (No Flow)")

    def predict_pcaps_with_flow(self):
        """Predict using the with-flow model."""
        self.open_prediction_window(predict_with_flow, "PCAP Predictions (With Flow)")

    # -------------------------------
    #  PREDICTION PROCESS & RESULTS
    # -------------------------------
    def open_prediction_window(self, prediction_function, model_name):
        """
        Opens a new window for each prediction session.
        `model_name` indicates whether it's "No Flow" or "With Flow."
        """
        prediction_window = tk.Toplevel(self.root)
        prediction_window.title(model_name)

        tree = ttk.Treeview(prediction_window, columns=("PCAP File", "Predicted App"), show="headings")
        tree.heading("PCAP File", text="PCAP File")
        tree.heading("Predicted App", text="Predicted App")
        tree.column("PCAP File", width=150)
        tree.column("Predicted App", width=150)
        tree.pack(fill="both", expand=True)

        files = filedialog.askopenfilenames(
            filetypes=[("PCAP Files", "*.pcap;*.pcapng"), ("All Files", "*.*")],
            title=f"Select PCAP files for {model_name}"
        )

        if files:
            threading.Thread(
                target=self.process_predictions,
                args=(files, prediction_function, model_name, prediction_window, tree),
                daemon=True
            ).start()

    def process_predictions(self, files, prediction_function, model_name, prediction_window, tree):
        """
        Runs predictions using the specified function and updates UI dynamically.
        """
        total_files = len(files)
        correct_predictions = 0
        y_true, y_pred = [], []

        for i, file in enumerate(files, start=1):
            self.root.after(0, lambda idx=i: prediction_window.title(f"{model_name} ({idx}/{total_files})"))

            predictions = prediction_function([file])
            if predictions:
                predicted_label = predictions[0]
                if isinstance(predicted_label, (list, tuple)):
                    predicted_label = predicted_label[0]

                # Extract actual label from filename
                actual_label = self.extract_actual_label(file)
                if actual_label:
                    y_true.append(actual_label)
                    y_pred.append(predicted_label)

                self.root.after(
                    0,
                    lambda f=file, p=predicted_label: tree.insert("", "end", values=(os.path.basename(f), p))
                )

                if actual_label and actual_label.lower() == predicted_label.lower():
                    correct_predictions += 1
            else:
                self.root.after(
                    0,
                    lambda f=file: tree.insert("", "end", values=(os.path.basename(f), "Unknown"))
                )

        self.root.after(0, lambda: prediction_window.title(f"{model_name} - Complete"))
        accuracy = (correct_predictions / total_files) * 100 if total_files > 0 else 0
        self.root.after(0, lambda: tree.insert("", "end", values=("Accuracy", f"{accuracy:.2f}%")))

        # Show confusion matrix after all predictions are done
        self.root.after(0, lambda: self.show_confusion_matrix(y_true, y_pred, list(set(y_true)), model_name))

        self.root.after(
            0,
            lambda: tk.messagebox.showinfo("Prediction Completed", f"Prediction ended!\nAccuracy: {accuracy:.2f}%")
        )

    # -------------------------------
    #  CONFUSION MATRIX & EXPLANATION
    # -------------------------------
    def show_confusion_matrix(self, y_true, y_pred, class_labels, model_name):
        """Displays a visual confusion matrix in a new Tkinter window with an automatic explanation."""
        if not y_true or not y_pred:
            tk.messagebox.showwarning("Confusion Matrix", "Not enough data to generate a confusion matrix.")
            return

        # Compute confusion matrix
        cm = confusion_matrix(y_true, y_pred, labels=class_labels)

        # Create new window
        cm_window = tk.Toplevel(self.root)
        cm_window.title(f"Confusion Matrix - {model_name}")

        # Create figure for the heatmap
        fig, ax = plt.subplots(figsize=(6, 5))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=class_labels, yticklabels=class_labels)
        ax.set_xlabel("Predicted Label")
        ax.set_ylabel("True Label")
        ax.set_title(f"Confusion Matrix - {model_name}")

        # Embed plot inside Tkinter window
        canvas = FigureCanvasTkAgg(fig, master=cm_window)
        canvas.draw()
        canvas.get_tk_widget().pack()

        # Auto-generate an explanation
        explanation = self.analyze_confusion_matrix(cm, class_labels, model_name)

        # Display explanation in Tkinter window
        label = Label(cm_window, text=explanation, justify="left", wraplength=500, padx=10, pady=5)
        label.pack()

    def analyze_confusion_matrix(self, cm, class_labels, model_name):
        """
        Builds a text explanation for the confusion matrix,
        specifically referencing possible apps: Chrome, Edge, YouTube, Spotify, Zoom.
        """
        explanation = f"🔹 **Analysis of {model_name} Classification Performance:**\n\n"
        num_classes = len(class_labels)

        # Quick dictionary for custom references
        # (You can expand or adjust these references or thresholds.)
        known_apps = {"chrome", "edge", "youtube", "spotify", "zoom"}

        # Analyze each row (actual label)
        for i, actual_label in enumerate(class_labels):
            total_actual = sum(cm[i, :])
            correct = cm[i, i]
            if total_actual == 0:
                continue

            accuracy = (correct / total_actual) * 100

            if accuracy == 100:
                explanation += f"✅ **{actual_label}** was perfectly classified ({int(correct)} correct).\n"
            elif accuracy >= 80:
                explanation += f"✅ **{actual_label}** had mostly correct classifications ({accuracy:.2f}%).\n"
            elif accuracy >= 50:
                explanation += f"⚠️ **{actual_label}** was only correct in {accuracy:.2f}% of cases.\n"
            else:
                explanation += f"❌ **{actual_label}** was frequently misclassified ({accuracy:.2f}% accuracy).\n"

            # If misclassified
            misclass_dict = {}
            for j, pred_label in enumerate(class_labels):
                if i != j and cm[i, j] > 0:
                    misclass_dict[pred_label] = cm[i, j]

            if misclass_dict:
                explanation += f"   - Misclassified as: "
                explanation += ", ".join([f"{pl} ({cnt} times)" for pl, cnt in misclass_dict.items()])
                explanation += "\n"

        # Additional context for browser/app traffic
        explanation += "\n🔹 **Key Observations for Browser/App Traffic (Chrome, Edge, YouTube, Spotify, Zoom):**\n"

        # Check specifically if Chrome <-> Edge confusion
        if "chrome" in class_labels and "edge" in class_labels:
            i_chrome = class_labels.index("chrome")
            i_edge = class_labels.index("edge")
            chrome_confused_as_edge = cm[i_chrome, i_edge]
            edge_confused_as_chrome = cm[i_edge, i_chrome]
            if chrome_confused_as_edge > 0 or edge_confused_as_chrome > 0:
                explanation += "⚠️ Observed confusion between **Chrome** and **Edge**.\n"

        # YouTube classification
        if "youtube" in class_labels:
            i_yt = class_labels.index("youtube")
            total_yt = sum(cm[i_yt, :])
            if total_yt > 0:
                correct_yt = cm[i_yt, i_yt]
                yt_acc = (correct_yt / total_yt) * 100
                if yt_acc < 80:
                    explanation += "❌ **YouTube** traffic had a significant misclassification rate.\n"
                else:
                    explanation += "✅ **YouTube** was reasonably well classified.\n"

        # Spotify classification
        if "spotify" in class_labels:
            i_sp = class_labels.index("spotify")
            total_sp = sum(cm[i_sp, :])
            if total_sp > 0:
                correct_sp = cm[i_sp, i_sp]
                sp_acc = (correct_sp / total_sp) * 100
                if sp_acc >= 90:
                    explanation += "✅ **Spotify** was classified very accurately.\n"
                elif sp_acc < 50:
                    explanation += "❌ **Spotify** was heavily misclassified.\n"

        # Zoom classification
        if "zoom" in class_labels:
            i_zm = class_labels.index("zoom")
            total_zm = sum(cm[i_zm, :])
            if total_zm > 0:
                correct_zm = cm[i_zm, i_zm]
                zm_acc = (correct_zm / total_zm) * 100
                if zm_acc < 80:
                    explanation += "⚠️ **Zoom** traffic wasn't classified very accurately.\n"
                else:
                    explanation += "✅ **Zoom** had decent classification accuracy.\n"

        return explanation

    # -------------------------------
    #  EXTRACT ACTUAL LABEL
    # -------------------------------
    def extract_actual_label(self, filename):
        """
        Extracts actual traffic type from filename, if applicable.
        e.g., "chrome_video1.pcap" => "chrome"
        """
        import re
        match = re.match(r"([a-zA-Z]+)", os.path.basename(filename))
        return match.group(1) if match else None

    # -------------------------------
    #  SHOW DATAFRAME & GRAPHS
    # -------------------------------
    def show_dataframe(self, empty_init=False):
        if not self.data_window or not self.data_window.winfo_exists():
            self.data_window = DataFrameWindow(self.root, [] if empty_init else self.processor.pcap_data)
            self.data_window.state("zoomed")
        else:
            self.data_window.update_data(self.processor.pcap_data)
            self.data_window.focus()

    def show_graphs(self):
        if not self.processor.pcap_data:
            messagebox.showwarning("No Data", "No PCAP files loaded.")
            return

        if not self.graph_window or not self.graph_window.winfo_exists():
            self.graph_window = Graph(self.root, self.processor.pcap_data)
            self.graph_window.state("zoomed")
        else:
            self.graph_window.focus()

