# Import necessary modules for GUI, file operations, threading, plotting, and ML predictions.
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, Label  # Submodules for file dialogs, message boxes, tree views, and labels
import os
import threading
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from data_frame import DataFrameWindow
from pcap_processor import PcapProcessor
from graph import Graph

# Import prediction functions for two different ML models (with and without flow data)
from src.rfc_ml_models.no_flow.rtc_model_no_flow import predict_traffic as predict_no_flow  # Prediction without flow data
from src.rfc_ml_models.with_flow.rfc_model_with_flow import predict_traffic as predict_with_flow  # Prediction with flow data

# Define the main GUI class for the PCAP Analyzer application
class PcapGUI:
    def __init__(self, root):
        """
        Initialize the main PCAP Analyzer GUI.
        :param root: The root Tkinter window.
        """
        self.root = root  # Save the root window reference
        self.root.title("PCAP Analyzer")  # Set the title of the window
        self.root.geometry("400x450")  # Set the dimensions of the window

        # Initialize the PCAP processor instance with sample_mode disabled
        self.processor = PcapProcessor(sample_mode=False)
        self.data_window = None  # Placeholder for the data frame window
        self.graph_window = None  # Placeholder for the graph window

        # -------------------------------
        #  Main Buttons Setup
        # -------------------------------
        # Create a button to load PCAP files and bind it to load_pcaps method
        self.load_button = tk.Button(root, text="Load PCAPs", command=self.load_pcaps)
        self.load_button.pack(pady=10)  # Pack the button with vertical padding

        # Create a button to show the data frame of processed PCAP data and bind to show_dataframe method
        self.show_button = tk.Button(root, text="Show DataFrame", command=self.show_dataframe)
        self.show_button.pack(pady=10)

        # Create a button to display graphs from the processed data and bind to show_graphs method
        self.graph_button = tk.Button(root, text="Show Graphs", command=self.show_graphs)
        self.graph_button.pack(pady=10)

        # Create separate buttons for each prediction model type
        # Button for prediction without flow data
        self.predict_no_flow_button = tk.Button(root, text="Predict without Flow", command=self.predict_pcaps_no_flow)
        self.predict_no_flow_button.pack(pady=10)

        # Button for prediction with flow data
        self.predict_with_flow_button = tk.Button(root, text="Predict with Flow", command=self.predict_pcaps_with_flow)
        self.predict_with_flow_button.pack(pady=10)

    # -------------------------------
    #  PCAP LOADING METHODS
    # -------------------------------
    def load_pcaps(self):
        """
        Opens a file dialog to select PCAP files and processes them in a separate thread.
        """
        # Open file dialog to select PCAP files; supports .pcap and .pcapng extensions.
        files = filedialog.askopenfilenames(
            filetypes=[
                ("PCAP Files", "*.pcap"),
                ("PCAPNG Files", "*.pcapng"),
                ("All Files", "*.*")  # Ensure visibility across OS
            ],
            title="Select PCAP files"
        )
        # If any files are selected, process them in a background thread.
        if files:
            threading.Thread(target=self.process_pcaps_thread, args=(files,), daemon=True).start()

    def process_pcaps_thread(self, files):
        """
        Processes multiple PCAP files in a separate thread and updates the UI dynamically.
        :param files: List of selected PCAP file paths.
        """
        total_files = len(files)  # Total number of files to process
        processed_files = 0  # Counter for files processed so far
        successfully_uploaded = 0  # Counter for successfully processed files

        # Iterate through each selected file
        for file in files:
            processed_files += 1  # Increment the counter for each file processed
            # Update the main window title to reflect processing progress using Tkinter's after method.
            self.root.after(
                0,
                lambda cnt=processed_files: self.root.title(f"Processing PCAPs ({cnt}/{total_files})")
            )

            # Process the current PCAP file using the processor instance.
            success = self.processor.process_pcap(file)
            if success:
                successfully_uploaded += 1  # Increment if file processed successfully

            # If the data window is open, update its displayed data with the latest processed data.
            if self.data_window:
                self.root.after(0, lambda: self.data_window.update_data(self.processor.pcap_data))

        # After processing all files, update the title to indicate completion.
        self.root.after(0, lambda: self.root.title("PCAP Processing - Complete"))

        # Inform the user of the processing result using a message box.
        if successfully_uploaded > 0:
            self.root.after(0, lambda: messagebox.showinfo("Success", "PCAPs loaded successfully!"))
        elif processed_files > 0 and successfully_uploaded == 0:
            self.root.after(0, lambda: messagebox.showinfo("No New Files", "No new PCAPs loaded."))

    # -------------------------------
    #  PREDICTION BUTTON HANDLERS
    # -------------------------------
    def predict_pcaps_no_flow(self):
        """Handle prediction using the no-flow model."""
        # Open a prediction window with the no-flow prediction function and corresponding model name.
        self.open_prediction_window(predict_no_flow, "PCAP Predictions (No Flow)")

    def predict_pcaps_with_flow(self):
        """Handle prediction using the with-flow model."""
        # Open a prediction window with the with-flow prediction function and corresponding model name.
        self.open_prediction_window(predict_with_flow, "PCAP Predictions (With Flow)")

    # -------------------------------
    #  PREDICTION PROCESS & RESULTS
    # -------------------------------
    def open_prediction_window(self, prediction_function, model_name):
        """
        Opens a new window for a prediction session.
        :param prediction_function: The function to call for making predictions.
        :param model_name: String indicating the model type ("No Flow" or "With Flow").
        """
        # Create a new top-level window for predictions.
        prediction_window = tk.Toplevel(self.root)
        prediction_window.title(model_name)  # Set the window title based on the model

        # Create a Treeview widget to list PCAP filenames and their predicted applications.
        tree = ttk.Treeview(prediction_window, columns=("PCAP File", "Predicted App"), show="headings")
        tree.heading("PCAP File", text="PCAP File")  # Define header for file column
        tree.heading("Predicted App", text="Predicted App")  # Define header for prediction column
        tree.column("PCAP File", width=150)  # Set width for file column
        tree.column("Predicted App", width=150)  # Set width for prediction column
        tree.pack(fill="both", expand=True)  # Pack the tree view to fill available space

        # Open a file dialog to select PCAP files for prediction using the chosen model.
        files = filedialog.askopenfilenames(
            filetypes=[
                ("PCAP Files", "*.pcap"),
                ("PCAPNG Files", "*.pcapng"),
                ("All Files", "*.*")  # Ensure visibility across OS
            ],
            title=f"Select PCAP files for {model_name}"
        )
        # If files are selected, start processing predictions in a new thread.
        if files:
            threading.Thread(
                target=self.process_predictions,
                args=(files, prediction_function, model_name, prediction_window, tree),
                daemon=True
            ).start()

    def process_predictions(self, files, prediction_function, model_name, prediction_window, tree):
        """
        Runs predictions on selected PCAP files using the provided prediction function and updates the UI.
        :param files: List of PCAP file paths.
        :param prediction_function: The prediction function to apply.
        :param model_name: Name of the model (used in window titles).
        :param prediction_window: The Tkinter window for displaying prediction progress.
        :param tree: The Treeview widget for showing prediction results.
        """
        total_files = len(files)  # Total number of files to predict
        correct_predictions = 0  # Counter for correct predictions
        y_true, y_pred = [], []  # Lists to store actual and predicted labels for evaluation

        # Process each file one by one
        for i, file in enumerate(files, start=1):
            # Update the prediction window title to reflect current progress.
            self.root.after(0, lambda idx=i: prediction_window.title(f"{model_name} ({idx}/{total_files})"))

            # Call the prediction function on the file (wrapped in a list).
            predictions = prediction_function([file])
            if predictions:
                # Retrieve the first prediction result; handle if result is nested in a list or tuple.
                predicted_label = predictions[0]
                if isinstance(predicted_label, (list, tuple)):
                    predicted_label = predicted_label[0]

                # Extract the actual label from the filename (e.g., "chrome_video1.pcap" -> "chrome")
                actual_label = self.extract_actual_label(file)
                if actual_label:
                    y_true.append(actual_label)  # Record actual label
                    y_pred.append(predicted_label)  # Record predicted label

                # Insert the filename (basename) and predicted label into the tree view.
                self.root.after(
                    0,
                    lambda f=file, p=predicted_label: tree.insert("", "end", values=(os.path.basename(f), p))
                )

                # If the prediction matches the actual label (ignoring case), count it as correct.
                if actual_label and actual_label.lower() == predicted_label.lower():
                    correct_predictions += 1
            else:
                # If no prediction is made, insert "Unknown" as the predicted label.
                self.root.after(
                    0,
                    lambda f=file: tree.insert("", "end", values=(os.path.basename(f), "Unknown"))
                )

        # Once all predictions are processed, update the window title to indicate completion.
        self.root.after(0, lambda: prediction_window.title(f"{model_name} - Complete"))
        # Calculate overall prediction accuracy.
        accuracy = (correct_predictions / total_files) * 100 if total_files > 0 else 0
        # Insert the accuracy metric as a row in the tree view.
        self.root.after(0, lambda: tree.insert("", "end", values=("Accuracy", f"{accuracy:.2f}%")))

        # After processing, display the confusion matrix in a new window.
        self.root.after(0, lambda: self.show_confusion_matrix(y_true, y_pred, list(set(y_true)), model_name))

        # Show a message box to inform the user that prediction is completed, including the accuracy.
        self.root.after(
            0,
            lambda: tk.messagebox.showinfo("Prediction Completed", f"Prediction ended!\nAccuracy: {accuracy:.2f}%")
        )

    # -------------------------------
    #  CONFUSION MATRIX & EXPLANATION
    # -------------------------------
    def show_confusion_matrix(self, y_true, y_pred, class_labels, model_name):
        """
        Displays a visual confusion matrix and an explanation in a new Tkinter window.
        :param y_true: List of actual labels.
        :param y_pred: List of predicted labels.
        :param class_labels: List of unique class labels.
        :param model_name: Name of the model (used in window title).
        """
        # Check if there is enough data to compute a confusion matrix.
        if not y_true or not y_pred:
            tk.messagebox.showwarning("Confusion Matrix", "Not enough data to generate a confusion matrix.")
            return

        # Compute the confusion matrix using sklearn.
        cm = confusion_matrix(y_true, y_pred, labels=class_labels)

        # Create a new top-level window for the confusion matrix display.
        cm_window = tk.Toplevel(self.root)
        cm_window.title(f"Confusion Matrix - {model_name}")

        # Create a Matplotlib figure and axis for the heatmap.
        fig, ax = plt.subplots(figsize=(6, 5))
        # Draw a heatmap using Seaborn with annotations for the confusion matrix.
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=class_labels, yticklabels=class_labels)
        ax.set_xlabel("Predicted Label")  # Label for x-axis
        ax.set_ylabel("True Label")  # Label for y-axis
        ax.set_title(f"Confusion Matrix - {model_name}")  # Title for the plot

        # Embed the Matplotlib figure into the Tkinter window.
        canvas = FigureCanvasTkAgg(fig, master=cm_window)
        canvas.draw()  # Render the plot
        canvas.get_tk_widget().pack()  # Pack the canvas widget

        # Generate an explanation of the confusion matrix analysis.
        explanation = self.analyze_confusion_matrix(cm, class_labels, model_name)

        # Display the generated explanation in the window using a Label widget.
        label = Label(cm_window, text=explanation, justify="left", wraplength=500, padx=10, pady=5)
        label.pack()

    def analyze_confusion_matrix(self, cm, class_labels, model_name):
        """
        Generates a textual explanation for the confusion matrix analysis.
        References specific applications (Chrome, Edge, YouTube, Spotify, Zoom) for detailed observations.
        :param cm: The confusion matrix array.
        :param class_labels: List of class labels.
        :param model_name: Name of the model.
        :return: A string containing the analysis explanation.
        """
        explanation = f"🔹 **Analysis of {model_name} Classification Performance:**\n\n"
        num_classes = len(class_labels)  # Determine the number of classes

        # Define a set of known app labels for custom analysis.
        known_apps = {"chrome", "edge", "youtube", "spotify", "zoom"}

        # Analyze performance for each actual class (row in the confusion matrix).
        for i, actual_label in enumerate(class_labels):
            total_actual = sum(cm[i, :])  # Total instances for this actual label
            correct = cm[i, i]  # Correctly predicted instances for this label
            if total_actual == 0:
                continue  # Skip if there are no instances

            accuracy = (correct / total_actual) * 100  # Calculate accuracy percentage for this label

            # Append observations based on accuracy thresholds.
            if accuracy == 100:
                explanation += f"✅ **{actual_label}** was perfectly classified ({int(correct)} correct).\n"
            elif accuracy >= 80:
                explanation += f"✅ **{actual_label}** had mostly correct classifications ({accuracy:.2f}%).\n"
            elif accuracy >= 50:
                explanation += f"⚠️ **{actual_label}** was only correct in {accuracy:.2f}% of cases.\n"
            else:
                explanation += f"❌ **{actual_label}** was frequently misclassified ({accuracy:.2f}% accuracy).\n"

            # Identify misclassifications for the current actual label.
            misclass_dict = {}
            for j, pred_label in enumerate(class_labels):
                if i != j and cm[i, j] > 0:
                    misclass_dict[pred_label] = cm[i, j]

            # If misclassifications exist, list them in the explanation.
            if misclass_dict:
                explanation += f"   - Misclassified as: "
                explanation += ", ".join([f"{pl} ({cnt} times)" for pl, cnt in misclass_dict.items()])
                explanation += "\n"

        # Provide additional specific observations for known applications.
        explanation += "\n🔹 **Key Observations for Browser/App Traffic (Chrome, Edge, YouTube, Spotify, Zoom):**\n"

        # Check for and note confusion between Chrome and Edge.
        if "chrome" in class_labels and "edge" in class_labels:
            i_chrome = class_labels.index("chrome")
            i_edge = class_labels.index("edge")
            chrome_confused_as_edge = cm[i_chrome, i_edge]
            edge_confused_as_chrome = cm[i_edge, i_chrome]
            if chrome_confused_as_edge > 0 or edge_confused_as_chrome > 0:
                explanation += "⚠️ Observed confusion between **Chrome** and **Edge**.\n"

        # Analyze YouTube classification accuracy.
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

        # Analyze Spotify classification accuracy.
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

        # Analyze Zoom classification accuracy.
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

        return explanation  # Return the detailed explanation text

    # -------------------------------
    #  ACTUAL LABEL EXTRACTION
    # -------------------------------
    def extract_actual_label(self, filename):
        """
        Extracts the actual traffic type from the filename, if applicable.
        Example: "chrome_video1.pcap" would return "chrome".
        :param filename: Full path of the PCAP file.
        :return: Extracted label as a string, or None if no match is found.
        """
        import re  # Import regex module for pattern matching
        # Use a regular expression to capture alphabetic characters from the start of the file's basename.
        match = re.match(r"([a-zA-Z]+)", os.path.basename(filename))
        # Return the matched group if found, otherwise return None.
        return match.group(1) if match else None

    # -------------------------------
    #  DATAFRAME & GRAPH DISPLAY
    # -------------------------------
    def show_dataframe(self, empty_init=False):
        """
        Opens or updates a DataFrame window to display processed PCAP data.
        :param empty_init: If True, initializes the window with an empty data list.
        """
        # If there is no existing data window or it has been closed, create a new one.
        if not self.data_window or not self.data_window.winfo_exists():
            self.data_window = DataFrameWindow(self.root, [] if empty_init else self.processor.pcap_data)
            self.data_window.state("normal")  # Maximize the window
        else:
            # If the window exists, update it with the current PCAP data and bring it to focus.
            self.data_window.update_data(self.processor.pcap_data)
            self.data_window.focus()

    def show_graphs(self):
        """
        Opens or brings into focus a window displaying graphs based on processed PCAP data.
        """
        # Check if any PCAP data has been loaded; if not, warn the user.
        if not self.processor.pcap_data:
            messagebox.showwarning("No Data", "No PCAP files loaded.")
            return

        # If the graph window doesn't exist or is closed, create a new one.
        if not self.graph_window or not self.graph_window.winfo_exists():
            self.graph_window = Graph(self.root, self.processor.pcap_data)
            self.graph_window.state("normal")  # Maximize the window
        else:
            # If the window exists, simply bring it into focus.
            self.graph_window.focus()
