import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd


class DataFrameWindow(tk.Toplevel):
    def __init__(self, master, data):
        super().__init__(master)
        self.title("PCAP DataFrame")
        self.geometry("1300x450")  # Increased width for better readability

        self.column_descriptions = {
            "Pcap file": "The name of the loaded PCAP file.",
            "Flow size": "Total number of packets in the flow.",
            "Flow Volume (bytes)": "Total size of packets in bytes.",
            "Flow duration (seconds)": "Total duration of the capture in seconds.",
            "Avg Packet size (bytes)": "Average packet size in bytes.",
            "Avg Packet IAT (seconds)": "Average inter-arrival time between packets.",
            "CV IAT": "Coefficient of Variation (Std dev / Avg) of Inter-Arrival Times.",
            "Unique Flows": "Count of unique flows (based on Src IP, Dst IP, Src port, Dst port).",
            "Flow Directionality Ratio": "Ratio of forward to backward packet count in the PCAP.",
            "Http Count": "Number of HTTP packets categorized by version.",
            "Tcp Flags": "Count of TCP flags (SYN, ACK, RST, PSH, FIN).",
            "Ip protocols": "Count of different IP protocols used in packets.",
        }

        self.tree = ttk.Treeview(self, columns=list(self.column_descriptions.keys()), show='headings')

        self.tree = ttk.Treeview(self, columns=list(self.column_descriptions.keys()), show='headings')
        self.sort_order = {}  # Track sorting order for each column

        for col in self.column_descriptions.keys():
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c))
            self.tree.column(col, width=120, anchor="center")

        self.tree.pack(expand=True, fill="both")

        self.tooltip = None  # Ensure only one tooltip is created at a time

        self.tree.bind("<Motion>", self.on_hover)
        self.tree.bind("<Leave>", self.hide_tooltip)

        self.export_button = tk.Button(self, text="Export to CSV", command=self.export_to_csv)
        self.export_button.pack(pady=10)

        self.data = data  # Store data internally for sorting
        self.update_data(data)

    def update_data(self, data):
        self.data = data  # Store updated data
        # Clear existing data
        for row in self.tree.get_children():
            self.tree.delete(row)

        # Insert new data
        for entry in data:
            self.tree.insert("", "end", values=[entry.get(col, "") for col in self.tree['columns']])

    def show_tooltip(self, column, event):
        if self.tooltip:
            self.tooltip.destroy()  # Destroy old tooltip before creating a new one

        text = self.column_descriptions.get(column, f"No description available for {column}")
        self.tooltip = tk.Label(self, text=text, bg="lightyellow", bd=1, relief="solid", padx=5, pady=2)

        x_offset = self.winfo_pointerx() - self.winfo_rootx() + 10
        y_offset = self.winfo_pointery() - self.winfo_rooty() + 15

        # Ensure tooltip does not go off-screen
        self.update_idletasks()  # Update window dimensions
        screen_width = self.winfo_width()
        tooltip_width = self.tooltip.winfo_reqwidth()  # Get actual width of tooltip

        # If tooltip exceeds the right boundary, adjust its position
        if x_offset + tooltip_width > screen_width:
            x_offset = screen_width - tooltip_width - 10  # Offset to keep it inside the window

        self.tooltip.place(x=x_offset, y=y_offset)

    def on_hover(self, event):
        item = self.tree.identify_column(event.x)
        col_index = int(item[1:]) - 1 if item.startswith("#") else None
        if col_index is not None and col_index < len(self.column_descriptions):
            column = list(self.column_descriptions.keys())[col_index]
            self.show_tooltip(column, event)
        else:
            self.hide_tooltip()

    def hide_tooltip(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

    def sort_column(self, col):
        reverse = self.sort_order.get(col, False)
        try:
            if col in ["CV_IAT", "CV_PS", "TCP %", "UDP %"]:
                self.data.sort(key=lambda x: float(x[col].replace('%', '')) if isinstance(x[col], str) else 0, reverse=reverse)
            else:
                self.data.sort(
                    key=lambda x: float(x[col].split()[0]) if isinstance(x[col], str) and x[col].split()[0].isdigit()
                    else x[col], reverse=reverse
                )
        except Exception:
            self.data.sort(key=lambda x: x[col], reverse=reverse)

        self.sort_order[col] = not reverse  # Toggle sorting order
        self.update_data(self.data)

    def export_to_csv(self):
        if not self.data:
            return

        # Extract only the data currently visible in the Treeview (this is the sorted/filtered data)
        displayed_data = [self.tree.item(item)["values"] for item in self.tree.get_children()]

        # Check if the displayed data is not empty
        if not displayed_data:
            messagebox.showwarning("No Data", "There is no data to export.")
            return

        # Create DataFrame from the displayed data
        df = pd.DataFrame(displayed_data, columns=self.tree['columns'])

        # Prompt the user to save the CSV file
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if file_path:
            df.to_csv(file_path, index=False)
            messagebox.showinfo("Export Successful", f"Data exported to {file_path}")
