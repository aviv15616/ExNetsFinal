import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd

class DataFrameWindow(tk.Toplevel):
    """
    A Tkinter-based GUI window to display and interact with a DataFrame.
    Allows sorting, tooltips for column descriptions, and exporting data to CSV.
    """
    def __init__(self, master, data):
        super().__init__(master)
        self.title("PCAP DataFrame")
        self.geometry("1300x450")

        # Dictionary containing descriptions for each column
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

        # Creating Treeview widget for tabular data display
        self.tree = ttk.Treeview(self, columns=list(self.column_descriptions.keys()), show='headings')
        self.sort_order = {}  # Dictionary to track sorting order of columns

        # Setting up column headings with sorting functionality
        for col in self.column_descriptions.keys():
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c))
            self.tree.column(col, width=120, anchor="center")

        self.tree.pack(expand=True, fill="both")

        self.tooltip = None  # Tooltip label to show column descriptions

        # Binding events for hover tooltips
        self.tree.bind("<Motion>", self.on_hover)
        self.tree.bind("<Leave>", self.hide_tooltip)

        # Button to export data to CSV file
        self.export_button = tk.Button(self, text="Export to CSV", command=self.export_to_csv)
        self.export_button.pack(pady=10)

        self.data = data  # Storing data reference
        self.update_data(data)  # Populating initial data

    def update_data(self, data):
        """
        Updates the displayed data in the Treeview.
        """
        self.data = data  # Update internal data reference

        # Clear existing entries in Treeview
        for row in self.tree.get_children():
            self.tree.delete(row)

        # Insert new data entries
        for entry in data:
            self.tree.insert("", "end", values=[entry.get(col, "") for col in self.tree['columns']])

    def show_tooltip(self, column, event):
        """
        Displays a tooltip with the column description when hovering over a column.
        """
        if self.tooltip:
            self.tooltip.destroy()

        # Get description text or fallback message
        text = self.column_descriptions.get(column, f"No description available for {column}")
        self.tooltip = tk.Label(self, text=text, bg="lightyellow", bd=1, relief="solid", padx=5, pady=2)

        # Calculate tooltip position
        x_offset = self.winfo_pointerx() - self.winfo_rootx() + 10
        y_offset = self.winfo_pointery() - self.winfo_rooty() + 15

        # Adjust position if tooltip overflows screen width
        self.update_idletasks()
        screen_width = self.winfo_width()
        tooltip_width = self.tooltip.winfo_reqwidth()
        if x_offset + tooltip_width > screen_width:
            x_offset = screen_width - tooltip_width - 10

        self.tooltip.place(x=x_offset, y=y_offset)

    def on_hover(self, event):
        """
        Handles mouse hover event to show tooltips for column descriptions.
        """
        item = self.tree.identify_column(event.x)
        col_index = int(item[1:]) - 1 if item.startswith("#") else None
        if col_index is not None and col_index < len(self.column_descriptions):
            column = list(self.column_descriptions.keys())[col_index]
            self.show_tooltip(column, event)
        else:
            self.hide_tooltip()

    def hide_tooltip(self, event=None):
        """
        Hides tooltip when mouse moves away.
        """
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

    def sort_column(self, col):
        """
        Sorts the data in the Treeview by the selected column.
        """
        reverse = self.sort_order.get(col, False)  # Get current sorting order
        try:
            if col in ["CV_IAT", "CV_PS", "TCP %", "UDP %"]:
                # Convert percentage values to float for sorting
                self.data.sort(key=lambda x: float(x[col].replace('%', '')) if isinstance(x[col], str) else 0, reverse=reverse)
            else:
                # Convert numeric values and sort, otherwise sort as string
                self.data.sort(
                    key=lambda x: float(x[col].split()[0]) if isinstance(x[col], str) and x[col].split()[0].isdigit()
                    else x[col], reverse=reverse
                )
        except Exception:
            self.data.sort(key=lambda x: x[col], reverse=reverse)  # Fallback to default sorting

        self.sort_order[col] = not reverse  # Toggle sorting order
        self.update_data(self.data)  # Refresh displayed data

    def export_to_csv(self):
        """
        Exports the currently displayed data to a CSV file.
        """
        if not self.data:
            return

        # Extract displayed data from Treeview
        displayed_data = [self.tree.item(item)["values"] for item in self.tree.get_children()]

        if not displayed_data:
            messagebox.showwarning("No Data", "There is no data to export.")
            return

        # Create DataFrame from displayed data
        df = pd.DataFrame(displayed_data, columns=self.tree['columns'])

        # Open file dialog for saving CSV
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if file_path:
            df.to_csv(file_path, index=False)
            messagebox.showinfo("Export Successful", f"Data exported to {file_path}")
