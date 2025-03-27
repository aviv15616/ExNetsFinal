import colorsys
import tkinter as tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import TABLEAU_COLORS

# Define the Graph class, which is a Tkinter Toplevel window that displays various plots
class Graph(tk.Toplevel):
    def __init__(self, master, data):
        """
        Initialize the Graph window.
        :param master: Parent Tkinter widget.
        :param data: List of dictionaries containing PCAP data.
        """
        super().__init__(master)  # Initialize the Toplevel window with the parent master
        self.title("PCAP Graphs")  # Set the window title
        self.geometry("1000x800")  # Set the window size (width x height)
        self.checkbox_widgets = {}  # Dictionary to store checkbox widgets for visibility control
        self.checkbox_frame = None  # Frame to hold checkboxes; initially not created

        # Define a color map for known categories (e.g., YouTube, Zoom, etc.)
        self.color_map = {
            "youtube": "#d62728",  # 🔴 Red
            "zoom": "#1f77b4",     # 🔵 Blue
            "chrome": "#bcbd22",   # 🟡 Yellow
            "firefox": "#ff7f0e",  # 🟠 Orange
            "spotify": "#2ca02c",  # 🟢 Green
            "edge": "#e377c2",     # 💗 Pink
            "default": "#BDBDBD"   # Neutral gray for unknown categories
        }

        self.data = data  # Store the PCAP data passed to the class
        self.canvas = None  # Canvas for embedding plots; initially not created

        # Create a frame to hold control buttons
        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)  # Add vertical padding

        # Create two rows for buttons within the button frame
        button_frame_row1 = tk.Frame(button_frame)
        button_frame_row1.pack()  # First row of buttons
        button_frame_row2 = tk.Frame(button_frame)
        button_frame_row2.pack()  # Second row of buttons

        # List of primary buttons with their labels and corresponding functions
        buttons = [
            ("Avg Packet Size", self.plot_avg_packet_size),
            ("Avg IAT", self.plot_avg_iat),
            ("Flow Volume Per Sec", self.plot_bytes_per_second),
            ("Flow Size vs. Volume", self.plot_flow_size_vs_volume),
            ("Flow Size Per PCAP", self.plot_flow_size_over_pcap),
            ("Flow Volume Per PCAP", self.plot_flow_volume_over_pcap),
        ]

        # List of extra buttons for additional plots
        extra_buttons = [
            ("Flow Direction", self.plot_flow_dir),
            ("IP Protocols Distribution", self.plot_ip_protocols),
            ("TCP Flags Distribution", self.plot_tcp_flags),
            ("HTTP Distribution", self.plot_http_distribution),
            # Replaced old references with new "CV IAT" & "Unique Flows"
            ("CV IAT", self.plot_cv_iat),
            ("Unique Flows", self.plot_unique_flows),
        ]
        # Create and pack primary buttons into the first row
        for text, command in buttons:
            tk.Button(button_frame_row1, text=text, command=command).pack(side=tk.LEFT, padx=5)

        # Create and pack extra buttons into the second row
        for text, command in extra_buttons:
            tk.Button(button_frame_row2, text=text, command=command).pack(side=tk.LEFT, padx=5)

        # Create a frame that will hold the graph (Matplotlib figure)
        self.graph_frame = tk.Frame(self)
        self.graph_frame.pack(expand=True, fill=tk.BOTH)

    # ==============================
    # Existing Plot Functions
    # ==============================

    def plot_tcp_flags(self):
        """Displays TCP flag distribution by calling a generic category plot function."""
        self.plot_category_graph("Tcp Flags", "TCP Flags Distribution")

    def plot_avg_packet_size(self):
        """Plots a bar chart of average packet size for each PCAP file."""
        self.plot_bar_chart(
            [entry["Pcap file"] for entry in self.data],  # X-axis: PCAP file names
            [entry.get("Avg Packet size (bytes)", 0) for entry in self.data],  # Y-axis: Average packet size values
            "Average Packet Size (bytes)",  # Y-axis label
            "Average Packet Size"  # Chart title
        )

    def plot_avg_iat(self):
        """Plots a bar chart of average inter-arrival time (IAT) for each PCAP file."""
        self.plot_bar_chart(
            [entry["Pcap file"] for entry in self.data],
            [entry.get("Avg Packet IAT (seconds)", 0) for entry in self.data],
            "Average Inter-Arrival Time (seconds)",
            "Average IAT"
        )


    def plot_flow_size_vs_volume(self):
        """Scatter plot of flow size vs. flow volume with a draggable legend."""
        # Destroy existing checkbox frame if it exists
        if hasattr(self, "checkbox_frame") and self.checkbox_frame:
            self.checkbox_frame.destroy()
            self.checkbox_frame = None

        # Create a new figure and axis for the scatter plot
        fig, ax = plt.subplots(figsize=(10, 6))

        # Extract flow sizes, flow volumes, and PCAP file labels from the data
        flow_sizes = [entry.get("Flow size", 0) for entry in self.data]
        flow_volumes = [entry.get("Flow Volume (bytes)", 0) for entry in self.data]
        labels = [entry["Pcap file"] for entry in self.data]

        # Determine a color for each PCAP file based on predefined rules in self.color_map
        pcap_colors = {}
        for pcap in set(labels):
            point_color = "gray"  # Default color if no match found
            for key in self.color_map:
                if key in pcap.lower():
                    point_color = self.color_map[key]
                    break
            pcap_colors[pcap] = point_color

        scatter_points = []  # List to store scatter plot points
        # Plot each data point with the assigned color and black edge
        for size, volume, pcap_file in zip(flow_sizes, flow_volumes, labels):
            point = ax.scatter(size, volume, color=pcap_colors[pcap_file],
                               edgecolors='black', alpha=0.7, label=pcap_file)
            scatter_points.append(point)

        # Set axis labels and title
        ax.set_xlabel("Flow Size (Packets)")
        ax.set_ylabel("Flow Volume (Bytes)")
        ax.set_title("Flow Size vs. Flow Volume")

        # Add a draggable legend to the plot
        legend = ax.legend(loc="upper right", frameon=True)
        legend.set_draggable(True)

        # Display the plot in the Tkinter window
        self.display_graph(fig)

    def plot_flow_size_over_pcap(self):
        """Displays a bar chart of the flow size per PCAP file."""
        self.plot_bar_chart(
            [entry["Pcap file"] for entry in self.data],
            [entry.get("Flow size", 0) for entry in self.data],
            "Flow Size (Packets)",
            "Flow Size Over PCAP"
        )

    def plot_flow_volume_over_pcap(self):
        """Displays a bar chart of the flow volume per PCAP file."""
        self.plot_bar_chart(
            [entry["Pcap file"] for entry in self.data],
            [entry.get("Flow Volume (bytes)", 0) for entry in self.data],
            "Flow Volume (Bytes)",
            "Flow Volume Over PCAP"
        )

    def plot_ip_protocols(self):
        """Displays a bar chart of IP protocol distribution across PCAP files."""
        self.plot_category_graph("Ip protocols", "IP Protocols Distribution")

    def plot_flow_dir(self):
        """
        Plots the number of forward vs backward packets per PCAP file.
        Includes Tkinter check buttons below for toggling visibility.
        """
        # Destroy existing canvas if present
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        # Create a new figure and axis for the bar chart
        fig, ax = plt.subplots(figsize=(10, 6))

        forward_counts = []  # List to store forward packet counts
        backward_counts = []  # List to store backward packet counts
        pcap_files = []  # List to store PCAP file names

        # Loop through the data and extract flow counts
        for entry in self.data:
            pcap_file = entry["Pcap file"]
            flows = entry.get("Flows", {})

            if not flows:
                continue  # Skip if no flow data available

            # Sum up forward and backward packet counts for each PCAP
            total_forward = sum(flow["forward"] for flow in flows.values())
            total_backward = sum(flow["backward"] for flow in flows.values())

            pcap_files.append(pcap_file)
            forward_counts.append(total_forward)
            backward_counts.append(total_backward)

        # If no PCAP files have flow data, display a message on the plot
        if not pcap_files:
            ax.text(0.5, 0.5, "No Flow Data Available", fontsize=12,
                    ha='center', va='center')
            ax.set_xticks([])
            ax.set_yticks([])
            bars_forward = []
            bars_backward = []
        else:
            # Create grouped bar charts for forward and backward counts
            x = np.arange(len(pcap_files))
            width = 0.3
            bars_forward = ax.bar(x - width / 2, forward_counts, width=width,
                                  label="Forward Packets", color="royalblue", edgecolor="black")
            bars_backward = ax.bar(x + width / 2, backward_counts, width=width,
                                   label="Backward Packets", color="tomato", edgecolor="black")

            ax.set_xticks(x)
            ax.set_xticklabels(pcap_files, rotation=45, ha="right")
            ax.set_xlabel("PCAP Files")
            ax.set_ylabel("Packet Count")
            ax.set_title("Forward vs Backward Packets per PCAP")

            # Add a draggable legend and grid for better readability
            legend = ax.legend(loc="upper right", frameon=True)
            legend.set_draggable(True)
            ax.grid(axis="y", linestyle="--", alpha=0.7)

        # Display the graph in the Tkinter frame
        self.display_graph(fig)

        # Store references to the bars for later toggling
        self.bar_references = {
            "Forward": bars_forward,
            "Backward": bars_backward,
        }

        def toggle_visibility(_=None):
            """Toggle visibility of forward/backward bars and individual PCAP bars."""
            forward_visible = self.check_vars["Forward"].get()
            backward_visible = self.check_vars["Backward"].get()

            # Set visibility for overall forward and backward bars
            for bar in bars_forward:
                bar.set_visible(forward_visible)
            for bar in bars_backward:
                bar.set_visible(backward_visible)

            # Set visibility for individual PCAP bars based on checkboxes
            for pcap, var in self.check_vars.items():
                if pcap in pcap_files:
                    index = pcap_files.index(pcap)
                    bars_forward[index].set_visible(var.get() and forward_visible)
                    bars_backward[index].set_visible(var.get() and backward_visible)

            fig.canvas.draw_idle()  # Redraw the figure to update changes

        # Create control frame with checkboxes to toggle bar visibility
        self.create_control_frame(
            title="Flow Direction Controls",
            check_options=["Forward", "Backward"] + pcap_files,
            check_callback=toggle_visibility
        )
        toggle_visibility()  # Initialize the visibility settings

    def plot_http_distribution(self):
        """Displays HTTP distribution by calling a generic category plot function."""
        self.plot_category_graph("Http Count", "HTTP Distribution")

    def plot_bytes_per_second(self):
        """
        Plots bytes transferred per second over time for each PCAP file.
        Uses unique colors for each line and provides checkboxes to toggle visibility.
        """
        # Destroy existing canvas if present
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
        # Destroy existing checkbox frame if present
        if hasattr(self, "checkbox_frame") and self.checkbox_frame is not None:
            self.checkbox_frame.destroy()

        # Create a new figure and axis for the time series plot
        fig, ax = plt.subplots(figsize=(12, 6))
        bytes_per_second_per_pcap = {}  # Dictionary to hold time bins and byte counts
        pcap_lines = {}  # Dictionary to hold plot line references for each PCAP

        # Get a sorted list of unique PCAP files
        unique_pcaps = sorted(set(entry["Pcap file"] for entry in self.data))
        # Create a distinct color map for these PCAP files
        color_map = get_distinct_color_map(unique_pcaps)

        # Loop through data entries to calculate bytes per second
        for entry in self.data:
            pcap_file = entry["Pcap file"]
            timestamps = entry.get("Packet Timestamps", [])
            packet_sizes = entry.get("Packet Sizes", [])

            if not timestamps or not packet_sizes:
                continue  # Skip if no timestamp or packet size data

            start_time = min(timestamps)
            # Calculate relative times with respect to the start time
            relative_times = [t - start_time for t in timestamps]
            # Create bins for each second
            bins = np.arange(0, max(relative_times) + 1, 1)
            # Sum packet sizes in each time bin
            byte_counts, _ = np.histogram(relative_times, bins=bins, weights=packet_sizes)
            # Store the bins and corresponding byte counts
            bytes_per_second_per_pcap[pcap_file] = (bins[:-1], byte_counts)

        # Plot each PCAP's bytes per second as a line plot
        for i, (pcap_file, (time_bins, byte_counts)) in enumerate(bytes_per_second_per_pcap.items()):
            line_color = color_map.get(pcap_file, "gray")
            line, = ax.plot(time_bins, byte_counts, marker='o', linestyle='-',
                            label=pcap_file, color=line_color)
            pcap_lines[pcap_file] = line

        ax.set_xlabel("Time (seconds)")
        ax.set_ylabel("Bytes Transferred Per Second")
        ax.set_title("Bytes Transferred Per Second Over Time for Each PCAP")
        ax.grid(True)

        # Add a draggable legend to the plot
        legend = ax.legend(loc="upper right", frameon=True)
        legend.set_draggable(True)

        # Display the plot
        self.display_graph(fig)

        # Create a frame for checkboxes to toggle line visibility
        self.checkbox_frame = tk.Frame(self.graph_frame, bg="white", relief=tk.RIDGE, bd=2)
        self.checkbox_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        # Label for the checkbox frame
        tk.Label(self.checkbox_frame, text="Toggle Visibility:", bg="white",
                 font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)

        self.pcap_visibility = {}  # Dictionary to store BooleanVars for each PCAP

        def toggle_visibility():
            """Toggle visibility of each PCAP line on the plot."""
            for pcap, var in self.pcap_visibility.items():
                pcap_lines[pcap].set_visible(var.get())
            fig.canvas.draw_idle()  # Redraw the figure

        # Create a checkbox for each PCAP file
        for label in pcap_lines.keys():
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(self.checkbox_frame, text=label, variable=var,
                                command=toggle_visibility, bg="white")
            cb.pack(side=tk.LEFT, padx=5)
            self.pcap_visibility[label] = var

    # =====================================
    # NEW FUNCTIONS FOR UNIQUE FLOWS & CV IAT
    # =====================================
    def plot_unique_flows(self):
        """Plots the number of unique flows per PCAP file using a bar chart."""
        pcap_files = [entry["Pcap file"] for entry in self.data]
        unique_flows_counts = [entry.get("Unique Flows", 0) for entry in self.data]  # Extract unique flow counts

        # If there is no unique flow data, display a message instead of plotting
        if not any(unique_flows_counts):
            self.display_no_data_message("No Unique Flow Data Available", "Unique Flows per PCAP")
            return

        # Plot a bar chart for unique flows per PCAP
        self.plot_bar_chart(
            x_labels=pcap_files,
            values=unique_flows_counts,
            ylabel="Unique Flows",
            title="Unique Flows per PCAP"
        )

    def plot_cv_iat(self):
        """Plots the Coefficient of Variation (CV IAT) per PCAP file using a bar chart."""
        pcap_files = [entry["Pcap file"] for entry in self.data]
        cv_iat_values = [entry.get("CV IAT", 0) for entry in self.data]  # Extract CV IAT values

        # If there is no CV IAT data, display a no-data message
        if not any(cv_iat_values):
            self.display_no_data_message("No CV IAT Data Available", "CV IAT per PCAP")
            return

        # Plot a bar chart for CV IAT per PCAP
        self.plot_bar_chart(
            x_labels=pcap_files,
            values=cv_iat_values,
            ylabel="Coefficient of Variation (IAT)",
            title="CV IAT per PCAP"
        )

    # =====================================
    # HELPER FUNCTIONS
    # =====================================
    def display_no_data_message(self, message, title):
        """
        Displays a message indicating that no data is available for the requested plot.
        :param message: Message text to display.
        :param title: Title of the plot.
        """
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, message, fontsize=12, ha='center', va='center')  # Centered text message
        ax.set_xticks([])  # Remove x-axis ticks
        ax.set_yticks([])  # Remove y-axis ticks
        ax.set_title(title)
        self.display_graph(fig)

    def add_draggable_legend(self, ax, pcap_colors=None, unique_pcaps=None):
        """
        Adds a draggable legend to the given axis.
        :param ax: Matplotlib axis.
        :param pcap_colors: (Optional) Dictionary mapping PCAP names to colors.
        :param unique_pcaps: (Optional) List of unique PCAP names.
        """
        if pcap_colors and unique_pcaps:
            # Create custom legend handles if color mapping is provided
            legend_patches = [plt.Line2D([0], [0], color=pcap_colors[pcap], lw=4, label=pcap)
                              for pcap in unique_pcaps]
            legend = ax.legend(handles=legend_patches, title="PCAP Files",
                               loc="upper right", frameon=True)
        else:
            legend = ax.legend(loc="upper right", frameon=True)
        legend.set_draggable(True)  # Make the legend draggable

    def plot_bar_chart(self, x_labels, values, ylabel, title):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
        if hasattr(self, "checkbox_frame") and self.checkbox_frame:
            self.checkbox_frame.destroy()
            self.checkbox_frame = None

        fig, ax = plt.subplots(figsize=(8, 5))
        # Create a bar for each x_label with a label
        bars = []
        for pcap, val in zip(x_labels, values):
            bar = ax.bar(pcap, val, color=self.get_pcap_color(pcap), edgecolor='black', label=pcap)
            bars.append(bar)

        ax.set_xlabel("PCAP File")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.tick_params(axis='x', rotation=45)  # Rotate x-axis labels for better readability

        # Pass labels and colors to add_draggable_legend
        self.add_draggable_legend(ax, pcap_colors={pcap: self.get_pcap_color(pcap) for pcap in x_labels},
                                  unique_pcaps=x_labels)
        self.display_graph(fig)

        # Create a checkbox frame below the graph for toggling visibility by type
        self.checkbox_frame = tk.Frame(self.graph_frame, bg="white", relief=tk.RIDGE, bd=2)
        self.checkbox_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        tk.Label(self.checkbox_frame, text="Toggle Visibility by Type:", bg="white",
                 font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)

        def get_label_group(pcap_name):
            """
            Determines the label group for a given PCAP file based on its name.
            :param pcap_name: Name of the PCAP file.
            :return: A string representing the group (e.g., 'youtube', 'chrome', etc.).
            """
            pcap_name = pcap_name.lower()
            if "youtube" in pcap_name:
                return "youtube"
            if "spotify" in pcap_name:
                return "spotify"
            if "firefox" in pcap_name:
                return "firefox"
            if "chrome" in pcap_name:
                return "chrome"
            if "edge" in pcap_name:
                return "edge"
            if "zoom" in pcap_name:
                return "zoom"
            return "default"

        grouped_bars = {}  # Dictionary to group bars by label group
        for pcap, bar in zip(x_labels, bars):
            label_group = get_label_group(pcap)
            if label_group not in grouped_bars:
                grouped_bars[label_group] = []
            grouped_bars[label_group].append(bar)

        self.label_visibility = {}  # Dictionary to store visibility BooleanVars for each label group

        def toggle_visibility():
            """Toggle visibility of bars based on label checkboxes."""
            for label_group, bars_list in grouped_bars.items():
                visible = self.label_visibility[label_group].get()
                for bar in bars_list:
                    bar.set_visible(visible)
            fig.canvas.draw_idle()  # Redraw the figure

        # Create a checkbox for each label group
        for label_group in grouped_bars.keys():
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(self.checkbox_frame, text=label_group.capitalize(), variable=var,
                                command=toggle_visibility, bg="white")
            cb.pack(side=tk.LEFT, padx=5)
            self.label_visibility[label_group] = var

    def plot_category_graph(self, column_name, ylabel):
        """
        Generalized function to plot a category-based bar chart.
        Parses category data from a specific column in each data entry.
        :param column_name: The key in the data entry containing category data.
        :param ylabel: Y-axis label for the chart.
        """
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
        if hasattr(self, "checkbox_frame") and self.checkbox_frame:
            self.checkbox_frame.destroy()
            self.checkbox_frame = None

        fig, ax = plt.subplots(figsize=(12, 6))
        category_per_pcap = {}  # Dictionary to store category counts per PCAP file

        # Build category counts for each PCAP file from the specified column
        for entry in self.data:
            pcap_file = entry["Pcap file"]
            category_per_pcap.setdefault(pcap_file, Counter())
            for item in entry[column_name].split():
                if '-' in item:
                    key, value = item.split('-')
                    category_per_pcap[pcap_file][key] += int(value)

        # Determine the set of all categories and sort PCAP files
        categories = sorted(set(cat for pcap in category_per_pcap.values() for cat in pcap))
        unique_pcaps = sorted(category_per_pcap.keys())
        # Get a distinct color map for the PCAP files
        color_map = get_distinct_color_map(unique_pcaps)
        num_categories = len(categories)
        num_pcaps = len(unique_pcaps)
        x = np.arange(num_categories)
        width = 0.8 / num_pcaps  # Width of each bar based on number of PCAPs

        bars_dict = {}  # Dictionary to store bar objects for each PCAP
        for i, (pcap_file, category_counts) in enumerate(category_per_pcap.items()):
            y = [category_counts.get(category, 0) for category in categories]
            bar_color = color_map.get(pcap_file, "gray")
            bars_dict[pcap_file] = ax.bar(
                x + (i - num_pcaps / 2) * width,
                y,
                width=width,
                label=pcap_file,
                color=bar_color,
                edgecolor='black'
            )

        ax.set_xticks(x)
        ax.set_xticklabels(categories, rotation=45, ha="right")
        ax.set_xlabel("Category")
        ax.set_ylabel(ylabel)
        ax.set_title(ylabel)

        legend = ax.legend(loc="upper right", frameon=True)
        legend.set_draggable(True)
        self.display_graph(fig)

        # Create a checkbox frame to toggle visibility by PCAP
        self.checkbox_frame = tk.Frame(self.graph_frame, bg="white", relief=tk.RIDGE, bd=2)
        self.checkbox_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        tk.Label(self.checkbox_frame, text="Toggle Visibility by PCAP:", bg="white",
                 font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)

        self.pcap_visibility = {}  # Dictionary to hold BooleanVars for each PCAP

        def toggle_visibility():
            """Toggle the visibility of bars based on PCAP checkboxes."""
            for pcap, bars in bars_dict.items():
                visible = self.pcap_visibility[pcap].get()
                for bar in bars:
                    bar.set_visible(visible)
            fig.canvas.draw_idle()

        # Create checkboxes for each PCAP
        for pcap in bars_dict.keys():
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(self.checkbox_frame, text=pcap, variable=var,
                                command=toggle_visibility, bg="white")
            cb.pack(side=tk.LEFT, padx=5)
            self.pcap_visibility[pcap] = var

    def display_graph(self, fig):
        """
        Embeds the provided Matplotlib figure into the Tkinter graph frame and renders it.
        :param fig: The Matplotlib figure to display.
        """
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
        plt.tight_layout()  # Adjust subplots to fit into the figure area.
        self.canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(expand=True, fill=tk.BOTH)
        self.canvas.draw()  # Render the canvas

    def create_control_frame(self, title, check_options=None, check_callback=None, radio_options=None,
                             radio_callback=None):
        """
        Creates a control frame with checkboxes and/or radio buttons below the graph.
        :param title: Title text for the control frame.
        :param check_options: List of options for checkboxes.
        :param check_callback: Callback function when a checkbox is toggled.
        :param radio_options: List of options for radio buttons.
        :param radio_callback: Callback function when a radio button is selected.
        """
        # Destroy any existing control frame
        if hasattr(self, "checkbox_frame") and self.checkbox_frame:
            self.checkbox_frame.destroy()

        self.checkbox_frame = tk.Frame(self.graph_frame, bg="white")
        self.checkbox_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

        tk.Label(self.checkbox_frame, text=title, font=("Arial", 10, "bold"), bg="white").pack()

        self.check_vars = {}  # Dictionary to store checkbox variables
        if not hasattr(self, "radio_var"):
            self.radio_var = tk.StringVar()

        control_wrapper = tk.Frame(self.checkbox_frame, bg="white")
        control_wrapper.pack(fill=tk.X)

        # Radio Button Section
        if radio_options:
            if not self.radio_var.get():
                self.radio_var.set(radio_options[0])
            radio_frame = tk.Frame(control_wrapper, bg="white")
            radio_frame.grid(row=0, column=0, sticky="w", padx=5)
            tk.Label(radio_frame, text="Select Option:", font=("Arial", 9, "bold"), bg="white")\
                .grid(row=0, column=0, sticky="w")
            max_columns = 5
            row, col = 1, 0
            for option in radio_options:
                rb = tk.Radiobutton(radio_frame, text=option, variable=self.radio_var, value=option,
                                    command=radio_callback, bg="white", anchor="w", wraplength=150)
                rb.grid(row=row, column=col, padx=5, pady=2, sticky="w")
                col += 1
                if col >= max_columns:
                    col = 0
                    row += 1

        # Checkbox Section
        if check_options:
            check_frame = tk.Frame(control_wrapper, bg="white")
            check_frame.grid(row=1, column=0, sticky="w", padx=5)
            tk.Label(check_frame, text="Toggle Visibility:", font=("Arial", 9, "bold"), bg="white")\
                .grid(row=0, column=0, sticky="w")
            max_columns = 5
            row, col = 1, 0
            for option in check_options:
                var = tk.BooleanVar(value=True)
                self.check_vars[option] = var
                cb = tk.Checkbutton(check_frame, text=option, variable=var,
                                    command=check_callback, bg="white", anchor="w", wraplength=150)
                cb.grid(row=row, column=col, padx=5, pady=2, sticky="w")
                col += 1
                if col >= max_columns:
                    col = 0
                    row += 1

    def get_pcap_color(self, pcap_file):
        """
        Returns the predefined color for a given PCAP file based on its name.
        :param pcap_file: The name of the PCAP file.
        :return: A hexadecimal color code as a string.
        """
        pcap_file = pcap_file.lower()
        if "youtube" in pcap_file:
            return self.color_map["youtube"]
        if "spotify" in pcap_file:
            return self.color_map["spotify"]
        if "chrome" in pcap_file:
            return self.color_map["chrome"]
        if "firefox" in pcap_file:
            return self.color_map["firefox"]
        if "edge" in pcap_file:
            return self.color_map["edge"]
        if "zoom" in pcap_file:
            return self.color_map["zoom"]
        return self.color_map["default"]

# Utility function to generate extra distinct colors using HSV color space
def generate_extra_colors(n):
    """
    Generate a list of n distinct colors using the HSV color model.
    :param n: Number of extra colors needed.
    :return: List of RGB tuples.
    """
    return [colorsys.hsv_to_rgb(i / n, 0.8, 0.9) for i in range(n)]

# Utility function to assign a distinct color to each unique PCAP file
def get_distinct_color_map(unique_pcaps):
    """
    Assigns distinct colors to each PCAP file.
    :param unique_pcaps: List of unique PCAP file names.
    :return: Dictionary mapping each PCAP file to a color.
    """
    tableau_colors = list(TABLEAU_COLORS.values())  # Use predefined Tableau colors
    num_pcaps = len(unique_pcaps)

    # If the number of PCAPs is less than or equal to the number of Tableau colors, use them directly.
    if num_pcaps <= len(tableau_colors):
        return {pcap: tableau_colors[i] for i, pcap in enumerate(unique_pcaps)}

    # Otherwise, generate additional colors
    extra_colors = generate_extra_colors(num_pcaps - len(tableau_colors))
    all_colors = tableau_colors + extra_colors

    return {pcap: all_colors[i] for i, pcap in enumerate(unique_pcaps)}
