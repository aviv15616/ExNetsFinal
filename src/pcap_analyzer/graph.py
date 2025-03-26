import colorsys
import tkinter as tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import TABLEAU_COLORS


class Graph(tk.Toplevel):
    def __init__(self, master, data):
        super().__init__(master)
        self.title("PCAP Graphs")
        self.geometry("1000x800")
        self.checkbox_widgets = {}
        self.checkbox_frame = None

        self.color_map = {
            "youtube": "#d62728",  # 🔴 Red
            "zoom": "#1f77b4",     # 🔵 Blue
            "chrome": "#bcbd22",   # 🟡 Yellow
            "firefox": "#ff7f0e",  # 🟠 Orange
            "spotify": "#2ca02c",  # 🟢 Green
            "edge": "#e377c2",     # 💗 Pink
            "default": "#BDBDBD"   # Neutral gray for unknown categories
        }

        self.data = data
        self.canvas = None

        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)

        button_frame_row1 = tk.Frame(button_frame)
        button_frame_row1.pack()

        button_frame_row2 = tk.Frame(button_frame)
        button_frame_row2.pack()

        buttons = [
            ("Avg Packet Size", self.plot_avg_packet_size),
            ("Avg IAT", self.plot_avg_iat),
            ("Flow Volume Per Sec", self.plot_bytes_per_second),
            ("Flow Size vs. Volume", self.plot_flow_size_vs_volume),
            ("Flow Size Per PCAP", self.plot_flow_size_over_pcap),
            ("Flow Volume Per PCAP", self.plot_flow_volume_over_pcap),
        ]

        extra_buttons = [
            ("Flow Direction", self.plot_flow_dir),
            ("IP Protocols Distribution", self.plot_ip_protocols),
            ("TCP Flags Distribution", self.plot_tcp_flags),
            ("HTTP Distribution", self.plot_http_distribution),
            # Replaced old references with new "CV IAT" & "Unique Flows"
            ("CV IAT", self.plot_cv_iat),
            ("Unique Flows", self.plot_unique_flows),
        ]
        # First row of buttons
        for text, command in buttons:
            tk.Button(button_frame_row1, text=text, command=command).pack(side=tk.LEFT, padx=5)

        # Second row of buttons (extra_buttons)
        for text, command in extra_buttons:
            tk.Button(button_frame_row2, text=text, command=command).pack(side=tk.LEFT, padx=5)

        self.graph_frame = tk.Frame(self)
        self.graph_frame.pack(expand=True, fill=tk.BOTH)

    # ==============================
    # Existing Plot Functions
    # ==============================

    def plot_tcp_flags(self):
        """ Displays TCP flag distribution. """
        self.plot_category_graph("Tcp Flags", "TCP Flags Distribution")

    def plot_avg_packet_size(self):
        self.plot_bar_chart(
            [entry["Pcap file"] for entry in self.data],
            [entry.get("Avg Packet size (bytes)", 0) for entry in self.data],
            "Average Packet Size (bytes)",
            "Average Packet Size"
        )

    def plot_avg_iat(self):
        self.plot_bar_chart(
            [entry["Pcap file"] for entry in self.data],
            [entry.get("Avg Packet IAT (seconds)", 0) for entry in self.data],
            "Average Inter-Arrival Time (seconds)",
            "Average IAT"
        )

    import numpy as np
    import matplotlib.pyplot as plt

    import numpy as np
    import matplotlib.pyplot as plt



    def plot_flow_size_vs_volume(self):
        """ Scatter plot of flow size vs. flow volume with a draggable legend. """
        if hasattr(self, "checkbox_frame") and self.checkbox_frame:
            self.checkbox_frame.destroy()
            self.checkbox_frame = None

        fig, ax = plt.subplots(figsize=(10, 6))

        flow_sizes = [entry.get("Flow size", 0) for entry in self.data]
        flow_volumes = [entry.get("Flow Volume (bytes)", 0) for entry in self.data]
        labels = [entry["Pcap file"] for entry in self.data]

        # Assign colors
        pcap_colors = {}
        for pcap in set(labels):
            point_color = "gray"  # Default color
            for key in self.color_map:
                if key in pcap.lower():
                    point_color = self.color_map[key]
                    break
            pcap_colors[pcap] = point_color

        scatter_points = []
        for size, volume, pcap_file in zip(flow_sizes, flow_volumes, labels):
            point = ax.scatter(size, volume, color=pcap_colors[pcap_file], edgecolors='black', alpha=0.7,
                               label=pcap_file)
            scatter_points.append(point)

        ax.set_xlabel("Flow Size (Packets)")
        ax.set_ylabel("Flow Volume (Bytes)")
        ax.set_title("Flow Size vs. Flow Volume")

        legend = ax.legend(loc="upper right", frameon=True)
        legend.set_draggable(True)

        self.display_graph(fig)

    def plot_flow_size_over_pcap(self):
        """ Displays the flow size per PCAP file. """
        self.plot_bar_chart(
            [entry["Pcap file"] for entry in self.data],
            [entry.get("Flow size", 0) for entry in self.data],
            "Flow Size (Packets)",
            "Flow Size Over PCAP"
        )

    def plot_flow_volume_over_pcap(self):
        self.plot_bar_chart(
            [entry["Pcap file"] for entry in self.data],
            [entry.get("Flow Volume (bytes)", 0) for entry in self.data],
            "Flow Volume (Bytes)",
            "Flow Volume Over PCAP"
        )

    def plot_ip_protocols(self):
        """ Displays IP protocol distribution across PCAP files. """
        self.plot_category_graph("Ip protocols", "IP Protocols Distribution")

    def plot_flow_dir(self):
        """Plots the number of forward vs backward packets per PCAP file with Tkinter check buttons below."""
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))

        forward_counts = []
        backward_counts = []
        pcap_files = []

        for entry in self.data:
            pcap_file = entry["Pcap file"]
            flows = entry.get("Flows", {})

            if not flows:
                continue

            total_forward = sum(flow["forward"] for flow in flows.values())
            total_backward = sum(flow["backward"] for flow in flows.values())

            pcap_files.append(pcap_file)
            forward_counts.append(total_forward)
            backward_counts.append(total_backward)

        if not pcap_files:
            ax.text(0.5, 0.5, "No Flow Data Available", fontsize=12, ha='center', va='center')
            ax.set_xticks([])
            ax.set_yticks([])
            bars_forward = []
            bars_backward = []
        else:
            x = np.arange(len(pcap_files))
            width = 0.3

            bars_forward = ax.bar(x - width / 2, forward_counts, width=width, label="Forward Packets",
                                  color="royalblue", edgecolor="black")
            bars_backward = ax.bar(x + width / 2, backward_counts, width=width, label="Backward Packets",
                                   color="tomato", edgecolor="black")

            ax.set_xticks(x)
            ax.set_xticklabels(pcap_files, rotation=45, ha="right")
            ax.set_xlabel("PCAP Files")
            ax.set_ylabel("Packet Count")
            ax.set_title("Forward vs Backward Packets per PCAP")

            legend = ax.legend(loc="upper right", frameon=True)
            legend.set_draggable(True)
            ax.grid(axis="y", linestyle="--", alpha=0.7)

        self.display_graph(fig)

        self.bar_references = {
            "Forward": bars_forward,
            "Backward": bars_backward,
        }

        def toggle_visibility(_=None):
            """Toggle visibility of Forward/Backward bars and individual PCAP bars."""
            forward_visible = self.check_vars["Forward"].get()
            backward_visible = self.check_vars["Backward"].get()

            # Forward/Backward overall toggles
            for bar in bars_forward:
                bar.set_visible(forward_visible)
            for bar in bars_backward:
                bar.set_visible(backward_visible)

            # Individual PCAP toggles
            for pcap, var in self.check_vars.items():
                if pcap in pcap_files:
                    index = pcap_files.index(pcap)
                    bars_forward[index].set_visible(var.get() and forward_visible)
                    bars_backward[index].set_visible(var.get() and backward_visible)

            fig.canvas.draw_idle()

        self.create_control_frame(
            title="Flow Direction Controls",
            check_options=["Forward", "Backward"] + pcap_files,
            check_callback=toggle_visibility
        )
        toggle_visibility()

    def plot_http_distribution(self):
        self.plot_category_graph("Http Count", "HTTP Distribution")

    def plot_bytes_per_second(self):
        """Plots bytes transferred per second for each PCAP file over time with unique colors and toggleable checkboxes."""
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
        if hasattr(self, "checkbox_frame") and self.checkbox_frame is not None:
            self.checkbox_frame.destroy()

        fig, ax = plt.subplots(figsize=(12, 6))
        bytes_per_second_per_pcap = {}
        pcap_lines = {}

        unique_pcaps = sorted(set(entry["Pcap file"] for entry in self.data))

        # Distinct color map
        color_map = get_distinct_color_map(unique_pcaps)

        for entry in self.data:
            pcap_file = entry["Pcap file"]
            timestamps = entry.get("Packet Timestamps", [])
            packet_sizes = entry.get("Packet Sizes", [])

            if not timestamps or not packet_sizes:
                continue

            start_time = min(timestamps)
            relative_times = [t - start_time for t in timestamps]
            bins = np.arange(0, max(relative_times) + 1, 1)
            byte_counts, _ = np.histogram(relative_times, bins=bins, weights=packet_sizes)

            bytes_per_second_per_pcap[pcap_file] = (bins[:-1], byte_counts)

        for i, (pcap_file, (time_bins, byte_counts)) in enumerate(bytes_per_second_per_pcap.items()):
            line_color = color_map.get(pcap_file, "gray")
            line, = ax.plot(time_bins, byte_counts, marker='o', linestyle='-', label=pcap_file, color=line_color)
            pcap_lines[pcap_file] = line

        ax.set_xlabel("Time (seconds)")
        ax.set_ylabel("Bytes Transferred Per Second")
        ax.set_title("Bytes Transferred Per Second Over Time for Each PCAP")
        ax.grid(True)

        legend = ax.legend(loc="upper right", frameon=True)
        legend.set_draggable(True)

        self.display_graph(fig)

        self.checkbox_frame = tk.Frame(self.graph_frame, bg="white", relief=tk.RIDGE, bd=2)
        self.checkbox_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        tk.Label(self.checkbox_frame, text="Toggle Visibility:", bg="white", font=("Arial", 10, "bold")).pack(
            side=tk.LEFT, padx=5)

        self.pcap_visibility = {}

        def toggle_visibility():
            """ Toggle visibility of each PCAP. """
            for pcap, var in self.pcap_visibility.items():
                pcap_lines[pcap].set_visible(var.get())
            fig.canvas.draw_idle()

        for label in pcap_lines.keys():
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(self.checkbox_frame, text=label, variable=var, command=toggle_visibility, bg="white")
            cb.pack(side=tk.LEFT, padx=5)
            self.pcap_visibility[label] = var

    # =====================================
    # NEW FUNCTIONS FOR UNIQUE FLOWS & CV IAT
    # =====================================
    def plot_unique_flows(self):
        """Plots the number of unique flows per PCAP file using a bar chart."""
        pcap_files = [entry["Pcap file"] for entry in self.data]
        # "Unique Flows" is already in each pcap entry
        unique_flows_counts = [entry.get("Unique Flows", 0) for entry in self.data]

        if not any(unique_flows_counts):
            self.display_no_data_message("No Unique Flow Data Available", "Unique Flows per PCAP")
            return

        self.plot_bar_chart(
            x_labels=pcap_files,
            values=unique_flows_counts,
            ylabel="Unique Flows",
            title="Unique Flows per PCAP"
        )

    def plot_cv_iat(self):
        """Plots the Coefficient of Variation (CV IAT) per PCAP file using a bar chart."""
        pcap_files = [entry["Pcap file"] for entry in self.data]
        # The code stores "CV IAT" in each dictionary entry
        cv_iat_values = [entry.get("CV IAT", 0) for entry in self.data]

        if not any(cv_iat_values):
            self.display_no_data_message("No CV IAT Data Available", "CV IAT per PCAP")
            return

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
        """Displays a no-data message when there is no data to plot."""
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, message, fontsize=12, ha='center', va='center')
        ax.set_xticks([])
        ax.set_yticks([])
        ax.set_title(title)
        self.display_graph(fig)

    def add_draggable_legend(self, ax, pcap_colors=None, unique_pcaps=None):
        if pcap_colors and unique_pcaps:
            legend_patches = [plt.Line2D([0], [0], color=pcap_colors[pcap], lw=4, label=pcap) for pcap in unique_pcaps]
            legend = ax.legend(handles=legend_patches, title="PCAP Files", loc="upper right", frameon=True)
        else:
            legend = ax.legend(loc="upper right", frameon=True)

        legend.set_draggable(True)

    def plot_bar_chart(self, x_labels, values, ylabel, title):
        """Generalized bar graph using distinct colors with black borders and label-based checkboxes."""
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        if hasattr(self, "checkbox_frame") and self.checkbox_frame:
            self.checkbox_frame.destroy()
            self.checkbox_frame = None

        fig, ax = plt.subplots(figsize=(8, 5))

        bars = ax.bar(
            x_labels, values,
            color=[self.get_pcap_color(pcap) for pcap in x_labels],
            edgecolor='black'
        )

        ax.set_xlabel("PCAP File")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.tick_params(axis='x', rotation=45)

        self.add_draggable_legend(ax)
        self.display_graph(fig)

        # Create label-based checkboxes for visibility control
        self.checkbox_frame = tk.Frame(self.graph_frame, bg="white", relief=tk.RIDGE, bd=2)
        self.checkbox_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        tk.Label(self.checkbox_frame, text="Toggle Visibility by Type:", bg="white", font=("Arial", 10, "bold")).pack(
            side=tk.LEFT, padx=5)

        def get_label_group(pcap_name):
            """Returns the appropriate group for a given PCAP file."""
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

        grouped_bars = {}
        for pcap, bar in zip(x_labels, bars):
            label_group = get_label_group(pcap)
            if label_group not in grouped_bars:
                grouped_bars[label_group] = []
            grouped_bars[label_group].append(bar)

        self.label_visibility = {}

        def toggle_visibility():
            """ Toggle visibility based on label checkboxes."""
            for label_group, bars_list in grouped_bars.items():
                visible = self.label_visibility[label_group].get()
                for bar in bars_list:
                    bar.set_visible(visible)
            fig.canvas.draw_idle()

        for label_group in grouped_bars.keys():
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(self.checkbox_frame, text=label_group.capitalize(), variable=var,
                                command=toggle_visibility, bg="white")
            cb.pack(side=tk.LEFT, padx=5)
            self.label_visibility[label_group] = var

    def plot_category_graph(self, column_name, ylabel):
        """Generalized category-based bar graph with distinct colors and check buttons for visibility."""
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        if hasattr(self, "checkbox_frame") and self.checkbox_frame:
            self.checkbox_frame.destroy()
            self.checkbox_frame = None

        fig, ax = plt.subplots(figsize=(12, 6))
        category_per_pcap = {}

        for entry in self.data:
            pcap_file = entry["Pcap file"]
            category_per_pcap.setdefault(pcap_file, Counter())

            for item in entry[column_name].split():
                if '-' in item:
                    key, value = item.split('-')
                    category_per_pcap[pcap_file][key] += int(value)

        categories = sorted(set(cat for pcap in category_per_pcap.values() for cat in pcap))
        unique_pcaps = sorted(category_per_pcap.keys())

        color_map = get_distinct_color_map(unique_pcaps)

        num_categories = len(categories)
        num_pcaps = len(unique_pcaps)
        x = np.arange(num_categories)
        width = 0.8 / num_pcaps

        bars_dict = {}

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

        self.checkbox_frame = tk.Frame(self.graph_frame, bg="white", relief=tk.RIDGE, bd=2)
        self.checkbox_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        tk.Label(self.checkbox_frame, text="Toggle Visibility by PCAP:", bg="white", font=("Arial", 10, "bold")).pack(
            side=tk.LEFT, padx=5)

        self.pcap_visibility = {}

        def toggle_visibility():
            """ Toggle visibility based on PCAP checkboxes."""
            for pcap, bars in bars_dict.items():
                visible = self.pcap_visibility[pcap].get()
                for bar in bars:
                    bar.set_visible(visible)
            fig.canvas.draw_idle()

        for pcap in bars_dict.keys():
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(self.checkbox_frame, text=pcap, variable=var, command=toggle_visibility, bg="white")
            cb.pack(side=tk.LEFT, padx=5)
            self.pcap_visibility[pcap] = var

    def display_graph(self, fig):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
        plt.tight_layout()
        self.canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(expand=True, fill=tk.BOTH)
        self.canvas.draw()

    def create_control_frame(self, title, check_options=None, check_callback=None, radio_options=None,
                             radio_callback=None):
        """Creates a Tkinter frame below the graph with checkboxes and/or radio buttons (if provided)."""

        # Destroy old frame before creating a new one
        if hasattr(self, "checkbox_frame") and self.checkbox_frame:
            self.checkbox_frame.destroy()

        self.checkbox_frame = tk.Frame(self.graph_frame, bg="white")
        self.checkbox_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

        tk.Label(self.checkbox_frame, text=title, font=("Arial", 10, "bold"), bg="white").pack()

        self.check_vars = {}
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

            tk.Label(radio_frame, text="Select Option:", font=("Arial", 9, "bold"), bg="white").grid(row=0, column=0, sticky="w")

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

            tk.Label(check_frame, text="Toggle Visibility:", font=("Arial", 9, "bold"), bg="white").grid(row=0, column=0, sticky="w")

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
        """Returns the color for a PCAP file based on predefined rules."""
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


def generate_extra_colors(n):
    """Generate additional distinct colors using HSV if more colors are needed."""
    return [colorsys.hsv_to_rgb(i / n, 0.8, 0.9) for i in range(n)]


def get_distinct_color_map(unique_pcaps):
    """Assigns distinct colors to each PCAP without repeating."""
    tableau_colors = list(TABLEAU_COLORS.values())
    num_pcaps = len(unique_pcaps)

    if num_pcaps <= len(tableau_colors):
        return {pcap: tableau_colors[i] for i, pcap in enumerate(unique_pcaps)}

    extra_colors = generate_extra_colors(num_pcaps - len(tableau_colors))
    all_colors = tableau_colors + extra_colors

    return {pcap: all_colors[i] for i, pcap in enumerate(unique_pcaps)}
