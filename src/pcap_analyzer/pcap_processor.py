import numpy as np
import pyshark
from collections import Counter
import os
import asyncio
import hashlib
import pandas as pd
import tkinter as tk
from tkinter import messagebox

# Define a class to process PCAP files
class PcapProcessor:
    def __init__(self, sample_mode=False):
        # Initialize the processor with an optional sample mode flag
        self.pcap_data = []  # List to store processed PCAP summary data
        self.processed_files = set()  # Set to track names of already processed files
        self.sample_mode = sample_mode  # Boolean flag for processing a sample of packets only

        # Get the current working directory
        current_dir = os.getcwd()  # Retrieve the current directory path
        # Construct the full path to the CSV file for PCAP features
        self.csv_file = os.path.join(current_dir, "data_set", "pcap_features.csv")

    def compute_flow_hash(self, src_ip, dst_ip, src_port, dst_port):
        """ מחשב Hash עבור Flow ID באמצעות כתובת מקור, יעד, ופורטים
        Compute a flow hash using source IP, destination IP, source port, and destination port.
        """
        # Create a string combining the flow details
        flow_string = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}"
        # Compute the MD5 hash of the flow string and convert to hexadecimal format
        flow_hash = hashlib.md5(flow_string.encode()).hexdigest()
        # Return the first 8 hex digits of the hash as an integer
        return int(flow_hash[:8], 16)

    def process_pcap(self, file_path):
        # Extract the base file name from the given file path
        file_name = os.path.basename(file_path)
        # Set a limit of 1000 packets if sample_mode is enabled, otherwise process all packets
        sample_limit = 1000 if self.sample_mode else None

        # Check if the file has already been processed
        if file_name in self.processed_files:
            # Show a message if the file was already loaded
            self.show_message("Error: PCAP file with the same name already loaded.")
            return False  # Exit processing with failure
        # Mark the file as processed
        self.processed_files.add(file_name)
        # Create and set a new asyncio event loop for asynchronous operations
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            # Try to open the PCAP file using pyshark with JSON support
            cap = pyshark.FileCapture(file_path, use_json=True)
        except Exception:
            # If opening the file fails, return False
            return False

        # Initialize variables to accumulate metrics from the packets
        packet_count = 0  # Counter for the number of packets processed
        total_size = 0  # Total size (in bytes) of all packets
        start_time = None  # Timestamp of the first packet
        end_time = None  # Timestamp of the last packet
        http_counter = Counter()  # Counter for HTTP protocol occurrences
        tcp_flags = Counter()  # Counter for TCP flag occurrences
        ip_protocols = Counter()  # Counter for IP protocol occurrences
        iat_list = []  # List to store inter-arrival times between packets
        timestamps_list = []  # List to store timestamps for each packet
        packet_sizes = []  # List to store sizes of individual packets
        flows = {}  # Dictionary to store flow information between endpoints

        prev_time = None  # Variable to hold the timestamp of the previous packet
        # ⬆⬆⬆ אנחנו לא נוגעים בקוד החישובים המקוריים ⬆⬆⬆
        # (We do not modify the original computation code)

        # ✅ נשמור כאן את כל החבילות בפורמט שרק 4 עמודות נרצה ב-CSV
        # Prepare a list to store packet-level data for CSV export (4 columns)
        packet_data_for_csv = []

        # Iterate through each packet in the capture
        for packet in cap:
            # If in sample mode and the sample limit is reached, stop processing further packets
            if self.sample_mode and packet_count >= sample_limit:
                break
            packet_count += 1  # Increment the packet counter

            # Get the packet length and add it to the total size
            packet_length = int(packet.length)
            total_size += packet_length

            # Append the current packet size to the list of packet sizes
            packet_sizes.append(packet_length)

            # Extract the current packet's timestamp and convert it to a float
            current_time = float(packet.sniff_time.timestamp())
            # Record the timestamp for later use
            timestamps_list.append(current_time)

            # Set the start time for the first packet and update end time for each packet
            if start_time is None:
                start_time = current_time
            end_time = current_time

            # Compute inter-arrival time (IAT) if this is not the first packet
            if prev_time is not None:
                iat_list.append(current_time - prev_time)
            prev_time = current_time  # Update previous packet time

            # ✅ החלק המקורי - לא נמחק
            # Process IP layer information if available in the packet
            if hasattr(packet, 'ip'):
                # Extract source and destination IP addresses
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                # Extract protocol information from the IP header
                proto = packet.ip.proto  # Capture ALL IP protocols

                # Attempt to extract port information from either TCP or UDP layers
                src_port = getattr(packet, 'tcp', getattr(packet, 'udp', None))
                dst_port = getattr(packet, 'tcp', getattr(packet, 'udp', None))
                src_port = src_port.srcport if src_port else "N/A"  # Default to "N/A" if not available
                dst_port = dst_port.dstport if dst_port else "N/A"

                # Increment the counter for the observed IP protocol
                ip_protocols[proto] += 1

                # Create a key for the flow and its reverse (for bidirectional matching)
                flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
                reverse_flow_key = (dst_ip, src_ip, dst_port, src_port, proto)

                # If this flow is not already tracked, initialize counters for both directions
                if flow_key not in flows and reverse_flow_key not in flows:
                    flows[flow_key] = {"forward": 0, "backward": 0}

                # Increment the appropriate flow direction count based on which key exists
                if flow_key in flows:
                    flows[flow_key]["forward"] += 1
                elif reverse_flow_key in flows:
                    flows[reverse_flow_key]["backward"] += 1

            # Process TCP layer flags if available
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags'):
                # Convert the TCP flags from a hex string to an integer
                flags = int(packet.tcp.flags, 16)
                # Check and count various TCP flag bits using bitwise operations
                if flags & 0x02:
                    tcp_flags['SYN'] += 1
                if flags & 0x10:
                    tcp_flags['ACK'] += 1
                if flags & 0x04:
                    tcp_flags['RST'] += 1
                if flags & 0x08:
                    tcp_flags['PSH'] += 1
                if flags & 0x01:
                    tcp_flags['FIN'] += 1

            # Count occurrences of different HTTP protocol versions
            if hasattr(packet, 'http'):
                http_counter['HTTP1'] += 1
            if hasattr(packet, 'http2'):
                http_counter['HTTP2'] += 1
            if hasattr(packet, 'http3'):
                http_counter['HTTP3'] += 1

            # ✅ יצירת flow_hash לכל פאקטה (ברירת מחדל "N/A" אם אין IP)
            # Default flow hash value is "N/A" if no IP layer exists
            flow_hash_hex = "N/A"
            if hasattr(packet, 'ip'):
                # Re-extract source and destination IP addresses and ports
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                src_port = getattr(packet, 'tcp', getattr(packet, 'udp', None))
                dst_port = getattr(packet, 'tcp', getattr(packet, 'udp', None))
                src_port = src_port.srcport if src_port else "N/A"
                dst_port = dst_port.dstport if dst_port else "N/A"
                # Compute a numeric flow hash using the compute_flow_hash function
                flow_hash_hex = self.compute_flow_hash(src_ip, dst_ip, src_port, dst_port)

                # Append packet-level details to the list for CSV export with 4 specific columns
                packet_data_for_csv.append({
                    "Pcap file": f"{file_name}_{packet_count}",  # Unique identifier combining file name and packet count
                    "Packet Size": packet_length,  # Size of the packet
                    "Timestamp": current_time,  # Timestamp of the packet
                    "Flow Hash Numeric": flow_hash_hex  # Computed numeric flow hash
                })

        # Close the pyshark capture to free system resources
        cap.close()

        # ⬇⬇⬇ המשך החישובים המקוריים (לא נוגעים בהם, לא מוחקים כלום) ⬇⬇⬇
        # Compute the duration of the capture session
        duration = (end_time - start_time) if start_time and end_time else 0
        # Calculate the average packet size
        avg_packet_size = total_size / packet_count if packet_count else 0
        # Calculate the average inter-arrival time between packets
        avg_packet_iat = duration / packet_count if packet_count else 0
        # The following lines for min/max calculations are commented out:
        # min_packet_size = min(packet_sizes) if packet_sizes else 0
        # max_packet_size = max(packet_sizes) if packet_sizes else 0
        # min_iat = min(iat_list) if iat_list else 0
        # max_iat = max(iat_list) if iat_list else 0

        # Create a Counter for flow hashes derived from the flow keys
        flow_hashes = Counter()
        for flow_key in flows.keys():
            # Compute a flow hash using the first four elements of the flow key (ignoring protocol)
            flow_hash = self.compute_flow_hash(*flow_key[:4])  # שימוש בארבעת הרכיבים של ה-Flow
            flow_hashes[flow_hash] += 1  # Count this flow hash

        # Calculate total backward and forward packet counts across all flows
        total_backward = sum(flow["backward"] for flow in flows.values())
        total_forward = sum(flow["forward"] for flow in flows.values())
        # Compute flow directionality ratio (forward to backward), rounded to 3 decimal places
        flow_directionality_ratio = round(total_forward / total_backward, 3) if total_backward > 0 else total_forward
        # Recalculate average inter-arrival time (for clarity)
        avg_packet_iat = duration / packet_count if packet_count else 0
        # Compute the standard deviation of inter-arrival times using numpy
        std_dev_iat = np.std(iat_list) if iat_list else 0
        # Calculate the coefficient of variation (CV) for the inter-arrival times
        cv_iat = (std_dev_iat / avg_packet_iat) if avg_packet_iat else 0

        # Determine unique flows based on source IP, destination IP, source port, and destination port
        unique_flows_set = set()
        for flow_key in flows:
            src_ip, dst_ip, src_port, dst_port, _ = flow_key
            unique_flows_set.add((src_ip, dst_ip, src_port, dst_port))
        unique_flows_count = len(unique_flows_set)  # Count the number of unique flows

        # Create a summary dictionary for this PCAP file with all computed metrics
        pcap_entry = {
            "Pcap file": file_name,  # Original file name
            "Flow size": packet_count,  # Total number of packets processed
            "Flow Volume (bytes)": total_size,  # Total byte volume of packets
            "Flow duration (seconds)": round(duration, 2),  # Duration of capture in seconds
            "Avg Packet size (bytes)": round(avg_packet_size, 2),  # Average packet size
            "Avg Packet IAT (seconds)": round(avg_packet_iat, 6),  # Average inter-arrival time
            "CV IAT": round(cv_iat, 6),  # Coefficient of Variation for inter-arrival times (new column)
            "Unique Flows": unique_flows_count,  # Number of unique flows (new column)
            "Inter-Packet Arrival Times": iat_list,  # List of inter-arrival times
            "Packet Timestamps": timestamps_list,  # List of packet timestamps
            "Packet Sizes": packet_sizes,  # List of individual packet sizes
            "Flow Directionality Ratio": flow_directionality_ratio,  # Ratio of forward to backward flows
            "Flows": flows,  # Dictionary of flow details
            "Http Count": " ".join([f"{k}-{v}" for k, v in http_counter.items()]) or "0",  # HTTP counts formatted as a string
            "Tcp Flags": " ".join([f"{k}-{v}" for k, v in tcp_flags.items()]) or "N/A",  # TCP flag counts formatted as a string
            "Ip protocols": " ".join([f"{k}-{v}" for k, v in ip_protocols.items()]) or "N/A",  # IP protocol counts formatted as a string
        }
        # Append the summary entry to the overall PCAP data list
        self.pcap_data.append(pcap_entry)

        # Uncomment the next line to save the packet-level CSV data for training models
        # self.save_to_csv(packet_data_for_csv)

        return True  # Return True indicating that processing was successful

    def save_to_csv(self, packet_data_for_csv):
        """ שמירת כל הפאקטות לקובץ CSV (4 עמודות)
        Save all packet-level data to a CSV file with 4 columns.
        """
        df = pd.DataFrame(packet_data_for_csv)  # Create a DataFrame from the list of packet dictionaries
        df.to_csv(self.csv_file, index=False, encoding='utf-8')  # Write the DataFrame to a CSV file without row indices

    def show_message(self, message):
        # Create a hidden Tkinter root window to allow messagebox display
        root = tk.Tk()
        root.withdraw()  # Hide the root window
        # Display an informational message box with the provided message
        messagebox.showinfo("Notification", message)
