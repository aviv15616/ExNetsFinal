import pyshark
from collections import Counter
import os
import asyncio
import hashlib  # נדרש כדי לחשב hash
import numpy as np
import pandas as pd  # נדרש כדי לשמור ל-CSV
import tkinter as tk
from tkinter import messagebox


class PcapProcessor:
    def __init__(self, sample_mode=False):
        self.pcap_data = []
        self.processed_files = set()
        self.sample_mode = sample_mode
        # Get current directory
        current_dir = os.getcwd()
        # Construct path to "data_set/pcap_features.csv"
        self.csv_file = os.path.join(current_dir, "data_set", "pcap_features.csv")

    def compute_flow_hash(self, src_ip, dst_ip, src_port, dst_port):
        """ מחשב Hash עבור Flow ID באמצעות כתובת מקור, יעד, ופורטים """
        flow_string = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}"
        flow_hash=hashlib.md5(flow_string.encode()).hexdigest()
        return int(flow_hash[:8], 16)


    def process_pcap(self, file_path):
        file_name = os.path.basename(file_path)
        sample_limit = 1000 if self.sample_mode else None

        if file_name in self.processed_files:
            self.show_message("Error: PCAP file with the same name already loaded.")
            return False
        self.processed_files.add(file_name)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            cap = pyshark.FileCapture(file_path, use_json=True)
        except Exception:
            return False

        # ⬇⬇⬇ אנחנו לא נוגעים בקוד החישובים המקוריים ⬇⬇⬇
        packet_count = 0
        total_size = 0
        start_time = None
        end_time = None
        http_counter = Counter()
        tcp_flags = Counter()
        ip_protocols = Counter()
        iat_list = []
        timestamps_list = []
        packet_sizes = []
        flows = {}

        prev_time = None
        # ⬆⬆⬆ אנחנו לא נוגעים בקוד החישובים המקוריים ⬆⬆⬆

        # ✅ נשמור כאן את כל החבילות בפורמט שרק 4 עמודות נרצה ב-CSV
        packet_data_for_csv = []

        for packet in cap:
            if self.sample_mode and packet_count >= sample_limit:
                break
            packet_count += 1
            packet_length = int(packet.length)
            total_size += packet_length

            packet_sizes.append(packet_length)

            current_time = float(packet.sniff_time.timestamp())
            timestamps_list.append(current_time)

            if start_time is None:
                start_time = current_time
            end_time = current_time

            if prev_time is not None:
                iat_list.append(current_time - prev_time)
            prev_time = current_time

            # ✅ החלק המקורי - לא נמחק
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                proto = packet.ip.proto  # Capture ALL IP protocols

                src_port = getattr(packet, 'tcp', getattr(packet, 'udp', None))
                dst_port = getattr(packet, 'tcp', getattr(packet, 'udp', None))
                src_port = src_port.srcport if src_port else "N/A"
                dst_port = dst_port.dstport if dst_port else "N/A"

                ip_protocols[proto] += 1

                flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
                reverse_flow_key = (dst_ip, src_ip, dst_port, src_port, proto)

                if flow_key not in flows and reverse_flow_key not in flows:
                    flows[flow_key] = {"forward": 0, "backward": 0}

                if flow_key in flows:
                    flows[flow_key]["forward"] += 1
                elif reverse_flow_key in flows:
                    flows[reverse_flow_key]["backward"] += 1

            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags'):
                flags = int(packet.tcp.flags, 16)
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

            if hasattr(packet, 'http'):
                http_counter['HTTP1'] += 1
            if hasattr(packet, 'http2'):
                http_counter['HTTP2'] += 1
            if hasattr(packet, 'http3'):
                http_counter['HTTP3'] += 1

            # ✅ יצירת flow_hash לכל פאקטה (ברירת מחדל "N/A" אם אין IP)
            flow_hash_hex = "N/A"
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                src_port = getattr(packet, 'tcp', getattr(packet, 'udp', None))
                dst_port = getattr(packet, 'tcp', getattr(packet, 'udp', None))
                src_port = src_port.srcport if src_port else "N/A"
                dst_port = dst_port.dstport if dst_port else "N/A"
                flow_hash_hex = self.compute_flow_hash(src_ip, dst_ip, src_port, dst_port)


                packet_data_for_csv.append({
                "Pcap file": f"{file_name}_{packet_count}",
                "Packet Size": packet_length,
                "Timestamp": current_time,
                "Flow Hash Numeric": flow_hash_hex
            })

        cap.close()

        # ⬇⬇⬇ המשך החישובים המקוריים (לא נוגעים בהם, לא מוחקים כלום) ⬇⬇⬇
        duration = (end_time - start_time) if start_time and end_time else 0
        avg_packet_size = total_size / packet_count if packet_count else 0
        avg_packet_iat = duration / packet_count if packet_count else 0
        # min_packet_size = min(packet_sizes) if packet_sizes else 0
        # max_packet_size = max(packet_sizes) if packet_sizes else 0
        # min_iat = min(iat_list) if iat_list else 0
        # max_iat = max(iat_list) if iat_list else 0

        flow_hashes = Counter()
        for flow_key in flows.keys():
            flow_hash = self.compute_flow_hash(*flow_key[:4])  # שימוש בארבעת הרכיבים של ה-Flow
            flow_hashes[flow_hash] += 1


        total_backward = sum(flow["backward"] for flow in flows.values())
        total_forward = sum(flow["forward"] for flow in flows.values())
        flow_directionality_ratio = round(total_forward / total_backward, 3) if total_backward > 0 else total_forward
        pcap_entry={
            "Pcap file": file_name,
            "Flow size": packet_count,
            "Flow Volume (bytes)": total_size,
            "Flow duration (seconds)": round(duration, 2),
            "Avg Packet size (bytes)": round(avg_packet_size, 2),
            "Avg Packet IAT (seconds)": round(avg_packet_iat, 6),
            "Inter-Packet Arrival Times": iat_list,
            "Packet Timestamps": timestamps_list,
            "Packet Sizes": packet_sizes,
            "Flow Directionality Ratio": flow_directionality_ratio,
            "Flows": flows,
            "Http Count": " ".join([f"{k}-{v}" for k, v in http_counter.items()]) or "0",
            "Tcp Flags": " ".join([f"{k}-{v}" for k, v in tcp_flags.items()]) or "N/A",
            "Ip protocols": " ".join([f"{k}-{v}" for k, v in ip_protocols.items()]) or "N/A",
        }
        self.pcap_data.append(pcap_entry)

        # self.save_to_csv(packet_data_for_csv)\\activate only to enter new data to the learning model

        return True

    def save_to_csv(self, packet_data_for_csv):
        """ שמירת כל הפאקטות לקובץ CSV (4 עמודות) """
        df = pd.DataFrame(packet_data_for_csv)
        df.to_csv(self.csv_file, index=False, encoding='utf-8')

    def show_message(self, message):
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Notification", message)
