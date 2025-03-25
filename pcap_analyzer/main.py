import tkinter as tk

from pcap_gui import PcapGUI

if __name__ == "__main__":
    root = tk.Tk()
    app = PcapGUI(root)
    root.mainloop()