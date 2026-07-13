import tkinter as tk
from tkinter import messagebox
import json
import os

# Find the path of gui.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# file paths (make sure these match the controller paths)
CONFIG_FILE = os.path.join(BASE_DIR, 'config.json')
LOG_FILE = os.path.join(BASE_DIR, 'firewall.log')

class FirewallGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Firewall Controller GUI")
        self.master.geometry("380x530")
        
        # STATE VARIABLES INITIALIZATION

        # counters and file position
        self.last_pos = 0
        self.count_ddos = 0
        self.count_scan = 0
        self.count_port = 0

        # UI LAYOUT: HEADER

        # main title
        tk.Label(self.master, text="SDN Firewall GUI Dashboard", font=("Arial", 14, "bold")).pack(pady=15)

        # UI LAYOUT: THRESHOLD SETTINGS
        
        # create a freame to groupt the detection threshold settings
        self.frame_top = tk.Frame(self.master)
        self.frame_top.pack(pady=5)

        # DDoS threshold label and text input field
        tk.Label(self.frame_top, text="DDoS max packets:").grid(row=0, column=0, sticky="e")
        self.entry_ddos = tk.Entry(self.frame_top, width=8)
        self.entry_ddos.insert(0, "200")
        self.entry_ddos.grid(row=0, column=1, padx=10, pady=5)

        # Port Scan threshold label and text input field
        tk.Label(self.frame_top, text="Port Scan threshold:").grid(row=1, column=0, sticky="e")
        self.entry_scan = tk.Entry(self.frame_top, width=8)
        self.entry_scan.insert(0, "5")
        self.entry_scan.grid(row=1, column=1, padx=10, pady=5)

        # UI LAYOUT: BAN TIMEOUT SETTINGS

        # create a LabelFrame form timeouts
        self.ban_box = tk.LabelFrame(self.master, text="Ban Timeouts (seconds)")
        self.ban_box.pack(fill="x", padx=30, pady=10)

        # DDoS timeout and text input field
        tk.Label(self.ban_box, text="DDoS Ban time:").grid(row=0, column=0, sticky="e", padx=10, pady=5)
        self.ban_time_input = tk.Entry(self.ban_box, width=8)
        self.ban_time_input.insert(0, "60")
        self.ban_time_input.grid(row=0, column=1, padx=10, pady=5)

        # Port Scan timeout and text input field
        tk.Label(self.ban_box, text="Port Scan Ban time:").grid(row=1, column=0, sticky="e", padx=10, pady=5)
        self.entry_scan_ban = tk.Entry(self.ban_box, width=8)
        self.entry_scan_ban.insert(0, "15")
        self.entry_scan_ban.grid(row=1, column=1, padx=10, pady=5)

       # Port 2020 timeout and text input field
        tk.Label(self.ban_box, text="Port 2020 Drop time:").grid(row=2, column=0, sticky="e", padx=10, pady=5)
        self.entry_port_ban = tk.Entry(self.ban_box, width=8)
        self.entry_port_ban.insert(0, "30")
        self.entry_port_ban.grid(row=2, column=1, padx=10, pady=5)

        # apply button
        self.btn_apply = tk.Button(self.master, text="Push config to Controller", 
                                   command=self.push_rules_to_firewall, bg="lightblue")
        self.btn_apply.pack(pady=10)

        # UI LAYOUT: LIVE STATISTICS

        # frame creation
        self.terminal_frame = tk.Frame(self.master, bg="black")
        self.terminal_frame.pack(fill="both", expand=True, side="bottom")

        # terminal section header
        tk.Label(self.terminal_frame, text="BLOCKED ATTACKS:", bg="black", fg="white").pack(pady=5)
        
        # dynamic labels for attack counters
        self.lbl_ddos = tk.Label(self.terminal_frame, text="DDoS blocked: 0", bg="black", fg="lime")
        self.lbl_ddos.pack()
        
        self.lbl_scan = tk.Label(self.terminal_frame, text="Scans blocked: 0", bg="black", fg="lime")
        self.lbl_scan.pack()
        
        self.lbl_port = tk.Label(self.terminal_frame, text="Port 2020 drops: 0", bg="black", fg="lime")
        self.lbl_port.pack()

        # STARTUP ROUTINE

        # check if json exists, otherwise create a default one
        if os.path.exists(CONFIG_FILE): 
            self.load_config_into_fields()
        else:
            self.push_rules_to_firewall()

        # start checking logs in loop
        self.check_log_updates()

    # check the config.json file and set the GUI inputs
    def load_config_into_fields(self):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                cfg = json.load(f)

                # Change the actual settings with the ones found on JSON file
                self.entry_ddos.delete(0, tk.END)
                self.entry_ddos.insert(0, str(cfg.get("ddos_threshold", 200)))
                
                self.entry_scan.delete(0, tk.END)
                self.entry_scan.insert(0, str(cfg.get("scan_threshold", 5)))
                
                self.ban_time_input.delete(0, tk.END)
                self.ban_time_input.insert(0, str(cfg.get("ddos_ban_duration", 60)))
                
                self.entry_scan_ban.delete(0, tk.END)
                self.entry_scan_ban.insert(0, str(cfg.get("scan_ban_duration", 15)))
                
                self.entry_port_ban.delete(0, tk.END)
                self.entry_port_ban.insert(0, str(cfg.get("port_2020_ban_duration", 30)))
                
        except Exception as e:
            print(f"Error loading config file: {e}")

    # save the GUI values into the config.json file
    def push_rules_to_firewall(self):
        try:
            # build python dictionary with all the GUI input values
            cfg = {
                "ddos_threshold": int(self.entry_ddos.get()),
                "scan_threshold": int(self.entry_scan.get()),
                "ddos_ban_duration": int(self.ban_time_input.get()),
                "scan_ban_duration": int(self.entry_scan_ban.get()),
                "port_2020_ban_duration": int(self.entry_port_ban.get())
            }
            
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(cfg, f)
            
            messagebox.showinfo("Success", "New rules applied!")
            
        except ValueError:
            messagebox.showerror("Error", "Please insert integers only")
        except Exception as e:
            print(f"Error writing file: {e}")

    # keep monitoring the firewall log file to register new attack events
    def check_log_updates(self):
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                f.seek(self.last_pos)
                lines = f.readlines()
                self.last_pos = f.tell() 
                
                for line in lines:
                    if "DDoS detected!" in line: 
                        self.count_ddos += 1
                    elif "Port Scan detected" in line: 
                        self.count_scan += 1
                    elif "Traffic on port 2020 blocked" in line: 
                        self.count_port += 1
        
        # update the text of the GUI                
        self.lbl_ddos.config(text=f"DDoS attacks blocked: {self.count_ddos}")
        self.lbl_scan.config(text=f"Scans attacks blocked: {self.count_scan}")
        self.lbl_port.config(text=f"Port 2020 attacks blocked: {self.count_port}")
        
        # keep executing after 2 seconds
        self.master.after(2000, self.check_log_updates)

# used to ensure that the code block below only runs if the script is executed directly
if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()