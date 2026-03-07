
<details>
<summary>📚 <b>Table of Contents</b></summary>

 1. [About the project](#-sdn-based-firewall-with-gui)  

 2. [Main Features](#️-Main-Features)
  
 3. [Network Topology](#️-network-topology)
  
 4. [Project Structure](#-project-structure)
  
 5. [Prerequisites](#-prerequisites)
  
 6. [How to run the Project](#-How-to-run-the-project)

 7. [How to test the Attacks](#-how-to-test-the-attacks)
  
</details>



# 🛡️ **SND-based Firewall with GUI**

This project implements a **Software-Defined Networking (SDN) Firewall** using the **Kathara** network emulator and the **Ryu** controller. It features advanced security logic and a **Graphical User Interface (GUI) Dashboard** for rule management and real-time statistics visualization.

# ✨ **Main Features**
* **Anti-DDoS Protection:** Detects and blocks bursts of packets directed to the same port within a short timeframe.
* **Anti-Port Scan Protection:** Detects and blocks "Zig-Zag" attacks (connection attempts to different ports in rapid succession).
* **Static Rules:** Unconditional blocking of traffic directed to specific ports (e.g., TCP 2020).
* **Whitelist (VIP Pass):** Trusted IP addresses (e.g., the Administrator) bypass firewall checks.
* **File Logging:** Persistent logging of alarms and BANs with formatted real-time timestamps in the `firewall.log` file.
* **GUI Dashboard:** User interface written in Python (Tkinter) to dynamically modify thresholds and BAN durations without restarting the controller.

---

# 🗺️ **Network Topology**

The laboratory simulates a protected corporate network and an external environment (Internet).

* **`host1` (Admin - 10.0.0.1):** Administrator's PC. Added to the Whitelist, its traffic is never blocked.
* **`host2` (Secretary - 10.0.0.2):** Standard internal user PC. It is subject to firewall rules.
* **`host3` (Server Backup - 10.0.0.3):** The main "victim". It hosts dummy services (Web on port 80, Trap on port 2020) to test attacks.
* **`internet` (Attacker - 203.0.113.80):** External host to the LAN, used to simulate hacker attacks from the outside against corporate servers.
* **`router1`:** Connects the corporate LAN to the outside world.
* **`switch1` & `controller1`:** The SDN core. The switch executes commands from the Ryu controller, which applies the firewall logic.

---
# 🗂️ **Project Structure**
```
Smart_Home_ESP32/  
│  
├── Readme_img/                                   # Readme images  
│   ├── ESP32.jpeg                                  # Image of ESP32 board  
│   ├── House.png                                   # Readme logo image   
│   └── wiring_diagram.jpg                          # Wiring diagram
│     
├── Smart_Home_project/                           # Main project directory  
│   ├── __pycache__/                                # Compiled Python cache  
│       └── __init__.cpython-312.pyc                  # Compiled init file  
│   
└── README.md  
```                                  
---
# 🚀 **Prerequisites**

To run this project on your computer, you need to have installed:
1. [Kathara](https://github.com/KatharaFramework/Kathara) (and Docker)
2. **Python 3.x** (can be run directly from the terminal/command line, or via any IDE like Thonny, VS Code, etc.)
3. The standard **Tkinter** library (usually included with Python on Windows/Mac. On Linux Ubuntu/Debian, it might be necessary to install it using `sudo apt-get install python3-tk`).

---

# 🛠️ **How to run the Project**

Follow these steps in the exact order:

## 1. Start the Virtual Network
Open a terminal in the main project folder and start Kathara:
```bash
# Cleans any previously hanging labs
kathara lclean

# Starts the network topology
kathara lstart
```
# ⚔️ **How to test the Attacks**