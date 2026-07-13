
<details>
<summary>📚 <b>Table of Contents</b></summary>

 1. [About the project](#about)  
 2. [Main Features](#feature)  
 3. [Network Topology](#topology)  
 4. [Project Structure](#structure)  
 5. [Prerequisites](#prerequisites)  
 6. [How to run the Project](#run)  
 7. [How to test the Attacks](#test)  
  
</details>

<a id="about"></a>
# **SND-based Firewall with GUI**

This repository contains the implementation for a **Software-Defined Networking (SDN) Firewall** developed for a university project. It uses the Ryu SDN Framework and the OpenFlow 1.3 protocol to dynamically secure a simulated enterprise network using the **Kathara** network emulator.
It features simple packet filtering by implementing a **Defense in Depth** architecture, dynamic behavioral analysis, and a **Graphical User Interface (GUI) Dashboard** for rule management and real-time statistics visualization.

<a id="feature"></a>
# **Main Features**
* **Anti-DDoS Protection:** Detects and blocks bursts of packets directed to the same port within a short timeframe.
* **Anti-Port Scan Protection:** Detects and blocks Port Scan attacks (connection attempts to different ports in rapid succession).
* **Static Rules:** Unconditional blocking of traffic directed to specific ports (e.g., TCP 2020).
* **Whitelist:** Trusted IP addresses (e.g., the It_dept) to bypass firewall checks.
* **File Logging:** Persistent logging of alarms and BANs with formatted real-time timestamps in the `firewall.log` file.
* **GUI Dashboard:** User interface written in Python (Tkinter) to dynamically modify thresholds and BAN durations without restarting the controller.

---
<a id="topology"></a>
# **Network Topology**

The laboratory represents a realistic corporate network divided into distinct zones and an external environment (Internet).

1.  **Internet (`203.0.113.x`):** The external untrusted zone (simulating external users and attackers).
2.  **Perimeter:** A NAT-enabled Router acting as the first line of defense.
3.  **Internal Network (`10.0.x.x`):**
    *   `it_dept` (System Administrators - IP `10.0.10.1`).
    *   `marketing1` (Normal Office - IP `10.0.20.1`).
    *   `web_server` (DMZ - IP `10.0.30.1`).
    *   `database` (Critical infrastructure - IP `10.0.40.1`).
4.  **SDN Switch:** The Open vSwitch hardware acting as the network's core, entirely managed by the Ryu controller.

---
<a id="structure"></a>
# **Project Structure**
```
SDN-based-firewall/  
│  
├── Code/   
│   ├── shared/
│   │    ├── __pycache__
│   │    │    └── controller.cpython-311.pyc    # Cached controller bytecode.
│   │    │
│   │    ├── config.json                        # Dynamic firewall settings
│   │    ├── controller.py                      # Core SDN controller.
│   │    ├── firewall.log                       # Security event logs.
│   │    └── gui.py                             # Interactive dashboard.
│   │                            
│   ├── controller.startup                      # SDN node init.          
│   ├── db_server.startup                       # Database node setup.          
│   ├── firewall.startup                        # Open vSwitch setup.
│   ├── internet.startup                        # Attacker node setup.
│   ├── it_dept1.startup                        # Admin node setup.
│   ├── lab.conf                                # Network topology map.
│   ├── marketing1.startup                      # Employee node setup.
│   ├── router.startup                          # NAT router setup.
│   ├── switch.startup                          # L2 switch setup.
│   └── web_server.startup                      # Web server setup
│     
├── sdn-image/                           
│   └── Dockerfile                              # Custom Ryu image.
│                    
├── README.md                                   # Project main documentation.
└── comandi kathara.txt                         # Useful CLI cheatsheet.
```                                  
---
<a id="prerequisites"></a>
# **Prerequisites**

To run this project on your computer, you need to have installed:
1. [Kathara](https://github.com/KatharaFramework/Kathara) (and Docker)
2. **Python 3.x** (can be run directly from the terminal/command line, or via any IDE like Thonny, VS Code, etc.)
3. The standard **Tkinter** library (usually included with Python on Windows/Mac. On Linux Ubuntu, it might be necessary to install it using `sudo apt-get install python3-tk`).

---
<a id="run"></a>
#  **How to run the Project**

Follow these steps in the exact order:

## 1. Start the Virtual Network
Open a terminal in the main project folder and start Kathara:
```bash
# Cleans any previously hanging labs
kathara lclean

# Starts the network topology
kathara lstart
```
## 2. Run the SDN Controller:
Open a terminal inside the controller node and run:
```bash
ryu-manager controller.py
```
## 3. Launch the Dashboard GUI:
In the terminal of the main project launch the Gui.py program:
```bash
python ./shared/gui.py
```
there you can change the number of packets for DDoS and Scan attack and the ban time for ip that does the attack (Presso "Push config to Cotnroller) to set it.

<a id="test"></a>
#  **Testing & Validation Guide**

Run these codes to test the firewall (you can find all the codes also into Kathara commands.txt):
## TEST 1. Perimeter Protection & NAT
From the internet device (external attacker):

### Ping test:
```bash
ping -c 3 203.0.113.1
```
Expected Result: 100% Packet loss. The perimeter router actively drops ICMP traffic.

### Legitimate Web Traffic:
```bash
nc -zv 203.0.113.1 80
```
Expected Result: succeeded!. The router's DNAT correctly forwards port 80 to the internal Web Server.

## TEST 2. External DDoS Attack
From the internet device (external attacker):
```bash
for i in {1..300}; do nc -zv -w 1 203.0.113.1 80 & done
```
Expected Result: The terminal executes a burst of connections and stops.
A message should appear on the Controller terminal detecting the DDoS attack.

## TEST 3. Port Scan Attack
Architectural note: Port scans from the internet are natively fropped by the NAT router
The SDN is designed to catch hacked internal machines.
From an unprivileged internal device (marketing or web_server):
```bash
for p in {81..99}; do nc -zv -w 1 10.0.40.1 $p & done
```
Expected Result: The controller's order-agnostic algorithm detects the Scan.
A message should appear on the Controller terminal detecting the Scan attack.

## TEST 4. Port 2020 attack and whitelist
First, setup a temporany listener on the database machine:
```bash
nc -lk -p 2020 &
```
### From a standard employee (web_server or marketing):
```bash
nc -zv 10.0.40.1 2020
```
Expected Result: Silent hardware drop (Connection Timeout).
A message should appear on the Controller terminal detecting the Port 2020 connection.

### From the IT Administrator (it_dept)
```bash
nc -zv 10.0.40.1 2020
```
Expected Result: succeeded, the connection is enstablished instantly.


##  **OpenFlow Hardware Monitoring (Custom CLI Alias)**
During live attacks, the SDN switch dynamically populates its OpenFlow flow tables. The firewall has a custom sed/grep parsing alias automatically injected into the .bashrc in the startup file.
Type this into the firewall terminal to check the timeouts:

```bash
show-flows
```
## All the logs are saved into the firewall.log file