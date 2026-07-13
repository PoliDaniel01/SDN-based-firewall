import logging
import time
import os
import json

# import Ryu SDN framework base classes and OpenFlow 1.3
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, tcp, in_proto, ipv4, vlan

class SimpleSwitch13(app_manager.RyuApp):
    # openFlow versione used
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        # ENVIRONMENT AND LOGGING SETUP

        # force timezone for log times
        os.environ['TZ'] = 'Europe/Rome'
        time.tzset()
        
        root_logger = logging.getLogger()
        file_handler = logging.FileHandler('/shared/firewall.log', mode='a')

        # log format message
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

        # logging level on info to record events
        root_logger.setLevel(logging.INFO)
        
        self.whitelist = ['10.0.10.1']  # it_dept whitelist
        self.monitor_stats = {}         # track connection statics per source ip
        self.banned_ips = {}            # track banned ip and exipration time
        
        # default values if config file fails to load
        self.DDOS_THRESHOLD = 200
        self.SCAN_THRESHOLD = 5
        self.TIME_WINDOW = 2.0
        self.DDOS_BAN_DURATION = 60
        self.SCAN_BAN_DURATION = 15
        self.PORT_2020_BAN_DURATION = 30

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        # extract datapath, openflow protocol and parser from the event
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # TABLE-MISS FLOW ENTRY

        # send everything to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # function to construct and send flow modification messages to the switch
    def add_flow(self, datapath, priority, match, actions, hard_timeout=0, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        # OpenFlow FlowMod message with specific parameters
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                instructions=inst, hard_timeout=hard_timeout, 
                                idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    # when a packet is forwarded from the swtich to the controller this event is triggered
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # drop lldp packets because they can flood all togheter
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        is_blocked = False

        # DYNAMIC CONFIGURATION LOADING
        
        # attempt to read security thresholds from the external JSON file
        if os.path.exists('/shared/config.json'):
            try:
                with open('/shared/config.json', 'r') as f:
                    config_data = json.load(f)
                    # update variables with values from JSON
                    self.DDOS_THRESHOLD = config_data.get('ddos_threshold', self.DDOS_THRESHOLD)
                    self.SCAN_THRESHOLD = config_data.get('scan_threshold', self.SCAN_THRESHOLD)
                    self.DDOS_BAN_DURATION = config_data.get('ddos_ban_duration', self.DDOS_BAN_DURATION)
                    self.SCAN_BAN_DURATION = config_data.get('scan_ban_duration', self.SCAN_BAN_DURATION)
                    self.PORT_2020_BAN_DURATION = config_data.get('port_2020_ban_duration', self.PORT_2020_BAN_DURATION)
            except Exception as e:
                pass

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        
        # L3 / L4 FIREWALL

        if tcp_pkt:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                src_ip = ip_pkt.src
                dst_port = tcp_pkt.dst_port
                current_time = time.time()
                
                if src_ip not in self.whitelist:
                    
                    # check if user is already banned
                    if src_ip in self.banned_ips:

                        if current_time > self.banned_ips[src_ip]:
                            del self.banned_ips[src_ip] # ban over
                        else:
                            return # ignore packet
                    
                    # isolate SYN and ACK flags using bitwise AND operations
                    syn_flag = tcp_pkt.bits & tcp.TCP_SYN
                    ack_flag = tcp_pkt.bits & tcp.TCP_ACK
                    
                    # analyze only if it's a pure SYN (connection start)
                    if syn_flag and not ack_flag:
                        
                        # Initialize tracking stats for new IPs we never seen
                        if src_ip not in self.monitor_stats:
                            self.monitor_stats[src_ip] = {
                                'last_port': dst_port,
                                'same': 0,
                                'diff': 0,
                                'scanned_ports': {dst_port},
                                'time': current_time
                            }
                        else:
                            stats = self.monitor_stats[src_ip]
                            
                            # reset stats if time window passed
                            if current_time - stats['time'] > self.TIME_WINDOW:
                                stats['same'] = 0
                                stats['diff'] = 0
                            
                            # update counters
                            if dst_port == stats['last_port']:
                                stats['same'] += 1
                            else:
                                stats['same'] = 0
                            
                            # add the requested port to the Set to count unique ports scanned
                            stats['scanned_ports'].add(dst_port)

                            # update tracking variables with current packet's info
                            stats['last_port'] = dst_port
                            stats['time'] = current_time

                            # check for DDoS attack
                            if stats['same'] > self.DDOS_THRESHOLD:
                                logging.info(f"DDoS detected! IP {src_ip} is flooding port {dst_port}")
                                
                                # create rule to drop ip and all IPv4 traffic from it
                                ban_match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                                # blocking rule install
                                self.add_flow(datapath, 250, ban_match, [], hard_timeout=self.DDOS_BAN_DURATION)
                                
                                self.banned_ips[src_ip] = current_time + self.DDOS_BAN_DURATION
                                del self.monitor_stats[src_ip]
                                is_blocked = True
                                return

                            # check for Port Scan attack
                            if len(stats['scanned_ports']) > self.SCAN_THRESHOLD:
                                logging.info(f"Port Scan detected from {src_ip}")
                                
                                # create rule to drop ip and all IPv4 traffic from it
                                ban_match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                                # create rule to drop ip and all IPv4 traffic from it
                                self.add_flow(datapath, 200, ban_match, [], hard_timeout=self.SCAN_BAN_DURATION)
                                
                                self.banned_ips[src_ip] = current_time + self.SCAN_BAN_DURATION 
                                del self.monitor_stats[src_ip]
                                is_blocked = True
                                return

                    # static rule to block port 2020 for everyone
                    if not is_blocked and dst_port == 2020:
                        logging.info(f"Traffic on port 2020 blocked (IP: {src_ip})")
                        # match (IPv4 + Source IP + TCP Protocol + Destination Port 2020) to trigger it
                        port_match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ip_proto=6, tcp_dst=2020)
                        self.add_flow(datapath, 100, port_match, [], hard_timeout=self.PORT_2020_BAN_DURATION)
                        is_blocked = True
                        return

        # L2 SWITCHING & VLAN LOGIC
        
        # handle MAC address learning
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
            
        # learn the source MAC address and link it to the port the packet arrived    
        self.mac_to_port[dpid][src] = in_port

        # check if we already know which physical port the Destination MAC address is connected to
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # output the packet to the port we determinated
        actions = [parser.OFPActionOutput(out_port)]
        
        # if not flooding, install rule in the switch
        if out_port != ofproto.OFPP_FLOOD:
            vlan_pkt = pkt.get_protocols(vlan.vlan)
            
            # differentiate between vlan tagged and untagged packets
            if len(vlan_pkt) > 0:
                vlan_id = vlan_pkt[0].vid | ofproto_v1_3.OFPVID_PRESENT
                rule_match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, vlan_vid=vlan_id)
            else:
                rule_match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                
            #self.add_flow(datapath, 1, rule_match, actions) -> commented to prevent double warning of attacks

        # extract the binary peyload if the swtich didn't buffer the packet    
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # construct the PacketOut message telling the switch what to do with it
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)