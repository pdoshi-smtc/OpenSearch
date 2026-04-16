"""
PCAP Analyzer Module
Contains all packet analysis logic, error detection, and data extraction functions
"""

import pyshark
import asyncio
import subprocess
import shutil
import json
import os
from datetime import datetime
import pandas as pd
import sys
from flask import jsonify
import numpy as np


# --- Fix for Python 3.14 async event loop ---
def ensure_event_loop():
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

# Node dictionaries for OPC to name mapping
HLR_OPC_DICT = {
    "3100": "I-HSS-FE1-FKT",
    "3000": "I-HSS-FE1-VTY",
    "3101": "I-HSS-FE2-FKT",
    "3001": "I-HSS-FE2-VTY",
}

VTY_STP_OPC_DICT = {
    "33": "STP-I-VTY",
    "14159": "STP-I-VTY",
    "1375": "STP-J-VTY",
    "30": "STP-J-VTY",
    "5298": "STP-SONUS-VTY",
    "4745": "STP-TELIA-STOCKHOLM-1",
}

FKT_STP_OPC_DICT = {
    "5300": "STP-I-FKT",    
    "43": "STP-I-FKT",
    "40": "STP-J-FKT",
    "1376": "STP-J-FKT",

}

MSC_OPC_DICT = {
    "31": "STPA1-AWS",
    "34": "STPA2-AWS",
    "41": "STPB1-AWS",
    "44": "STPB2-AWS",

}

RP_OPC_DICT = {
    "4215": "STP-BICS-MAR22",   
    "4201": "STP-BICS-STR21",
    "4558": "STP-COMFONE-ALIAS",
    "4591": "STP-COMFONE-ALIAS",
    "650": "STP-JT-ITPN",
    "651": "STP-JT-ITPW",
    "5715": "STP-ORANGE-TK1",
    "5716": "STP-ORANGE-TK2",
    "4466": "STP-SPARKLE-TIS1",
    "4460": "STP-SPARKLE-TIS2",

}

# Error meaning definitions
ERROR_MEANINGS = {
    "unexpectedly_transient_failure": "Transient failures include the momentary loss of network connectivity to components and services, the temporary unavailability of a service, and timeouts that occur when a service is busy",
    "system_failure": "ISD ack not received by HLR from RP within 14 seconds.",
    "roaming_not_allowed": "The subscriber is not allowed to roam in the current network",
    "facility_not_supported": "The requested facility or service is not supported",
    "unexpected_data_value": "The data value received is unexpected or invalid",
    "teleservice_not_provisioned": "The requested teleservice is not provisioned for this subscriber",
    "unknown_subscriber": "The subscriber is not recognized in the network",
    "diameter_error_rat_not_allowed": "The Radio Access Technology is not allowed for this subscriber",
    "unknownEquipment": "The serving node is unknown to the network",
    "Sm_delivery_failure": "Short message delivery has failed",
    "lost_service": "Service connection was lost unexpectedly",
    "generic_error": "An unspecified error has occurred"
}

# GTPv2 message type constants
CREATE_SESSION_REQUEST = "32"
DELETE_SESSION_REQUEST = "36"

class PCAPAnalyzer:
    """Main class for PCAP file analysis"""
    
    def __init__(self):
        self.node = {
            "rp": "",
            "hlr": "",
            "vty_stp": "",
            "fkt_stp": "",
            "msc": ""
        }
        self.reset_analysis()
    
    def reset_analysis(self):
        """Reset analysis state for new PCAP file"""
        self.first_error = None
        self.error_type = None
        self.packets_data = []
        self.packet_count = 0
        self.match = None
        
    def map_opc_to_node(self, opc):
        """Map OPC (Originating Point Code) to node name"""
        if opc in HLR_OPC_DICT:
            self.node["hlr"] = HLR_OPC_DICT[opc]
            # print(f"HLR OPC: {opc} -> {self.node['hlr']}")
        elif opc in RP_OPC_DICT:
            self.node["rp"] = RP_OPC_DICT[opc]
            # print(f"RP OPC: {opc} -> {self.node['rp']}")
        elif opc in VTY_STP_OPC_DICT:
            self.node["vty_stp"] = VTY_STP_OPC_DICT[opc]
            # print(f"VTY STP OPC: {opc} -> {self.node['vty_stp']}")
        elif opc in FKT_STP_OPC_DICT:
            self.node["fkt_stp"] = FKT_STP_OPC_DICT[opc]
            # print(f"FKT STP OPC: {opc} -> {self.node['fkt_stp']}")
        elif opc in MSC_OPC_DICT:
            self.node["msc"] = MSC_OPC_DICT[opc]
            # print(f"MSC OPC: {opc} -> {self.node['msc']}")
        else:
            print(f"OPC: {opc} -> Unknown")
    
    def process_diameter_packet(self, pkt, packet_info):
        """Process DIAMETER protocol packets"""
        packet_info['protocol'] = 'DIAMETER'
        diameter_layer = pkt.diameter
        
        info_parts = []
        
        # Process command code
        if hasattr(diameter_layer, 'cmd_code'):
            cmd_code = str(diameter_layer.cmd_code)
            info_parts.append(f"cmd={cmd_code}")
            
            cmd_names = {
                '316': '3GPP-Update-Location',
                '318': '3GPP-Authentication-Information',
                '323': '3GPP-Notify',
                '324': '3GPP-Purge-UE',
                '321': '3GPP-Insert-Subscriber-Data',
                '272': 'Credit-Control',
                '280': 'Device-Watchdog'
            }
            
            cmd_name = cmd_names.get(cmd_code, f"Code-{cmd_code}")
            
            # Determine if it's a request or answer
            request_type = "Request"
            if hasattr(diameter_layer, 'flags_request'):
                if str(diameter_layer.flags_request) == '0':
                    request_type = "Answer"
            
            info_parts[0] = f"cmd={cmd_name} {request_type}({cmd_code})"
        
        # Process flags
        if hasattr(diameter_layer, 'flags'):
            flag_chars = []
            flag_chars.append('R' if hasattr(diameter_layer, 'flags_request') and diameter_layer.flags_request == '1' else '-')
            flag_chars.append('P' if hasattr(diameter_layer, 'flags_proxyable') and diameter_layer.flags_proxyable == '1' else '-')
            flag_chars.append('E' if hasattr(diameter_layer, 'flags_error') and diameter_layer.flags_error == '1' else '-')
            flag_chars.append('T' if hasattr(diameter_layer, 'flags_t_bit') and diameter_layer.flags_t_bit == '1' else '-')
            info_parts.append(f"flags={''.join(flag_chars)}")
        
        # Process application ID
        if hasattr(diameter_layer, 'applicationid'):
            app_id = str(diameter_layer.applicationid)
            app_names = {
                '16777251': '3GPP S6a/S6d',
                '16777252': '3GPP S13/S13\'',
                '16777267': '3GPP S9',
                '16777238': '3GPP Gx',
                '16777236': '3GPP Rx',
                '4': 'Diameter Credit-Control'
            }
            app_name = app_names.get(app_id, app_id)
            info_parts.append(f"appl={app_name}({app_id})" if app_id in app_names else f"appl={app_id}")
        
        packet_info['info'] = ' '.join(info_parts) if info_parts else 'DIAMETER Message'
        
        # Check for errors
        self.check_diameter_errors(pkt, diameter_layer, packet_info)
        
        return packet_info
    
    def check_diameter_errors(self, pkt, diameter_layer, packet_info):
        """Check for DIAMETER protocol errors"""
        if hasattr(diameter_layer, 'error_message'):
            error_msg = str(diameter_layer.error_message)
            if "DIAMETER_TOO_BUSY" in error_msg:
                packet_info['is_error'] = True
                packet_info['error_details'] = 'UnexpectedlyTransientFailure'
                packet_info['info'] = 'Error-Message: UnexpectedlyTransientFailure'
                packet_info['rp'] = 'lost'
                if not self.first_error:
                    self.first_error = 'UnexpectedlyTransientFailure'
                    self.error_type = 'unexpectedly_transient_failure'
                    
        elif hasattr(diameter_layer, 'error_diagnostic'):
            error_msg = pkt.diameter.error_diagnostic.showname_value
            if "gprs_data_subscribed (0)" in error_msg.lower():
                packet_info['is_error'] = True
                packet_info['error_details'] = 'diameterErrorRatNotAllowed (5421)'
                packet_info['info'] = 'Error-Message: diameterErrorRatNotAllowed (5421)'
                if not self.first_error:
                    self.first_error = 'diameterErrorRatNotAllowed (5421)'
                    self.error_type = 'diameter_error_rat_not_allowed'
                    
        elif hasattr(diameter_layer, 'experimental_result_code'):
            error_msg = pkt.diameter.experimental_result_code.showname_value
            if "DIAMETER_ERROR_UNKNOWN_SERVING_NODE (5423)" in error_msg:
                packet_info['is_error'] = True
                packet_info['error_details'] = 'unknownEquipment'
                packet_info['info'] = 'Error-Message: unknownEquipment (5423)'
                if not self.first_error:
                    self.first_error = 'unknownEquipment'
                    self.error_type = 'unknownEquipment'
    
    def process_gsm_map_packet(self, pkt, packet_info):
        """Process GSM MAP protocol packets"""
        packet_info['protocol'] = 'GSM_MAP'
        pkt_str = str(pkt)
        
        # Check for various GSM MAP errors
        error_mappings = [
            ("systemFailure (34)", "systemFailure (34)", "systemFailure (34)", "system_failure"),
            ("roamingNotAllowed (8)", "roamingNotAllowed (8)", "roamingNotAllowed (8)", "roaming_not_allowed"),
            ("facilityNotSupported (21)", "facilityNotSupported (21)", "facilityNotSupported (21)", "facility_not_supported"),
            ("unexpectedDataValue (36)", "unexpectedDataValue (36)", "unexpectedDataValue (36)", "unexpected_data_value"),
            ("teleserviceNotProvisioned (11)", "teleserviceNotProvisioned (11)", "teleserviceNotProvisioned (11)", "teleservice_not_provisioned"),
            ("unknownSubscriber (1)", "unknownSubscriber (1)", "unknownSubscriber (1)", "unknown_subscriber"),
            ("subscriberNotSC-Subscriber (6)", "SmDeliveryFailure", "SmDeliveryFailure (6)", "Sm_delivery_failure")
        ]
        
        for search_str, error_detail, first_error_str, error_type_str in error_mappings:
            if search_str in pkt_str or search_str.split()[0] in pkt_str:
                packet_info['is_error'] = True
                packet_info['error_details'] = error_detail
                packet_info['info'] = f'returnError: {error_detail}'
                if not self.first_error:
                    self.first_error = first_error_str
                    self.error_type = error_type_str
                return packet_info


        # Check for operations
        if "returnError" in pkt_str:
            packet_info['is_error'] = True
            packet_info['info'] = 'returnError'
            if not self.first_error:
                self.first_error = 'Generic Error'
                self.error_type = 'generic_error'
        elif "updateLocation" in pkt_str:
            packet_info['info'] = 'invoke updateLocation'
        elif "insertSubscriberData" in pkt_str:
            packet_info['info'] = 'invoke insertSubscriberData'
        elif "sendAuthenticationInfo" in pkt_str:
            packet_info['info'] = 'invoke sendAuthenticationInfo'
        elif "provideRoamingNumber" in pkt_str:
            packet_info['info'] = 'invoke provideRoamingNumber'
        else:
            if hasattr(pkt.gsm_map, 'opcode'):
                packet_info['info'] = f'Operation {pkt.gsm_map.opcode}'
            else:
                packet_info['info'] = 'GSM_MAP Message'

    
    def process_gtpv2_packet(self, pkt, packet_info):
        """Process GTPv2 protocol packets"""
        packet_info['protocol'] = 'GTPv2'
        
        if hasattr(pkt.gtpv2, 'message_type'):
            msg_type = str(pkt.gtpv2.message_type)
            msg_type_names = {
                '32': 'Create Session Request',
                '33': 'Create Session Response',
                '36': 'Delete Session Request',
                '37': 'Delete Session Response',
                '34': 'Modify Bearer Request',
                '35': 'Modify Bearer Response'
            }
            packet_info['info'] = msg_type_names.get(msg_type, f'GTPv2 Message Type {msg_type}')
        else:
            packet_info['info'] = 'GTPv2 Message'
        
        return packet_info
    
    def process_sctp_packet(self, pkt, packet_info):
        """Process SCTP protocol packets"""
        if hasattr(pkt, 'sctp'):
            if hasattr(pkt.sctp, 'data_tsn'):
                tsn = pkt.sctp.data_tsn
                packet_info['info'] = f'DATA (TSN={tsn})'
                if hasattr(pkt.sctp, 'retransmission') or 'retransmission' in str(pkt).lower():
                    packet_info['info'] += ' (retransmission)'
            elif hasattr(pkt.sctp, 'chunk_type'):
                chunk_types = {
                    '1': 'INIT',
                    '2': 'INIT ACK'
                }
                packet_info['info'] = chunk_types.get(pkt.sctp.chunk_type, 'SCTP Control')
            elif hasattr(pkt.sctp, 'sack_cumulative_tsn_ack'):
                packet_info['info'] = 'SACK'
            else:
                packet_info['info'] = 'SCTP Control'
        else:
            packet_info['info'] = 'SCTP'
        
        return packet_info


def extract_pcap_data(pcap_path, mermaid_div=None):
    """Main function to extract and analyze PCAP data"""
    analyzer = PCAPAnalyzer()
    
    # # Ensure event loop exists
    # try:
    #     asyncio.get_running_loop()
    # except RuntimeError:
    #     loop = asyncio.new_event_loop()
    #     asyncio.set_event_loop(loop)
    
    # First pass - extract OPC mappings
    cap = pyshark.FileCapture(pcap_path, display_filter="m3ua or diameter")
    
    for pkt in cap:
        try:
            if hasattr(pkt, "m3ua") and hasattr(pkt.m3ua, "protocol_data_opc"):
                opc = pkt.m3ua.protocol_data_opc
                analyzer.map_opc_to_node(opc)
        except Exception as e:
            print(f"Error in OPC extraction: {e}")
            continue
    
    # print(f"Final Node Mapping: {analyzer.node}")
    cap.close()
    
    # Second pass - extract packet data
    cap = pyshark.FileCapture(pcap_path)
    
    for pkt in cap:
        analyzer.packet_count += 1
        packet_info = {
            'id': analyzer.packet_count,
            'time': '',
            'source': '',
            'destination': '',
            'protocol': '',
            'info': '',
            'length': 0,
            'is_error': False,
            'error_details': None,
            'rp': '',
            'hlr': '',
            'vty_stp': '',
            'fkt_stp': '',
            'msc': '',
            'meaning': '',
            'error_type': '',
            'sop': '',
            'mermaid_div': mermaid_div,
            'match': ''
        }
        
        try:
            # Extract basic packet information
            if hasattr(pkt, 'sniff_time'):
                packet_info['time'] = pkt.sniff_time.strftime('%H:%M:%S.%f')[:-3]
            
            if hasattr(pkt, 'length'):
                packet_info['length'] = int(pkt.length)
            
            if hasattr(pkt, 'ip'):
                packet_info['source'] = str(pkt.ip.src) if hasattr(pkt.ip, 'src') else ''
                packet_info['destination'] = str(pkt.ip.dst) if hasattr(pkt.ip, 'dst') else ''
            
            if hasattr(pkt, 'highest_layer'):
                packet_info['protocol'] = str(pkt.highest_layer).upper()
            
            # Process specific protocols
            if hasattr(pkt, 'diameter'):
                analyzer.process_diameter_packet(pkt, packet_info)
            elif hasattr(pkt, 'gsm_map'):
                analyzer.process_gsm_map_packet(pkt, packet_info)
            elif hasattr(pkt, 'gtpv2'):
                analyzer.process_gtpv2_packet(pkt, packet_info)
            elif packet_info['protocol'] == 'SCTP':
                analyzer.process_sctp_packet(pkt, packet_info)
            else:
                if packet_info['protocol'] and not packet_info['info']:
                    packet_info['info'] = f'{packet_info["protocol"]} packet'
            
        except Exception as e:
            print(f"Error processing packet {analyzer.packet_count}: {e}")
            continue
        
        if packet_info['protocol']:
            analyzer.packets_data.append(packet_info)
    
    cap.close()
    
    # Detect lost service
    lost_service_data = detect_lost_service_with_tshark(pcap_path)
    
    if lost_service_data['has_lost_service'] and not analyzer.first_error:
        analyzer.first_error = 'Lost Service Detected'
        analyzer.error_type = 'lost_service'
        rp="lost"
        sop = get_sop(analyzer.node['rp'],"lost")
    elif packet_info['error_details']=="roamingNotAllowed (8)":
        sop = get_sop(analyzer.node['rp'],"lost")
    else:
        sop = get_sop(analyzer.node['rp'],packet_info['error_details']) if analyzer.node['rp'] else ""
    
    print(f"Extracted {len(analyzer.packets_data)} packets")
    print(f"Error meaning: {ERROR_MEANINGS.get(analyzer.error_type, 'Unknown Error')}")

    #If Roaming Not Allowed display the Roaming Sponser table
    if "roaming_not_allowed" in analyzer.error_type:
        cap = pyshark.FileCapture(pcap_path)
        
        for pkt in cap:
            if hasattr(pkt, 'gsm_map'):
                fields = pkt.gsm_map._all_fields
                # print(fields)
                
                imsi = fields.get('e212.imsi', None)
                mcc = fields.get('e212.mcc', None)
                mnc = fields.get('e212.mnc', None)
                
                print("imsi",imsi)
                if imsi:
                    product_version = 'SmartSIM 4.0 ADVANCED'
                    country='France'
                    
                    excel_file = r"data\\coverage.xlsx"
                    print(f"\n📘 Searching for coverage in Excel: Product version={product_version} Country={country}")
                    df = pd.read_excel(excel_file)
                    
                    match = df[(df['country'] == "France")& (df['Product version'] == 'SmartSIM 4.0 ADVANCED')] if country and product_version else pd.DataFrame()
    
                    # Replace NaN and blank strings with "NA"
                    match = match.replace({np.nan: 'NA', '': 'NA'})
                    analyzer.match = match.to_dict(orient='records')
                    
                    if not match.empty:
                        row = match.iloc[0]
                        print("\n✅ Coverage Match Found:")
                    else:
                        print("❌ No matching MCC/MNC found in pcap file.")
                    cap.close()
                    break
        cap.close()
                    
    
    return {
        'mermaid_div': mermaid_div,
        'match': analyzer.match,
        'packets': analyzer.packets_data,
        'first_error': analyzer.first_error,
        'error_type': analyzer.error_type,
        'total_packets': len(analyzer.packets_data),
        'error_packets': len([p for p in analyzer.packets_data if p['is_error']]),
        'success_packets': len([p for p in analyzer.packets_data if not p['is_error']]),
        'lost_service': lost_service_data,
        'rp': analyzer.node['rp'],
        'hlr': analyzer.node['hlr'],
        'vty_stp': analyzer.node['vty_stp'],
        'fkt_stp': analyzer.node['fkt_stp'],
        'msc': analyzer.node['msc'],
        'meaning': ERROR_MEANINGS.get(analyzer.error_type, ""),
        'sop': sop
    }


def detect_lost_service_with_tshark(pcap_path, max_delta=1.0):
    """Detect lost service using tshark for GTPv2 analysis"""
    if shutil.which("tshark") is None:
        print("WARNING: tshark is not installed or not in PATH. Skipping lost service detection.")
        return {
            'has_lost_service': False,
            'lost_service_events': [],
            'error': 'tshark not available'
        }
    
    try:
        # Extract GTPv2 packet information using tshark
        cmd = [
            "tshark",
            "-r", pcap_path,
            "-Y", "gtpv2",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "gtpv2.message_type"
        ]
        
        proc = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True, 
            check=False, 
            timeout=30
        )
        
        events = []
        for line in proc.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) < 3:
                continue
            
            frame, ts, msg_type = parts
            try:
                ts = float(ts)
                frame = int(frame)
            except:
                continue
            
            if msg_type == CREATE_SESSION_REQUEST:
                events.append(("create", ts, frame))
            elif msg_type == DELETE_SESSION_REQUEST:
                events.append(("delete", ts, frame))
        
        # Find pairs of create/delete requests
        creates = [e for e in events if e[0] == "create"]
        deletes = [e for e in events if e[0] == "delete"]
        pairs = []
        
        for c in creates:
            c_ts = c[1]
            candidates = [d for d in deletes if d[1] > c_ts and (d[1] - c_ts) <= max_delta]
            if candidates:
                nearest = min(candidates, key=lambda x: x[1])
                delta = nearest[1] - c_ts
                pairs.append({
                    'create_frame': c[2],
                    'create_time': c[1],
                    'delete_frame': nearest[2],
                    'delete_time': nearest[1],
                    'time_gap': delta
                })
        
        return {
            'has_lost_service': len(pairs) > 0,
            'lost_service_events': pairs,
            'total_create_requests': len(creates),
            'total_delete_requests': len(deletes),
            'paired_requests': len(pairs)
        }
        
    except subprocess.TimeoutExpired:
        return {
            'has_lost_service': False,
            'lost_service_events': [],
            'error': 'tshark timeout'
        }
    except Exception as e:
        return {
            'has_lost_service': False,
            'lost_service_events': [],
            'error': f'tshark error: {str(e)}'
        }


def get_sop(rp,error):
    """Get Standard Operating Procedure (SOP) for a given RP"""
    # print(f"Getting SOP for RP: {rp}")
    
    # Load SOP data from JSON file
    sop_file = os.path.join(os.path.dirname(__file__), 'static', 'sops.json')

    # print(f"SOP file path: {sop_file}")
    try:
        with open(sop_file) as f:
            # print(f"Loading SOP file: {sop_file}")
            data = json.load(f)
    except FileNotFoundError:
        return "SOP file not found"
    except json.JSONDecodeError:
        return "Invalid SOP file format"

    sops = data.get("sops", {})
    rp_to_sop = data.get("rp_to_sop", {})

    sop_id = None
    if error=="lost" or error=="roamingNotAllowed (8)":
        # Get the SOP ID for the given RP
        sop_id = rp_to_sop.get("lost")
    elif error=="systemFailure (34)":
        sop_id = rp_to_sop.get(rp)

    if sop_id is None:
            return "We are working on the SOP for this error, please check back later."
    
    sop_value = sops.get(sop_id)
    if sop_value is None:
        return "SOP content missing for the given ID"
    
    return sop_value