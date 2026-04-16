#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Enhanced version with timeline integrated into messages
# python call_flow_timeline_modified.py -f sample.pcap -o output.html

import pyshark
import sys
import os
import argparse
import json
from pathlib import Path
import asyncio
from datetime import datetime

class NodeResolver:
    """Resolves IP addresses and point codes to node names with enhanced node identification"""
    
    def __init__(self, config_file='data/node.json'):
        self.ip_map = {}
        self.point_code_map = {}
        self.ssn_map = {
            '0': 'Not used/Unknown',
            '1': 'SCCP-MG',
            '6': 'HLR',
            '7': 'VLR',
            '8': 'MSC',
            '9': 'EIR',
            '10': 'AuC',
            '142': 'RANAP',
            '143': 'RNSAP',
            '145': 'GMLC',
            '146': 'CAP',
            '147': 'gsmSCF/IM-SSF',
            '148': 'SIWF',
            '149': 'SGSN',
            '150': 'GGSN',
            '241': 'INAP',
            '249': 'PCAP',
            '250': 'BSC-LE',
            '251': 'MSC-LE',
            '252': 'SMLC',
            '253': 'BSS-O&M',
            '254': 'BSSAP',
            '232': 'CNAM',
            '247': 'LNP',
            '248': '800-AIN',
            '254_ANSI': '800-TCAP',
        }
        self.load_config(config_file)
    
    def load_config(self, config_file):
        """Load node configuration from JSON file"""
        try:
            config_path = Path(config_file)
            if not config_path.exists():
                possible_paths = [
                    Path(config_file),
                    Path.cwd() / 'data' / 'node.json',
                ]
                for path in possible_paths:
                    if path.exists():
                        config_path = path
                        break
                else:
                    print(f"Warning: Configuration file not found. Using addresses directly.")
                    return
            
            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Try to parse JSON
            try:
                config = json.loads(content)
            except json.JSONDecodeError as je:
                print(f"Error: Invalid JSON in {config_path}")
                print(f"  JSON Error: {je}")
                print(f"  Please fix the JSON syntax errors in your node.json file")
                print(f"  Common issues: trailing commas, missing quotes, unclosed brackets")
                
                # Try to fix common JSON errors
                print("\nAttempting to auto-fix common JSON errors...")
                import re
                fixed_content = re.sub(r',\s*([}\]])', r'\1', content)
                try:
                    config = json.loads(fixed_content)
                    print("  Successfully auto-fixed JSON!")
                except:
                    print("  Auto-fix failed. Please manually fix the JSON file.")
                    return
            
            self.ip_map = config.get('ip', {})
            self.point_code_map = config.get('point_code', {})
            
            # print(f"Loaded configuration from {config_path}")
            # print(f"  - {len(self.ip_map)} IP mappings")
            # print(f"  - {len(self.point_code_map)} point code mappings")
            
            # Show some example mappings for verification
            if self.point_code_map:
                examples = list(self.point_code_map.items())[:3]
                print(f"  - Example point codes: {examples}")
            
        except Exception as e:
            print(f"Warning: Error loading configuration: {e}")
            import traceback
            traceback.print_exc()
    
    def resolve_ip(self, ip_address):
        """Resolve IP address to node name"""
        if not ip_address:
            return ip_address
        return self.ip_map.get(ip_address, ip_address)
    
    def resolve_point_code(self, point_code):
        """Resolve point code to node name"""
        if not point_code:
            return "Unknown"
        
        # Convert point code to string and try different formats
        pc_str = str(point_code)
        
        # Try direct lookup
        if pc_str in self.point_code_map:
            return self.point_code_map[pc_str]
        
        # Sometimes point codes come with extra zeros or formatting
        # Try without leading zeros
        pc_int = None
        try:
            pc_int = int(point_code)
            if str(pc_int) in self.point_code_map:
                return self.point_code_map[str(pc_int)]
        except:
            pass
        
        # Return unresolved point code
        return f"PC_{pc_str}"
    
    def resolve_ssn(self, ssn):
        """Resolve SSN to node type"""
        if not ssn:
            return None
        ssn_str = str(ssn)
        return self.ssn_map.get(ssn_str, None)


def extract_ssn_info(packet):
    """Extract SSN information from SCCP layer"""
    calling_ssn = None
    called_ssn = None
    calling_entity = None
    called_entity = None
    
    if hasattr(packet, 'sccp'):
        try:
            # Try different field names for calling SSN
            if hasattr(packet.sccp, 'calling_ssn'):
                calling_ssn = str(packet.sccp.calling_ssn)
            elif hasattr(packet.sccp, 'calling_party_ssn'):
                calling_ssn = str(packet.sccp.calling_party_ssn)
            elif hasattr(packet.sccp, 'calling_ssn_number'):
                calling_ssn = str(packet.sccp.calling_ssn_number)
            
            # Try different field names for called SSN
            if hasattr(packet.sccp, 'called_ssn'):
                called_ssn = str(packet.sccp.called_ssn)
            elif hasattr(packet.sccp, 'called_party_ssn'):
                called_ssn = str(packet.sccp.called_party_ssn)
            elif hasattr(packet.sccp, 'called_ssn_number'):
                called_ssn = str(packet.sccp.called_ssn_number)
                
        except Exception as e:
            pass
    
    return calling_ssn, called_ssn


def extract_gtpv2_interface_info(packet):
    """Extract F-TEID interface information from GTPv2 packets"""
    src_interface = None
    dst_interface = None
    
    if hasattr(packet, 'gtpv2'):
        try:
            # Parse F-TEID information
            # Common interface types in GTPv2
            interface_types = {
                '0': 'S1-U-eNodeB',
                '1': 'S1-U-SGW',
                '2': 'S12-RNC',
                '3': 'S12-SGW',
                '4': 'S5/S8-SGW-GTP-U',
                '5': 'S5/S8-PGW-GTP-U',
                '6': 'S5/S8-SGW-GTP-C',
                '7': 'S5/S8-PGW-GTP-C',
                '8': 'S5/S8-SGW-PMIPv6',
                '9': 'S5/S8-PGW-PMIPv6',
                '10': 'S11-MME-GTP-C',
                '11': 'S11/S4-SGW-GTP-C',
                '16': 'S2b-ePDG-GTP-C',
                '17': 'S2b-ePDG-GTP-U',
                '18': 'S2b-PGW-GTP-C',
                '19': 'S2b-PGW-GTP-U',
                '25': 'S2a-TWAN-GTP-U',
                '26': 'S2a-TWAN-GTP-C',
                '27': 'S2a-PGW-GTP-C',
                '28': 'S2a-PGW-GTP-U',
            }
            
            # Look for F-TEID fields
            layer_str = str(packet.gtpv2)
            
            # Extract interface type from F-TEID
            if hasattr(packet.gtpv2, 'f_teid_interface_type'):
                iface_type = str(packet.gtpv2.f_teid_interface_type)
                iface_name = interface_types.get(iface_type, f'Interface-{iface_type}')
                
                # Determine the node type from interface
                if 'MME' in iface_name:
                    dst_interface = 'MME'
                elif 'SGW' in iface_name:
                    dst_interface = 'SGW'
                elif 'PGW' in iface_name:
                    dst_interface = 'PGW'
                elif 'eNodeB' in iface_name:
                    dst_interface = 'eNodeB'
                elif 'ePDG' in iface_name:
                    dst_interface = 'ePDG'
                elif 'TWAN' in iface_name:
                    dst_interface = 'TWAN'
                    
        except Exception as e:
            pass
            
    return src_interface, dst_interface


def extract_diameter_host_info(packet):
    """Extract Origin-Host and Destination-Host from Diameter packets"""
    origin_host = None
    dest_host = None
    origin_realm = None
    dest_realm = None
    
    if hasattr(packet, 'diameter'):
        try:
            # Look for AVP fields
            if hasattr(packet.diameter, 'avp_origin_host'):
                origin_host = str(packet.diameter.avp_origin_host)
                # Extract node type from host name (e.g., orsmme.17.58.epc.mnc031.mcc901.3gppnetwork.org -> MME)
                if 'mme' in origin_host.lower():
                    origin_host = 'MME'
                elif 'hss' in origin_host.lower():
                    origin_host = 'HSS'
                elif 'pcrf' in origin_host.lower():
                    origin_host = 'PCRF'
                elif 'pgw' in origin_host.lower():
                    origin_host = 'PGW'
                elif 'sgw' in origin_host.lower():
                    origin_host = 'SGW'
                    
            if hasattr(packet.diameter, 'avp_destination_host'):
                dest_host = str(packet.diameter.avp_destination_host)
                # Extract node type from host name
                if 'mme' in dest_host.lower():
                    dest_host = 'MME'
                elif 'hss' in dest_host.lower():
                    dest_host = 'HSS'
                elif 'pcrf' in dest_host.lower():
                    dest_host = 'PCRF'
                elif 'pgw' in dest_host.lower():
                    dest_host = 'PGW'
                elif 'sgw' in dest_host.lower():
                    dest_host = 'SGW'
                    
            # Try alternative field names
            if not origin_host and hasattr(packet.diameter, 'origin_host'):
                origin_host = str(packet.diameter.origin_host)
                if 'mme' in origin_host.lower():
                    origin_host = 'MME'
                elif 'hss' in origin_host.lower():
                    origin_host = 'HSS'
                    
            if not dest_host and hasattr(packet.diameter, 'destination_host'):
                dest_host = str(packet.diameter.destination_host)
                if 'mme' in dest_host.lower():
                    dest_host = 'MME'
                elif 'hss' in dest_host.lower():
                    dest_host = 'HSS'
                    
        except Exception as e:
            pass
            
    return origin_host, dest_host


def extract_point_codes(packet):
    """Extract point codes from various protocol layers"""
    src_pc = None
    dst_pc = None
    
    # M3UA point codes - most common in modern 2G/3G networks
    if hasattr(packet, 'm3ua'):
        try:
            # Try different M3UA field names for originating point code
            if hasattr(packet.m3ua, 'protocol_data_opc'):
                src_pc = packet.m3ua.protocol_data_opc
            elif hasattr(packet.m3ua, 'opc'):
                src_pc = packet.m3ua.opc
            elif hasattr(packet.m3ua, 'affected_point_code'):
                # Sometimes in management messages
                src_pc = packet.m3ua.affected_point_code
                
            # Try different M3UA field names for destination point code
            if hasattr(packet.m3ua, 'protocol_data_dpc'):
                dst_pc = packet.m3ua.protocol_data_dpc
            elif hasattr(packet.m3ua, 'dpc'):
                dst_pc = packet.m3ua.dpc
        except Exception as e:
            pass
    
    # MTP3 point codes
    if not src_pc and hasattr(packet, 'mtp3'):
        try:
            if hasattr(packet.mtp3, 'opc'):
                src_pc = packet.mtp3.opc
            elif hasattr(packet.mtp3, 'mtp3_opc'):
                src_pc = packet.mtp3.mtp3_opc
                
            if hasattr(packet.mtp3, 'dpc'):
                dst_pc = packet.mtp3.dpc
            elif hasattr(packet.mtp3, 'mtp3_dpc'):
                dst_pc = packet.mtp3.mtp3_dpc
        except Exception as e:
            pass
    
    # SCCP point codes (for TCAP/MAP messages)
    if not src_pc and hasattr(packet, 'sccp'):
        try:
            # SCCP calling/called party addresses may contain point codes
            if hasattr(packet.sccp, 'calling_ssn_pc'):
                src_pc = packet.sccp.calling_ssn_pc
            elif hasattr(packet.sccp, 'calling_pc'):
                src_pc = packet.sccp.calling_pc
            elif hasattr(packet.sccp, 'calling_party_point_code'):
                src_pc = packet.sccp.calling_party_point_code
                
            if hasattr(packet.sccp, 'called_ssn_pc'):
                dst_pc = packet.sccp.called_ssn_pc
            elif hasattr(packet.sccp, 'called_pc'):
                dst_pc = packet.sccp.called_pc
            elif hasattr(packet.sccp, 'called_party_point_code'):
                dst_pc = packet.sccp.called_party_point_code
        except Exception as e:
            pass
    
    # Clean up point codes - remove any decimal points or formatting
    if src_pc:
        # Handle different point code formats (e.g., "3.8.0" -> "3100")
        src_pc_str = str(src_pc)
        if '.' in src_pc_str:
            # Convert ITU point code format (3.8.0) to decimal
            parts = src_pc_str.split('.')
            if len(parts) == 3:
                try:
                    # ITU format: 3-8-3 bits
                    zone = int(parts[0])
                    area = int(parts[1])
                    sp = int(parts[2])
                    src_pc = str((zone << 11) | (area << 3) | sp)
                except:
                    src_pc = src_pc_str.replace('.', '')
        else:
            src_pc = src_pc_str
            
    if dst_pc:
        # Handle different point code formats
        dst_pc_str = str(dst_pc)
        if '.' in dst_pc_str:
            # Convert ITU point code format
            parts = dst_pc_str.split('.')
            if len(parts) == 3:
                try:
                    zone = int(parts[0])
                    area = int(parts[1])
                    sp = int(parts[2])
                    dst_pc = str((zone << 11) | (area << 3) | sp)
                except:
                    dst_pc = dst_pc_str.replace('.', '')
        else:
            dst_pc = dst_pc_str
    
    return src_pc, dst_pc


def is_2g_3g_protocol(packet):
    """Check if packet contains 2G/3G protocols that should use point codes"""
    protocols_2g_3g = [
        'gsm_map',     # MAP protocol
        'sccp',        # Signaling Connection Control Part
        'tcap',        # Transaction Capabilities Application Part
        'm3ua',        # MTP3 User Adaptation Layer
        'mtp3',        # Message Transfer Part Level 3
        'ranap',       # Radio Access Network Application Part (3G)
        'bssmap',      # BSS Management Application Part (2G)
        'gsm_a',       # GSM A-interface
        'camel',       # CAMEL protocol
        'isup',        # ISDN User Part
        'bicc',        # Bearer Independent Call Control
        'gsm_sms',     # GSM SMS
        'gsm_a_rr',    # GSM Radio Resource
        'gsm_a_dtap',  # GSM DTAP
    ]
    
    for proto in protocols_2g_3g:
        if hasattr(packet, proto):
            return True
    return False


def get_packet_info(packet, node_resolver, verbose=False):
    """Extract packet information with enhanced node identification and timestamp"""
    
    # Get timestamp
    timestamp = None
    timestamp_str = ""
    if hasattr(packet, 'sniff_timestamp'):
        timestamp = float(packet.sniff_timestamp)
        # Format timestamp as HH:MM:SS.mmm
        dt = datetime.fromtimestamp(timestamp)
        timestamp_str = dt.strftime("%H:%M:%S.%f")[:-3]
    
    # Default to IP addressing
    src = None
    dst = None
    src_node_type = None
    dst_node_type = None
    
    # Get IP addresses first (as fallback)
    ip_src = None
    ip_dst = None
    
    if hasattr(packet, 'ip'):
        ip_src = packet.ip.src
        ip_dst = packet.ip.dst
    elif hasattr(packet, 'ipv6'):
        ip_src = packet.ipv6.src
        ip_dst = packet.ipv6.dst
    
    # If no IP at all, return None
    if not ip_src or not ip_dst:
        return None
    
    # Check if this is a 2G/3G packet
    if is_2g_3g_protocol(packet):
        # Extract point codes
        src_pc, dst_pc = extract_point_codes(packet)
        
        # Extract SSN information for node identification
        calling_ssn, called_ssn = extract_ssn_info(packet)
        
        if verbose:
            print(f"Debug: 2G/3G packet - src_pc={src_pc}, dst_pc={dst_pc}")
            print(f"Debug: SSN - calling={calling_ssn}, called={called_ssn}")
        
        # Use point codes if available, otherwise fallback to IP
        if src_pc:
            src = node_resolver.resolve_point_code(src_pc)
            if calling_ssn:
                src_node_type = node_resolver.resolve_ssn(calling_ssn)
            if verbose and src.startswith("PC_"):
                print(f"Debug: Could not resolve point code {src_pc}")
        else:
            # For 2G/3G without point codes, still try to resolve the IP
            src = node_resolver.resolve_ip(ip_src)
            if calling_ssn:
                src_node_type = node_resolver.resolve_ssn(calling_ssn)
            if src == ip_src:  # If not resolved, mark as IP
                src = f"IP_{ip_src}"
        
        if dst_pc:
            dst = node_resolver.resolve_point_code(dst_pc)
            if called_ssn:
                dst_node_type = node_resolver.resolve_ssn(called_ssn)
            if verbose and dst.startswith("PC_"):
                print(f"Debug: Could not resolve point code {dst_pc}")
        else:
            dst = node_resolver.resolve_ip(ip_dst)
            if called_ssn:
                dst_node_type = node_resolver.resolve_ssn(called_ssn)
            if dst == ip_dst:  # If not resolved, mark as IP
                dst = f"IP_{ip_dst}"
    else:
        # For 4G, SIP, RTP, and other IP-based protocols
        src = node_resolver.resolve_ip(ip_src)
        dst = node_resolver.resolve_ip(ip_dst)
        
        # Check for GTPv2 interface information
        if hasattr(packet, 'gtpv2'):
            src_iface, dst_iface = extract_gtpv2_interface_info(packet)
            if src_iface:
                src_node_type = src_iface
            if dst_iface:
                dst_node_type = dst_iface
        
        # Check for Diameter host information
        if hasattr(packet, 'diameter'):
            origin_host, dest_host = extract_diameter_host_info(packet)
            if origin_host:
                src_node_type = origin_host
            if dest_host:
                dst_node_type = dest_host
    
    # Format the source and destination with node type if available
    if src_node_type:
        src = f"{src}\\n[{src_node_type}]"
    if dst_node_type:
        dst = f"{dst}\\n[{dst_node_type}]"
    
    # Now identify the protocol and message
    message = None
    
    # GSM MAP (2G/3G) - WITH TIMESTAMP
    if hasattr(packet, 'gsm_map'):
        arrow = "->>"
        operation = "MAP Message"
        
        try:
            # Method 1: Check for localValue (operation code)
            if hasattr(packet.gsm_map, 'localvalue'):
                local_val = str(packet.gsm_map.localvalue)
                # MAP operation codes
                operations_by_code = {
                    '2': 'updateLocation',
                    '3': 'cancelLocation',
                    '4': 'provideRoamingNumber',
                    '7': 'insertSubscriberData',
                    '8': 'deleteSubscriberData',
                    '22': 'sendRoutingInfo',
                    '23': 'updateGprsLocation',
                    '44': 'mt-forwardSM',
                    '45': 'sendRoutingInfoForSM',
                    '46': 'mo-forwardSM',
                    '47': 'reportSM-DeliveryStatus',
                    '56': 'sendAuthenticationInfo',
                    '67': 'purgeMS',
                    '70': 'provideSubscriberInfo',
                    '71': 'anyTimeInterrogation',
                }
                operation = operations_by_code.get(local_val, f"Op-{local_val}")
            
            # Method 2: Check for opCode field
            elif hasattr(packet.gsm_map, 'opcode'):
                opcode = str(packet.gsm_map.opcode)
                operations_by_code = {
                    '2': 'updateLocation',
                    '3': 'cancelLocation',
                    '7': 'insertSubscriberData',
                    '8': 'deleteSubscriberData',
                    '23': 'updateGprsLocation',
                    '56': 'sendAuthenticationInfo',
                    '4': 'provideRoamingNumber',
                    '22': 'sendRoutingInfo',
                }
                operation = operations_by_code.get(opcode, f"Op-{opcode}")
            
            # Method 3: Check for returnError, returnResult, reject components
            if operation == "MAP Message":
                # Check if it's a return error
                if hasattr(packet.gsm_map, 'problem'):
                    operation = 'returnError'
                elif hasattr(packet.gsm_map, 'errorcode'):
                    operation = 'returnError'
                elif hasattr(packet.gsm_map, 'returnerror'):
                    operation = 'returnError'
                # Check if it's a return result
                elif hasattr(packet.gsm_map, 'returnresult'):
                    operation = 'returnResult'
                # Check component field
                elif hasattr(packet.gsm_map, 'component'):
                    comp = str(packet.gsm_map.component)
                    if 'returnError' in comp or 'return-error' in comp:
                        operation = 'returnError'
                    elif 'returnResult' in comp or 'return-result' in comp:
                        operation = 'returnResult'
                    elif 'reject' in comp:
                        operation = 'reject'
                    elif 'invoke' in comp:
                        operation = 'invoke'
            
            # Method 4: Parse from the packet layers
            if operation == "MAP Message":
                for layer in packet.layers:
                    layer_str = str(layer)
                    
                    # Check for specific operations in layer string
                    operations = [
                        'updateGprsLocation', 'updateLocation', 'insertSubscriberData',
                        'cancelLocation', 'purgeMS', 'sendAuthenticationInfo',
                        'provideRoamingNumber', 'sendRoutingInfo', 'mt-forwardSM',
                        'mo-forwardSM', 'reportSM-DeliveryStatus', 'returnError',
                        'returnResult', 'reject'
                    ]
                    
                    for op in operations:
                        if op in layer_str:
                            operation = op
                            break
                    
                    if operation != "MAP Message":
                        break
                        
        except Exception as e:
            print(f"GSM MAP parsing error: {e}") if verbose else None
            
        # Include timestamp in the message
        if timestamp_str:
            message = [src, arrow, dst, arrow, f"MAP: {operation}<br/>[{timestamp_str}]"]
        else:
            message = [src, arrow, dst, arrow, f"MAP: {operation}"]
    
    # RANAP (3G) - WITH TIMESTAMP
    elif hasattr(packet, 'ranap'):
        arrow = "->>"
        proc = "RANAP Message"
        try:
            if hasattr(packet.ranap, 'procedureCode'):
                pc = str(packet.ranap.procedureCode)
                procs = {
                    '0': 'RAB-Assignment',
                    '1': 'Iu-Release',
                    '19': 'InitialUE-Message',
                    '20': 'DirectTransfer',
                }
                proc = procs.get(pc, f"Proc-{pc}")
        except:
            pass
        
        if timestamp_str:
            message = [src, arrow, dst, arrow, f"RANAP: {proc}<br/>[{timestamp_str}]"]
        else:
            message = [src, arrow, dst, arrow, f"RANAP: {proc}"]
    
    # BSSMAP (2G) - WITH TIMESTAMP
    elif hasattr(packet, 'bssmap'):
        arrow = "->>"
        msg_type = "BSSMAP Message"
        try:
            if hasattr(packet.bssmap, 'msgtype'):
                mt = str(packet.bssmap.msgtype)
                types = {
                    '1': 'Assignment Request',
                    '2': 'Assignment Complete',
                    '16': 'Handover Request',
                    '32': 'Clear Command',
                }
                msg_type = types.get(mt, f"Type-{mt}")
        except:
            pass
        if timestamp_str:
            message = [src, arrow, dst, arrow, f"BSSMAP: {msg_type}<br/>[{timestamp_str}]"]
        else:
            message = [src, arrow, dst, arrow, f"BSSMAP: {msg_type}"]
    
    # SCCP - WITH TIMESTAMP
    elif hasattr(packet, 'sccp'):
        arrow = "->"
        msg_type = "SCCP Message"
        try:
            if hasattr(packet.sccp, 'message_type'):
                mt = str(packet.sccp.message_type)
                types = {
                    '1': 'CR',
                    '2': 'CC',
                    '6': 'DT1',
                    '9': 'UDT',
                    '10': 'UDTS',
                    '17': 'XUDT',
                }
                msg_type = types.get(mt, f"Type-{mt}")
        except:
            pass
        if timestamp_str:
            message = [src, arrow, dst, arrow, f"SCCP: {msg_type}<br/>[{timestamp_str}]"]
        else:
            message = [src, arrow, dst, arrow, f"SCCP: {msg_type}"]
    
    # ISUP - WITH TIMESTAMP
    elif hasattr(packet, 'isup'):
        arrow = "->>"
        msg_type = "ISUP Message"
        try:
            if hasattr(packet.isup, 'message_type'):
                mt = str(packet.isup.message_type)
                types = {
                    '1': 'IAM',
                    '6': 'ACM',
                    '9': 'ANM',
                    '12': 'REL',
                    '16': 'RLC',
                }
                msg_type = types.get(mt, f"Type-{mt}")
        except:
            pass
        if timestamp_str:
            message = [src, arrow, dst, arrow, f"ISUP: {msg_type}<br/>[{timestamp_str}]"]
        else:
            message = [src, arrow, dst, arrow, f"ISUP: {msg_type}"]
    
    # S1AP (4G) - WITH TIMESTAMP
    elif hasattr(packet, 's1ap'):
        arrow = "->>"
        proc = "S1AP Message"
        try:
            if hasattr(packet.s1ap, 'procedurecode'):
                pc = str(packet.s1ap.procedurecode)
                procs = {
                    '12': 'InitialUEMessage',
                    '9': 'InitialContextSetup',
                    '5': 'E-RABSetup',
                    '13': 'UplinkNASTransport',
                    '11': 'DownlinkNASTransport',
                }
                proc = procs.get(pc, f"Proc-{pc}")
        except:
            pass
        if timestamp_str:
            message = [src, arrow, dst, arrow, f"S1AP: {proc}<br/>[{timestamp_str}]"]
        else:
            message = [src, arrow, dst, arrow, f"S1AP: {proc}"]
    
    # Diameter - WITH TIMESTAMP
    elif hasattr(packet, 'diameter'):
        arrow = "->>"
        cmd = "Diameter Message"
        try:
            if hasattr(packet.diameter, 'cmd_code'):
                code = str(packet.diameter.cmd_code)
                
                # Check if it's a request or answer
                is_request = False
                if hasattr(packet.diameter, 'flags_request'):
                    # Convert to string and check if it's true
                    is_request = str(packet.diameter.flags_request).lower() == 'true' or str(packet.diameter.flags_request) == '1'
                
                # 3GPP Diameter commands (request_name, answer_name)
                cmds = {
                    # S6a/S6d Interface (MME-HSS)
                    '316': ('Update-Location-Request', 'Update-Location-Answer'),
                    '317': ('Cancel-Location-Request', 'Cancel-Location-Answer'),
                    '318': ('Authentication-Information-Request', 'Authentication-Information-Answer'),
                    '319': ('Authentication-Information-Answer', 'Authentication-Information-Answer'),
                    '320': ('Insert-Subscriber-Data-Request', 'Insert-Subscriber-Data-Answer'),
                    '321': ('Purge-UE-Request', 'Purge-UE-Answer'),
                    '322': ('Purge-UE-Answer', 'Purge-UE-Answer'),
                    '323': ('Notify-Request', 'Notify-Answer'),
                    '324': ('Notify-Answer', 'Notify-Answer'),
                    '304': ('Delete-Subscriber-Data-Request', 'Delete-Subscriber-Data-Answer'),
                    '305': ('Delete-Subscriber-Data-Answer', 'Delete-Subscriber-Data-Answer'),
                    '306': ('Reset-Request', 'Reset-Answer'),
                    '307': ('Reset-Answer', 'Reset-Answer'),
                    
                    # Cx/Dx Interface (IMS)
                    '300': ('User-Authorization-Request', 'User-Authorization-Answer'),
                    '301': ('User-Authorization-Answer', 'User-Authorization-Answer'),
                    '302': ('Server-Assignment-Request', 'Server-Assignment-Answer'),
                    '303': ('Server-Assignment-Answer', 'Server-Assignment-Answer'),
                    
                    # Base Diameter Protocol
                    '257': ('Capabilities-Exchange-Request', 'Capabilities-Exchange-Answer'),
                    '258': ('Re-Auth-Request', 'Re-Auth-Answer'),
                    '271': ('Accounting-Request', 'Accounting-Answer'),
                    '272': ('Credit-Control-Request', 'Credit-Control-Answer'),
                    '274': ('Abort-Session-Request', 'Abort-Session-Answer'),
                    '275': ('Session-Termination-Request', 'Session-Termination-Answer'),
                    '280': ('Device-Watchdog-Request', 'Device-Watchdog-Answer'),
                    '281': ('Device-Watchdog-Answer', 'Device-Watchdog-Answer'),
                    '282': ('Disconnect-Peer-Request', 'Disconnect-Peer-Answer'),
                    '283': ('Disconnect-Peer-Answer', 'Disconnect-Peer-Answer'),
                }
                
                # Get command name based on code and request/answer flag
                if code in cmds:
                    cmd_name = cmds[code][0] if is_request else cmds[code][1]
                else:
                    # For unknown commands, build descriptive name
                    suffix = 'Request' if is_request else 'Answer'
                    if hasattr(packet.diameter, 'applicationid'):
                        app_id = str(packet.diameter.applicationid)
                        app_names = {
                            '16777251': 'S6a/S6d',
                            '16777216': 'Cx/Dx',
                            '16777238': 'Gx',
                            '16777252': 'S13',
                            '16777272': 'S6b',
                            '16777265': 'SWa/STa',
                            '16777267': 'SWx',
                            '16777291': 'S9',
                        }
                        app_name = app_names.get(app_id, f'App{app_id}')
                        cmd_name = f"3GPP-{app_name}-{suffix}({code})"
                    else:
                        cmd_name = f"Cmd-{code}-{suffix}"
                
                cmd = cmd_name
                
        except:
            pass
        
        if timestamp_str:
            message = [src, arrow, dst, arrow, f"Diameter: {cmd}<br/>[{timestamp_str}]"]
        else:
            message = [src, arrow, dst, arrow, f"Diameter: {cmd}"]
    
    # SIP - WITH TIMESTAMP
    elif hasattr(packet, 'sip'):
        arrow = "->>"
        msg = "SIP Message"
        try:
            if hasattr(packet.sip, 'method'):
                msg = packet.sip.method
            elif hasattr(packet.sip, 'status_line'):
                msg = packet.sip.status_line
        except:
            pass
        if timestamp_str:
            message = [src, arrow, dst, arrow, f"SIP: {msg}<br/>[{timestamp_str}]"]
        else:
            message = [src, arrow, dst, arrow, f"SIP: {msg}"]
    
    # RTP - WITH TIMESTAMP
    elif hasattr(packet, 'rtp'):
        arrow = "-->"
        codec = "Media"
        try:
            if hasattr(packet.rtp, 'p_type'):
                pt = str(packet.rtp.p_type)
                codecs = {
                    '0': 'PCMU/G.711u',
                    '8': 'PCMA/G.711a',
                    '3': 'GSM',
                    '9': 'G.722',
                    '18': 'G.729',
                }
                codec = codecs.get(pt, f"PT-{pt}")
        except:
            pass
        # Only show RTP if packet is large enough (avoid RTCP)
        if int(packet.length) >= 100:
            if timestamp_str:
                message = [src, arrow, dst, arrow, f"RTP: {codec}<br/>[{timestamp_str}]"]
            else:
                message = [src, arrow, dst, arrow, f"RTP: {codec}"]
    
    # GTPv2 - WITH TIMESTAMP
    elif hasattr(packet, 'gtpv2'):
        arrow = "->>"
        msg_type = "GTPv2 Message"
        try:
            if hasattr(packet.gtpv2, 'message_type'):
                mt = str(packet.gtpv2.message_type)
                types = {
                    '1': 'Echo Request',
                    '2': 'Echo Response',
                    '32': 'Create Session Request',
                    '33': 'Create Session Response',
                    '34': 'Modify Bearer Request',
                    '35': 'Modify Bearer Response',
                    '36': 'Delete Session Request',
                    '37': 'Delete Session Response',
                    '95': 'Create Bearer Request',
                    '96': 'Create Bearer Response',
                    '97': 'Update Bearer Request',
                    '98': 'Update Bearer Response',
                    '99': 'Delete Bearer Request',
                    '100': 'Delete Bearer Response',
                    '170': 'Release Access Bearers Request',
                    '171': 'Release Access Bearers Response',
                    '176': 'Downlink Data Notification',
                    '177': 'Downlink Data Notification Acknowledge',
                }
                msg_type = types.get(mt, f"Type-{mt}")
        except:
            pass
        if timestamp_str:
            message = [src, arrow, dst, arrow, f"GTPv2: {msg_type}<br/>[{timestamp_str}]"]
        else:
            message = [src, arrow, dst, arrow, f"GTPv2: {msg_type}"]
    
    # SCTP - WITH TIMESTAMP
    elif hasattr(packet, 'sctp'):
        arrow = "->"
        msg = "SCTP Message"
        
        try:
            # Try to get chunk information from different fields
            chunk_info = []
            
            # Method 1: Check for specific chunk type fields
            if hasattr(packet.sctp, 'data_tsn'):
                tsn = packet.sctp.data_tsn
                msg = f"DATA (TSN={tsn})"
                
                # Check for retransmission
                if hasattr(packet.sctp, 'retransmitted') and str(packet.sctp.retransmitted) == '1':
                    msg = f"DATA (TSN={tsn}) (retransmission)"
                elif hasattr(packet.sctp, 'retransmission') and str(packet.sctp.retransmission) == '1':
                    msg = f"DATA (TSN={tsn}) (retransmission)"
                    
            elif hasattr(packet.sctp, 'chunk_type'):
                chunk_type = str(packet.sctp.chunk_type)
                chunk_types = {
                    '0': 'DATA',
                    '1': 'INIT',
                    '2': 'INIT_ACK',
                    '3': 'SACK',
                    '4': 'HEARTBEAT',
                    '5': 'HEARTBEAT_ACK',
                    '6': 'ABORT',
                    '7': 'SHUTDOWN',
                    '8': 'SHUTDOWN_ACK',
                    '9': 'ERROR',
                    '10': 'COOKIE_ECHO',
                    '11': 'COOKIE_ACK',
                    '14': 'SHUTDOWN_COMPLETE'
                }
                msg = chunk_types.get(chunk_type, f"Chunk-{chunk_type}")
                
            # Method 2: Check for INIT/INIT_ACK specific fields
            elif hasattr(packet.sctp, 'init_chunk_initiate_tag'):
                msg = "INIT"
            elif hasattr(packet.sctp, 'init_ack_chunk_initiate_tag'):
                msg = "INIT_ACK"
            elif hasattr(packet.sctp, 'sack_chunk_cumulative_tsn_ack'):
                msg = f"SACK (TSN_ACK={packet.sctp.sack_chunk_cumulative_tsn_ack})"
            elif hasattr(packet.sctp, 'heartbeat_chunk_info'):
                msg = "HEARTBEAT"
            elif hasattr(packet.sctp, 'heartbeat_ack_chunk_info'):
                msg = "HEARTBEAT_ACK"
            elif hasattr(packet.sctp, 'shutdown_chunk_cumulative_tsn_ack'):
                msg = "SHUTDOWN"
            elif hasattr(packet.sctp, 'abort_chunk'):
                msg = "ABORT"
            
        except Exception as e:
            print(f"SCTP parsing error: {e}") if verbose else None
        
        if timestamp_str:
            message = [src, arrow, dst, arrow, f"SCTP: {msg}<br/>[{timestamp_str}]"]
        else:
            message = [src, arrow, dst, arrow, f"SCTP: {msg}"]
    
    # RADIUS - WITH TIMESTAMP
    elif hasattr(packet, 'radius'):
        arrow = "->>"
        msg = "RADIUS Message"
        
        try:
            if hasattr(packet.radius, 'code'):
                code = str(packet.radius.code)
                codes = {
                    '1': 'Access-Request',
                    '2': 'Access-Accept',
                    '3': 'Access-Reject',
                    '4': 'Accounting-Request',
                    '5': 'Accounting-Response',
                    '11': 'Access-Challenge',
                    '12': 'Status-Server',
                    '13': 'Status-Client',
                    '40': 'Disconnect-Request',
                    '41': 'Disconnect-ACK',
                    '42': 'Disconnect-NAK',
                    '43': 'CoA-Request',
                    '44': 'CoA-ACK',
                    '45': 'CoA-NAK'
                }
                msg = codes.get(code, f"Code-{code}")
                
                # Add packet ID if available
                if hasattr(packet.radius, 'id'):
                    msg = f"{msg} id={packet.radius.id}"
                    
        except Exception as e:
            print(f"RADIUS parsing error: {e}") if verbose else None
        
        if timestamp_str:
            message = [src, arrow, dst, arrow, f"RADIUS: {msg}<br/>[{timestamp_str}]"]
        else:
            message = [src, arrow, dst, arrow, f"RADIUS: {msg}"]
    
    # GTP - WITH TIMESTAMP
    elif hasattr(packet, 'gtp'):
        arrow = "-->"
        if timestamp_str:
            message = [src, arrow, dst, arrow, f"GTP: Data<br/>[{timestamp_str}]"]
        else:
            message = [src, arrow, dst, arrow, "GTP: Data"]
    
    if message and timestamp:
        return {'message': message, 'timestamp': timestamp}
    elif message:
        return {'message': message, 'timestamp': None}
    else:
        return None


def process_pcap(capture_file, verbose=False):
    """
    Process PCAP file and return Mermaid diagram content
    
    Args:
        capture_file: Path to the PCAP file
        verbose: Enable verbose output (optional)
    
    Returns:
        str: Mermaid diagram content
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    
    config_file = 'data/node.json'
    node_resolver = NodeResolver(config_file)
    
    sequences = []
    entities = set()
    # Track all node types seen for each address
    address_node_types = {}
    # Track first appearance time for each entity
    entity_first_time = {}
    packet_count = 0
    processed_count = 0
    
    if verbose:
        print(f"Processing {capture_file}...")
    
    try:
        pcap = pyshark.FileCapture(capture_file)
        
        for packet in pcap:
            packet_count += 1
            
            if verbose and packet_count % 100 == 0:
                print(f"  Processed {packet_count} packets...")
            
            # Get packet info with timestamp
            info = get_packet_info(packet, node_resolver, verbose)
            
            if info:
                message = info['message'] if isinstance(info, dict) else info
                timestamp = info.get('timestamp') if isinstance(info, dict) else None
                
                # Check for duplicates
                if message not in sequences:
                    sequences.append(message)
                    
                    # Extract base addresses and node types
                    for entity in [message[0], message[2]]:  # src and dst
                        # Track first appearance time
                        base_entity = entity.split('\\n[')[0] if '\\n[' in entity else entity
                        if timestamp and base_entity not in entity_first_time:
                            entity_first_time[base_entity] = timestamp
                        
                        if '\\n[' in entity:
                            base_address, node_part = entity.split('\\n[')
                            node_type = node_part.rstrip(']')
                            
                            # Aggregate node types for this address
                            if base_address not in address_node_types:
                                address_node_types[base_address] = set()
                            address_node_types[base_address].add(node_type)
                            
                            # Add entity as-is for now (we'll consolidate later)
                            entities.add(entity)
                        else:
                            entities.add(entity)
                            if entity not in address_node_types:
                                address_node_types[entity] = set()
                    
                    processed_count += 1
                    
                    if verbose:
                        print(f"  Message {processed_count}: {message[0]} -> {message[2]} : {message[4]}")
        pcap.close()    
        
        # Post-process entities to consolidate node types
        consolidated_entities = set()
        entity_mapping = {}
        
        for entity in entities:
            if '\\n[' in entity:
                base_address, node_part = entity.split('\\n[')
                node_type = node_part.rstrip(']')
            else:
                base_address = entity
                node_type = None
            
            # Get all node types for this address
            all_types = address_node_types.get(base_address, set())
            
            if all_types:
                # Create consolidated entity with all node types
                types_str = '/'.join(sorted(all_types))
                consolidated = f"{base_address}\\n[{types_str}]"
            else:
                consolidated = base_address
            
            consolidated_entities.add(consolidated)
            
            # Map original entity to consolidated version
            entity_mapping[entity] = consolidated
        
        # Update sequences to use consolidated entities
        updated_sequences = []
        for seq in sequences:
            updated_seq = [
                entity_mapping.get(seq[0], seq[0]),  # src
                seq[1],  # arrow
                entity_mapping.get(seq[2], seq[2]),  # dst
                seq[3],  # arrow
                seq[4]   # message (already includes timestamp)
            ]
            # Avoid duplicates after consolidation
            if updated_seq not in updated_sequences:
                updated_sequences.append(updated_seq)
        
        # Sort entities by first appearance time
        entity_order = {}
        for entity in consolidated_entities:
            base_entity = entity.split('\\n[')[0] if '\\n[' in entity else entity
            if base_entity in entity_first_time:
                entity_order[entity] = entity_first_time[base_entity]
            else:
                entity_order[entity] = float('inf')
        
        sorted_entities = sorted(consolidated_entities, key=lambda x: entity_order[x])
        
        if verbose:
            print(f"Processed {packet_count} packets, found {processed_count} unique messages")
            print(f"Found {len(consolidated_entities)} unique entities")
            if address_node_types:
                print("Node type mapping:")
                for addr, types in address_node_types.items():
                    if types:
                        print(f"  {addr}: {', '.join(sorted(types))}")
        
        if not updated_sequences:
            if verbose:
                print("No messages found!")
            return None
        
        # Generate Mermaid diagram with sorted entities
        mermaid_content = generate_mermaid(updated_sequences, sorted_entities)
        
        # print("Diagram generation complete.")
        return mermaid_content
    
    except Exception as e:
        if verbose:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
        return None

def generate_mermaid(sequences, entities):
    """
    Generate Mermaid sequence diagram content with entities sorted by appearance
    
    Args:
        sequences: List of message sequences
        entities: List of entities sorted by first appearance time
    
    Returns:
        str: Mermaid diagram content
    """
    
    # Create Mermaid diagram
    mermaid = ["sequenceDiagram", "    autonumber"]
    
    # Add participants in order of first appearance
    entity_map = {}
    participant_counter = {}
    
    for entity in entities:  # entities is already sorted by first appearance
        # Extract base address and node type if present
        if '\\n[' in entity:
            # Entity has format: "address\n[node_type]"
            base_address, node_part = entity.split('\\n[')
            node_type = node_part.rstrip(']')
            
            # Create a unique identifier based on both address and node type
            unique_key = f"{base_address}_{node_type}"
        else:
            base_address = entity
            node_type = None
            unique_key = base_address
        
        # Sanitize the unique key for use as Mermaid identifier
        safe_id = unique_key.replace('.', '_').replace('[', '').replace(']', '').replace('-', '_').replace(':', '_').replace('/', '_')
        
        # Ensure uniqueness if same ID already exists
        if safe_id in participant_counter:
            participant_counter[safe_id] += 1
            safe_id = f"{safe_id}_{participant_counter[safe_id]}"
        else:
            participant_counter[safe_id] = 1
        
        entity_map[entity] = safe_id
        
        # Create the display label
        if node_type:
            # Use HTML break in the alias (display text), not in the identifier
            display_label = f"{base_address}<br/>[{node_type}]"
            mermaid.append(f"    participant {safe_id} as {display_label}")
        else:
            # No node type, just use the address
            mermaid.append(f"    participant {safe_id} as {base_address}")
    
    # Add messages
    for seq in sequences:
        src_safe = entity_map[seq[0]]
        dst_safe = entity_map[seq[2]]
        arrow = seq[1]
        msg = seq[4]
        
        # Convert arrow style to Mermaid format
        if arrow == "->>":
            mermaid_arrow = "->>"
        elif arrow == "-->":
            mermaid_arrow = "-->"
        else:
            mermaid_arrow = "->"
        
        mermaid.append(f"    {src_safe}{mermaid_arrow}{dst_safe}: {msg}")
    
    return "\n".join(mermaid)


def generate_html_file(capture_file, output_file, verbose=False):
    """
    Generate HTML file with Mermaid diagram (timestamps integrated in messages)
    
    Args:
        capture_file: Path to the PCAP file
        output_file: Path for output HTML file
        verbose: Enable verbose output
    """
    
    mermaid_content = process_pcap(capture_file, verbose)
    if not mermaid_content:
        print("Failed to generate diagram")
        return
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <script>
        mermaid.initialize({{
            startOnLoad:true,
            theme: 'default',
            sequence: {{
                showSequenceNumbers: true,
                wrap: false,
                width: 150,
                messageSpacing: 50,  // Increased to accommodate timestamp
                boxTextMargin: 5,
                noteMargin: 10,
                messageMargin: 35,
                mirrorActors: false,
                bottomMarginAdj: 10,
                useMaxWidth: false
            }}
        }});
    </script>
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background: #f5f5f5;
        }}

        .container {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px;
            overflow-x: auto;
        }}
        
        .mermaid {{
            min-width: 1200px;
        }}
        
        /* Style for message text with timestamp */
        .messageText {{
            font-size: 12px !important;
        }}
        
        /* Style for timestamp within messages */
        .messageText tspan:last-child {{
            font-size: 10px !important;
            fill: #666 !important;
            font-style: italic !important;
        }}
        
        h1 {{
            color: #333;
            border-bottom: 2px solid #5e35b1;
            padding-bottom: 10px;
        }}
    </style>
</head>
<body>
    <h1>Mobile Network Call Flow Analysis</h1>
    <div class="container">
        <div class="mermaid">
{mermaid_content}
        </div>
    </div>
</body>
</html>"""
    
    with open(output_file, 'w', encoding="utf-8") as f:
        f.write(html)
    
    print(f"Output written to {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mobile Network Call Flow Analyzer with Integrated Timeline")
    parser.add_argument("-f", "--file", required=True, help="PCAP file to analyze")
    parser.add_argument("-o", "--output", help="Output HTML file (optional)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # If output file specified, generate HTML file
    if args.output:
        generate_html_file(args.file, args.output, args.verbose)
    else:
        # Otherwise just print the Mermaid content
        mermaid_content = process_pcap(args.file, args.verbose)
        if mermaid_content:
            print("=== MERMAID DIAGRAM ===")
            print(mermaid_content)