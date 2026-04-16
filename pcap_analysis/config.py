"""
PCAP Analysis Configuration Module
Contains configuration settings and constants for PCAP analysis
"""

import os

# Upload configuration
UPLOAD_FOLDER = os.environ.get('PCAP_UPLOAD_FOLDER', 'uploads')
MAX_FILE_SIZE = int(os.environ.get('PCAP_MAX_FILE_SIZE', 100 * 1024 * 1024))  # 100MB default
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}

# Analysis configuration
DEFAULT_MAX_DELTA = 1.0  # Maximum time delta for lost service detection
TSHARK_TIMEOUT = 30  # Timeout for tshark commands in seconds

# Node OPC mappings
NODE_MAPPINGS = {
    'hlr_opc': {
        "3100": "I-HSS-FE1-FKT"
    },
    'vty_stp_opc': {
        "33": "STP-I-VTY"
    },
    'fkt_stp_opc': {
        "5300": "STP-I-FKT"
    },
    'msc_opc': {
        "31": "STPA1-AWS"
    },
    'rp_opc': {
        "4215": "STP-BICS-MAR22"
    }
}

# Protocol message type mappings
GTPV2_MESSAGE_TYPES = {
    '32': 'Create Session Request',
    '33': 'Create Session Response',
    '36': 'Delete Session Request',
    '37': 'Delete Session Response',
    '34': 'Modify Bearer Request',
    '35': 'Modify Bearer Response'
}

DIAMETER_COMMAND_CODES = {
    '316': '3GPP-Update-Location',
    '318': '3GPP-Authentication-Information',
    '323': '3GPP-Notify',
    '324': '3GPP-Purge-UE',
    '321': '3GPP-Insert-Subscriber-Data',
    '272': 'Credit-Control',
    '280': 'Device-Watchdog'
}

DIAMETER_APPLICATION_IDS = {
    '16777251': '3GPP S6a/S6d',
    '16777252': '3GPP S13/S13\'',
    '16777267': '3GPP S9',
    '16777238': '3GPP Gx',
    '16777236': '3GPP Rx',
    '4': 'Diameter Credit-Control'
}

# Error definitions
ERROR_DESCRIPTIONS = {
    "unexpectedly_transient_failure": "Transient failures include the momentary loss of network connectivity to components and services, the temporary unavailability of a service, and timeouts that occur when a service is busy",
    "system_failure": "A general system failure has occurred in the network element",
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

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS