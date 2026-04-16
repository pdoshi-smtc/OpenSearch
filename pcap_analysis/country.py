import pyshark
import asyncio
import pandas as pd
import sys

import phonenumbers
from phonenumbers import geocoder

# --- 🧠 Fix for Python 3.14 async event loop ---
def ensure_event_loop():
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

def get_country_name_from_code(cc):
    """Return country name from a 1–3 digit E.164 country code."""

    # Normalize input: remove whitespace, leading zeros, and make string
    cc = str(cc).strip().lstrip("0")
    return country_map.get(cc, "Unknown Country")


def extract_mcc_mnc_from_pcap(pcap_file):
    print("🔍 Extracting MCC and MNC from PCAP...")

    try:
        ensure_event_loop() 

        # Correct display filter (gsm_map instead of map)
        cap = pyshark.FileCapture(
            pcap_file,
            display_filter="diameter || gtp || gsm_map"
        )

        for pkt in cap:
            try:
                if hasattr(pkt.gsm_map, "e164_country_code"):
                    cc = pkt.gsm_map.e164_country_code
                    country_name = get_country_name_from_code(cc)
                    print(f"Country code: {cc} → {country_name}")
                                        
            except Exception:
                continue
        
    except Exception as e:
        print(f"⚠️ PyShark failed: {e}")
        print("💡 Try checking your Tshark installation or PCAP format.")
        

def main():
    pcap_file = r"pcap_analysis\sample_pcap\Identified_pcap_error_files\2g_3g_errors\Roaming_not_allowed.pcap"
    excel_file = r"data\\coverage.xlsx"

    extract_mcc_mnc_from_pcap(pcap_file)


if __name__ == "__main__":
    main()
