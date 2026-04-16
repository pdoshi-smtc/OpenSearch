## Needs
# Data required: 
# imsi, iccid
# Product version 
# public imsi to know the Roaming Sponser name and tell rs service is not available
# we can tell which specific RS  serviees are not available

# using 1 imis we get device iccid then we will get all imis for the specific iccid
# tell which rs are not available for that imis 
# need sim status to check if sim is retired
# need county we cannot use MCC MNC filter for Visisted Network eg person from india went to france

import pyshark
import asyncio
import pandas as pd
import sys


# --- 🧠 Fix for Python 3.14 async event loop ---
def ensure_event_loop():
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)


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
                if hasattr(pkt, 'diameter'):
                    fields = pkt.diameter._all_fields
                    imsi = fields.get('diameter.imsi', None)
                    mcc = fields.get('e212.mcc', None) or fields.get('diameter.mcc', None)
                    mnc = fields.get('e212.mnc', None) or fields.get('diameter.mnc', None)
                    if mcc or mnc:
                        print(f"📡 Diameter Found -> MCC={mcc}, MNC={mnc}, IMSI={imsi}")
                        return mcc, mnc, imsi
                        break
                    

                elif hasattr(pkt, 'gtp'):
                    fields = pkt.gtp._all_fields
                    imsi = fields.get('gtp.imsi', None)
                    mcc = fields.get('e212.mcc', None) or fields.get('gtp.mcc', None)
                    mnc = fields.get('e212.mnc', None) or fields.get('gtp.mnc', None)
                    if mcc or mnc:
                        print(f"📡 GTP Found -> MCC={mcc}, MNC={mnc}, IMSI={imsi}")
                        return mcc, mnc, imsi
                        break

                elif hasattr(pkt, 'gsm_map'):
                    fields = pkt.gsm_map._all_fields
                    # print(fields)
                    imsi = fields.get('e212.imsi', None)
                    mcc = fields.get('e212.mcc', None)
                    mnc = fields.get('e212.mnc', None)

                    print(mcc,mnc)
                    if imsi:
                        print(f"📡 MAP Found -> MCC={mcc}, MNC={mnc}, IMSI={imsi}")
                        return mcc, mnc, imsi
                        
            except Exception:
                continue

            print("❌ No MCC/MNC found in PCAP packets.")
        return None, None, None

    except Exception as e:
        print(f"⚠️ PyShark failed: {e}")
        print("💡 Try checking your Tshark installation or PCAP format.")
        return None, None, None


def find_coverage_in_excel(mcc, mnc, excel_file):
    product_version = 'SmartSIM 4.0 ADVANCED'
    print(f"\n📘 Searching for coverage in Excel: Product version={product_version} MCC={mcc}, MNC={mnc}")
    df = pd.read_excel(excel_file)
    
    match = df[(df['mcc'] == int(mcc)) & (df['mnc'] == int(mnc)) & (df['Product version'] == 'SmartSIM 4.0 ADVANCED')] if mcc and mnc and product_version else pd.DataFrame()
    # print(match)
    if not match.empty:
        row = match.iloc[0]
        print("\n✅ Coverage Match Found:")
        print(match[[ 'Product version', 'country', 'Roaming Sponsors', 'Available','Who blocked']].to_string(index=False))
        print(f"🤝 Roaming Sponsor: {row['Roaming Sponsors']}")
        print(f"📶 Available: {row['Available']}")
        return row
    else:
        print("❌ No matching MCC/MNC found in pcap file.")
        return None


def main():
    pcap_file = r"pcap_analysis\sample_pcap\Identified_pcap_error_files\2g_3g_errors\Roaming_not_allowed.pcap"
    excel_file = r"data\\coverage.xlsx"

    mcc, mnc, imsi = extract_mcc_mnc_from_pcap(pcap_file)
    if imsi:
        find_coverage_in_excel(mcc, mnc, excel_file)
    else:
        print("⚠️ Unable to determine MCC/MNC. Please check PCAP contents.")


if __name__ == "__main__":
    main()
