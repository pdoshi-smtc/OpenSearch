import json
from datetime import datetime, timedelta
import re

# ---------------- LOAD ALERTS ----------------
with open('data/alerts.json', 'r', encoding='utf-8', errors='ignore') as f:
    alerts_data = json.load(f)

tiny_id = input("Enter tinyId: ")

# ---------------- FIND ALERT ----------------
alert_found = None
for alert in alerts_data.get("alerts", []):
    if alert.get("tinyId") == tiny_id:
        alert_found = alert
        break

if not alert_found:
    print("Alert not found!")
    exit()

# ---------------- EXTRACT MESSAGE ----------------
message = alert_found.get("message", "")
print("\nMessage:", message)

# ---------------- EXTRACT VPLMN ----------------
match = re.search(r"-\s*(.*?)\s*\[", message)
if match:
    vplmn = match.group(1).strip()
else:
    print("VPLMN not found!")
    exit()

print("Extracted VPLMN:", vplmn)

# ---------------- TIME HANDLING ----------------
created_at_str = alert_found.get("createdAt_readable")
created_time = datetime.strptime(created_at_str, "%Y-%m-%d %H:%M:%S UTC")

# Time windows (±1 hour)
start_time = created_time - timedelta(hours=1)
end_time = created_time + timedelta(hours=1)

prev_start = start_time - timedelta(days=1)
prev_end = end_time - timedelta(days=1)

print("\nDEBUG: Time Window Current:", start_time, "to", end_time)
print("DEBUG: Time Window Previous:", prev_start, "to", prev_end)

# ---------------- LOAD DATA ----------------
with open('data/data.json', 'r', encoding='utf-8') as f:
    data_json = json.load(f)

hits = data_json.get("hits", {}).get("hits", [])

# ---------------- ANALYSIS FUNCTION ----------------
def analyze_entries(start, end):
    count = 0

    unique_customers = set()
    unique_roaming_partners = set()
    unique_sim_versions = set()
    unique_service_types = set()

    for item in hits:
        doc = item.get("_source", {}).get("doc", {})

        # Normalize values
        doc_vplmn = doc.get("vplmn", "").strip()
        result_detail = doc.get("result_detail", "").strip().lower()

        # Filters
        if doc_vplmn != vplmn:
            continue

        if result_detail != "lost-service":
            continue

        # Timestamp handling
        timestamp_str = doc.get("timestamp") or doc.get("Event-Timestamp")
        if not timestamp_str:
            continue

        try:
            ts = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
        except:
            continue

        if start <= ts <= end:
            count += 1

            # Collect unique values
            customer = doc.get("customer_name", "").strip()
            partner = doc.get("roaming_partner", "").strip()
            sim_version = doc.get("sim_version", "").strip()
            service_type = doc.get("service_type", "").strip()

            if customer:
                unique_customers.add(customer)
            if partner:
                unique_roaming_partners.add(partner)
            if sim_version:
                unique_sim_versions.add(sim_version)
            if service_type:
                unique_service_types.add(service_type)

    return {
        "count": count,
        "customers": unique_customers,
        "roaming_partners": unique_roaming_partners,
        "sim_versions": unique_sim_versions,
        "service_types": unique_service_types
    }

# ---------------- RUN ANALYSIS ----------------
current_data = analyze_entries(start_time, end_time)
previous_data = analyze_entries(prev_start, prev_end)

# ---------------- OUTPUT ----------------
print("\n--- RESULTS ---")
print(f"VPLMN: {vplmn}")

print("\n--- CURRENT WINDOW ---")
print(f"Count: {current_data['count']}")

print("\nUnique Customers:" )
print(", ".join(sorted(current_data['customers'])) or "None")

print("\nRoaming Partners:")
print(", ".join(sorted(current_data['roaming_partners'])) or "None")

print("\nSIM Versions:")
print(", ".join(sorted(current_data['sim_versions'])) or "None")

print("\nService Types:")
print(", ".join(sorted(current_data['service_types'])) or "None")

print("\n--- PREVIOUS DAY WINDOW ---")
print(f"Count: {previous_data['count']}")