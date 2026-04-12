import json
from datetime import datetime, timedelta
import re

# Load alerts.json
with open('data/alerts.json', 'r', encoding='utf-8', errors='ignore') as f:
    alerts_data = json.load(f)

tiny_id = input("Enter tinyId: ")

# Find alert
alert_found = None
for alert in alerts_data.get("alerts", []):
    if alert.get("tinyId") == tiny_id:
        alert_found = alert
        break

if not alert_found:
    print("Alert not found!")
    exit()

# Extract message
message = alert_found.get("message", "")
print("\nMessage:", message)

# Extract VPLMN
match = re.search(r"-\s*(.*?)\s*\[", message)
if match:
    vplmn = match.group(1).strip()
else:
    print("VPLMN not found!")
    exit()

print("Extracted VPLMN:", vplmn)

# Get time
created_at_str = alert_found.get("createdAt_readable")
created_time = datetime.strptime(created_at_str, "%Y-%m-%d %H:%M:%S UTC")

# Time windows (±1 hour)
start_time = created_time - timedelta(hours=1)
end_time = created_time + timedelta(hours=1)

prev_start = start_time - timedelta(days=1)
prev_end = end_time - timedelta(days=1)

print("\nDEBUG: Time Window Current:", start_time, "to", end_time)
print("DEBUG: Time Window Previous:", prev_start, "to", prev_end)

# Load data.json
with open('data/data.json', 'r', encoding='utf-8') as f:
    data_json = json.load(f)

hits = data_json.get("hits", {}).get("hits", [])

# Count function
def count_entries(start, end):
    count = 0

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

        # Try both timestamps
        timestamp_str = doc.get("timestamp") or doc.get("Event-Timestamp")
        if not timestamp_str:
            continue

        try:
            ts = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
        except:
            continue

        if start <= ts <= end:
            count += 1

    return count

# Counts
current_count = count_entries(start_time, end_time)
previous_count = count_entries(prev_start, prev_end)

# Output
print("\n--- RESULTS ---")
print(f"VPLMN: {vplmn}")
print(f"Current Count: {current_count}")
print(f"Previous Day Count: {previous_count}")