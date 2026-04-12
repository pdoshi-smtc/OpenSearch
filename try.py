import json
import os

file_path = 'data/data.json'

# ==============================
# STEP 1: BASIC FILE INFO
# ==============================
if not os.path.exists(file_path):
    print("❌ File not found")
    exit()

print("📁 File size (MB):", round(os.path.getsize(file_path)/1024/1024, 2))


# ==============================
# STEP 2: PREVIEW FILE START
# ==============================
print("\n--- FILE START PREVIEW ---")
with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
    for i in range(5):
        print(f.readline().strip())


# ==============================
# STEP 3: LOAD JSON
# ==============================
with open(file_path, 'r', encoding='utf-8') as f:
    data = json.load(f)

hits = data.get("hits", {}).get("hits", [])

print("\n📊 Total records loaded:", len(hits))
print("📊 OpenSearch total:", data.get("hits", {}).get("total"))


# ==============================
# STEP 4: ITERATE ONE BY ONE
# ==============================
print("\n--- ITERATING RECORDS ---")

for i, item in enumerate(hits):
    _id = item.get("_id")

    # Print first few
    if i < 5:
        print(f"Start Record {i+1}: {_id}")

    # Print middle record
    if i == len(hits)//2:
        print(f"Middle Record {i+1}: {_id}")

    # Print last few
    if i >= len(hits) - 5:
        print(f"End Record {i+1}: {_id}")

# ==============================
# STEP 5: LAST RECORD DIRECT
# ==============================
if hits:
    print("\n🔚 Last Record _id:", hits[-1].get("_id"))


# ==============================
# STEP 6: CHECK FILE END (RAW)
# ==============================
print("\n--- FILE END PREVIEW ---")
with open(file_path, 'rb') as f:
    f.seek(-300, 2)  # go near end
    print(f.read().decode(errors='ignore'))


# ==============================
# STEP 7: CHECK FOR 12TH DATE
# ==============================
found_12 = False

for item in hits:
    doc = item.get("_source", {}).get("doc", {})
    ts = doc.get("Event-Timestamp")

    if ts and ts.startswith("2026-04-12"):
        found_12 = True
        print("\n✅ Found 12th data:", ts)
        break

if not found_12:
    print("\n❌ No data found for 2026-04-12")