"""Fetch SingleStepTests nes6502 vectors (MIT), first 300 per opcode.

    python3 formal/tools/fetch_vectors.py <directory>

The vectors are third-party test data, about 1 GB to download and 90 MB kept.
They are not stored in this repository.
"""
import json, os, sys, urllib.request
N = 300
os.makedirs(sys.argv[1], exist_ok=True); os.chdir(sys.argv[1])
for op in range(256):
    out = f"{op:02x}.json"
    if os.path.exists(out):
        continue
    url = f"https://raw.githubusercontent.com/SingleStepTests/65x02/main/nes6502/v1/{op:02x}.json"
    try:
        data = json.load(urllib.request.urlopen(url, timeout=120))
    except Exception as exc:
        print(op, "failed", exc, flush=True); continue
    with open(out + ".tmp", "w") as h:
        json.dump(data[:N], h)
    os.rename(out + ".tmp", out)
print("done", len([f for f in os.listdir('.') if f.endswith('.json')]))
