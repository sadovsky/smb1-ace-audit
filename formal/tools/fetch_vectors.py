"""Fetch SingleStepTests nes6502 vectors (MIT licence, public test data).

    python3 formal/tools/fetch_vectors.py <dir> [--count N|all] [--jobs J]

`nes6502/v1` holds one file per opcode with 10,000 recorded instructions each.
`--count 300` (the default) keeps the first 300 per opcode, about 90 MB, which
is what `formal.validate_model` samples.  `--count all` keeps every vector,
about 1.4 GB on disk; put that under `~/big` and not in the repository.

The vectors are third-party test data and are not stored in this repository.
Requests carry a generic user agent and no identifying information.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import io
import json
import os
import sys
import urllib.request

BASE = ("https://raw.githubusercontent.com/SingleStepTests/65x02"
        "/main/nes6502/v1")
#: a generic client name: no contact details, nothing about the operator
USER_AGENT = "nes6502-vector-fetch/1.0"


def fetch(opcode: int, directory: str,
          count: int | None) -> tuple[int, int, str]:
    """Download one opcode's file.  Returns (opcode, kept, status)."""
    out = os.path.join(directory, f"{opcode:02x}.json")
    if os.path.exists(out):
        try:
            with open(out) as handle:
                have = len(json.load(handle))
        except (ValueError, OSError):
            have = -1
        if have >= 0 and (count is None or have >= count):
            return opcode, have, "cached"
    request = urllib.request.Request(
        f"{BASE}/{opcode:02x}.json",
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"})
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            raw = response.read()
            if response.headers.get("Content-Encoding") == "gzip":
                raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
        cases = json.loads(raw)
    except Exception as exc:                       # network or decode failure
        return opcode, 0, f"failed: {exc}"
    if count is not None:
        cases = cases[:count]
    with open(out + ".tmp", "w") as handle:
        json.dump(cases, handle)
    os.replace(out + ".tmp", out)
    return opcode, len(cases), "fetched"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--count", default="300",
                        help="vectors kept per opcode, or 'all'")
    parser.add_argument("--jobs", type=int, default=4,
                        help="parallel downloads (keep this small)")
    args = parser.parse_args(argv)
    count = None if args.count == "all" else int(args.count)
    os.makedirs(args.directory, exist_ok=True)

    failures, total = [], 0
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        futures = [pool.submit(fetch, op, args.directory, count)
                   for op in range(256)]
        for future in concurrent.futures.as_completed(futures):
            opcode, kept, status = future.result()
            if status.startswith("failed"):
                failures.append((opcode, status))
                print(f"{opcode:02x} {status}", flush=True)
            else:
                total += kept
                print(f"{opcode:02x} {status} {kept}", flush=True)
    print(f"done: {256 - len(failures)}/256 files, {total} vectors")
    if failures:
        print("failed: " + ", ".join(f"{op:02x}" for op, _ in failures),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
