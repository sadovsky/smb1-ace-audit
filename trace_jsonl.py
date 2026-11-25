"""Structured writer for native instruction-trace events."""
from __future__ import annotations
import json
from pathlib import Path


def write_events(path: str, events, *, frame: int, rom_sha1: str, source: str = "controller_only") -> int:
    """Append native trace events as portable JSONL and return their count."""
    count = 0
    with Path(path).open("a", encoding="utf-8") as out:
        for event in events:
            row = {"frame": frame, "cycle": int(event.cycles),
                   "pc": f"0x{int(event.pc):04X}", "opcode": f"0x{int(event.opcode):02X}",
                   "a": f"0x{int(event.a):02X}", "x": f"0x{int(event.x):02X}",
                   "y": f"0x{int(event.y):02X}", "sp": f"0x{int(event.sp):02X}",
                   "status": f"0x{int(event.status):02X}", "source": source,
                   "rom_sha1": rom_sha1}
            out.write(json.dumps(row, sort_keys=True) + "\n")
            count += 1
    return count
