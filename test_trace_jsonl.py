import json
import tempfile
import unittest
from types import SimpleNamespace
from trace_jsonl import write_events

class TraceJSONLTests(unittest.TestCase):
    def test_writes_required_fields(self):
        event = SimpleNamespace(pc=0x8E16, opcode=0x6C, a=0x34, x=0, y=0x68, sp=0xFD, status=0x24, cycles=456)
        with tempfile.NamedTemporaryFile() as output:
            self.assertEqual(write_events(output.name, [event], frame=12, rom_sha1="abc"), 1)
            with open(output.name) as trace_file:
                row = json.loads(trace_file.read())
        self.assertEqual((row["pc"], row["opcode"], row["rom_sha1"]), ("0x8E16", "0x6C", "abc"))
