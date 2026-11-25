"""Access to nes-py's native instruction tracer, for corroboration only.

The nes-py checkout on this machine compiles an optional instruction tracer
into `lib_nes_env` (`nes_py/nes/include/tracer.hpp`) and exports it through the
ctypes boundary, but `nes_py.nes_env` does not bind those symbols, so
`NESEnv` exposes only per-frame RAM.  This module binds them.

Why it matters: it makes the cross-validation of `formal.dyn.tracer` an
instruction-by-instruction comparison against an independently written C++
emulator -- program counter, A, X, Y, S and P at every fetch -- instead of a
comparison of RAM once per frame.  It also gives a second, much faster source
for the observations that need only register state at a fetch (which program
counters are reached, the accumulator at each dispatch site, the stack
pointer's range), so those can be run over many more frames than the Python
interpreter manages.

What it cannot do, and why `formal.dyn.tracer` still exists: a trace event
carries no memory operand, so it cannot say what a cell held at a fetch or
which instruction wrote where, and nes-py takes an NMI only at a vertical
blank, so it cannot run the unconstrained-NMI experiment.

A trace event is 16 bytes: `u16 pc, u8 opcode, a, x, y, sp, status, flags`,
three pad bytes, then the low 32 bits of nes-py's instruction counter.  `flags`
bit 0 means the fetch was below `$8000`.
"""
from __future__ import annotations

import ctypes

import numpy as np

EVENT_DTYPE = np.dtype([
    ("pc", "<u2"), ("opcode", "u1"), ("a", "u1"), ("x", "u1"), ("y", "u1"),
    ("sp", "u1"), ("status", "u1"), ("flags", "u1"), ("pad", "u1", (3,)),
    ("index", "<u4"),
])
assert EVENT_DTYPE.itemsize == 16

TRACE_FLAG_NON_ROM = 0x01


def _bind():
    from nes_py.nes_env import _LIB
    void = ctypes.c_void_p
    signatures = {
        "EnableTrace": ([void, ctypes.c_int], None),
        "TraceWatch": ([void, ctypes.c_uint, ctypes.c_int], None),
        "TraceClearWatches": ([void], None),
        "TraceRecordNonROM": ([void, ctypes.c_int], None),
        "TraceSetCapacity": ([void, ctypes.c_uint], None),
        "TraceClear": ([void], None),
        "TraceCount": ([void], ctypes.c_uint),
        "TraceDropped": ([void], ctypes.c_ulonglong),
        "TraceActive": ([void], ctypes.c_int),
        "TraceGet": ([void, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint],
                     ctypes.c_uint),
    }
    missing = [name for name in signatures if not hasattr(_LIB, name)]
    if missing:
        raise RuntimeError(
            "this lib_nes_env has no instruction tracer (missing "
            + ", ".join(missing) + "); rebuild nes-py from its sources")
    for name, (argtypes, restype) in signatures.items():
        function = getattr(_LIB, name)
        function.argtypes = argtypes
        function.restype = restype
    return _LIB


class TracedNESEnv:
    """`NESEnv` with the native tracer bound and drained per frame."""

    def __init__(self, rom_path: str, *, capacity: int = 1 << 21,
                 record_all: bool = True, watch: tuple[int, ...] = (),
                 record_non_rom: bool = False):
        from nes_py import NESEnv
        self.lib = _bind()
        self.env = NESEnv(rom_path)
        self.env.reset()
        handle = ctypes.c_void_p(self.env._env)
        self.handle = handle
        self.capacity = capacity
        self.lib.TraceSetCapacity(handle, capacity)
        self.lib.TraceClear(handle)
        if record_all:
            self.lib.EnableTrace(handle, 1)
        for address in watch:
            self.lib.TraceWatch(handle, address, 1)
        if record_non_rom:
            self.lib.TraceRecordNonROM(handle, 1)
        self._buffer = (ctypes.c_ubyte * (capacity * 16))()
        self.dropped = 0

    # -- stepping ----------------------------------------------------------

    def reset(self) -> None:
        self.env.reset()
        self.lib.TraceClear(self.handle)

    def step(self, action: int) -> np.ndarray:
        """Run one frame and return that frame's trace events."""
        self.lib.TraceClear(self.handle)
        self.env.step(action)
        return self.drain()

    def drain(self) -> np.ndarray:
        count = self.lib.TraceGet(self.handle, self._buffer, self.capacity)
        self.dropped = int(self.lib.TraceDropped(self.handle))
        events = np.frombuffer(self._buffer, dtype=EVENT_DTYPE, count=count)
        return events.copy()

    @property
    def ram(self) -> np.ndarray:
        return self.env.ram

    def close(self) -> None:
        self.env.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
