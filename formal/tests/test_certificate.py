"""Tests for the joint-invariant certificate checker.

Every fixture is an original synthetic program in an otherwise zeroed 32 KiB
image; no ROM is needed and none is used.  The point of these tests is not
that the checker accepts certificates -- that is easy and worthless -- but
that it *rejects* wrong ones.  Each verification-condition kind therefore has
a negative test in `NegativeTests`: a certificate that is wrong in exactly one
way, which must come back `fails`.
"""
from __future__ import annotations

import unittest

from analysis.cfg import CFG, JUMPENGINE
from formal.verify.certificate import (FAILS, FORMAT, HOLDS, Checker, Context,
                                       parse_context)


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

def image(blobs: dict[int, bytes], *, nmi: int | None = None,
          reset: int | None = None, irq: int = 0xFFF0) -> bytes:
    """A 32 KiB PRG that is zero except for `blobs` and the three vectors."""
    prg = bytearray(0x8000)
    for base, blob in blobs.items():
        prg[base - 0x8000:base - 0x8000 + len(blob)] = blob
    def word(address: int, value: int) -> None:
        prg[address - 0x8000] = value & 0xFF
        prg[address - 0x8000 + 1] = value >> 8 & 0xFF
    word(0xFFFA, nmi if nmi is not None else 0x8000)
    word(0xFFFC, reset if reset is not None else 0x8000)
    word(0xFFFE, irq)
    return bytes(prg)


def graph_of(prg: bytes, entries: dict[int, str]) -> CFG:
    graph = CFG(lambda a: prg[(a & 0xFFFF) - 0x8000],
                code_range=(0x8000, 0x10000))
    for address, why in entries.items():
        graph.add_entry(address, why)
    return graph.build()


def certificate(routines: dict, contexts: dict, **extra) -> dict:
    return {"format": FORMAT, "routines": routines, "contexts": contexts,
            **extra}


def verdicts(checker: Checker, *, globals_too: bool = False) -> dict:
    return {v.id: v for v in checker.check_all(globals_too=globals_too)}


def failing(results: dict) -> list[str]:
    return sorted(k for k, v in results.items() if v.status != HOLDS)


#: `LDA #$05 / STA $0300 / RTS` at $9000
SIMPLE = bytes.fromhex("a905" "8d0003" "60")
SIMPLE_ROUTINE = {"9000": {"kind": "normal", "mod": ["0300"], "use": 0,
                           "post": {"a": [[5, 5]],
                                    "cells": {"0300": [[5, 5]]}}}}
SIMPLE_CONTEXTS = {
    "9000@9000/0": {"depth": [0], "frame": True},
    "9002@9000/0": {"a": [[5, 5]], "depth": [0], "frame": True},
    "9005@9000/0": {"a": [[5, 5]], "depth": [0], "frame": True,
                    "cells": {"0300": [[5, 5]]}},
}


MISSING = object()


def simple_checker(routines=MISSING, contexts=MISSING) -> Checker:
    prg = image({0x9000: SIMPLE})
    graph = graph_of(prg, {0x9000: "test"})
    return Checker(certificate(
        SIMPLE_ROUTINE if routines is MISSING else routines,
        SIMPLE_CONTEXTS if contexts is MISSING else contexts), graph, prg,
        timeout_ms=20000)


# --------------------------------------------------------------------------


class ParsingTests(unittest.TestCase):
    def test_context_keys_round_trip(self):
        self.assertEqual(parse_context("92C8@8212/1"),
                         Context(0x92C8, 0x8212, 1))
        self.assertEqual(Context(0x92C8, 0x8212, 1).key, "92C8@8212/1")

    def test_an_unknown_format_is_refused(self):
        with self.assertRaises(ValueError):
            Checker({"format": "nope", "routines": {}, "contexts": {}},
                    graph_of(image({}), {}), image({}))

    def test_a_context_without_a_contract_is_refused(self):
        with self.assertRaises(ValueError):
            simple_checker(routines={}, contexts=SIMPLE_CONTEXTS)


class PositiveTests(unittest.TestCase):
    """Certificates that are right, so that the negatives mean something."""

    def test_a_straight_line_routine_is_accepted(self):
        results = verdicts(simple_checker())
        self.assertEqual(failing(results), [])
        self.assertIn("VC-RET-POST:9005@9000/0", results)
        self.assertIn("VC-MOD:9002@9000/0:0", results)

    def test_pushes_are_charged_to_the_routine_stack_area(self):
        #: $9000 PHA / $9001 PLA / $9002 RTS
        prg = image({0x9000: bytes.fromhex("48" "68" "60")})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {"9000": {"kind": "normal", "mod": [], "use": 1,
                             "post": {}}}
        # the stack pointer has to be bounded away from the bottom of the
        # page, or the push wraps and `S <= s0` fails -- which is the point
        # of that conjunct
        contexts = {"9000@9000/0": {"depth": [0], "frame": True,
                                    "s": [[0x80, 0xFF]]},
                    "9001@9000/0": {"depth": [1], "frame": True,
                                    "s": [[0x7F, 0xFE]]},
                    "9002@9000/0": {"depth": [0], "frame": True,
                                    "s": [[0x80, 0xFF]]}}
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertEqual(failing(results), [])

    def test_a_push_that_could_wrap_the_stack_is_rejected(self):
        #: the same routine with the stack pointer unbounded
        prg = image({0x9000: bytes.fromhex("48" "68" "60")})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {"9000": {"kind": "normal", "mod": [], "use": 1,
                             "post": {}}}
        contexts = {"9000@9000/0": {"depth": [0], "frame": True},
                    "9001@9000/0": {"depth": [1], "frame": True},
                    "9002@9000/0": {"depth": [0], "frame": True}}
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertIn("VC-STEP:9000@9000/0:0", failing(results))

    def test_a_branch_the_flags_forbid_makes_the_target_false(self):
        #: $9000 LDX #$08 / $9002 BNE $9006 / $9004 JAM / $9005 JAM /
        #: $9006 RTS -- the BNE is always taken, so the JAMs are unreachable
        prg = image({0x9000: bytes.fromhex("a208" "d002" "0202" "60")})
        graph = graph_of(prg, {0x9000: "test"})
        self.assertIn(0x9004, graph.nodes)
        routines = {"9000": {"kind": "normal", "mod": [], "use": 0,
                             "post": {}}}
        contexts = {"9000@9000/0": {"depth": [0], "frame": True},
                    "9002@9000/0": {"x": [[8, 8]], "z": False,
                                    "depth": [0], "frame": True},
                    "9006@9000/0": {"x": [[8, 8]], "z": False,
                                    "depth": [0], "frame": True}}
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertEqual(failing(results), [])
        forbidden = {v.id: v for v in Checker(
            certificate(routines, contexts), graph, prg).vc_forbidden()}
        self.assertEqual(forbidden["VC-FORBIDDEN:9004"].status, HOLDS)

    def test_a_comparison_relation_lets_a_branch_bound_a_register(self):
        #: $9000 CMP #$05 / $9002 BCS $9007 / $9004 STA $0300 / $9007 RTS
        prg = image({0x9000: bytes.fromhex("c905" "b003" "8d0003" "60")})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {"9000": {"kind": "normal", "mod": ["0300"], "use": 0,
                             "post": {}}}
        contexts = {
            "9000@9000/0": {"depth": [0], "frame": True},
            "9002@9000/0": {"depth": [0], "frame": True,
                            "rel": [["c", "uge", "a", 5]]},
            # the taken side of BCS; A is not bounded here
            "9007@9000/0": {"depth": [0], "frame": True},
            # the fallthrough: carry clear, so A < 5
            "9004@9000/0": {"a": [[0, 4]], "depth": [0], "frame": True,
                            "c": False},
        }
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertEqual(failing(results), [])

    def test_a_call_uses_the_callee_contract_and_the_frame_rule(self):
        #: $9000 JSR $9010 / $9003 LDA $0300 / $9006 RTS
        #: $9010 LDA #$07 / $9012 STA $0300 / $9015 RTS
        prg = image({0x9000: bytes.fromhex("201090" "ad0003" "60"),
                     0x9010: bytes.fromhex("a907" "8d0003" "60")})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {
            "9000": {"kind": "normal", "mod": ["0300"], "use": 2,
                     "post": {}},
            "9010": {"kind": "normal", "mod": ["0300"], "use": 0,
                     "post": {"a": [[7, 7]], "en": [0],
                              "cells": {"0300": [[7, 7]]}}},
        }
        contexts = {
            "9000@9000/0": {"depth": [0], "frame": True},
            "9003@9000/0": {"depth": [0], "frame": True,
                            "cells": {"0300": [[7, 7]]}},
            "9006@9000/0": {"depth": [0], "frame": True,
                            "a": [[7, 7]], "cells": {"0300": [[7, 7]]}},
            "9010@9010/0": {"depth": [0], "frame": True},
            "9012@9010/0": {"depth": [0], "frame": True, "a": [[7, 7]]},
            "9015@9010/0": {"depth": [0], "frame": True, "a": [[7, 7]],
                            "cells": {"0300": [[7, 7]]}},
        }
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertEqual(failing(results), [])

    def test_a_store_outside_the_frame_keeps_it_intact(self):
        #: $9000 STA $01F0 / $9003 RTS, with S pinned to $FF so the entry
        #: frame is at $0100-$0101 and cannot be the store's target
        prg = image({0x9000: bytes.fromhex("8df001" "60")})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {"9000": {"kind": "normal", "mod": ["01F0"], "use": 0,
                             "post": {}}}
        contexts = {"9000@9000/0": {"depth": [0], "frame": True,
                                    "s": [[0xFF, 0xFF]]},
                    "9003@9000/0": {"depth": [0], "frame": True,
                                    "s": [[0xFF, 0xFF]]}}
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertEqual(failing(results), [])


class ExtensionTests(unittest.TestCase):
    """The two conjuncts section 3 does not have: `pairs` and `zero_runs`."""

    def test_a_pair_set_survives_a_store_to_one_of_its_cells(self):
        #: $9000 LDA #$04 / $9002 STA $0300 / $9005 RTS, with the pair
        #: ($0300, $0301) constrained on both sides of the store
        prg = image({0x9000: bytes.fromhex("a904" "8d0003" "60")})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {"9000": {"kind": "normal", "mod": ["0300"], "use": 0,
                             "post": {}}}
        contexts = {
            "9000@9000/0": {"depth": [0], "frame": True,
                            "cells": {"0301": [[9, 9]]}},
            "9002@9000/0": {"depth": [0], "frame": True, "a": [[4, 4]],
                            "cells": {"0301": [[9, 9]]}},
            "9005@9000/0": {"depth": [0], "frame": True, "a": [[4, 4]],
                            "pairs": {"0300,0301": [[4, 9]]}},
        }
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertEqual(failing(results), [])

    def test_a_wrong_pair_set_is_rejected(self):
        prg = image({0x9000: bytes.fromhex("a904" "8d0003" "60")})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {"9000": {"kind": "normal", "mod": ["0300"], "use": 0,
                             "post": {}}}
        contexts = {
            "9000@9000/0": {"depth": [0], "frame": True,
                            "cells": {"0301": [[9, 9]]}},
            "9002@9000/0": {"depth": [0], "frame": True, "a": [[4, 4]],
                            "cells": {"0301": [[9, 9]]}},
            "9005@9000/0": {"depth": [0], "frame": True, "a": [[4, 4]],
                            "pairs": {"0300,0301": [[5, 9]]}},
        }
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertIn("VC-STEP:9002@9000/0:0", failing(results))

    #: $9000 LDY #$03 / LDA #$00 / $9004 STA $0300,Y / DEY / CPY #$FF /
    #: $900A BNE $9004 / $900C RTS -- the clearing-loop shape
    CLEAR = bytes.fromhex("a003" "a900" "990003" "88" "c0ff" "d0f8" "60")

    def clear_contexts(self, final):
        return {
            "9000@9000/0": {"depth": [0], "frame": True},
            "9002@9000/0": {"depth": [0], "frame": True, "y": [[3, 3]]},
            "9004@9000/0": {"depth": [0], "frame": True, "a": [[0, 0]],
                            "zero_runs": [{"page": 3, "reg": "y", "cmp": "ule1", "upto": 3}]},
            "9007@9000/0": {"depth": [0], "frame": True, "a": [[0, 0]],
                            "zero_runs": [{"page": 3, "reg": "y", "cmp": "ule", "upto": 3}]},
            "9008@9000/0": {"depth": [0], "frame": True, "a": [[0, 0]],
                            "zero_runs": [{"page": 3, "reg": "y", "cmp": "ule1", "upto": 3}]},
            "900A@9000/0": {"depth": [0], "frame": True, "a": [[0, 0]],
                            "zero_runs": [{"page": 3, "reg": "y", "cmp": "ule1", "upto": 3}],
                            "rel": [["z", "eq", "y", 0xFF]]},
            "900C@9000/0": {"depth": [0], "frame": True, "a": [[0, 0]],
                            "cells": final},
        }

    def test_a_parametric_zero_run_carries_a_clearing_loop(self):
        contexts = self.clear_contexts(
            {f"030{k}": [[0, 0]] for k in range(4)})
        prg = image({0x9000: self.CLEAR})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {"9000": {"kind": "normal", "mod": ["0300-03FF"],
                             "use": 0, "post": {}}}
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertEqual(failing(results), [])

    def test_claiming_one_cell_too_many_cleared_is_rejected(self):
        contexts = self.clear_contexts(
            {f"030{k}": [[0, 0]] for k in range(5)})
        prg = image({0x9000: self.CLEAR})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {"9000": {"kind": "normal", "mod": ["0300-03FF"],
                             "use": 0, "post": {}}}
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertIn("VC-STEP:900A@9000/0:1", failing(results))


class EnableBitTests(unittest.TestCase):
    """`no_ppu`: the ghost enable bit is the identity across a call."""

    #: $9000 JSR $9010 / $9003 RTS ;  $9010 STA $0300 / $9013 RTS
    QUIET = {0x9000: bytes.fromhex("201090" "60"),
             0x9010: bytes.fromhex("8d0003" "60")}
    #: the callee writes PPU control instead
    LOUD = {0x9000: bytes.fromhex("201090" "60"),
            0x9010: bytes.fromhex("8d0020" "60")}

    def build(self, blobs, *, no_ppu: bool, caller_en: int = 0):
        prg = image(blobs)
        graph = graph_of(prg, {0x9000: "test"})
        cell = ["0300"] if blobs is self.QUIET else []
        routines = {
            "9000": {"kind": "normal", "mod": cell, "use": 2, "post": {},
                     "no_ppu": False},
            "9010": {"kind": "normal", "mod": cell, "use": 0,
                     "no_ppu": no_ppu, "post": {"en": [0, 1]}},
        }
        contexts = {
            f"9000@9000/{caller_en}": {"depth": [0], "frame": True},
            f"9003@9000/{caller_en}": {"depth": [0], "frame": True},
            f"9010@9010/{caller_en}": {"depth": [0], "frame": True},
            f"9013@9010/{caller_en}": {"depth": [0], "frame": True},
        }
        return Checker(certificate(routines, contexts), graph, prg)

    def test_a_quiet_callee_keeps_the_enable_bit(self):
        results = verdicts(self.build(self.QUIET, no_ppu=True))
        self.assertEqual(failing(results), [])

    def test_without_no_ppu_the_flat_post_forces_both_contexts(self):
        results = verdicts(self.build(self.QUIET, no_ppu=False))
        self.assertIn("VC-CALL-RETURN:9000@9000/0->9010", failing(results))

    def test_a_no_ppu_routine_that_writes_ppu_control_is_rejected(self):
        results = verdicts(self.build(self.LOUD, no_ppu=True))
        self.assertIn("VC-MOD:9010@9010/0:0", failing(results))


class ContractRelationTests(unittest.TestCase):
    """`preserves` and `en_bit`: the shape of `$8EED`.

    A three-instruction routine that writes the accumulator to PPU control
    and to a RAM mirror.  It is called both to enable and to disable NMI, so
    a flat `Post.en` would leak the enable bit to both call sites; the
    relation `en = bit 7 of A` plus `A` being preserved pins it instead.
    """

    #: $9000 LDA #$00 / JSR $9020 / $9005 LDA #$80 / JSR $9020 / $900A RTS
    #: $9020 STA $2000 / STA $0778 / RTS
    BLOBS = {0x9000: bytes.fromhex("a900" "202090" "a980" "202090" "60"),
             0x9020: bytes.fromhex("8d0020" "8d7807" "60")}

    def build(self, *, preserves=("a",), en_bit=("a", 7), contexts=None):
        prg = image(self.BLOBS)
        graph = graph_of(prg, {0x9000: "test"})
        post = {"cells": {"0778": [[0, 255]]}}
        if preserves:
            post["preserves"] = list(preserves)
        if en_bit:
            post["en_bit"] = list(en_bit)
        routines = {
            "9000": {"kind": "normal", "mod": ["0778"], "use": 2,
                     "post": {}, "no_ppu": False},
            "9020": {"kind": "normal", "mod": ["0778"], "use": 0,
                     "post": post, "no_ppu": False},
        }
        default = {
            "9000@9000/0": {"depth": [0], "frame": True},
            "9002@9000/0": {"depth": [0], "frame": True, "a": [[0, 0]]},
            # A had bit 7 clear, so the call left the enable bit clear
            "9005@9000/0": {"depth": [0], "frame": True},
            "9007@9000/0": {"depth": [0], "frame": True,
                            "a": [[0x80, 0x80]]},
            # ... and here it set it
            "900A@9000/1": {"depth": [0], "frame": True},
            # the entry context is shared by both call sites
            "9020@9020/0": {"depth": [0], "frame": True, "keeps": ["a"],
                            "a": [[0, 0], [0x80, 0x80]]},
            # the write to PPU control splits them again
            "9023@9020/0": {"depth": [0], "frame": True, "keeps": ["a"],
                            "a": [[0, 0]]},
            "9026@9020/0": {"depth": [0], "frame": True, "keeps": ["a"],
                            "a": [[0, 0]]},
            "9023@9020/1": {"depth": [0], "frame": True, "keeps": ["a"],
                            "a": [[0x80, 0x80]]},
            "9026@9020/1": {"depth": [0], "frame": True, "keeps": ["a"],
                            "a": [[0x80, 0x80]]},
        }
        return Checker(certificate(
            routines, default if contexts is None else contexts), graph, prg)

    def test_the_relation_pins_the_enable_bit_at_both_call_sites(self):
        results = verdicts(self.build())
        # this fixture declares no handler, so its contexts with the enable
        # bit set cannot meet the NMI obligations; everything else must hold
        self.assertEqual([k for k in failing(results)
                          if "NMI" not in k], [])
        self.assertEqual(results["VC-CALL-RETURN:9002@9000/0->9020"].status,
                         HOLDS)
        self.assertEqual(results["VC-CALL-RETURN:9007@9000/0->9020"].status,
                         HOLDS)

    def test_without_the_relation_the_enable_bit_leaks(self):
        results = verdicts(self.build(en_bit=None))
        self.assertIn("VC-CALL-RETURN:9002@9000/0->9020", failing(results))

    def test_a_routine_that_does_not_preserve_what_it_claims_is_rejected(self):
        #: the same routine, but it clobbers A before returning
        blobs = dict(self.BLOBS)
        blobs[0x9020] = bytes.fromhex("8d0020" "8d7807" "a900" "60")
        prg = image(blobs)
        graph = graph_of(prg, {0x9000: "test"})
        routines = {
            "9020": {"kind": "normal", "mod": ["0778"], "use": 0,
                     "no_ppu": False,
                     "post": {"preserves": ["a"], "en_bit": ["a", 7],
                              "cells": {"0778": [[0, 255]]}}},
        }
        contexts = {
            "9020@9020/0": {"depth": [0], "frame": True, "keeps": ["a"],
                            "a": [[0, 0]]},
            "9023@9020/0": {"depth": [0], "frame": True, "keeps": ["a"],
                            "a": [[0, 0]]},
            "9026@9020/0": {"depth": [0], "frame": True, "keeps": ["a"],
                            "a": [[0, 0]]},
            "9028@9020/0": {"depth": [0], "frame": True, "a": [[0, 0]]},
        }
        routines["9020"]["post"]["en"] = [0]
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertIn("VC-RET-POST:9028@9020/0", failing(results))


class PageZeroingTests(unittest.TestCase):
    """`zero_pages` and the `when` guard, on a two-level clearing loop."""

    #: $9000 LDX #$01 / $9002 STX $07 / $9004 STA $0200,X / $9007 DEX /
    #: $9008 BPL $9002 / $900A RTS
    #: Each outer iteration clears exactly one cell, so after the loop both
    #: $0200 and $0201 are zero -- and that only survives the final `DEX`
    #: because the page comparison is signed.
    BLOB = bytes.fromhex("a201" "8607" "9d0002" "ca" "10f8" "60")

    def build(self, contexts):
        prg = image({0x9000: self.BLOB})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {"9000": {"kind": "normal", "mod": ["0007", "0200-02FF"],
                             "use": 0, "post": {}, "no_ppu": True}}
        return Checker(certificate(routines, contexts), graph, prg)

    def contexts(self, final):
        run = [{"page": 2, "reg": "x", "cmp": "ule1", "upto": 1}]
        return {
            "9000@9000/0": {"depth": [0], "frame": True},
            "9002@9000/0": {"depth": [0], "frame": True, "a": [[0, 0]],
                            "x": [[0, 1]], "zero_runs": run},
            "9004@9000/0": {"depth": [0], "frame": True, "a": [[0, 0]],
                            "x": [[0, 1]], "zero_runs": run},
            "9007@9000/0": {"depth": [0], "frame": True, "a": [[0, 0]],
                            "x": [[0, 1]],
                            "zero_runs": [{"page": 2, "reg": "x",
                                           "cmp": "ule", "upto": 1}]},
            "9008@9000/0": {"depth": [0], "frame": True, "a": [[0, 0]],
                            "x": [[0, 1], [255, 255]], "zero_runs": run,
                            "rel": [["n", "bit7sub", "x", 0]]},
            "900A@9000/0": {"depth": [0], "frame": True, "a": [[0, 0]],
                            "cells": final},
        }

    def test_the_loop_establishes_both_cells(self):
        contexts = self.contexts({"0200": [[0, 0]], "0201": [[0, 0]]})
        # A must be zero on entry for the stores to clear anything
        contexts["9000@9000/0"]["a"] = [[0, 0]]
        results = verdicts(self.build(contexts))
        self.assertEqual(failing(results), [])

    def test_claiming_a_cell_the_loop_never_reaches_is_rejected(self):
        contexts = self.contexts({"0200": [[0, 0]], "0201": [[0, 0]],
                                  "0202": [[0, 0]]})
        contexts["9000@9000/0"]["a"] = [[0, 0]]
        results = verdicts(self.build(contexts))
        self.assertIn("VC-STEP:9008@9000/0:1", failing(results))

    def test_a_guarded_run_applies_only_under_its_guard(self):
        """`when` makes a run conditional, so the wrong guard proves nothing."""
        contexts = self.contexts({"0200": [[0, 0]], "0201": [[0, 0]]})
        contexts["9000@9000/0"]["a"] = [[0, 0]]
        for key in ("9002@9000/0", "9004@9000/0", "9008@9000/0"):
            contexts[key]["zero_runs"] = [
                {"page": 2, "reg": "x", "cmp": "ule1", "upto": 1,
                 "when": ["y", 0x55]}]
        results = verdicts(self.build(contexts))
        self.assertIn("VC-STEP:9008@9000/0:1", failing(results))


class MachineTests(unittest.TestCase):
    """A whole toy machine: reset, idle loop, NMI handler, cold boot."""

    #: $9000 SEI / LDX #$FF / TXS / LDA #$80 / STA $2000 / JMP $9009
    ROOT = bytes.fromhex("78" "a2ff" "9a" "a980" "8d0020" "4c0990")
    #: $9100 LDA #$00 / STA $2000 / LDA #$80 / STA $2000 / RTI
    HANDLER = bytes.fromhex("a900" "8d0020" "a980" "8d0020" "40")

    def build(self, *, contexts=None, routines=None, **extra) -> Checker:
        prg = image({0x9000: self.ROOT, 0x9100: self.HANDLER},
                    reset=0x9000, nmi=0x9100)
        graph = graph_of(prg, {0x9000: "reset", 0x9100: "nmi"})
        default_routines = {
            "9000": {"kind": "root", "s0": 0xFF, "mod": [], "use": 0,
                     "post": {}},
            "9100": {"kind": "handler", "mod": [], "use": 0,
                     "post": {"en": [1]}},
        }
        default_contexts = {
            "9000@9000/0": {},
            "9001@9000/0": {},
            "9003@9000/0": {"x": [[0xFF, 0xFF]]},
            "9004@9000/0": {"s": [[0xFF, 0xFF]], "depth": [0]},
            "9006@9000/0": {"s": [[0xFF, 0xFF]], "depth": [0],
                            "a": [[0x80, 0x80]]},
            "9009@9000/1": {"s": [[0xFF, 0xFF]], "depth": [0]},
            "9100@9100/1": {"depth": [0], "frame": True, "status_i": True},
            "9102@9100/1": {"depth": [0], "frame": True, "status_i": True,
                            "a": [[0, 0]]},
            "9105@9100/0": {"depth": [0], "frame": True, "status_i": True},
            "9107@9100/0": {"depth": [0], "frame": True, "status_i": True,
                            "a": [[0x80, 0x80]]},
            "910A@9100/1": {"depth": [0], "frame": True, "status_i": True},
        }
        return Checker(certificate(
            routines or default_routines, contexts or default_contexts,
            i_frame={}, nmi_windows=["9100", "9102", "910A"],
            reset_clears_enable=True,
            reset_clears_enable_assumption="MA-PPU-RESET (toy)"), graph, prg)

    def test_the_toy_machine_is_fully_accepted(self):
        results = verdicts(self.build(), globals_too=True)
        self.assertEqual(failing(results), [])
        for key in ("VC-COLD", "VC-IRQ", "VC-SAFETY", "VC-COVERAGE",
                    "VC-RESET:any/0", "VC-NMI-ENTRY:9009@9000/1",
                    "VC-NMI-RESUME:9009@9000/1",
                    "VC-NMI-EXIT-I:910A@9100/1"):
            self.assertIn(key, results)
            self.assertEqual(results[key].status, HOLDS, key)

    def test_the_nmi_windows_are_reported_as_assumed_not_proved(self):
        results = verdicts(self.build(), globals_too=True)
        window = results["VC-NMI-WINDOW:9100@9100/1"]
        self.assertIn("MA-NMI-EDGE", window.detail["excluded_by"])

    def test_a_handler_that_leaves_nmi_disabled_breaks_the_resume(self):
        contexts = dict(self.build().raw["contexts"])
        routines = {
            "9000": {"kind": "root", "s0": 0xFF, "mod": [], "use": 0,
                     "post": {}},
            "9100": {"kind": "handler", "mod": [], "use": 0,
                     "post": {"en": [0]}},
        }
        results = verdicts(self.build(contexts=contexts, routines=routines),
                           globals_too=True)
        self.assertIn("VC-NMI-EXIT-EN:910A@9100/1", failing(results))


class DispatchTests(unittest.TestCase):
    """A jump engine of our own at the address the CFG treats as one."""

    #: $8E04 ASL A / TAY / INY / PLA / STA $04 / PLA / STA $05 /
    #:       LDA ($04),Y / STA $06 / INY / LDA ($04),Y / STA $07 /
    #:       JMP ($0006)
    #: Behaviourally a table dispatch, written here from scratch; the order of
    #: the INY and the pulls differs from any particular game's engine.
    ENGINE = bytes.fromhex("0a" "a8" "c8" "68" "8504" "68" "8505"
                           "b104" "8506" "c8" "b104" "8507" "6c0600")

    def build(self, contexts, *, entries=2, routines=None):
        #: $9000 JSR $8E04 / table of `entries` words / targets at $9010...
        table = b"".join(bytes([(0x9010 + 8 * i) & 0xFF,
                                (0x9010 + 8 * i) >> 8])
                         for i in range(entries))
        blobs = {0x8E04: self.ENGINE,
                 0x9000: bytes.fromhex("20048e") + table}
        for i in range(entries):
            blobs[0x9010 + 8 * i] = bytes.fromhex("60")       # RTS
        prg = image(blobs)
        graph = graph_of(prg, {0x9000: "test"})
        self.assertIn(0x9000, graph.dispatches)
        self.assertEqual(len(graph.dispatches[0x9000].entries), entries)
        default = {"9000": {"kind": "normal",
                            "mod": ["0004", "0005", "0006", "0007"],
                            "use": 2, "post": {}}}
        return Checker(certificate(routines or default, contexts), graph, prg)

    def base_contexts(self, index_values, *, entries=2, refine=None):
        contexts = {"9000@9000/0": {"a": index_values, "depth": [0],
                                    "frame": True, "s": [[0xFF, 0xFF]]}}
        if refine:
            contexts["9000@9000/0"].update(refine)
        for i in range(entries):
            target = 0x9010 + 8 * i
            contexts[f"{target:04X}@9000/0"] = {
                "depth": [0], "frame": True, "s": [[0xFF, 0xFF]]}
        return contexts

    def test_an_index_inside_the_table_dispatches_into_the_routine(self):
        checker = self.build(self.base_contexts([[0, 1]]))
        results = verdicts(checker)
        self.assertEqual(failing(results), [])
        self.assertEqual(results["VC-DISPATCH-INDEX:9000@9000/0"].status,
                         HOLDS)

    def test_the_cell_the_index_came_from_is_refined_at_each_target(self):
        """`A == RAM[$0300]` at the site plus index `i` gives `RAM[$0300] = i`."""
        contexts = {
            "9000@9000/0": {"a": [[0, 1]], "depth": [0], "frame": True,
                            "s": [[0xFF, 0xFF]], "copies": [["a", "0300"]],
                            "cells": {"0300": [[0, 1]]}},
            "9010@9000/0": {"depth": [0], "frame": True,
                            "s": [[0xFF, 0xFF]], "cells": {"0300": [[0, 0]]}},
            "9018@9000/0": {"depth": [0], "frame": True,
                            "s": [[0xFF, 0xFF]], "cells": {"0300": [[1, 1]]}},
        }
        results = verdicts(self.build(contexts))
        self.assertEqual(failing(results), [])

    def test_a_refinement_that_swaps_the_targets_is_rejected(self):
        contexts = {
            "9000@9000/0": {"a": [[0, 1]], "depth": [0], "frame": True,
                            "s": [[0xFF, 0xFF]], "copies": [["a", "0300"]],
                            "cells": {"0300": [[0, 1]]}},
            "9010@9000/0": {"depth": [0], "frame": True,
                            "s": [[0xFF, 0xFF]], "cells": {"0300": [[1, 1]]}},
            "9018@9000/0": {"depth": [0], "frame": True,
                            "s": [[0xFF, 0xFF]], "cells": {"0300": [[0, 0]]}},
        }
        results = verdicts(self.build(contexts))
        self.assertEqual(
            sorted(failing(results)),
            ["VC-DISPATCH:9000@9000/0:9010", "VC-DISPATCH:9000@9000/0:9018"])


class NegativeTests(unittest.TestCase):
    """One wrong certificate per verification-condition kind."""

    def test_an_invariant_that_is_not_preserved_is_rejected(self):
        contexts = dict(SIMPLE_CONTEXTS)
        contexts["9005@9000/0"] = {"a": [[5, 5]], "depth": [0],
                                   "frame": True,
                                   "cells": {"0300": [[0, 0]]}}
        results = verdicts(simple_checker(contexts=contexts))
        self.assertIn("VC-STEP:9002@9000/0:0", failing(results))

    def test_a_mod_set_missing_a_written_cell_is_rejected(self):
        routines = {"9000": {"kind": "normal", "mod": ["0301"], "use": 0,
                             "post": {}}}
        results = verdicts(simple_checker(routines=routines))
        self.assertIn("VC-MOD:9002@9000/0:0", failing(results))

    def test_a_store_that_can_clobber_the_entry_frame_is_rejected(self):
        #: the same store as the positive test, but S is not pinned, so the
        #: entry frame may sit at $01F0
        prg = image({0x9000: bytes.fromhex("8df001" "60")})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {"9000": {"kind": "normal", "mod": ["01F0"], "use": 0,
                             "post": {}}}
        contexts = {"9000@9000/0": {"depth": [0], "frame": True},
                    "9003@9000/0": {"depth": [0], "frame": True}}
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertIn("VC-STEP:9000@9000/0:0", failing(results))

    def test_an_rts_at_a_nonzero_depth_is_rejected(self):
        #: $9000 PHA / $9001 RTS -- the push is never undone
        prg = image({0x9000: bytes.fromhex("48" "60")})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {"9000": {"kind": "normal", "mod": [], "use": 1,
                             "post": {}}}
        contexts = {"9000@9000/0": {"depth": [0], "frame": True},
                    "9001@9000/0": {"depth": [1], "frame": True}}
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertIn("VC-RET-FRAME:9001@9000/0", failing(results))

    def test_an_rts_without_the_frame_conjunct_is_rejected(self):
        contexts = dict(SIMPLE_CONTEXTS)
        contexts["9005@9000/0"] = {"a": [[5, 5]], "depth": [0],
                                   "cells": {"0300": [[5, 5]]}}
        results = verdicts(simple_checker(contexts=contexts))
        self.assertIn("VC-RET-FRAME:9005@9000/0", failing(results))

    def test_a_dispatch_index_invariant_that_is_too_weak_is_rejected(self):
        test = DispatchTests("test_an_index_inside_the_table_dispatches_into_"
                             "the_routine")
        checker = test.build(test.base_contexts([[0, 2]]))
        results = verdicts(checker)
        self.assertIn("VC-DISPATCH-INDEX:9000@9000/0", failing(results))

    def test_a_callee_post_that_is_too_strong_is_rejected(self):
        routines = dict(SIMPLE_ROUTINE)
        routines["9000"] = dict(routines["9000"],
                                post={"a": [[6, 6]],
                                      "cells": {"0300": [[5, 5]]}})
        results = verdicts(simple_checker(routines=routines))
        self.assertIn("VC-RET-POST:9005@9000/0", failing(results))

    def test_a_caller_that_does_not_cover_the_callee_mod_is_rejected(self):
        prg = image({0x9000: bytes.fromhex("201090" "60"),
                     0x9010: bytes.fromhex("8d0003" "60")})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {
            "9000": {"kind": "normal", "mod": [], "use": 2, "post": {}},
            "9010": {"kind": "normal", "mod": ["0300"], "use": 0,
                     "post": {}},
        }
        contexts = {
            "9000@9000/0": {"depth": [0], "frame": True},
            "9003@9000/0": {"depth": [0], "frame": True},
            "9010@9010/0": {"depth": [0], "frame": True},
            "9013@9010/0": {"depth": [0], "frame": True},
        }
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertIn("VC-CALL-MOD:9000@9000/0->9010", failing(results))

    def test_a_callee_deeper_than_the_caller_budget_is_rejected(self):
        prg = image({0x9000: bytes.fromhex("201090" "60"),
                     0x9010: bytes.fromhex("60")})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {
            "9000": {"kind": "normal", "mod": [], "use": 0, "post": {}},
            "9010": {"kind": "normal", "mod": [], "use": 0, "post": {}},
        }
        contexts = {"9000@9000/0": {"depth": [0], "frame": True},
                    "9003@9000/0": {"depth": [0], "frame": True},
                    "9010@9010/0": {"depth": [0], "frame": True}}
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertIn("VC-CALL-USE:9000@9000/0->9010", failing(results))

    def test_a_vacuous_call_return_query_is_rejected(self):
        """A `Post` that contradicts the caller must not pass as `holds`."""
        prg = image({0x9000: bytes.fromhex("201090" "60"),
                     0x9010: bytes.fromhex("8d0003" "60")})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {
            "9000": {"kind": "normal", "mod": ["0300"], "use": 2,
                     "post": {}},
            # `$0300` is outside the callee's `Mod`, so the query does not
            # havoc it -- and the callee's `Post` then contradicts the
            # caller's invariant, making the hypotheses unsatisfiable
            "9010": {"kind": "normal", "mod": [], "use": 0,
                     "post": {"en": [0], "cells": {"0300": [[1, 1]]}}},
        }
        contexts = {
            "9000@9000/0": {"depth": [0], "frame": True,
                            "cells": {"0300": [[2, 2]]}},
            "9003@9000/0": {"depth": [0], "frame": True},
            "9010@9010/0": {"depth": [0], "frame": True},
            "9013@9010/0": {"depth": [0], "frame": True},
        }
        checker = Checker(certificate(routines, contexts), graph, prg)
        results = {v.id: v for v in checker.check_all(globals_too=False)}
        verdict = results["VC-CALL-RETURN:9000@9000/0->9010"]
        self.assertEqual(verdict.status, FAILS)
        self.assertIn("vacuous", verdict.detail["reason"])

    def test_a_missing_successor_context_is_rejected(self):
        contexts = {k: v for k, v in SIMPLE_CONTEXTS.items()
                    if k != "9005@9000/0"}
        results = verdicts(simple_checker(contexts=contexts))
        self.assertIn("VC-STEP:9002@9000/0:0", failing(results))

    def test_a_reachable_forbidden_instruction_is_rejected(self):
        #: $9000 LDX #$00 / $9002 BNE $9006 / $9004 JAM -- the branch is
        #: never taken, so the JAM really is reachable
        prg = image({0x9000: bytes.fromhex("a200" "d002" "0202" "60")})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {"9000": {"kind": "normal", "mod": [], "use": 0,
                             "post": {}}}
        contexts = {"9000@9000/0": {"depth": [0], "frame": True},
                    "9002@9000/0": {"x": [[0, 0]], "z": True, "depth": [0],
                                    "frame": True},
                    "9006@9000/0": {"depth": [0], "frame": True}}
        checker = Checker(certificate(routines, contexts), graph, prg)
        results = verdicts(checker)
        # successor 0 is the (infeasible) branch, successor 1 the fallthrough
        self.assertIn("VC-STEP:9002@9000/0:1", failing(results))
        forbidden = {v.id: v for v in checker.vc_forbidden()}
        self.assertEqual(forbidden["VC-FORBIDDEN:9004"].status, HOLDS)
        contexts["9004@9000/0"] = {"depth": [0], "frame": True}
        checker = Checker(certificate(routines, contexts), graph, prg)
        self.assertEqual(
            {v.id: v for v in checker.vc_forbidden()}[
                "VC-FORBIDDEN:9004"].status, FAILS)
        self.assertIn("VC-FORBIDDEN:9004@9000/0",
                      failing(verdicts(checker)))

    def test_a_cold_boot_state_outside_the_root_invariant_is_rejected(self):
        prg = image({0x9000: bytes.fromhex("60")}, reset=0x9000)
        graph = graph_of(prg, {0x9000: "reset"})
        routines = {"9000": {"kind": "root", "s0": 0xFF, "mod": [], "use": 0,
                             "post": {}}}
        contexts = {"9000@9000/0": {"a": [[0, 0]]}}
        checker = Checker(certificate(routines, contexts), graph, prg)
        results = {v.id: v for v in checker.vc_cold()}
        self.assertEqual(results["VC-COLD"].status, FAILS)

    def test_a_context_that_does_not_assert_the_interrupt_mask_is_rejected(self):
        contexts = dict(SIMPLE_CONTEXTS)
        contexts["9000@9000/0"] = {"depth": [0], "frame": True, "i": None}
        checker = simple_checker(contexts=contexts)
        results = {v.id: v for v in checker.vc_irq()}
        self.assertEqual(results["VC-IRQ"].status, FAILS)
        self.assertEqual(results["VC-IRQ"].detail["count"], 1)

    def test_an_rti_whose_saved_status_is_unconstrained_is_rejected(self):
        machine = MachineTests("test_the_toy_machine_is_fully_accepted")
        contexts = dict(machine.build().raw["contexts"])
        contexts["910A@9100/1"] = {"depth": [0], "frame": True}
        results = verdicts(machine.build(contexts=contexts),
                           globals_too=True)
        self.assertIn("VC-NMI-EXIT-I:910A@9100/1", failing(results))

    def test_txs_outside_a_root_routine_is_rejected(self):
        prg = image({0x9000: bytes.fromhex("9a" "60")})
        graph = graph_of(prg, {0x9000: "test"})
        routines = {"9000": {"kind": "normal", "mod": [], "use": 0,
                             "post": {}}}
        contexts = {"9000@9000/0": {"depth": [0], "frame": True},
                    "9001@9000/0": {"depth": [0], "frame": True}}
        results = verdicts(Checker(certificate(routines, contexts), graph,
                                   prg))
        self.assertIn("VC-TXS:9000@9000/0", failing(results))


class ProposerTests(unittest.TestCase):
    """End to end on a toy machine: the proposer's output must check out.

    This is the only test that runs both sides.  It is here because the
    interesting failure mode is a proposer that emits something the checker
    cannot parse or cannot accept even when the program is trivial; the two
    still share no code, and the checker's verdict is what is asserted.
    """

    #: $9000 SEI / LDX #$FF / TXS / JSR $9020 / LDA #$80 / STA $2000 /
    #: $900C JMP $900C         (reset: set up, call, enable NMI, idle)
    #: $9020 LDA #$03 / STA $0300 / RTS
    #: $9100 LDA #$00 / STA $2000 / INC $0301 / LDA #$80 / STA $2000 / RTI
    ROOT = bytes.fromhex("78" "a2ff" "9a" "202090" "a980" "8d0020" "4c0c90")
    SUB = bytes.fromhex("a903" "8d0003" "60")
    HANDLER = bytes.fromhex("a900" "8d0020" "ee0103" "a980" "8d0020" "40")

    def setUp(self):
        from analysis.cfg import CFG

        self.prg = image({0x9000: self.ROOT, 0x9020: self.SUB,
                          0x9100: self.HANDLER},
                         reset=0x9000, nmi=0x9100)
        graph = CFG(lambda a: self.prg[(a & 0xFFFF) - 0x8000],
                    code_range=(0x8000, 0x10000))
        graph.add_entry(0x9000, "reset")
        graph.add_entry(0x9100, "nmi")
        self.graph = graph.build()

    def test_the_proposed_certificate_parses_and_checks(self):
        from formal.analysis.invariants import propose

        certificate, proposer = propose(self.graph, self.prg, "test",
                                        max_rounds=3)
        checker = Checker(certificate, self.graph, self.prg)
        self.assertGreater(len(checker.live()), 10)
        results = {v.id: v for v in checker.check_all()}
        bad = failing(results)
        self.assertEqual(bad, [], "\n".join(
            f"{k}: {results[k].detail}" for k in bad[:6]))
        self.assertEqual(results["VC-COLD"].status, HOLDS)
        self.assertEqual(results["VC-IRQ"].status, HOLDS)
        # the proposer must have found the one place an NMI can begin
        self.assertEqual(certificate["nmi_windows"],
                         ["9100", "9102", "910D"])

    def test_a_tampered_certificate_is_rejected(self):
        """Sanity: the acceptance above is not vacuous."""
        from formal.analysis.invariants import propose

        certificate, _ = propose(self.graph, self.prg, "test", max_rounds=3)
        routine = certificate["routines"]["9020"]
        routine["mod"] = []
        checker = Checker(certificate, self.graph, self.prg)
        results = {v.id: v for v in checker.check_all()}
        self.assertTrue([k for k in failing(results)
                         if k.startswith("VC-MOD")])


if __name__ == "__main__":
    unittest.main()
