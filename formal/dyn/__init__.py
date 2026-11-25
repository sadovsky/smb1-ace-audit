"""Dynamic, instruction-level observation of the image on a 6502 interpreter.

Nothing in this package proves anything.  It executes the image on py65's NMOS
6502 core behind a minimal NES device stub and records what happened, so that
proposed invariants can be checked against observed behaviour (a proposed
domain that excludes an observed value is wrong) and so that the abstract
model's counterexamples can be followed concretely.

Every report carries a manifest and states its own limitations.  See
`formal/dyn/README.md` for the device stub's assumptions and for the
cross-validation result against nes-py.
"""
