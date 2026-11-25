# Machine-Checked Control-Flow Properties of Super Mario Bros.

## 1. Research objective

Determine whether a historically significant commercial video game can be shown, directly from its immutable program image, to satisfy a global instruction-location invariant for every permitted controller input sequence.

The target is the NTSC / World release of Super Mario Bros. for the Nintendo Entertainment System, using the NROM cartridge configuration. This is a software correctness and formal methods project. Its output should be reproducible mathematical statements, independently checkable evidence, and a transparent record of unresolved properties.

The objective is not to establish a predetermined conclusion. A proof, a counterexample, or a rigorously characterized partial result is acceptable.

## 2. Target and scope

- Expected complete iNES image SHA-1: `ea343f4e445a9050d4b4fbac2c77d0693b1d0922`.
- PRG: 32 KiB, mapped at `$8000–$FFFF`.
- CPU: Ricoh 2A03 (NMOS 6502-derived instruction semantics, with decimal arithmetic disabled).
- Internal RAM: 2 KiB, mirrored through `$1FFF`.
- The original program image is supplied locally by the researcher and is not distributed.
- Model ordinary NES operation with explicitly specified controller, reset, interrupt, timing, cartridge and initial-memory assumptions.
- Exclude external changes to the program image, direct changes to machine state by debugging tools, electrical faults and hardware modifications from the main theorem. Synthetic test fixtures remain appropriate for validating the verification infrastructure.

Define separate model variants for cold boot, warm reset, physically realizable controller signals and an overapproximation allowing arbitrary legal serial controller responses. Proving a property for the larger input domain also proves it for any subset, provided all other assumptions match.

## 3. The primary theorem

Let `S` be the machine state space, `I(s)` the initial-state predicate, `U(s,u)` the admissible input predicate, and `T(s,u,s')` the transition relation. Let `Fetch(s)` denote the start of an architectural instruction fetch (as distinct from operand reads, dummy reads, and DMA transactions).

Define:

```text
P(s) := Fetch(s) implies 0x8000 <= PC(s) <= 0xFFFF

Reach(s) := least fixed point containing I and closed under T

Theorem: forall s: Reach(s) implies P(s)
```

The reset-vector acquisition phase must be modeled separately or excluded explicitly from `Fetch`. Define instruction-boundary semantics precisely. A cycle-level implementation must distinguish actual opcode-fetch events from other bus activity.

An inductive certificate `J` is sufficient if:

```text
Initiation:   I(s)                         => J(s)
Consecution:  J(s) and U(s,u) and T(s,u,s') => J(s')
Safety:       J(s)                         => P(s)
```

A finite number of successful simulation runs does not establish this theorem. Nor does a proof limited to a finite time horizon. The theorem is about all reachable states and arbitrarily long input sequences.

### 3.1 What the theorem does not establish

It is an instruction-location property, not full semantic correctness. It does not establish that every ROM instruction is entered as intended, that gameplay always progresses, that the machine cannot halt, or that arbitrary computations cannot be expressed using existing program routines. Stronger properties must be stated and verified independently.

## 4. Secondary theorems

| ID | Property | Initial status |
|---|---|---|
| P1 | Every instruction fetch occurs within PRG ROM | Unproved |
| P2 | Every reachable dynamic dispatch uses a valid table entry | Unproved |
| P3 | Every dispatch reads its table from the intended immutable program location | Unproved |
| P4 | Every ordinary subroutine return consumes its corresponding return frame | Unproved |
| P5 | Every interrupt return consumes its corresponding interrupt frame | Unproved |
| P6 | Every critical state variable satisfies its required domain at each relevant program point | Unproved |
| P7 | Every reachable instruction start belongs to a verified instruction-start set | Unproved |

These properties are related but not interchangeable. For example, P1 can hold even when P2 fails. A sufficient conjunction of verified invariants may imply P1 without proving every stronger property.

## 5. Verification architecture

```text
Immutable program image
    |
Validated instruction semantics and memory model
    |
Conservative control-flow representation
    |
Abstract interpretation and local routine summaries
    |
Inductive invariant candidates
    |
SMT verification conditions
    |
Independent certificate checking and evidence report
```

Recommended implementation: Python, Z3 bit-vectors, pytest or unittest, versioned JSON artifacts, and a pinned independent NES implementation for differential validation. Start with quantifier-free finite bit-vector obligations where practical. Use an abstract interpreter to propose invariants, not as a substitute for checking them.

## 6. Machine model

Represent the accumulator, X, Y, stack pointer, and status flags as 8-bit quantities; the program counter and effective addresses as 16-bit quantities. Model RAM as a finite byte array, with explicit mirror normalization. Model immutable program reads directly from the verified image.

Include correct instruction decoding, arithmetic and flag semantics, address wrapping, branch behavior, stack behavior, interrupt entry and return, and relevant undocumented instructions. Model memory-mapped device reads, writes and side effects; timing-dependent behavior may be conservatively nondeterministic only if that abstraction includes every concrete behavior admitted by the stated hardware model.

Do not assume that an unmodeled device value is zero. Do not silently omit DMA, interrupt scheduling, power-on RAM uncertainty, or controller serialization. Where an abstraction cannot yet be justified, mark the relevant theorem conditional.

### Validation requirements

- Compare instruction semantics against independent CPU test fixtures and an independent emulator.
- Test wraparound, flags, interrupt priority, reset behavior and address mirroring.
- Test documented and relevant undocumented instruction behavior.
- Pin source versions and record known differences.
- Distinguish model validation from a proof that the model faithfully implements physical hardware.

## 7. First milestone: prove a local dispatch property

Begin with the existing dispatch at `$92C8`, because the earlier analysis identified an assumption that was incorrectly described as a locally enforced upper bound.

The reported transformation of `$071F` replaces zero with eight and then decrements the value. Confirm the exact instruction sequence, including the transfer into the accumulator, against the supplied program image before encoding it.

For the reported transformation:

```python
from z3 import BitVec, BitVecVal, If, ULE, Solver, Not, unsat

v = BitVec('v', 8)
idx = If(v == 0, BitVecVal(8, 8), v) - 1
s = Solver()
s.add(ULE(v, 8), Not(ULE(idx, 7)))
assert s.check() == unsat
```

This proves only the local implication `v <= 8 => idx <= 7`. It does not prove the precondition holds in the actual game. As a negative regression test, remove the precondition and check that the universal bound is no longer valid.

The next obligation is a program-point invariant:

```text
PC at the relevant dispatch preparation point => RAM[0x071F] <= 8
```

Prefer this precise local invariant over the stronger global claim that the byte is always within range. Temporary values elsewhere in execution may be legitimate.

To establish the program-point invariant, generate conservative writer summaries, initialization conditions, and predecessor-path conditions. Verify every proof obligation or retain it as unresolved. Account for indirect and indexed addressing, mirrored RAM, and intervening interrupts.

Acceptance: the local mathematical implication is machine checked; its connection to actual instruction semantics is validated; the upstream program-point precondition has its own independent proof status.

## 8. Compositional program analysis

Construct routine contracts of the form:

```text
requires: entry-state predicate
modifies: conservative set of state components
ensures: exit-state predicate
exits: permitted successor locations
```

Derive contracts from machine instructions rather than treating conventional routine names as evidence. Include all entry points and permitted asynchronous transitions. Use summaries to avoid repeatedly exploring long deterministic routines.

For every relevant state variable, maintain an evidence record containing:

- Program points where the property is needed.
- Candidate value domain.
- Initialization evidence.
- Conservative set of possible writers.
- Preservation obligations.
- Dependencies and unresolved assumptions.
- Solver result and reproducible query identifier.

Candidate domains include finite sets, unsigned intervals, bit masks, congruences and relationships among registers, flags and memory values.

A control-flow representation is useful but cannot be presumed complete merely because a recursive decoder reached a set of addresses. Preserve overlapping instruction starts, account for unresolved successors and justify any restriction on dynamic control transfers. If the proof relies on the completeness of a graph, graph completeness itself is a proof obligation.

## 9. Dispatch and return contracts

Verify the ordinary dispatch routine as a compositional contract. Given an authentic call frame, appropriate input domain and valid table metadata, establish that its result is one of the expected destinations. Verify table metadata independently of heuristic decoding.

Represent raw accumulator values and effective table offsets separately; validate actual 8-bit arithmetic and address semantics against the instruction model.

For ordinary subroutine and interrupt returns, establish frame-consistency contracts using an abstract shadow stack. This is an analysis data structure, not a modification to the game. Include direct writes to stack-page memory, mirrored addresses, interrupt effects, stack-pointer changes and intentional consumption of call frames by dispatch routines. A measured stack-depth range is supporting empirical evidence, not a proof of frame integrity.

## 10. Avoid circular proof assumptions

It is invalid to assume correct control flow to prove state domains, then use those same unproved domains as evidence for correct control flow.

Instead, form a joint invariant:

```text
J = J_location AND J_state AND J_dispatch AND J_stack AND J_device
```

Prove initialization and preservation of the conjunction simultaneously. In the preservation query, assumptions about the current state are legitimate because induction establishes them for that state. The successor state must satisfy the complete conjunction again.

Maintain a dependency graph. For cyclic components, generate a joint verification condition or explicitly mark the component unresolved.

## 11. Verification methods

Use an escalating sequence of methods:

1. **Local bit-vector lemmas:** verify arithmetic transformations and small straight-line instruction blocks.
2. **Abstract interpretation:** derive conservative program-point domains and propose inductive invariants.
3. **Compositional verification:** establish routine contracts and their compatibility at call boundaries.
4. **Bounded model checking:** evaluate a precisely stated finite horizon, with a separate report for each horizon.
5. **Inductive verification:** use invariant checking, k-induction with strengthening predicates, or property-directed reachability where the abstraction is suitable.
6. **Certificate validation:** independently check initiation, preservation and safety obligations for any claimed unbounded result.

For k-induction, establish both the base case and inductive step. For a finite abstraction, justify its simulation relationship to the concrete machine. A solver result over an incomplete model is not a theorem about the original program.

### Solver result taxonomy

| Result | Meaning |
|---|---|
| `proved` | All necessary verification obligations discharged under established model assumptions |
| `conditional` | Obligation discharged only with additional unresolved assumptions |
| `bounded` | Established only through an explicitly stated finite horizon |
| `refuted` | A counterexample validated against the stated property and model |
| `abstract_counterexample` | Model permits a violation; concrete reachability is not established |
| `unknown` | No conclusion |
| `timeout` | Computation ended before obtaining a conclusion |
| `observed` | Empirical evidence only |

## 12. Reproducibility and certificate format

Store each obligation and its result in a versioned manifest. Example:

```json
{
  "id": "P6-071F-local",
  "statement": "input byte <= 8 implies transformed index <= 7",
  "scope": "local arithmetic lemma",
  "status": "conditional",
  "assumptions": ["input byte <= 8", "instruction sequence matches verified model"],
  "dependencies": ["CPU-SEMANTICS", "P6-071F-PROGRAM-POINT"],
  "solver": "z3",
  "solver_version": null,
  "query_artifact": null,
  "result_artifact": null,
  "independent_check": null
}
```

This example is a proposed schema, not an executed result. Populate version information and artifact paths only after actual runs.

Preserve SMT-LIB queries, solver configuration, result logs, machine-model version, original image hash, repository revision and certificate artifacts where available. Prefer an independent proof checker or a second solver for important obligations. If a solver does not provide independently checkable certificates for the chosen theory, disclose the remaining trusted computing base.

## 13. Suggested repository layout

```text
formal/
  README.md
  model/
    cpu.py
    memory.py
    devices.py
    transitions.py
  analysis/
    cfg.py
    abstract_domains.py
    routine_contracts.py
    invariants.py
  verify/
    obligations.py
    induction.py
    certificates.py
  properties/
    instruction_location.py
    dispatch.py
    state_domains.py
    returns.py
  tests/
  results/
    manifests/
    queries/
    certificates/
    reports/
```

Keep the original research tools and results intact. The formal work should consume verified artifacts from the existing project only when their provenance and assumptions are explicit.

## 14. Implementation milestones

| Milestone | Deliverable | Completion criterion |
|---|---|---|
| M0 | Baseline and scope specification | Image identity, repository revision, model assumptions and initial state documented |
| M1 | Local arithmetic lemmas | Machine-checked results with positive and negative regression tests |
| M2 | Validated instruction and memory model | Independent semantic tests and documented discrepancies |
| M3 | First program-point invariant | Verified initialization and preservation, or explicit unresolved obligations |
| M4 | Conservative routine contracts | Contracts checked against modeled execution |
| M5 | Dispatch and return properties | Separate proof status for each property and dependency |
| M6 | Joint inductive invariant | Initialization and preservation queries generated and checked |
| M7 | Global instruction-location theorem | Safety implication checked, or precise remaining obligations reported |
| M8 | Independent replication | Clean-environment reproduction and certificate validation |
| M9 | Research report | Claims limited to supported theorems, with assumptions and limitations |

Do not proceed by declaring a milestone complete merely because tests pass. Tests, empirical observations, bounded results and unbounded proofs require different evidence.

## 15. Publication strategy

Possible paper titles:

- Machine-Checked Control-Flow Invariants in Super Mario Bros.
- Formal Verification of Instruction-Location Properties in a Commercial NES Program
- Compositional Verification of a 1985 Video Game Binary

A meaningful intermediate publication could present a verified collection of local and compositional invariants, a reusable machine model and a transparent account of the remaining global obligations. The strongest publication would include a reproducible unbounded theorem with an independently checkable certificate and a clearly stated trusted computing base.

Academic novelty is not yet established. Conduct a literature review covering binary-level formal verification, legacy software model checking, 6502 semantics, inductive invariant synthesis and prior verification work on video games before making novelty claims.

## 16. Instructions for implementation agents

- Treat this as a formal software correctness investigation of a fixed local program image.
- Verify image identity before running program-specific analysis.
- Preserve existing results and attribution.
- Start with M0 and M1; do not claim a global theorem based on local checks.
- Use conservative abstractions and document every assumption.
- Add negative tests that intentionally violate a candidate invariant in original synthetic fixtures.
- Never invent solver results, experimental observations, or proof artifacts.
- Do not convert an unresolved obligation into a proven claim.
- Keep implementation, model validation and mathematical proof statuses separate.
- Commit incremental, reproducible changes and update the proof manifest.
- Document material limitations in the research report and acknowledge substantive contributions, including ChatGPT (OpenAI) where appropriate.

## 17. Definition of success

The ideal result is a machine-checked, unbounded instruction-location theorem under a precisely defined NES machine and input model. A validated counterexample refutes that theorem for the corresponding model. A partial proof with clearly specified unresolved obligations is also scientifically useful.

The purpose is to establish what is true, not to defend an existing conclusion.
