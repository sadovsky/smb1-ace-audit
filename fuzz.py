"""Emulator search for the ACE precondition (see ACE_AUDIT.md section 6).

DEPENDENCY: this needs a Game-Genie-patched nes-py exposing CheatNESEnv (the
read-intercept cheat build; see the companion `rommage` project). Point at it
with $CHEAT_ENV_DIR. The static analysis (trace.py, audit.py) needs none of this.

Does controller input ever drive a JumpEngine index past its table, or an enemy
slot to ID $34/$35 (the only two whose $C907 dispatch reaches controllable RAM)?
"""

import sys, io, contextlib, random, json, os
from multiprocessing import Pool
sys.path.insert(0, os.environ.get("CHEAT_ENV_DIR", "../rommage/genie_search"))
with contextlib.redirect_stderr(io.StringIO()):
    from cheat_env import CheatNESEnv
from rom import ROM, image

A,B,SEL,ST,U,D,L,R = 1,2,4,8,16,32,64,128
BOOT=[(0,40),(ST,10),(0,40)]
# index variable -> (RAM addr, tightest table bound = N-1 across its dispatch uses)
IDX={"$0770":(0x0770,3), "$0772":(0x0772,2), "$0733":(0x0733,4), "$073C":(0x073C,14),
     "$0746":(0x0746,4), "$000E":(0x000E,12), "$001D":(0x001D,3), "$071F":(0x071F,7)}
ENEMY_SLOTS=range(0x16,0x1B)

def episode(args):
    seed, start_area = args
    rng=random.Random(seed)
    env=CheatNESEnv(ROM); env.reset()
    for a,n in BOOT:
        for _ in range(n): env.step(a)
    if start_area is not None:
        # coverage aid: force a different start area, then re-enter gameplay
        env.add_cheat((0x9CBC, start_area, None)); env.reset()
        for a,n in BOOT:
            for _ in range(n): env.step(a)
    maxv={k:0 for k in IDX}; ids=set(); derail=False; frames=3000
    # structured bias: mostly move right + jump, occasional random, occasional B
    for f in range(frames):
        roll=rng.random()
        if roll<0.55: a=R|(A if rng.random()<0.4 else 0)|(B if rng.random()<0.3 else 0)
        elif roll<0.70: a=L|(A if rng.random()<0.4 else 0)
        elif roll<0.85: a=A|(B if rng.random()<0.5 else 0)
        else: a=rng.getrandbits(8)
        env.step(a); r=env.ram
        for k,(addr,_) in IDX.items():
            v=int(r[addr]);  maxv[k]=max(maxv[k],v)
        for s in ENEMY_SLOTS:
            if int(r[0x0F+ (s-0x16)]):   # enemy flag active
                ids.add(int(r[s]))
        if int(r[0x0770]) not in (0,1,2,3): derail=True
        if int(r[0x075A])>200: break   # lives underflow -> game over garbage, stop
    env.close()
    return dict(seed=seed, cov=start_area, maxv=maxv, ids=sorted(ids), derail=derail)

if __name__=="__main__":
    N=int(sys.argv[1]) if len(sys.argv)>1 else 48
    # Native results are the only controller-only evidence. Area forcing uses a
    # ROM-read intercept and is separately labelled assisted coverage.
    areas=[0x00,0x01,0x21,0x25,0x2B,0x34,0x65,0xC2]
    jobs=[]
    for i in range(N):
        jobs.append((1000+i, None if i%3 else areas[(i//3)%len(areas)]))
    with Pool(12) as pool: res=pool.map(episode, jobs)
    # aggregate
    agg={k:0 for k in IDX}; allids=set(); covids=set(); derails=0
    for r in res:
        for k in IDX: agg[k]=max(agg[k],r["maxv"][k])
        (covids if r["cov"] is not None else allids).update(r["ids"])
        derails+=r["derail"]
    native=[r for r in res if r["cov"] is None]
    assisted=[r for r in res if r["cov"] is not None]
    print(f"native controller-only episodes={len(native)}  assisted coverage episodes={len(assisted)}")
    print(f"derailments(OperMode left 0-3)={derails}")
    print("\nindex variable   max-seen   table-bound(N-1)   OOB?")
    for k,(addr,bnd) in IDX.items():
        oob="  <-- EXCEEDS BOUND" if agg[k]>bnd else ""
        print(f"  {k}  {agg[k]:>8}   {bnd:>12}{oob}")
    print(f"\nenemy IDs seen (native controller-only): {[hex(i) for i in sorted(allids)]}")
    print(f"enemy IDs seen (assisted area coverage): {[hex(i) for i in sorted(covids)]}")
    native_danger=sorted(allids & {0x34,0x35})
    assisted_danger=sorted(covids & {0x34,0x35})
    print(f"\n$34/$35 in native runs: {[hex(i) for i in native_danger] or 'NEVER'}")
    print(f"$34/$35 in assisted runs: {[hex(i) for i in assisted_danger] or 'NEVER'}")
    json.dump({
        "experiment_type": "mixed_native_and_assisted_separated",
        "rom_sha1": image().sha1,
        "seed_range": [1000, 1000 + N - 1],
        "frames_per_episode": 3000,
        "native": {"episodes": len(native), "ids": sorted(allids)},
        "assisted": {"episodes": len(assisted), "ids": sorted(covids)},
        "max": agg, "derails": derails,
    }, open("fuzz_result.json","w"), indent=2, sort_keys=True)
