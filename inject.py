import sys, io, contextlib, os
sys.path.insert(0, os.environ.get("CHEAT_ENV_DIR", "../rommage/genie_search"))
with contextlib.redirect_stderr(io.StringIO()):
    from cheat_env import CheatNESEnv
from rom import ROM
R,A,ST=128,1,8
_dn=os.open(os.devnull,os.O_WRONLY)
class mute:          # redirect BOTH fd1 and fd2 (native core prints to stdout)
    def __enter__(self): self.o1,self.o2=os.dup(1),os.dup(2); os.dup2(_dn,1); os.dup2(_dn,2)
    def __exit__(self,*a): os.dup2(self.o1,1); os.dup2(self.o2,2); os.close(self.o1); os.close(self.o2)
def run_to_enemy(env):
    for a,n in [(0,40),(ST,10),(0,120)]:
        for _ in range(n): env.step(a)
    for i in range(400):
        env.step(R|(A if i%40<20 else 0))
        if int(env.ram[0x0F]) and 0<int(env.ram[0x16])<0x37: return True
    return False
def test(idval, hold=120):
    env=CheatNESEnv(ROM); env.reset()
    if not run_to_enemy(env): env.close(); return dict(id=hex(idval),note="no enemy")
    fc=int(env.ram[0x0009]); stuck=0; bad=None; base=int(env.ram[0x16])
    for f in range(hold):
        r=env.ram
        if int(r[0x0F]): r[0x16]=idval
        env.step(R|(A if f%48<24 else 0))
        nfc=int(r[0x0009]); stuck=stuck+1 if nfc==fc else 0; fc=nfc
        if bad is None and (int(r[0x0770]) not in (0,1,2,3) or int(r[0x075A])>100 or stuck>4): bad=f
    env.close()
    return dict(id=hex(idval), replaced=hex(base), derailed=bad is not None, frame=bad)
results=[]
with mute():
    for idv in (0x06,0x00,0x11,0x2D,0x34,0x35,0x33,0x3F,0x7F): results.append(test(idv))
print("overwrite a live enemy's ID each frame (mixes out-of-range index AND id/state mismatch):\n")
for r in results: print(" ", r)
