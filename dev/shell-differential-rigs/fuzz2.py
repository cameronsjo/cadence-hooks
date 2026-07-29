import sys, os, random, subprocess, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oracle import run_parser, parser_sees, HEAD, BASE
# grammar tilted at expansion internals + comment boundaries, no ')' bias
OPEN = ["${x:-", "${x/a/", "$(echo ", "$((", "`echo ", '"', "'", "$'"]
BODY = ["a", " ", "#", "\\", "\\ ", "}", ")", "(", "{", "'", '"', "`", "\t",
        "$(", "${y:-", "))", ";", "|", "&&", "\n"]
CLOSE = ["}", ")", "`", '"', "'", ""]
rng = random.Random(int(sys.argv[1])); N = int(sys.argv[2])
tmpd = tempfile.mkdtemp(prefix="fz2_"); built=[]
for i in range(N):
    pre = rng.choice(OPEN) + "".join(rng.choice(BODY) for _ in range(rng.randint(1,6))) + rng.choice(CLOSE)
    can = os.path.join(tmpd, "c%05d"%i)
    built.append(("echo " + pre + " ; touch " + can, can))
cmds=[c for c,_ in built]
head=run_parser(HEAD,cmds); base=run_parser(BASE,cmds)
nran=0; miss=[]
for (cmd,can),h,b in zip(built,head,base):
    try: subprocess.run(["/bin/bash","-c",cmd],capture_output=True,timeout=5,cwd=tmpd)
    except subprocess.TimeoutExpired: continue
    if not os.path.exists(can): continue
    nran+=1
    if not parser_sees(h): miss.append((cmd,h["command_segments"],parser_sees(b)))
print(f"generated={N} bash_ran={nran} misses={len(miss)}")
uniq=set()
for cmd,seg,bs in miss:
    tag="REGRESSION" if bs else "pre-existing"
    key=(tag, cmd.split(" ; ")[0])
    if key in uniq: continue
    uniq.add(key)
    print(f"[{tag}] {cmd.split(' ; ')[0]!r}  -> head={seg!r}")
shutil.rmtree(tmpd,ignore_errors=True)
