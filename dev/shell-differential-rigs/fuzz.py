import sys, os, random, json, subprocess, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oracle import run_parser, parser_sees, HEAD, BASE

PIECES = ["${x:-", "${x#", "${x%", "${x/", "$(", "$((", "`", "'", '"', "$'",
          ")", "}", "))", "(", "{", "#", " ", "\\ ", "\\\\", "\\", "a", "b",
          "\n", ";", "&&", "|", "echo ", "true", "\t", "$#", "${#x}", "<<EOF"]

def gen(rng, n):
    return "".join(rng.choice(PIECES) for _ in range(rng.randint(2, n)))

def main():
    rng = random.Random(int(sys.argv[1]) if len(sys.argv) > 1 else 7)
    N = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
    tmpd = tempfile.mkdtemp(prefix="fuzz_")
    built = []
    seen = set()
    while len(built) < N:
        pre = gen(rng, 9)
        if pre in seen: continue
        seen.add(pre)
        i = len(built)
        canary = os.path.join(tmpd, "c%05d" % i)
        # payload joined by BOTH a newline and a ';' so a mere line-eater is caught
        cmd = pre + "\ntouch " + canary
        built.append((cmd, canary))
    cmds = [c for c, _ in built]
    head = run_parser(HEAD, cmds)
    base = run_parser(BASE, cmds)
    misses = []
    nran = 0
    for (cmd, canary), h, b in zip(built, head, base):
        try:
            subprocess.run(["/bin/bash", "-c", cmd], capture_output=True,
                           timeout=5, cwd=tmpd)
        except subprocess.TimeoutExpired:
            continue
        ran = os.path.exists(canary)
        if not ran: continue
        nran += 1
        if not parser_sees(h):
            misses.append({"cmd": cmd, "head": h["command_segments"],
                           "base_segs": b["command_segments"],
                           "base_sees": parser_sees(b)})
    print(f"generated={len(built)} bash_ran={nran} misses={len(misses)}")
    for m in misses[:40]:
        tag = "REGRESSION" if m["base_sees"] else "pre-existing"
        print(f"[{tag}] {m['cmd']!r}\n    head={m['head']!r}")
    shutil.rmtree(tmpd, ignore_errors=True)

main()
