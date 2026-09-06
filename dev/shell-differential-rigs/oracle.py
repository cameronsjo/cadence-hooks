#!/usr/bin/env python3
"""Differential: bash (oracle) vs the shell parser (subject).

Each case is a command template containing {P}, the payload position.
The payload is `touch <canary>`. We ask two questions:
  bash:   does the canary file exist after `bash -c <cmd>`?
  parser: does any command_segment have `touch` as its command word?
A MISS is bash=yes, parser=no -- a command bash runs that reaches no guard.
"""
import json, os, subprocess, sys, tempfile, shutil

SCRATCH = os.path.dirname(os.path.abspath(__file__))
HEAD = os.path.join(SCRATCH, "probe_head/target/release/probe_head")
BASE = os.path.join(SCRATCH, "probe_base/target/release/probe_base")

def run_parser(binpath, cmds):
    p = subprocess.run([binpath], input=json.dumps(cmds), capture_output=True, text=True)
    if p.returncode != 0:
        print("PARSER FAILED", p.stderr[:2000], file=sys.stderr)
        sys.exit(1)
    return json.loads(p.stdout)

def bash_runs(cmd, canary):
    """True if bash actually creates the canary."""
    if os.path.exists(canary):
        os.remove(canary)
    subprocess.run(["/bin/bash", "-c", cmd], capture_output=True, text=True, timeout=10,
                   cwd=tempfile.gettempdir())
    return os.path.exists(canary)

def parser_sees(row):
    """True if some command_segment's command word is `touch`."""
    for toks in row["tokens"]:
        if not toks:
            continue
        # strip common transparent prefixes / assignments the way guards do
        j = 0
        while j < len(toks) and ("=" in toks[j].split(" ")[0] and not toks[j].startswith("-")):
            j += 1
        if j < len(toks) and os.path.basename(toks[j]) == "touch":
            return True
    return False

def main(cases):
    tmpd = tempfile.mkdtemp(prefix="oracle_")
    built = []
    for i, (name, tmpl) in enumerate(cases):
        canary = os.path.join(tmpd, "c%03d" % i)
        built.append((name, tmpl.replace("{P}", "touch " + canary), canary))
    cmds = [c for _, c, _ in built]
    head = run_parser(HEAD, cmds)
    base = run_parser(BASE, cmds)
    rows = []
    for (name, cmd, canary), h, b in zip(built, head, base):
        ran = bash_runs(cmd, canary)
        rows.append({
            "name": name, "cmd": cmd, "bash_runs": ran,
            "head_sees": parser_sees(h), "base_sees": parser_sees(b),
            "head_text": any(canary in x for x in h["command_segments"]),
            "base_text": any(canary in x for x in b["command_segments"]),
            "head_segs": h["command_segments"], "base_segs": b["command_segments"],
        })
    shutil.rmtree(tmpd, ignore_errors=True)
    return rows

def report(rows):
    n_miss = 0
    for r in rows:
        verdict = "OK "
        if r["bash_runs"] and not r["head_sees"]:
            verdict = "MISS"; n_miss += 1
        elif not r["bash_runs"] and r["head_sees"]:
            verdict = "over"  # parser sees something bash doesn't run: safe
        cls = ""
        if verdict == "MISS":
            cls = " [REGRESSION]" if r["base_sees"] else " [PRE-EXISTING]"
        print(f"{verdict}{cls} {r['name']}")
        print(f"      cmd:  {r['cmd']!r}")
        print(f"      bash_runs={r['bash_runs']} head_sees={r['head_sees']} base_sees={r['base_sees']} head_text={r['head_text']} base_text={r['base_text']}")
        if (not r["head_text"]) and r["base_text"]:
            print("      *** TEXT-LOSS vs baseline (payload text vanished from inspection)")
        if verdict == "MISS" or (not r["head_text"] and r["base_text"]) or os.environ.get("VERBOSE"):
            print(f"      head_segs={r['head_segs']!r}")
    print(f"\n=== {n_miss} MISS of {len(rows)} ===")
    return n_miss
