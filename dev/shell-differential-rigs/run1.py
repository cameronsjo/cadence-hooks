import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oracle import main, report

cases = [
  # --- controls ---
  ("CTRL-neg  bare payload (must be OK)",            "{P}"),
  ("CTRL-pos  pipe-to-bash (must be MISS both)",     "echo '{P}' | bash"),
  ("CTRL-safe short-circuit (bash no, parser yes)",  "false && {P}"),
  ("CTRL-real real comment (bash must NOT run)",     "echo hi # {P}"),
  # --- the five the brief says were fixed ---
  ("FIX1 ${x:- # } then ;",        "echo ${x:- # } ; {P}"),
  ("FIX2 backtick with #",         "echo `date # x`; {P}"),
  ("FIX3 escaped space then #",    "echo a\\ #x && {P}"),
  ("FIX4 ${B:-a # b} then &&",     "gh pr create --body ${B:-a # b} && {P}"),
  ("FIX5 unterminated heredoc",    "cat <<EOF\nprose # $({P})\n"),
]
report(main(cases))
