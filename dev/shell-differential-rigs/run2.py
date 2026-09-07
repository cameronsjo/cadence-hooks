import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oracle import main, report

cases = [
  ("CTRL-neg bare",                      "{P}"),
  ("CTRL-pos pipe-to-bash",              "echo '{P}' | bash"),

  # --- A1: closer inside ${...} drives depth to 0 early ---
  ("A1a ${x:-a)b # c} then ;",           "echo ${x:-a)b # c} ; {P}"),
  ("A1b ${x:-)) # } then ;",             "echo ${x:-)) # } ; {P}"),
  ("A1c ${x:-)} then # then ;",          "echo ${x:-)} # y\n{P}"),
  ("A1d ${x:-}} # } then ;",             "echo ${x:-}} # y\n{P}"),
  ("A1e nested ${a:-$(b # c)} then ;",   "echo ${a:-$(true # c)} ; {P}"),
  ("A1f ${x/)/y} # then ;",              "echo ${x/)/y} # z\n{P}"),
  ("A1g ${x:-a)b} plain (no #)",         "echo ${x:-a)b} ; {P}"),

  # --- A2: $(( vs $( disambiguation ---
  ("A2a $((1+2)) then # then ;",         "echo $((1+2)) # y\n{P}"),
  ("A2b $(( )) with ) inside string",    "echo $(( 1 )) ; {P}"),
  ("A2c $( ((1)) ) then ;",              "echo $( ((1)) ) ; {P}"),
  ("A2d ${ inside $(",                   "echo $(echo ${x:-a} # c) ; {P}"),
  ("A2e $( inside ${",                   "echo ${x:-$(echo a # b)} ; {P}"),

  # --- A3: backticks ---
  ("A3a backtick inside $( )",           "echo $(echo `true` ) ; {P}"),
  ("A3b $( ) inside backticks",          "echo `echo $(true)` ; {P}"),
  ("A3c odd backtick in a real comment", "echo hi # it's a ` tick\n{P}"),
  ("A3d two backticks in a comment",     "echo hi # a ` b ` c\n{P}"),
  ("A3e escaped backtick",               "echo \\` # y\n{P}"),

  # --- A4: escaped whitespace (the old bug's family) ---
  ("A4a escaped space  a\\ #x",          "echo a\\ #x && {P}"),
  ("A4b escaped backslash  a\\\\ #x",    "echo a\\\\ #x && {P}"),
  ("A4c a\\\\\\ #x",                     "echo a\\\\\\ #x && {P}"),
  ("A4d escaped TAB then #",             "echo a\\\t#x && {P}"),
  ("A4e real TAB then #",                "echo a\t# x\n{P}"),
  ("A4f line continuation then #",       "echo a\\\n#x\n{P}"),

  # --- A5: quote state across newlines ---
  ("A5a dq opened L1, # on L2",          "git commit -m \"one\ntwo # three\" ; {P}"),
  ("A5b sq opened L1, # on L2",          "git commit -m 'one\ntwo # three' ; {P}"),
  ("A5c dq closed L1, # on L2",          "git commit -m \"one\" \ntwo=3 # three\n{P}"),
  ("A5d apostrophe in comment L1",       "echo hi # don't\n{P}"),
  ("A5e $'..' ansi-c with #",            "echo $'a#b' ; {P}"),
  ("A5f $'..\\'..' escaped quote",       "echo $'a\\'b # c' ; {P}"),

  # --- A6: boundary characters ---
  ("A6a # glued after ;",                "echo a;#x\n{P}"),
  ("A6b # glued after &&",               "true &&#x\n{P}"),
  ("A6c # glued after |",                "echo a |#x\n{P}"),
  ("A6d # after ( subshell",             "( echo a ) # y\n{P}"),
  ("A6e # glued after (",                "(#x\necho a) ; {P}"),
  ("A6f # after > redirect",             "echo a > #f\n{P}"),
  ("A6g # at very start",                "#x\n{P}"),
  ("A6h ${#x} length op",                "echo ${#x} ; {P}"),
  ("A6i $# positional",                  "echo $# ; {P}"),
  ("A6j ${x#pre} strip op",              "echo ${x#pre} ; {P}"),

  # --- A7: heredoc seam ---
  ("A7a commented-out introducer",       "echo hi # cat <<EOF\n{P}\nEOF"),
  ("A7b real heredoc, # in body",        "cat <<EOF\nprose # x\nEOF\n{P}"),
  ("A7c unterminated heredoc + payload", "cat <<EOF\nprose # $({P})\n"),
  ("A7d unterminated, payload after #",  "cat <<EOF\n# $({P})\n"),
  ("A7e heredoc introducer w/ comment",  "cat <<EOF # note\n$({P})\nEOF"),
  ("A7f quoted heredoc introducer",      "cat <<'EOF' # note\nx\nEOF\n{P}"),
  ("A7g intro hidden behind bad-depth #","echo ${x:-)} # cat <<EOF\n{P}\nEOF"),
  ("A7h backtick before # <<EOF",        "echo $(echo `true`) # cat <<EOF\n{P}\nEOF"),

  # --- A8: pipe/redirect operator seam (#491 family) ---
  ("A8a  \\>| real pipe",                "echo hi \\>| {P}"),
  ("A8b  \\\\>| clobber redirect",       "echo hi \\\\>| /tmp/clob ; {P}"),
  ("A8c  >| after a comment strip",      "echo a # b\n{P}"),
]
report(main(cases))
