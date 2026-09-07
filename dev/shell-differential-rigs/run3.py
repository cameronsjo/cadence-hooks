import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oracle import main, report
cases = [
  ("CTRL-neg bare",                    "{P}"),
  ("CTRL-pos pipe-to-bash",            "echo '{P}' | bash"),
  # the confirmed family, across every parameter-expansion operator
  ("B1 :-  default",                   "echo ${x:-a)b # c} ; {P}"),
  ("B2 :=  assign-default",            "echo ${x:=a)b # c} ; {P}"),
  ("B3 :+  alt value",                 "x=1; echo ${x:+a)b # c} ; {P}"),
  ("B4 :?  error msg",                 "x=1; echo ${x:?a)b # c} ; {P}"),
  ("B5 #   prefix strip w/ )",         "x=a; echo ${x#)} # y\n{P}"),
  ("B6 %   suffix strip w/ )",         "x=a; echo ${x%)b # c} ; {P}"),
  ("B7 /   substitution w/ )",         "x=a; echo ${x/a/)b # c} ; {P}"),
  ("B8 //  global subst w/ )",         "x=a; echo ${x//a/)b # c} ; {P}"),
  ("B9 nested ${ } inside default",    "echo ${x:-${y:-)}b # c} ; {P}"),
  ("B10 two ) in default",             "echo ${x:-))a # c} ; {P}"),
  ("B11 ) inside $( ) inside ${ }",    "echo ${x:-$(echo a) )b # c} ; {P}"),
  ("B12 ) in default, # on next line", "echo ${x:-a)b} ;\n# y\n{P}"),
  ("B13 ) in default, no # (control)", "echo ${x:-a)b} ; {P}"),
  ("B14 ) in default, && instead of ;","echo ${x:-a)b # c} && {P}"),
  ("B15 ) in default, | instead",      "echo ${x:-a)b # c} | cat ; {P}"),
  ("B16 quoted \"${x:-a)b # c}\"",     "echo \"${x:-a)b # c}\" ; {P}"),
  ("B17 ) via array subscript",        "echo ${a[0]:-x)y # z} ; {P}"),
  ("B18 $( ) with stray } then #",     "echo $(echo a} # b) ; {P}"),
  ("B19 backtick with stray } then #", "echo `echo a} # b` ; {P}"),
  # trailing-backslash-in-comment family
  ("C1 comment ends with backslash",   "echo a #\\\n{P}"),
  ("C2 comment ends with \\\\",        "echo a #\\\\\n{P}"),
  ("C3 comment w/ backslash mid",      "echo a # x\\y\n{P}"),
  ("C4 bare-# line ends w/ backslash", "#\\\n{P}"),
]
report(main(cases))
