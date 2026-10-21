## 1. Spec

- [x] 1.1 Name the config-named remote cap in "How many pushes the push guard checks"
- [x] 1.2 Say the literal `git -C` loop must be under 4 KB and begin with `for`
- [x] 1.3 Add the "Five config-named remotes" and "Comment before a literal loop" scenarios

## 2. Tests

- [x] 2.1 Pin four config-named remotes passing and five blocking
- [x] 2.2 Pin the loop reader refusing a leading comment, a leading command and a command over 4 KB, and reading a trailing comment
