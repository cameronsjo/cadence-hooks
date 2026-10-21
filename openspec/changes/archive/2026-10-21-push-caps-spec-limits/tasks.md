## 1. Spec

- [x] 1.1 Name the config cap, counted in directory and remote pairs, in "How many pushes the push guard checks"
- [x] 1.2 Move the literal `git -C` loop to its own requirement, with the 4096-byte and `for` limits
- [x] 1.3 Add the "Five config-named remotes" and "Comment before a literal loop" scenarios

## 2. Tests

- [x] 2.1 Pin four config-named remotes passing and five blocking
- [x] 2.2 Pin the loop reader reading a 4096-byte command and refusing a 4097-byte one, a leading comment and a leading command, and reading a trailing comment
- [x] 2.3 Pin, at the hook, a comment before the scenario's loop blocking with `too many push-loop remotes to verify`
