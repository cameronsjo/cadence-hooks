## 1. Hook

- [x] 1.1 Count two or more blanks or a tab before `pass`, a word before it ending in `:` or starting with `-`, and a field with a leading `{ ( [ &` as key position
- [x] 1.2 Out of key position, mask the unquoted value of a bare `pass:` only when the rules of a bare `pass` mask it and the first word of the value that holds a letter or a digit looks like a credential; otherwise spend only that word, so a later field on the line is read
- [x] 1.3 Pin the grep, `cat -n`, Go `%+v` and `openssl` rows, one masked row per opener and marker byte, and the prose rows that stay unmasked
- [x] 1.4 Pin the credential-plus-note, later-field and mark-first rows that mask, the code-shaped and tally rows that stay unmasked, and mutate each clause

## 2. Docs

- [x] 2.1 Update the CHANGELOG.md bullet under [Unreleased]
