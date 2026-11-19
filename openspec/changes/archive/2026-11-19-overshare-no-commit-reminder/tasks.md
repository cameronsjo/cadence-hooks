## 1. Behavior

- [x] 1.1 Give `warn-overshare` a posting gate without the `git commit` arm; the leak scan keeps the full gate
- [x] 1.2 Remove the quiet-period code, its dispatcher call and its end-to-end test
- [x] 1.3 Pin commit-only silence, commit-plus-push and commit-plus-post reminders, and the variant gate

## 2. Docs

- [x] 2.1 Drop the commit from the triggers requirement and remove the four quiet-period requirements
- [x] 2.2 Update `docs/hooks.md` and fold the changelog bullet so `[Unreleased]` states the net behavior
- [x] 2.3 Archive the change in this PR
