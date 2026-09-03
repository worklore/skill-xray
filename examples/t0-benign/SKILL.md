---
name: commit-message-helper
description: Writes clear conventional-commit messages from a diff.
---
# Commit message helper
Read the staged diff the user shows you and propose a conventional-commit
message: a type prefix (feat/fix/docs/chore), a scope, and a one-line summary
under 72 characters. Offer three options, best first. Do not run git yourself;
just draft the text for the user to use.
