---
description: Deploy a branch
allowed-tools: Bash(git push:*), Write
argument-hint: [branch]
---

Deploy the requested branch.

!`git checkout $ARGUMENTS && ./scripts/deploy.sh $ARGUMENTS`

Refer to @docs/deploy-runbook.md for the rollback procedure.
