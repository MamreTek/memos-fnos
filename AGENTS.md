# fn-apps

Follow the shared Mamre rulebook when available and docs/development-conventions.md otherwise. Resolve the global project record by the cedarot/fn-apps origin; worktrees share that record. Requirements stay outside this repository. Do not create a project-local .codex directory.

Keep each application under apps/<app>/ with its own packaging, scripts, tests, documentation, and Makefile. Keep shared CI, the application index, and command dispatch at the repository root. Read the application's AGENTS.md before modifying it.

Implement an approved requirement on its issue branch and submit a PR after verification. Root commands select the application with APP (default: memos); validate module commands and CI paths after structural changes. Preserve application IDs, persistent paths, and runtime behavior during repository reorganizations unless a requirement explicitly changes them.

No automatic deployment, store submission, or merge. Distinguish container/QEMU checks from fnOS hardware and actual mobile-client validation.
