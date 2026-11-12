# memos-fnos

Follow the shared Mamre rulebook when available and the portable snapshot in ../../docs/development-conventions.md otherwise. This module belongs to cedarot/fn-apps and shares its global Mamre record. Keep requirements outside this repository and do not create a project-local .codex directory.

Implement only an approved requirement on its issue branch. From this directory, validate with `make check test`, `make verify-image`, official `make package`, and real-container `make integration`; the repository root also supports `make APP=memos <target>`. If local Docker is unavailable, run the real integration job on a dedicated CI runner before marking the PR ready. Never substitute lifecycle mocks for that job or describe QEMU as fnOS hardware testing.

Preserve existing data and ACLs; no privileged containers, global Docker changes, automatic deployment, or merges. Record exact versions and all unverified hardware/client behavior.
