# VPS Console Redesign — Approved Design (2026-11-01)

## Problem and intent
The existing VPS page combines inventory, creation, Agent pairing, Root Helper trust, SSH verification, and dangerous manual actions in one long view. Operators cannot quickly scan servers or find the relevant single-node workflow. Adopt the information hierarchy of Komari without copying its monitoring product.

## Scope
- Independent hash-routed dashboard, VPS directory, single-node details, key manager, task center, audit and settings.
- Directory: searchable/sortable/filterable full-width table; simple online/pairing/initialization labels; optional group and notes.
- Create node: short wizard (basic information, Agent pairing, confirmation). Pairing token remains ephemeral and never stored in URL, logs or persistent browser storage.
- Single-node detail tabs: overview, Agent, SSH security, task history, settings.
- Node settings: edit display metadata and group/notes; edits to SSH host, port or login user may be made only while unpaired. No delete/re-pair bypass.
- Task center: last 100 operations, explicit RESULT_UNKNOWN display, per-node filter, periodic refresh while visible.
- Preserve current SSH verification proof and Root Helper protocol unchanged.

## Non-goals
Full VPS resource/traffic monitoring, browser SSH terminals, bulk SSH changes, automatic recovery, silent key rotation, password-based login to the management service.

## Constraints
- GitHub/Cloudflare Access identity flow is unchanged.
- Single-node UUID + human reason + server-side constraints remain mandatory for dangerous SSH commands.
- Never automatically rollback, restore password auth, or enable rescue keys.
- Existing migration history is immutable; use additive D1 migration.
- Main branch auto-deploys Staging: implementation lands on a reviewed feature branch/PR first.

## Approaches
1. Keep expanding the old page: lowest effort, retains the fundamental usability problem.
2. Rewrite backend + frontend: disproportionate risk to an unverified SSH safety system.
3. **Chosen: focused React UI redesign with small additive, audited metadata and task-list APIs.** Keeps safety-critical Agent and helper behavior intact.

## Acceptance
Every existing privileged action is still gated; existing and new tests pass; Cloudflare/Vite build succeeds; node URL is shareable; mobile layout functions; no mock production data is presented as real. Real VPS/Staging validation remains a separate safety gate.