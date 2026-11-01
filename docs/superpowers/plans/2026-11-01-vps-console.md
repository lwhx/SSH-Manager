# SSH Manager VPS Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or equivalent native implementation; track tasks and verify each stage.

**Goal:** Replace the monolithic VPS admin view with a usable directory, node detail tabs, creation wizard, tasks, and settings while preserving SSH safety boundaries.

**Architecture:** Keep existing control Worker and Agent protocols. Add whitelisted metadata PATCH and read-only operation list APIs, then split React presentation into focused modules. Use hash routes to avoid Cloudflare SPA fallback changes.

**Tech Stack:** React 19, TypeScript, Vite, Vitest, Cloudflare Workers and D1.

**Spec:** docs/superpowers/specs/2026-11-01-vps-console-design.md

## Global constraints
- No new unauthenticated routes or dangerous SSH endpoints.
- Never automatically roll back; single VPS and explicit human confirmation only.
- Pairing and verification secrets remain transient, never persisted in URL.
- Main auto-deploys; change must go through PR, not a direct main push.

## Review Focus
- Unknown/malformed hash route: safe dashboard or directory fallback.
- Nodes with stale heartbeat: must not appear online.
- Paired node connection edits: reject server-side regardless of UI.
- Operation RESULT_UNKNOWN: display uncertainty, never successful outcome.
- Non-owner: no owner-only audit, proof pinning or manual changes.

### Task 1: Pure routing and directory selection
**Files:** apps/console/src/nodeNavigation.ts(.test.ts), nodeDisplay.ts(.test.ts)
**Interfaces:** parseConsoleRoute(hash): ConsoleRoute; consoleRouteHref(page,nodeId?); filterNodes(nodes,options,now).
- [ ] Write route and filter tests first.
- [ ] Run npm run test and confirm expected failure from missing functions.
- [ ] Implement pure functions.
- [ ] Run npm run test and confirm pass.
- [ ] Commit.

### Task 2: Audited node metadata APIs
**Files:** apps/control-worker/src/nodeMetadata.ts(.test.ts), index.ts; packages/db/migrations/0007_node_metadata.sql
**Interfaces:** parseNodeChanges(input,current) returns complete sanitized fields; PATCH /nodes/:id and GET /operations.
- [ ] Write tests for validation, unknown fields, paired connection lock, empty input.
- [ ] Run test to confirm expected failure.
- [ ] Add additive migration and API with admin role and Origin checks.
- [ ] Run migration tests, npm run check and npm run test.
- [ ] Commit.

### Task 3: Reusable inventory and wizard components
**Files:** apps/console/src/NodeDirectory.tsx, AddNodeWizard.tsx
**Interfaces:** NodeDirectory({nodes,onSelect}); AddNodeWizard({open,onClose,onCreate,onNewToken,onRefresh,onOpenNode}).
- [ ] Add component behavior assertions / route and filter tests.
- [ ] Render full-width inventory with filters and sorting.
- [ ] Implement create+pair+confirmation steps using existing safe AgentInstallWizard.
- [ ] Verify with typecheck and tests.
- [ ] Commit.

### Task 4: Split the node workflows and navigation
**Files:** apps/console/src/main.tsx, NodeSettings.tsx, TaskCenter.tsx
**Interfaces:** hash-based navigation; details with overview/agent/security/history/settings.
- [ ] Add tests for metadata submission and route handling.
- [ ] Keep preflight/proof/verification/manual handlers and their guards.
- [ ] Render separate views, task list and owner settings, no simulated SSH success.
- [ ] Verify npm run check / test.
- [ ] Commit.

### Task 5: Responsive polish, safety review and PR
**Files:** apps/console/src/style.css, docs and relevant tests.
- [ ] Verify mobile and desktop layout structure, keyboard actions and accessible dialogs.
- [ ] Run npm run check, test, build:web, migration test and CI.
- [ ] Inspect diff for accidental privileged behavior change.
- [ ] Open reviewable PR; do not merge into main or activate high-risk toggles.