# Responsible use

Ouroboros Red Team is an **ethical red-team and defensive** tool. It exists to
harden LLM agents you own or are explicitly authorized to test. Read this before
pointing it at anything.

## Rules

1. **Never run against production.** Ouroboros targets local checkouts or staging
   deployments only. It must never send payloads to a live, user-facing endpoint.
2. **Never test third-party agents without permission.** Authorization is your
   responsibility. The tool's safeguards reduce blast radius; they are not consent.
3. **Auditor mode is the default and the floor.** Without confirmed write access,
   Ouroboros only produces a report — it will not, and structurally cannot,
   mutate the target.
4. **Dynamic analysis in auditor mode runs against a mocked client**, not the real
   third-party agent, and its findings are labelled reduced-confidence so they are
   never over-represented.
5. **Rate limiting is mandatory** for the Dynamic Attacker (from week 4) to avoid
   abusing API costs, even on your own repositories.

## Why the safeguards exist

The same capability that hardens your agents could harass someone else's. The
fail-safe to auditor mode, the mocked-client dynamic path, and the
`AuditReport` invariant that forbids auditor-mode writes are all there to make the
irresponsible path the hard one. Keep it that way.

## Framing

This project is a defensive, auditing tool — red team in service of blue team —
not a general-purpose attack utility. Present and use it as such.
