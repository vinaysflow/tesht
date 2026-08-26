# Phase 1.5 — Design Partner Discovery Script

Use this script **before** choosing the Phase 2 vertical pack.
Do **not** pick SecOps vs EU AI Act from recency — pick from these conversations.

Target: **3–5 MSSP / SecOps** conversations + **2–3 EU AI Act / AI governance** conversations.

## Goals

1. Confirm whether buyers put agents **in the live action path** today (or next 90 days).
2. Learn who owns budget (CISO / AI platform / compliance / fraud).
3. Map their pain to Tesht’s Session runtime: handoff → decide → step_up → revoke.
4. Decide Phase 2 pack: `secops_actions` **or** `eu_ai_act_evidence` (evidence-driven).

## Qualification (any vertical)

- Are AI agents (or agentic workflows) already calling tools / APIs / MCP servers?
- What happens today when an agent is wrong or compromised? (manual revoke? keys? hope?)
- Do you need a portable proof of *who authorized this agent for this action*?
- Budget line: security-for-AI / agent governance / compliance tooling / other?
- Can they run a **90-day paid pilot** with one workflow in path?

## MSSP / Agentic SecOps questions

1. Do remediation / containment / enrichment agents take **actions** (isolate host, disable account), or only suggest?
2. How are those agents authenticated today (shared API key, service account, human SSO)?
3. When a playbook agent escalates privileges mid-incident, can you **revoke mid-session**?
4. Do you use MCP or similar tool buses for SOC agents?
5. Would you put an authorization gateway in front of remediation tools if it added &lt;100ms?
6. Multi-tenant: do you need per-customer scope isolation for the same agent fleet?
7. Who signs? (MSSP CISO, customer CISO, both)
8. Rough ACV comfort for a pilot ($50–150K)?

**Green flags for SecOps pack:** agents already act; MCP/tool path exists; revoke/audit is a board question.

## EU AI Act / governance questions

1. Are you treating any agents as high-risk or limited-risk under the AI Act?
2. Do you already retain **≥6 months** of action logs with integrity guarantees?
3. Can you prove **human oversight / stop** for a given agent action (Art. 14 / deployer duties)?
4. Is Aug 2026 transparency / Dec 2027 high-risk driving a procurement this year?
5. Do you need evidence export mapped to Art. 12 / Art. 26, or enforcement in the path?
6. Is legal/compliance the buyer, or security engineering?

**Green flags for EU AI Act pack:** deadline-driven budget; missing tamper-evident logs; oversight/step-up required.

## Scorecard (fill per conversation)

| Signal | Score 1–5 | Notes |
|--------|-----------|-------|
| Agents already in production path | | |
| Clear owner + budget | | |
| Pain matches handoff/revoke/continuous trust | | |
| Willing to pilot in 90 days | | |
| Connector they need is feasible (SSF / MCP / IdP) | | |

**Decision rule:** First partner with average ≥4 and a signed pilot intent picks the vertical. If both verticals score well, prefer the one that lands a written pilot SOW first.

## Out of scope for Phase 2

- Competing with Visa/Mastercard agent payment trust layers
- Building a SIEM / alert triage platform
- Prompt-driven agent configuration DX

## After conversations

Record: company, role, date, scorecard, preferred pack, blockers.  
Feed into Phase 2: one pack + one connector only.
