# Domain Docs

## Layout and reading

Single-context: root `GLOSSARY.md` and `docs/adr/`.

Before exploring, read the glossary and ADRs relevant to the area. If a root `GLOSSARY-MAP.md` later exists, follow it to relevant context glossaries and also check `src/<context>/docs/adr/`.

If these files are absent, proceed silently. `/domain-modeling` creates them lazily when terms or decisions are resolved.

## Vocabulary

Use the glossary's terms in issue titles, proposals, hypotheses, and test names. If a concept is missing, reconsider invented language or note the gap for `/domain-modeling`.

## ADR conflicts

Explicitly flag proposals that contradict an ADR, citing its identifier and why reopening it is warranted.
