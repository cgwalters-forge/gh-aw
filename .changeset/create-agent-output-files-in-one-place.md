---
"gh-aw": patch
---

Create the files an agent execution step writes (the step summary, `agent-stdio.log` and engine debug logs) through one shared helper for every engine, with and without AWF. Compiled lock files change only in where these `touch` lines appear; Claude's debug log is now created together with the agent log, and the `sandbox.agent: false` Claude step no longer has stray indentation.
