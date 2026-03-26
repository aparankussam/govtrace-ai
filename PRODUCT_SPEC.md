# GoVTraceAI

Tagline: Check before you send.

Vision:
Before a user sends anything to AI, this tool tells them if it is safe.

Core UX:
- One screen
- One action: "Check Risk"
- One result:
  - SAFE
  - WARNING
  - BLOCK

Core Checks:
- PII/PHI detection (regex-based)
- Prompt injection detection
- Risk / hallucination heuristics
- Basic policy-style checks

Findings Structure:
- type
- severity
- confidence
- example
- rationale
- recommended_action

Legal:
This tool provides automated risk screening and does not constitute legal or regulatory advice.

Constraints:
- Web-first
- Works on MacBook + iPhone
- No native apps
- No overengineering