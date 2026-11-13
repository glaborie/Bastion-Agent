### IDEA-044: Scan the whole prompt for injection and confidentiality, not the first 8192 tokens

- status: inbox
- priority: P0
- phase: v0.3
- area: agent
- tags: classifier, prompt-injection, routing, onnx
- depends-on: -
- spec: ADR-011
- created: 2026-11-13
- updated: 2026-11-13
- source: security review of feat/backlog-list on 2026-11-13

**Problem**

`agent/routing/classifier.py:377` slices the token list to `_MAX_DOCUMENT_TOKENS` (8192) before
`_windows()` at `:773`, so no window ever covers the tail, while `gateway/routers/chat.py:86`
admits `MAX_TOTAL_CHARS = 65_536` (roughly 16k tokens). ADR-011 section 6 and the module
docstring both claim windowing exists so that an instruction planted late in a tool output is
not lost to truncation.

A caller pads the request with benign filler and puts the injection in the last message: the
injection probability is never computed, `decide_ensemble` returns `PUBLIC`, the reason is not
`prompt_injection_detected`, so the refusal gate at `chat.py:446` does not fire and the prompt
plus the answer come from the cloud alias. The same padding hides unmarked confidential content.
Only the whole-text regex floor remains, and it knows 12 markers.

**Outcome**

Every token of an accepted request is scored by at least one window, or the request is refused
when it exceeds the scannable length. Text that was never classified cannot reach a cloud
provider.

**Acceptance**

- [ ] A test builds a prompt above 8192 tokens with an injection as the last message and asserts the reason is `prompt_injection_detected`
- [ ] A test builds a prompt above 8192 tokens with unmarked confidential content and asserts the route is local
- [ ] ADR-011 section 6 and the classifier docstring describe what the code does, or are corrected
