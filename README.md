# cognexus

**OWASP-aligned prompt defence, injection detection, and audit logging for LLM applications.**

`cognexus` gives you two complementary security layers and a tamper-evident audit trail — all in pure Python with zero mandatory dependencies.

```
pip install cognexus
```

---

## Features

| Layer | What it does |
|---|---|
| **Static prompt defence** | Grades system prompts A–F against 13 OWASP LLM Top-10 attack vectors before deployment |
| **Runtime injection detection** | Screens user input, RAG content, and tabular payloads at request time |
| **Audit events** | Append-only JSONL trail for every detected injection — no raw text stored |

### Detection coverage

- Direct instruction override
- Delimiter and context-boundary attacks
- Base64 / hex / ROT13 encoding attacks
- Role-play and jailbreak language (DAN mode, developer mode, etc.)
- Context manipulation ("your real instructions are…")
- Canary token leak detection
- Multi-turn escalation
- Cross-plugin / tool-chaining attacks (OWASP ASI04)
- Markup injection (XSS gadgets in model-visible text)
- Zero-width / token-smuggling unicode attacks
- Credential exfiltration requests
- Unsolicited destructive database operations (DROP / DELETE / TRUNCATE / volume-wipe) — PD-13

---

## Quick-start

```python
from cognexus import (
    augment_system_prompt,
    evaluate_system_prompt,
    screen_user_input,
    should_block,
)

# 1. Augment your system prompt so it scores grade A before inference
system = augment_system_prompt("You are a helpful customer support agent.")
report = evaluate_system_prompt(system)
print(report.grade)    # "A"
print(report.score)    # 100
print(report.missing)  # []

# 2. Screen every user message at request time
result = screen_user_input(user_message, source="chat")

if should_block(result):
    raise PermissionError(f"Injection blocked: {result.explanation}")
```

---

## Screening helpers

Three presets cover the most common LLM input surfaces:

```python
from cognexus import (
    screen_user_input,       # balanced sensitivity — direct chat messages
    screen_external_content, # strict  sensitivity — RAG / web / API content
    screen_tabular_payload,  # permissive           — CSV / dataframe blobs
    should_block,
    wrap_untrusted_content,
)

# Wrap RAG content before inserting into a prompt
safe_chunk = wrap_untrusted_content("web_search", raw_text)

# Screen it too
result = screen_external_content(raw_text, source="web_search", user_id=user.id)
```

### Sensitivity presets

| Preset | Threshold | Min threat flagged | Use for |
|---|---|---|---|
| `strict` | 0.3 | LOW | External / RAG content |
| `balanced` | 0.5 | LOW | Direct user input |
| `permissive` | 0.7 | HIGH | CSV / tabular payloads |

Override via environment variables:

```
COGNEXUS_PROMPT_INJECTION_USER_SENSITIVITY=balanced
COGNEXUS_PROMPT_INJECTION_EXTERNAL_SENSITIVITY=strict
COGNEXUS_PROMPT_INJECTION_TABULAR_SENSITIVITY=permissive
COGNEXUS_PROMPT_INJECTION_BLOCK=0   # set to 1 to block any hit, not just CRITICAL
```

---

## Using the core classes directly

```python
from cognexus import PromptInjectionDetector, DetectionConfig, InjectionType

detector = PromptInjectionDetector(
    config=DetectionConfig(
        sensitivity="strict",
        blocklist=["my-internal-keyword"],
        allowlist=["safe phrase"],
    )
)

result = detector.detect(text, source="api_gateway")
print(result.is_injection)       # True / False
print(result.threat_level)       # ThreatLevel.HIGH
print(result.injection_type)     # InjectionType.DIRECT_OVERRIDE
print(result.confidence)         # 0.9
print(result.matched_patterns)   # ["direct_override:..."]
```

---

## Audit events

Detections are automatically written to a JSONL file (no raw input stored):

```python
# Events go to $COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR/prompt_defense_events.jsonl
# (falls back to $REPORTS_DIR, then /tmp)

from cognexus.events import read_recent_events

rows = read_recent_events(user_id=42, limit=20)
# [{"ts": "...", "kind": "prompt_injection", "threat": "high", ...}, ...]
```

### Custom event sink (database, queue, dashboard)

Pass an `on_event` callback to mirror records into your own store:

```python
def save_to_db(record: dict) -> None:
    db.execute("INSERT INTO security_events ...", record)

screen_user_input(text, source="chat", user_id=user.id, on_event=save_to_db)
```

---

## Static prompt defence — standalone

```python
from cognexus import PromptDefenseEvaluator, PromptDefenseConfig

evaluator = PromptDefenseEvaluator(
    config=PromptDefenseConfig(min_grade="B")
)
report = evaluator.evaluate(my_system_prompt)

print(report.grade)     # "C"
print(report.score)     # 58
print(report.missing)   # ["unicode-attack", "context-overflow"]

if report.is_blocking():
    print("System prompt is below minimum grade — fix before deploying.")

# Evaluate a file
report = evaluator.evaluate_file("prompts/assistant.txt")

# Batch evaluation
reports = evaluator.evaluate_batch({
    "chat": chat_prompt,
    "analyst": analyst_prompt,
})
```

---

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR` | `/tmp` | JSONL audit file directory |
| `COGNEXUS_PROMPT_INJECTION_LOG` | `1` | Log clean scans at DEBUG |
| `COGNEXUS_PROMPT_INJECTION_BLOCK` | `0` | Block any injection (not just CRITICAL) |
| `COGNEXUS_PROMPT_INJECTION_USER_SENSITIVITY` | `balanced` | User-input preset |
| `COGNEXUS_PROMPT_INJECTION_EXTERNAL_SENSITIVITY` | `strict` | External/RAG preset |
| `COGNEXUS_PROMPT_INJECTION_TABULAR_SENSITIVITY` | `permissive` | CSV/tabular preset |

---

## Security notes

- All detection is **pure regex** — deterministic, zero LLM calls, zero network access, < 5 ms per input.
- Audit records store a **SHA-256 hash** and a **96-character redacted preview** of the input. Raw user text is never written to disk.
- The package ships **sample rules** that cover common attack patterns. Review and extend them for your production threat model using `DetectionConfig.custom_patterns` or a YAML config file loaded with `load_prompt_injection_config()`.

---

## License

MIT — see [LICENSE](LICENSE).

Detection rules and evaluator logic originally derived from [microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) (MIT).
