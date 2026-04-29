"""cognexus — LLM prompt defence and audit logging.

Two complementary layers for securing LLM applications:

**Static prompt defence** (:mod:`cognexus.prompt_defense`)
    Evaluates system prompts against 12 OWASP LLM Top-10 attack vectors before
    deployment.  Pure regex, deterministic, < 5 ms per prompt, zero network or
    LLM cost.

**Runtime injection detection** (:mod:`cognexus.prompt_injection`)
    Screens user input, RAG content, and tabular payloads at inference time for
    direct override, delimiter, encoding, jailbreak, context-manipulation,
    canary-leak, multi-turn-escalation, cross-plugin, markup, token-smuggling,
    and credential-exfiltration patterns.

**Audit events** (:mod:`cognexus.events`)
    Append-only JSONL audit trail for every detected injection (no raw text
    stored).  Pluggable ``on_event`` callback for custom sinks (databases,
    queues, dashboards).

Quick-start::

    from cognexus import (
        screen_user_input,
        should_block,
        augment_system_prompt,
        evaluate_system_prompt,
    )

    # Augment your system prompt before inference
    system = augment_system_prompt("You are a helpful assistant.")
    report = evaluate_system_prompt(system)
    print(report.grade)  # "A"

    # Screen user input at request time
    result = screen_user_input(user_message, source="chat")
    if should_block(result):
        raise PermissionError("Injection detected")
"""

from cognexus._helpers import (
    augment_system_prompt,
    evaluate_system_prompt,
    maybe_log_prompt_defense,
    reset_detectors,
    screen_external_content,
    screen_tabular_payload,
    screen_user_input,
    should_block,
    wrap_untrusted_content,
)
from cognexus.events import (
    read_recent_events,
    record_prompt_defense_event,
)
from cognexus.prompt_defense import (
    GRADE_THRESHOLDS,
    VECTOR_COUNT,
    PromptDefenseConfig,
    PromptDefenseEvaluator,
    PromptDefenseFinding,
    PromptDefenseReport,
)
from cognexus.prompt_injection import (
    AuditRecord,
    DetectionConfig,
    DetectionResult,
    InjectionType,
    PromptInjectionDetector,
    ThreatLevel,
    load_prompt_injection_config,
)

__version__ = "0.1.0"

__all__ = [
    # Version
    "__version__",
    # Screening helpers (most common entry-points)
    "screen_user_input",
    "screen_external_content",
    "screen_tabular_payload",
    "should_block",
    "wrap_untrusted_content",
    "reset_detectors",
    # Prompt defence helpers
    "augment_system_prompt",
    "evaluate_system_prompt",
    "maybe_log_prompt_defense",
    # Audit events
    "record_prompt_defense_event",
    "read_recent_events",
    # Core data models — prompt defence
    "PromptDefenseEvaluator",
    "PromptDefenseReport",
    "PromptDefenseFinding",
    "PromptDefenseConfig",
    "GRADE_THRESHOLDS",
    "VECTOR_COUNT",
    # Core data models — injection detection
    "PromptInjectionDetector",
    "DetectionResult",
    "DetectionConfig",
    "InjectionType",
    "ThreatLevel",
    "AuditRecord",
    "load_prompt_injection_config",
]
