"""cognexus — LLM prompt defence, runtime guards, and audit logging.

Four complementary safety layers for AI-agent applications, all in pure
Python with zero mandatory dependencies:

**Static prompt defence** (:mod:`cognexus.prompt_defense`)
    Evaluates system prompts against the OWASP LLM Top-10 (and Agentic ASI)
    attack vectors before deployment.  Pure regex, deterministic, < 5 ms
    per prompt, zero network or LLM cost.  Includes the post-PocketOS /
    Cursor / Claude vectors ``never-guess-destructive`` and
    ``kill-switch-awareness``.

**Runtime input injection detection** (:mod:`cognexus.prompt_injection`)
    Screens user input, RAG content, and tabular payloads at inference
    time for direct override, delimiter, encoding, jailbreak,
    context-manipulation, canary-leak, multi-turn-escalation, cross-plugin,
    markup, token-smuggling, and credential-exfiltration patterns.

**Runtime output destructive-action guard**
(:mod:`cognexus.destructive_action_guard`)
    Screens *model-generated* SQL / shell / git / cloud commands for
    catastrophic, irreversible operations (``DROP DATABASE``,
    ``git push --force``, ``rm -rf /``, ``terraform destroy --auto-approve``,
    etc.) **before** they execute.  Pattern-classified by severity
    (``low / medium / high / critical``).

**Agent kill switch** (:mod:`cognexus.kill_switch`)
    Cooperative-cancellation + programmatic + manual stop for in-flight
    agent runs.  Trips automatically on a CRITICAL destructive-action
    signal, fires a pluggable ``on_kill`` callback, and raises
    :class:`AgentKilledError` so orchestrators unwind cleanly.

**Audit events** (:mod:`cognexus.events`)
    Append-only JSONL audit trail for every detected injection (no raw
    text stored).  Pluggable ``on_event`` callback for custom sinks
    (databases, queues, dashboards).

Quick-start::

    from cognexus import (
        screen_user_input,
        should_block,
        augment_system_prompt,
        evaluate_system_prompt,
        screen_agent_action,
        raise_if_killed,
        AgentKilledError,
    )

    # 1. Augment your system prompt before inference
    system = augment_system_prompt("You are a helpful assistant.")
    report = evaluate_system_prompt(system)
    print(report.grade)  # "A"

    # 2. Screen user input at request time
    result = screen_user_input(user_message, source="chat")
    if should_block(result):
        raise PermissionError("Injection detected")

    # 3. Wrap every tool call with the destructive-action guard + kill switch
    try:
        for step in plan:
            raise_if_killed(run_id)
            screen_agent_action(
                step.payload, run_id=run_id, agent_id="my-agent",
                source=step.tool,
            )
            execute(step)
    except AgentKilledError as kex:
        mark_run_killed(run_id, kex.reason)

The PocketOS / Cursor / Claude database-deletion incident
(Guardian, Apr 2026) showed that prompt-only safety is insufficient: an
agent can acknowledge a "never run destructive commands" rule and violate
it nine seconds later.  Together, the four layers above catch the
violation at three independent points (system prompt, runtime output,
operator-controlled cancel).
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
from cognexus.destructive_action_guard import (
    ActionMatch,
    ActionScreenResult,
    ActionSeverity,
    DestructiveActionGuard,
    DestructiveActionGuardConfig,
    reset_guard,
    screen_action,
)
from cognexus.events import (
    read_recent_events,
    record_prompt_defense_event,
)
from cognexus.kill_switch import (
    AgentKilledError,
    KillRecord,
    OnKillCallback,
    clear_global_panic,
    clear_run,
    global_panic_record,
    is_global_panic_active,
    is_killed,
    kill_record,
    raise_if_killed,
    recent_activations,
    screen_agent_action,
    set_default_on_kill,
    trip,
    trip_global,
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

__version__ = "0.2.1"

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
    # Destructive action guard
    "screen_action",
    "ActionScreenResult",
    "ActionMatch",
    "ActionSeverity",
    "DestructiveActionGuard",
    "DestructiveActionGuardConfig",
    "reset_guard",
    # Kill switch
    "AgentKilledError",
    "KillRecord",
    "OnKillCallback",
    "screen_agent_action",
    "raise_if_killed",
    "is_killed",
    "kill_record",
    "trip",
    "trip_global",
    "clear_global_panic",
    "clear_run",
    "recent_activations",
    "is_global_panic_active",
    "global_panic_record",
    "set_default_on_kill",
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
