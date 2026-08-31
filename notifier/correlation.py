"""
correlation.py (draft)

Lightweight cross-event correlation for the honeypot alert pipeline.

realtime_alert.py already alerts on single events (one failed login, one
successful login, one session's command list) with a per-(ip, alert_type)
cooldown - see ALERT_COOLDOWN_SECONDS there. What it can't express is a
pattern across MULTIPLE events/types for the same attacker, e.g. "5 failed
logins from one IP inside 60s" or "failed login -> success -> command in the
same session". That's what this module adds.

Unlike the SIEM-dashboard reference this was adapted from, there's no Redis
Stream and no rule-storage model here: this project's watch_log() loops
already hand one parsed Cowrie event at a time to process_event() in-process
(see log_watcher.py / realtime_alert.py), so evaluate_event() below is meant
to be called directly from that same loop, synchronously, no daemon thread
or lock needed. Rules are a plain module-level list - edit CORRELATION_RULES
to add/tune one, no DB or config file involved.

Wired into realtime_alert.py's process_event() - see the call to
evaluate_event() there, right after the existing per-event Telegram alerts.

Deliberately NOT attempted here: correlating across the SSH honeypot
(Cowrie, watched by this file's process) and the HTTP honeypot
(watched by a SEPARATE OS process - see notifier/http_honeypot_alert.py,
its own `docker-compose.yml` service). CorrelationState is an in-memory,
single-process object - two independent processes can't share one without
an external store (Redis, Mongo). A "same IP hit both honeypots" rule
would need that external store; skipped rather than half-built.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from notify_log_setup import get_logger

logger = get_logger(__name__)

# How long a fired rule stays silent for the same group_key before it can
# fire again. Independent from realtime_alert.py's ALERT_COOLDOWN_SECONDS -
# these are different alert types.
CORRELATION_COOLDOWN_SECONDS = 5 * 60


def _matches(event: dict[str, Any], event_filter: dict[str, Any]) -> bool:
    """A filter value that's callable is a predicate applied to the
    event's value for that key (e.g. substring-matching a command line,
    which exact equality can't express); anything else is compared with
    ==, same as before."""
    for key, expected in event_filter.items():
        actual = event.get(key)
        if callable(expected):
            if not expected(actual):
                return False
        elif actual != expected:
            return False
    return True


@dataclass
class WindowEntry:
    timestamp: float
    event: dict[str, Any]
    step_index: int | None = None


@dataclass
class CorrelationRule:
    id: str
    rule_type: str  # "threshold" | "sequence" | "aggregation"
    group_by: str = "src_ip"
    window_seconds: int = 60
    # threshold / aggregation only:
    event_filter: dict[str, Any] = field(default_factory=dict)
    threshold: int = 1
    aggregation_field: str = ""
    # sequence only: list of {"event_filter": {...}, "count": 1}
    steps: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""
    # One of notify_severity.{LOW,MEDIUM,HIGH,CRITICAL} - not imported as
    # the type here (plain str) so a rule can be written without pulling
    # in notify_severity just to spell the constant; the values match.
    severity: str = "low"


def _input_contains(*keywords: str) -> Callable[[Any], bool]:
    """Predicate for an event_filter value: True if the event's `input`
    (a cowrie.command.input's shell text) contains any of these keywords,
    case-insensitively. `_matches` calls this with the field's actual
    value - see its callable-predicate handling above."""
    def predicate(value: Any) -> bool:
        return bool(value) and any(kw in value.lower() for kw in keywords)
    return predicate


# Example rules tuned to Cowrie's event shape (eventid, src_ip, session,
# username, command - see log_watcher.py's parse_event() for the full doc).
CORRELATION_RULES: list[CorrelationRule] = [
    CorrelationRule(
        id="brute_force_burst",
        rule_type="threshold",
        group_by="src_ip",
        window_seconds=60,
        event_filter={"eventid": "cowrie.login.failed"},
        threshold=5,
        message="{group_key}: {count} failed logins in {window}s",
        severity="medium",
    ),
    CorrelationRule(
        id="compromise_chain",
        rule_type="sequence",
        group_by="src_ip",
        window_seconds=120,
        steps=[
            {"event_filter": {"eventid": "cowrie.login.failed"}, "count": 1},
            {"event_filter": {"eventid": "cowrie.login.success"}, "count": 1},
            {"event_filter": {"eventid": "cowrie.command.input"}, "count": 1},
        ],
        message="{group_key}: failed login -> success -> command within {window}s (likely compromise)",
        severity="high",
    ),
    CorrelationRule(
        id="credential_scan",
        rule_type="aggregation",
        group_by="src_ip",
        window_seconds=60,
        event_filter={"eventid": "cowrie.login.failed"},
        aggregation_field="username",
        threshold=4,
        message="{group_key}: {count} distinct usernames tried in {window}s (credential scan)",
        severity="medium",
    ),
    CorrelationRule(
        id="dictionary_attack_multi_session",
        rule_type="aggregation",
        group_by="src_ip",
        window_seconds=300,
        event_filter={"eventid": "cowrie.login.failed"},
        # Distinct SESSIONS, not distinct usernames (that's credential_scan
        # above) - a bot that disconnects and reconnects for every attempt
        # (common when Cowrie's own login-attempt limit kicks it after a
        # few tries per session) looks different from one that just keeps
        # retrying inside a single long-lived session.
        aggregation_field="session",
        threshold=3,
        message="{group_key}: {count} separate sessions retrying logins in {window}s (reconnect-and-retry bot)",
        severity="medium",
    ),
    CorrelationRule(
        id="download_and_execute",
        rule_type="sequence",
        group_by="src_ip",
        window_seconds=180,
        steps=[
            {
                "event_filter": {
                    "eventid": "cowrie.command.input",
                    "input": _input_contains("wget", "curl", "tftp", "ftpget"),
                },
                "count": 1,
            },
            {
                "event_filter": {
                    "eventid": "cowrie.command.input",
                    "input": _input_contains("chmod +x", "chmod 777", "chmod 755", "./"),
                },
                "count": 1,
            },
        ],
        message="{group_key}: downloaded then staged/executed a file within {window}s (payload drop)",
        severity="critical",
    ),
]


class CorrelationState:
    """In-memory sliding window + cooldown tracker, keyed by (rule_id, group_key).

    No lock: evaluate_event() is called synchronously from a single-threaded
    watch_log() loop, same as everything else it calls (get_geo, Mongo
    insert_one). Add a threading.Lock if this ever gets called from more
    than one thread.
    """

    def __init__(self) -> None:
        self._windows: dict[str, dict[str, list[WindowEntry]]] = {}
        self._cooldowns: dict[str, dict[str, float]] = {}

    def record(self, rule_id: str, group_key: str, event: dict, step_index: int | None = None) -> None:
        entries = self._windows.setdefault(rule_id, {}).setdefault(group_key, [])
        entries.append(WindowEntry(timestamp=time.time(), event=event, step_index=step_index))

    def window(self, rule_id: str, group_key: str, window_seconds: int) -> list[WindowEntry]:
        cutoff = time.time() - window_seconds
        entries = self._windows.get(rule_id, {}).get(group_key, [])
        valid = [e for e in entries if e.timestamp >= cutoff]
        if rule_id in self._windows and group_key in self._windows[rule_id]:
            self._windows[rule_id][group_key] = valid
        return valid

    def is_cooling_down(self, rule_id: str, group_key: str) -> bool:
        last = self._cooldowns.get(rule_id, {}).get(group_key, 0.0)
        return (time.time() - last) < CORRELATION_COOLDOWN_SECONDS

    def mark_fired(self, rule_id: str, group_key: str) -> None:
        self._cooldowns.setdefault(rule_id, {})[group_key] = time.time()


@dataclass
class CorrelationAlert:
    rule_id: str
    group_key: str
    message: str
    severity: str
    matched_events: list[dict[str, Any]]


def _eval_threshold(rule: CorrelationRule, event: dict, state: CorrelationState, group_key: str) -> CorrelationAlert | None:
    if not _matches(event, rule.event_filter):
        return None
    state.record(rule.id, group_key, event)
    entries = state.window(rule.id, group_key, rule.window_seconds)
    if len(entries) < rule.threshold:
        return None
    state.mark_fired(rule.id, group_key)
    return CorrelationAlert(
        rule_id=rule.id,
        group_key=group_key,
        message=rule.message.format(group_key=group_key, count=len(entries), window=rule.window_seconds),
        severity=rule.severity,
        matched_events=[e.event for e in entries],
    )


def _eval_sequence(rule: CorrelationRule, event: dict, state: CorrelationState, group_key: str) -> CorrelationAlert | None:
    matched_step = next(
        (idx for idx, step in enumerate(rule.steps) if _matches(event, step["event_filter"])),
        None,
    )
    if matched_step is None:
        return None
    state.record(rule.id, group_key, event, step_index=matched_step)
    entries = state.window(rule.id, group_key, rule.window_seconds)
    for idx, step in enumerate(rule.steps):
        required = step.get("count", 1)
        if len([e for e in entries if e.step_index == idx]) < required:
            return None
    state.mark_fired(rule.id, group_key)
    return CorrelationAlert(
        rule_id=rule.id,
        group_key=group_key,
        message=rule.message.format(group_key=group_key, window=rule.window_seconds),
        severity=rule.severity,
        matched_events=[e.event for e in entries],
    )


def _eval_aggregation(rule: CorrelationRule, event: dict, state: CorrelationState, group_key: str) -> CorrelationAlert | None:
    if not _matches(event, rule.event_filter):
        return None
    state.record(rule.id, group_key, event)
    entries = state.window(rule.id, group_key, rule.window_seconds)
    distinct = {e.event.get(rule.aggregation_field) for e in entries if e.event.get(rule.aggregation_field)}
    if len(distinct) < rule.threshold:
        return None
    state.mark_fired(rule.id, group_key)
    return CorrelationAlert(
        rule_id=rule.id,
        group_key=group_key,
        message=rule.message.format(group_key=group_key, count=len(distinct), window=rule.window_seconds),
        severity=rule.severity,
        matched_events=[e.event for e in entries],
    )


_EVALUATORS: dict[str, Callable] = {
    "threshold": _eval_threshold,
    "sequence": _eval_sequence,
    "aggregation": _eval_aggregation,
}


def evaluate_event(
    event: dict[str, Any],
    state: CorrelationState,
    rules: list[CorrelationRule] = CORRELATION_RULES,
) -> list[CorrelationAlert]:
    """Run one raw Cowrie event through every rule, return the alerts (if
    any) that fired. Call this once per event from watch_log()'s loop,
    right where realtime_alert.py's process_event() already handles that
    event."""
    fired: list[CorrelationAlert] = []
    for rule in rules:
        group_key = event.get(rule.group_by, "")
        if not group_key:
            continue
        if state.is_cooling_down(rule.id, group_key):
            continue
        evaluator = _EVALUATORS[rule.rule_type]
        result = evaluator(rule, event, state, group_key)
        if result is not None:
            fired.append(result)
            logger.info(
                "Correlation rule fired: %s", result.message,
                extra={"rule_id": rule.id, "group_key": group_key},
            )
    return fired
