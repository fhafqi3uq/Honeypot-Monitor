"""Maps a parsed event's MITRE ATT&CK technique IDs to a triage severity
level (critical/high/medium/low). Built on top of mitre_mapping.py's
technique classification rather than a second independent keyword system -
one command already resolves to technique(s) via map_mitre_techniques(),
this just ranks those technique(s) by how serious an analyst would treat
them.

Duplicated into notifier/notify_severity.py rather than shared - same
separate-venvs/sys.path reasoning as parser/log_setup.py vs
notifier/notify_log_setup.py (see CLAUDE.md).
"""

from __future__ import annotations

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

_SEVERITY_RANK: dict[str, int] = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}

# technique_id -> severity. Techniques not listed here (recon-ish ones:
# T1082 system info, T1033 whoami, T1057 ps, T1049 netstat, and the
# T1059.004 generic-shell-execution fallback) default to LOW - typing
# something into the fake shell isn't itself alarming, what matters is
# WHAT gets typed.
_TECHNIQUE_SEVERITY: dict[str, str] = {
    "T1136":     CRITICAL,  # Create Account
    "T1562.004": CRITICAL,  # Disable/modify the firewall
    "T1552.001": CRITICAL,  # Read /etc/shadow or /etc/passwd
    "T1105":     HIGH,      # Ingress Tool Transfer (wget/curl a payload)
    "T1078":     HIGH,      # Valid Accounts (a login actually succeeded)
    "T1053.003": HIGH,      # Persistence via cron
    "T1222":     MEDIUM,    # chmod +x / 777 (staging a downloaded binary)
    "T1070.003": MEDIUM,    # Clear command history (covering tracks)
    "T1110":     LOW,       # Brute force (one failed/attempted login)
    "T1021.004": LOW,       # A session merely connecting
}


def classify_severity(mitre_techniques: list[str]) -> str:
    """Highest severity among this event's MITRE techniques - LOW if the
    event carries no technique tag at all (e.g. cowrie.session.closed)."""
    if not mitre_techniques:
        return LOW
    return max(
        (_TECHNIQUE_SEVERITY.get(t, LOW) for t in mitre_techniques),
        key=_SEVERITY_RANK.__getitem__,
    )
