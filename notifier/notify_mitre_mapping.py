"""Maps a Cowrie eventid (and, for cowrie.command.input, the command text
itself) to the MITRE ATT&CK Enterprise techniques an analyst would tag it
with during triage. Command-text matching is deliberately simple keyword
matching, not full parsing - enough to demonstrate technique classification
against real captured commands, not a substitute for a real EDR/SIEM parser.

Duplicated from parser/mitre_mapping.py rather than shared, and named
differently (notify_ prefix) for the same reason as notify_log_setup.py
vs log_setup.py: parser/ and notifier/ are both on sys.path in the test
session, so an identically-named module in both dirs would collide in
sys.modules (see CLAUDE.md).
"""

from __future__ import annotations

# technique_id -> human-readable name, for display/reference.
TECHNIQUES: dict[str, str] = {
    "T1110":     "Brute Force",
    "T1078":     "Valid Accounts",
    "T1021.004": "Remote Services: SSH",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1105":     "Ingress Tool Transfer",
    "T1082":     "System Information Discovery",
    "T1033":     "System Owner/User Discovery",
    "T1057":     "Process Discovery",
    "T1049":     "System Network Connections Discovery",
    "T1070.003": "Indicator Removal: Clear Command History",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1136":     "Create Account",
    "T1222":     "File and Directory Permissions Modification",
    "T1562.004": "Impair Defenses: Disable or Modify System Firewall",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
}

# cowrie.command.input text -> technique(s). Checked as substrings against
# the lowercased command; first-match keyword groups can stack (e.g. a
# command can match both a download rule and a chmod rule).
_COMMAND_RULES: list[tuple[tuple[str, ...], tuple[str, ...]]] = [
    (("wget", "curl", "tftp", "ftpget"), ("T1105",)),
    (("chmod +x", "chmod 777", "chmod 755"), ("T1222",)),
    (("useradd", "adduser", "usermod"), ("T1136",)),
    (("crontab", "/etc/cron"), ("T1053.003",)),
    (("history -c", ".bash_history", "unset histfile"), ("T1070.003",)),
    (("iptables", "ufw disable", "systemctl stop firewalld"), ("T1562.004",)),
    (("/etc/shadow", "cat /etc/passwd"), ("T1552.001",)),
    (("uname", "/proc/cpuinfo", "lscpu", "/proc/version"), ("T1082",)),
    (("whoami", "who", "w "), ("T1033",)),
    (("ps ", "ps -", "top"), ("T1057",)),
    (("netstat", "ss -", "ifconfig", "ip addr"), ("T1049",)),
]

# Events that map to a fixed technique set regardless of any other field.
_EVENT_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "cowrie.session.connect": ("T1021.004",),
    "cowrie.login.failed":    ("T1110",),
    "cowrie.login.success":   ("T1110", "T1078"),
}


def classify_command(command: str | None) -> list[str]:
    """Technique(s) for a single cowrie.command.input's shell text. Falls
    back to generic shell execution (T1059.004) if no keyword rule fires,
    since typing anything at all into the fake shell is itself execution."""
    if not command:
        return []
    lowered = command.lower()
    matched: list[str] = []
    for keywords, techniques in _COMMAND_RULES:
        if any(kw in lowered for kw in keywords):
            for t in techniques:
                if t not in matched:
                    matched.append(t)
    return matched or ["T1059.004"]


def map_mitre_techniques(eventid: str, command: str | None = None) -> list[str]:
    """ATT&CK technique IDs to tag a parsed Cowrie event with. `command` is
    only consulted for cowrie.command.input; other event types ignore it."""
    if eventid == "cowrie.command.input":
        return classify_command(command)
    return list(_EVENT_TECHNIQUES.get(eventid, ()))
