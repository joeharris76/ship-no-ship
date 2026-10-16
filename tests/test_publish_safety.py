from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.fast]

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_publish_safety.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_publish_safety", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


safety = _load()


def _rules(path: str, text: str) -> list[str]:
    return [violation.rule for violation in safety.scan_text(path, text)]


def test_tracked_files_are_publishable() -> None:
    result = subprocess.run([sys.executable, str(SCRIPT), str(ROOT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("see /" + "Users/someone/project", "home path"),
        ("cd /" + "home/someone", "home path"),
        ("C:" + "\\Users\\someone\\x", "home path"),
        ("token " + "ghp_" + "a" * 36, "GitHub token"),
        ("github_" + "pat_" + "A1" * 20, "GitHub token"),
        ("AKIA" + "ABCDEFGHIJKLMNOP", "AWS access key"),
        ("-----BEGIN " + "RSA PRIVATE KEY-----", "private key"),
        ("key=sk-" + "proj-" + "x" * 30, "API key"),
        ("xoxb-" + "1234567890-abc", "Slack token"),
        ("AIza" + "B" * 35, "Google API key"),
        ("mail " + "someone" + "@" + "gmail.com", "email address"),
    ],
)
def test_each_rule_flags_its_pattern(text: str, rule: str) -> None:
    assert rule in _rules("src/module.py", text)


@pytest.mark.parametrize(
    "text",
    [
        "user.email=t" + "@example.com",
        "a" + "@b.com",
        "ops" + "@team.example",
        "git -C /tmp/repo status",
        "version 1.2.3.4",
        "app_id: 12345",
        "host.local",
    ],
)
def test_placeholders_and_non_template_values_pass(text: str) -> None:
    assert _rules("src/module.py", text) == []


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("addr 192.168." + "1.10", "IP address"),
        ("installation_id = " + "987654", "numeric App or installation ID"),
        ("App ID: " + "1234", "numeric App or installation ID"),
        ("ssh build-" + "mac.local", "local host name"),
    ],
)
def test_templates_and_examples_carry_no_host_or_account_identifiers(text: str, rule: str) -> None:
    assert rule in _rules("examples/service.example.toml", text)
    assert rule in _rules("macos/launchd/daemon.plist.in", text)
