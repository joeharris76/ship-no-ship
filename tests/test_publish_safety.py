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
TOKEN = "ghp_" + "Zq9" * 12


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_publish_safety", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


safety = _load()


def _rules(path: str, text: str, allowlist: object | None = None) -> list[str]:
    return [violation.rule for violation in safety.scan_text(path, text, allowlist)]


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo(tmp_path: Path, email: str = "dev@example.com") -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Dev")
    _git(repo, "config", "user.email", email)
    _git(repo, "config", "commit.gpgsign", "false")
    return repo


def _commit(repo: Path, message: str = "change") -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_tracked_files_are_publishable() -> None:
    result = _run(str(ROOT))
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("see /" + "Users/someone/project", "home path"),
        ("cd /" + "home/someone", "home path"),
        ("C:" + "\\Users\\someone\\x", "home path"),
        ("token " + TOKEN, "GitHub token"),
        ("github_" + "pat_" + "A1" * 20, "GitHub token"),
        ("AKIA" + "ABCDEFGHIJKLMNOP", "AWS access key"),
        ("-----BEGIN " + "RSA PRIVATE KEY-----", "private key"),
        ("key=sk-" + "proj-" + "x" * 30, "API key"),
        ("xoxb-" + "1234567890-abc", "Slack token"),
        ("AIza" + "B" * 35, "Google API key"),
        ("mail " + "someone" + "@" + "gmail.com", "email address"),
        ("addr 192.168." + "1.10", "IP address"),
        ("addr fe80" + "::1c2a", "IPv6 address"),
        ("addr 2001:db8:" + "85a3:0:0:8a2e:370:7334", "IPv6 address"),
        ("installation_id = " + "987654", "numeric App or installation ID"),
        ("App ID: " + "1234", "numeric App or installation ID"),
        ("ssh build-" + "mac.local", "private host name"),
        ("ssh mac.tail" + "net.ts.net", "private host name"),
        ("http://nas" + ".lan/", "private host name"),
        ("db.corp" + ".internal", "private host name"),
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
        "bind 127.0.0.1 and 0.0.0.0",
        "pairs = flags[1::2], flags[2::2]",
        "at 12:34:56",
        "python 3.12.1",
    ],
)
def test_placeholders_and_ordinary_text_pass(text: str) -> None:
    assert _rules("src/module.py", text) == []


def test_allowlisted_paths_skip_only_the_host_rules() -> None:
    allowlist = safety.Allowlist(host_rule_paths=("docs/networking.md",))
    text = "host build-" + "mac.local at 10.0." + "0.5, token " + TOKEN
    assert _rules("docs/networking.md", text, allowlist) == ["GitHub token"]
    assert "private host name" in _rules("docs/other.md", text, allowlist)


def test_credentials_are_reported_without_their_value() -> None:
    (violation,) = safety.scan_text("a.py", "token " + TOKEN)
    assert TOKEN not in str(violation) and str(violation).endswith("ghp_****")


def test_the_command_never_prints_a_matched_credential(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "config.py").write_text(f"TOKEN = '{TOKEN}'\n", encoding="utf-8")
    _commit(repo)
    for args in ((str(repo),), (str(repo), "--history")):
        result = _run(*args)
        assert result.returncode == 1
        assert TOKEN not in result.stdout + result.stderr
        assert "config.py:1: GitHub token: ghp_****" in result.stdout


def test_history_mode_finds_a_secret_removed_from_the_tree(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "notes.txt").write_text("AKIA" + "ABCDEFGHIJKLMNOP\n", encoding="utf-8")
    _commit(repo, "add")
    (repo / "notes.txt").write_text("clean\n", encoding="utf-8")
    _commit(repo, "remove")
    assert _run(str(repo)).returncode == 0
    result = _run(str(repo), "--history")
    assert result.returncode == 1 and "notes.txt:1: AWS access key: AKIA****" in result.stdout


def test_history_mode_reports_commit_emails(tmp_path: Path) -> None:
    address = "someone" + "@" + "gmail.com"
    repo = _repo(tmp_path, email=address)
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _commit(repo)
    result = _run(str(repo), "--history")
    assert result.returncode == 1 and f"commit email address: {address}" in result.stdout


def test_allowlisted_commit_emails_pass_but_are_listed(tmp_path: Path) -> None:
    address = "owner" + "@" + "gmail.com"
    repo = _repo(tmp_path, email=address)
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _commit(repo)
    report = safety.scan(repo, True, safety.Allowlist(commit_email_hashes=frozenset({safety.email_hash(address)})))
    assert report.violations == []
    assert report.allowed_commit_emails == {address: 1}


def test_a_symlink_is_scanned_as_its_link_text(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "target.txt").write_text("clean\n", encoding="utf-8")
    (repo / "link").symlink_to("/" + "Users/someone/secret")
    _commit(repo)
    result = _run(str(repo))
    assert result.returncode == 1 and "link:1: home path" in result.stdout


def test_binary_files_are_reported_as_skipped(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "blob.bin").write_bytes(b"\0\1\2")
    _commit(repo)
    result = _run(str(repo))
    assert result.returncode == 0 and "skipped binary file blob.bin" in result.stdout


def test_the_allowlist_file_parses() -> None:
    allowlist = safety.load_allowlist()
    assert all(len(value) == 64 for value in allowlist.commit_email_hashes)
