from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.fast]

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_publish_safety.py"
TOKEN = "ghp_" + "Zq9" * 12
SERVER_TOKEN = "ghs_" + "Wx7" * 12
GMAIL = "@" + "gmail.com"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_publish_safety", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


safety = _load()


def _rules(text: str, exempt: frozenset[str] = frozenset()) -> list[str]:
    return [violation.rule for violation in safety.scan_text("src/module.py", text, exempt)]


def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env={**os.environ, **(env or {})}
    )
    return result.stdout.strip()


def _repo(tmp_path: Path, email: str = "dev@example.com") -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Dev")
    _git(repo, "config", "user.email", email)
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "config", "tag.gpgsign", "false")
    return repo


def _commit(repo: Path, message: str = "change", env: dict[str, str] | None = None) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", message, env=env)


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
        ("https://user" + ":hunter2@" + "example.com/x", "URL credentials"),
        ("mail someone" + GMAIL, "email address"),
        ("addr 192.168." + "1.10", "IP address"),
        ("addr fe80" + "::1c2a", "IPv6 address"),
        ("addr 2001:db8:85a3:0" + ":0:8a2e:370:7334", "IPv6 address"),
        ("installation_id = " + "987654", "numeric App or installation ID"),
        ("App ID: " + "1234", "numeric App or installation ID"),
        ("ssh build-mac" + ".local", "private host name"),
        ("ssh mac.tailnet" + ".ts.net", "private host name"),
        ("http://nas" + ".lan/", "private host name"),
        ("db.corp" + ".internal", "private host name"),
    ],
)
def test_each_rule_flags_its_pattern(text: str, rule: str) -> None:
    assert rule in _rules(text)


@pytest.mark.parametrize(
    "text",
    [
        "user.email=t" + "@example.com",
        "a" + "@b.com",
        "ops" + "@team.example",
        "noreply" + "@github.com",
        "git -C /tmp/repo status",
        "bind 127.0.0.1 and 0.0.0.0",
        "pairs = flags[1::2], flags[2::2]",
        "at 12:34:56",
        "python 3.12.1",
    ],
)
def test_placeholders_and_ordinary_text_pass(text: str) -> None:
    assert _rules(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "git clone https://x-access-token:" + SERVER_TOKEN + "@github.com/o/r",
        "postgres://admin:" + "s3cret-Pw" + "@db.corp" + ".internal/app",
        "s3://" + "AKIA" + "ABCDEFGHIJKLMNOP:wJalr" + "XUtnFEMI@bucket.example/x",
    ],
)
def test_credentials_in_url_userinfo_are_never_printed(text: str) -> None:
    violations = safety.scan_text("a.py", text)
    printed = "\n".join(str(violation) for violation in violations)
    assert "URL credentials" in printed
    for secret in (SERVER_TOKEN, "s3cret-Pw", "wJalr" + "XUtnFEMI", "ABCDEFGHIJKLMNOP"):
        assert secret not in printed
    assert "email address" not in printed


def test_email_addresses_are_printed_masked() -> None:
    (violation,) = safety.scan_text("a.py", "contact someone" + GMAIL)
    assert str(violation).endswith("email address: s***" + GMAIL)


def test_an_exempt_rule_is_skipped_for_that_text_only() -> None:
    text = "host build-mac" + ".local at 10.0." + "0.5, token " + TOKEN
    assert _rules(text, frozenset({"host", "ip"})) == ["GitHub token"]
    assert "private host name" in _rules(text, frozenset({"ip"}))


def test_credentials_are_reported_without_their_value() -> None:
    (violation,) = safety.scan_text("a.py", "token " + TOKEN)
    assert TOKEN not in str(violation) and str(violation).endswith("ghp_****")


def test_the_command_never_prints_a_matched_credential(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "config.py").write_text(
        f"TOKEN = '{TOKEN}'\nURL = 'https://x" + f":{SERVER_TOKEN}@github.com/o/r'\n", "utf-8"
    )
    _commit(repo)
    for args in ((str(repo),), (str(repo), "--history")):
        result = _run(*args)
        assert result.returncode == 1
        assert TOKEN not in result.stdout + result.stderr
        assert SERVER_TOKEN not in result.stdout + result.stderr
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


def test_history_mode_reads_commit_and_tag_messages(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _commit(repo, "deploy to build-mac" + ".local")
    _git(repo, "tag", "-a", "v1", "-m", "token " + TOKEN)
    result = _run(str(repo), "--history")
    assert result.returncode == 1
    assert "message:1: private host name: build-mac" + ".local" in result.stdout
    assert "refs/tags/v1 message:1: GitHub token: ghp_****" in result.stdout
    assert TOKEN not in result.stdout


def test_history_mode_reports_commit_and_tagger_emails_masked(tmp_path: Path) -> None:
    repo = _repo(tmp_path, email="someone" + GMAIL)
    _commit(repo)
    _git(repo, "tag", "-a", "v1", "-m", "release")
    result = _run(str(repo), "--history")
    assert result.returncode == 1
    assert "metadata email address: s***" + GMAIL in result.stdout
    assert "refs/tags/v1:0: metadata email address" in result.stdout
    assert "someone" + GMAIL not in result.stdout


def test_github_merge_and_noreply_committers_are_not_reported(tmp_path: Path) -> None:
    repo = _repo(tmp_path, email="12345+dev" + "@users.noreply.github.com")
    _commit(repo, env={"GIT_COMMITTER_EMAIL": "noreply" + "@github.com"})
    assert _run(str(repo), "--history").returncode == 0


def test_allowlisted_commit_emails_pass_but_are_listed(tmp_path: Path) -> None:
    address = "owner" + GMAIL
    repo = _repo(tmp_path, email=address)
    _commit(repo)
    report = safety.scan(repo, True, safety.Allowlist(commit_email_hashes=frozenset({safety.email_hash(address)})))
    assert report.violations == []
    assert report.allowed_commit_emails == {address: 1}


def test_a_blob_exemption_applies_to_that_blob_wherever_it_is(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    text = "host build-mac" + ".local\n"
    (repo / "a.txt").write_text(text, encoding="utf-8")
    (repo / "copy.txt").write_text(text, encoding="utf-8")
    (repo / "other.txt").write_text(text + "x\n", encoding="utf-8")
    _commit(repo)
    blob = _git(repo, "rev-parse", "HEAD:a.txt")
    allowlist = safety.Allowlist(blob_rules=frozenset({(blob, "host")}))
    for history in (False, True):
        report = safety.scan(repo, history, allowlist)
        assert [violation.path for violation in report.violations] == ["other.txt"]


def test_a_blob_at_several_paths_is_reported_once(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    for name in ("a.txt", "b.txt"):
        (repo / name).write_text("ssh build-mac" + ".local\n", encoding="utf-8")
    _commit(repo)
    report = safety.scan(repo, False, safety.Allowlist())
    assert [violation.path for violation in report.violations] == ["a.txt (and 1 other path(s))"]


def test_a_symlink_is_scanned_as_its_link_text(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "link").symlink_to("/" + "Users/someone/secret")
    _commit(repo)
    result = _run(str(repo))
    assert result.returncode == 1 and "link:1: home path" in result.stdout


def test_binary_files_are_listed_as_not_checked(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "blob.bin").write_bytes(b"\0\1\2")
    _commit(repo)
    blob = _git(repo, "rev-parse", "HEAD:blob.bin")
    result = _run(str(repo))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "publish-safety: not checked (1 object(s), 1 not in the allow file):" in result.stdout
    assert f"  blob.bin (blob {blob}): binary: contains NUL bytes\n" in result.stdout


def test_history_mode_lists_skipped_blobs_with_their_id(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "blob.bin").write_bytes(b"\0\1\2")
    _commit(repo, "add")
    blob = _git(repo, "rev-parse", "HEAD:blob.bin")
    (repo / "blob.bin").unlink()
    _commit(repo, "remove")
    assert "not checked" not in _run(str(repo)).stdout
    result = _run(str(repo), "--history")
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"  blob.bin (blob {blob}): binary: contains NUL bytes" in result.stdout


SUBMODULE = "1" * 40


def _add_submodule(repo: Path, path: str = "vendor/lib") -> None:
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{SUBMODULE},{path}")
    _git(repo, "commit", "-q", "-m", "add a submodule")


def test_a_submodule_is_listed_as_not_checked(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _add_submodule(repo)
    for args in ((), ("--history",)):
        result = _run(str(repo), *args)
        assert result.returncode == 0, result.stdout + result.stderr
        assert f"  vendor/lib (commit {SUBMODULE}): submodule\n" in result.stdout


def test_history_mode_lists_a_submodule_removed_from_the_tree(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _commit(repo, "start")
    _git(repo, "checkout", "-q", "-b", "side")
    _add_submodule(repo, "deep/dir/lib")
    _git(repo, "rm", "-q", "--cached", "deep/dir/lib")
    _git(repo, "commit", "-q", "-m", "remove the submodule")
    assert "not checked" not in _run(str(repo)).stdout
    result = _run(str(repo), "--history", "--fail-on-skipped")
    assert result.returncode == 1
    assert f"  deep/dir/lib (commit {SUBMODULE}): submodule\n" in result.stdout


@pytest.mark.parametrize("history", [False, True])
def test_fail_on_skipped_fails_for_an_unlisted_skip(tmp_path: Path, history: bool) -> None:
    repo = _repo(tmp_path)
    (repo / "blob.bin").write_bytes(b"\0\1\2")
    _commit(repo)
    args = [str(repo), "--fail-on-skipped", *(["--history"] if history else [])]
    result = _run(*args)
    assert result.returncode == 1
    assert "1 object(s)" in result.stderr and "not in the allow file" in result.stderr


def test_fail_on_skipped_passes_only_for_listed_object_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path)
    (repo / "logo.png").write_bytes(b"\0\1\2")
    _commit(repo)
    _add_submodule(repo)
    blob = _git(repo, "rev-parse", "HEAD:logo.png")
    allow = tmp_path / "allow.txt"
    allow.write_text(f"blob\t{blob}\tskipped\nblob\t{SUBMODULE}\tskipped\n", encoding="utf-8")
    monkeypatch.setattr(safety, "ALLOWLIST", allow)
    for history in ([], ["--history"]):
        assert safety.main([str(repo), "--fail-on-skipped", *history]) == 0
        out = capsys.readouterr().out
        assert f"  logo.png (blob {blob}): binary: contains NUL bytes, allowed\n" in out
        assert f"  vendor/lib (commit {SUBMODULE}): submodule, allowed\n" in out
    # Different content at the allowed path is not covered by the allowance.
    (repo / "logo.png").write_bytes(b"\0\1\2\3")
    _git(repo, "add", "logo.png")
    _git(repo, "commit", "-q", "-m", "change the logo")
    assert safety.main([str(repo), "--fail-on-skipped"]) == 1
    assert "logo.png (blob " in capsys.readouterr().out


def test_tracked_files_have_no_unlisted_skips() -> None:
    result = _run(str(ROOT), "--fail-on-skipped")
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_allowlist_file_parses(tmp_path: Path) -> None:
    allowlist = safety.load_allowlist()
    assert all(len(value) == 64 for value in allowlist.commit_email_hashes)
    assert all(rule in safety.RULE_IDS | {safety.SKIP_RULE} for _, rule in allowlist.blob_rules)
    bad = tmp_path / "allow.txt"
    bad.write_text("blob\t" + "a" * 40 + "\tnot-a-rule\n", encoding="utf-8")
    with pytest.raises(ValueError, match="expected blob"):
        safety.load_allowlist(bad)
    bad.write_text("skipped-path\tlogo.png\n", encoding="utf-8")
    with pytest.raises(ValueError, match="expected blob"):
        safety.load_allowlist(bad)
    bad.write_text("blob\t" + "a" * 40 + "\tskipped\n", encoding="utf-8")
    assert safety.load_allowlist(bad).exempt("a" * 40) == frozenset({"skipped"})
