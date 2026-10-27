"""Tests for the scs-security-scan skill scanner."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / ".bob" / "skills" / "scs-security-scan"


def _load():
    sys.path.insert(0, str(SKILL))
    spec = importlib.util.spec_from_file_location("scs_scan", SKILL / "scan.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["scs_scan"] = mod
    spec.loader.exec_module(mod)
    return mod


scan = _load()


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _vulnerable_repo(root: Path) -> None:
    # fake tokens are assembled at runtime so this test file itself holds no secret-shaped literal
    aws = "AKIA" + "ABCDEFGHIJKLMNOP"
    gh = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    _write(root, "src/app.py", f'AWS_KEY = "{aws}"\nimport hashlib\nhashlib.md5(b"x")\n')
    _write(root, "src/ok.py", 'import os\npassword = os.environ["DB_PASSWORD"]\n')
    _write(root, "src/ignored.py", f'K = "{aws}"  # scs-ignore\n')
    _write(root, ".env", f"TOKEN={gh}\n")
    _write(root, "tests/fixture.py", f'K = "{aws}"\n')
    _write(root, ".github/workflows/ci.yml", (
        "on:\n  pull_request_target:\n    types: [opened]\n"
        "permissions: write-all\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: some-org/some-action@v1\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: echo \"${{ github.event.pull_request.title }}\"\n"
        "      - run: curl -sSL https://example.org/i.sh | bash\n"
        "      - run: echo ${{ secrets.TOKEN }}\n"
    ))
    _write(root, "Dockerfile", "FROM python:latest\nENV API_TOKEN=abcdef123456\nADD https://x.test/a.tgz /a\n")
    _write(root, "package.json", '{"dependencies": {"left": "latest"}, "scripts": {"postinstall": "node x.js"}}')
    _write(root, "requirements.txt", "requests\n--extra-index-url https://pypi.internal/simple\n")
    _write(root, "main.tf", 'http_tokens = "optional"\n')


def _ids(findings):
    return {f.rule_id for f in findings}


def test_detects_expected_issues(tmp_path):
    _vulnerable_repo(tmp_path)
    rules = scan.compile_rules()
    findings, rels = scan.scan_worktree(tmp_path, rules, include_tests=False)
    findings += scan.scan_structure(tmp_path, rels)
    ids = _ids(findings)
    expected = {
        "SCS-SEC-001", "SCS-FILE-001", "SCS-APP-004", "SCS-CICD-001", "SCS-CICD-003",
        "SCS-CICD-004", "SCS-CICD-005", "SCS-CICD-007", "SCS-CICD-009", "SCS-CTR-001",
        "SCS-CTR-003", "SCS-CTR-004", "SCS-DEP-001", "SCS-DEP-003", "SCS-DEP-005",
        "SCS-DEP-006", "SCS-DEP-100", "SCS-IAC-003", "SCS-CICD-100",
    }
    assert expected <= ids, f"missing: {expected - ids}"


def test_false_positive_controls(tmp_path):
    _vulnerable_repo(tmp_path)
    findings, _ = scan.scan_worktree(tmp_path, scan.compile_rules(), include_tests=False)
    files = {f.file for f in findings}
    assert "src/ok.py" not in files          # env lookup is not a hardcoded secret
    assert "src/ignored.py" not in files      # scs-ignore marker
    assert "tests/fixture.py" not in files    # test paths skipped by default
    with_tests, _ = scan.scan_worktree(tmp_path, scan.compile_rules(), include_tests=True)
    assert "tests/fixture.py" in {f.file for f in with_tests}
    # first-party action is low severity, not the medium third-party rule
    assert not any(f.rule_id == "SCS-CICD-001" and "actions/checkout" in f.evidence for f in findings)


def test_secrets_are_masked(tmp_path):
    _vulnerable_repo(tmp_path)
    findings, _ = scan.scan_worktree(tmp_path, scan.compile_rules(), include_tests=False)
    aws = [f for f in findings if f.rule_id == "SCS-SEC-001"]
    assert aws and all("ABCDEFGHIJKLMNOP" not in f.evidence for f in aws)
    assert all("REDACTED" in f.evidence for f in aws)


def test_pinned_action_and_lockfile_clean(tmp_path):
    _write(tmp_path, ".github/workflows/ci.yml",
           "jobs:\n  b:\n    steps:\n      - uses: some-org/act@" + "a" * 40 + "\n")
    _write(tmp_path, "package.json", '{"dependencies": {"left": "1.0.0"}}')
    _write(tmp_path, "package-lock.json", "{}")
    findings, rels = scan.scan_worktree(tmp_path, scan.compile_rules(), include_tests=False)
    findings += scan.scan_structure(tmp_path, rels)
    ids = _ids(findings)
    assert "SCS-CICD-001" not in ids and "SCS-DEP-100" not in ids


def test_history_scan_finds_deleted_secret(tmp_path):
    aws = "AKIA" + "ABCDEFGHIJKLMNOP"
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
           "HOME": str(tmp_path)}

    def git(*a):
        subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True, env=env)

    git("init", "-q")
    _write(tmp_path, "cfg.txt", f"key={aws}\n")
    git("add", "."); git("commit", "-qm", "add")
    (tmp_path / "cfg.txt").write_text("key=removed\n")
    git("commit", "-qam", "remove")
    assert "AKIA" not in (tmp_path / "cfg.txt").read_text()
    hist = scan.scan_history(tmp_path, scan.compile_rules(), 50)
    assert any(f.rule_id == "SCS-SEC-001" and f.source == "history" for f in hist)


def test_cli_json_and_fail_on(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _vulnerable_repo(repo)
    out = tmp_path / "rep.json"
    rc = scan.main([str(repo), "--format", "json", "-o", str(out), "--fail-on", "critical"])
    assert rc == 1
    data = json.loads(out.read_text())
    assert data["findings"] and data["findings"][0]["severity"] == "critical"
    clean = tmp_path / "clean"
    clean.mkdir()
    _write(clean, "a.txt", "hello\n")
    assert scan.main([str(clean), "--fail-on", "critical", "-o", str(tmp_path / "c.md")]) == 0


def test_bad_target_returns_2():
    assert scan.main(["not a repo"]) == 2
