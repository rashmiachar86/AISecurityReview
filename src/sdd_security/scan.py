#!/usr/bin/env python3
"""scs-security-scan: static NHI / software-supply-chain security scanner for GitHub repos.

Rules live in scs_rules.py and are derived from SCSforAI.md. Standard library only.

Usage:
    scan.py <path | https://github.com/org/repo[.git] | org/repo> [options]

Exit codes: 0 ok, 1 findings at/above --fail-on, 2 usage/runtime error.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scs_rules as R  # noqa: E402

SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build",
    ".tox", ".mypy_cache", ".pytest_cache", ".terraform", "site-packages",
}
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".jar", ".war",
    ".class", ".so", ".dylib", ".dll", ".exe", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
    ".mov", ".pyc", ".bin", ".lock", ".svg", ".min.js", ".map",
}
SELF_DIR = Path(__file__).resolve().parent  # rule definitions would match their own patterns
MAX_FILE_BYTES = 1_000_000
MAX_LINE_CHARS = 2000
IGNORE_MARKER = "scs-ignore"
TEST_PATH_RE = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|testdata|examples?|samples?|docs?)(/|$)", re.I)
GITHUB_SHORT_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
PR_URL_RE = re.compile(r"^https://github\.com/([\w.-]+/[\w.-]+)/pull/(\d+)")
GH_SLUG_RE = re.compile(r"github\.com[:/]([\w.-]+/[\w.-]+?)(?:\.git)?/?$")
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
SEV_RANK = {s: i for i, s in enumerate(reversed(R.SEVERITIES))}  # info=0 ... critical=4

# --exclude-tests: test *files* (by name) and test-support directories. Broader than TEST_PATH_RE,
# which only covers directories and is what the default "skip tests" behaviour uses.
TEST_FILE_RE = re.compile(
    r"(_test\.(go|py|rb|exs?)$|^test_.*\.py$|_tests?\.(js|jsx|ts|tsx|php)$|\.(test|spec)\.[\w]+$|"
    r"_spec\.rb$|^conftest\.py$|tests?\.(java|kt|cs)$|Tests?\.(java|kt|cs)$)", re.I)
TEST_DIR_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|fixtures?|testdata|test[-_]data|testing|e2e[\w-]*|"
    r"integration[-_]tests?|mocks?|testutils?|test[-_]utils?|test[-_]helpers?)(/|$)", re.I)


def is_test_path(rel: str) -> bool:
    return bool(TEST_DIR_RE.search(rel) or TEST_FILE_RE.search(rel.rsplit("/", 1)[-1]))


def load_exclude_list(path: str) -> list[str]:
    """One glob per line; blank lines and `#` comments ignored."""
    try:
        lines = Path(path).expanduser().read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SystemExit(f"error: cannot read exclude list '{path}': {exc}")
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def make_excluder(patterns: list[str], exclude_tests: bool):
    """Return rel_path -> bool. Pattern forms (case-insensitive, like .gitignore-lite):
         dir/        any directory with that path or name        (e.g. e2e/, docs/legacy/)
         a/b/*.yml   path glob relative to the repo root
         name.ext    basename glob or any path segment           (e.g. *_gen.go, vendor)
    """
    pats = [p.lower().replace("\\", "/") for p in patterns]

    def excluded(rel: str) -> bool:
        if exclude_tests and is_test_path(rel):
            return True
        rl = rel.lower()
        segs = rl.split("/")
        for p in pats:
            if p.endswith("/"):
                d = p.rstrip("/")
                if rl.startswith(p) or ("/" + p) in ("/" + rl) or (("/" not in d) and d in segs[:-1]):
                    return True
            elif "/" in p:
                p = p.removeprefix("./")
                if fnmatch.fnmatch(rl, p) or rl.startswith(p.rstrip("/") + "/"):
                    return True
            elif any(fnmatch.fnmatch(s, p) for s in segs):
                return True
        return False

    return excluded


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    file: str
    line: int
    evidence: str
    fix: str
    ref: str
    confidence: str = "high"
    source: str = "worktree"  # worktree | history | structure
    test_path: bool = False
    commit: str = ""
    vuln_type: str = ""  # SCS vulnerability type (SCSforAI.md threat name); filled from R.META
    details: str = ""
    impact: str = ""

    def __post_init__(self):
        vt, det, imp = R.META.get(self.rule_id, R.DEFAULT_META)
        self.vuln_type = self.vuln_type or vt
        self.details = self.details or det
        self.impact = self.impact or imp


@dataclass
class Compiled:
    rule: dict
    files: list[str]
    pattern: re.Pattern
    ignore: re.Pattern | None


def compile_rules() -> list[Compiled]:
    out = []
    for r in R.RULES:
        out.append(Compiled(
            rule=r,
            files=[g.lower() for g in r["files"]],
            pattern=re.compile(r["pattern"]),
            ignore=re.compile(r["ignore"]) if r["ignore"] else None,
        ))
    return out


def file_matches(rel_lower: str, base_lower: str, globs: list[str]) -> bool:
    for g in globs:
        if g == "*":
            return True
        if "/" in g:
            if fnmatch.fnmatch(rel_lower, g) or rel_lower.endswith("/" + g):
                return True
        elif fnmatch.fnmatch(base_lower, g):
            return True
    return False


def mask(text: str, secret_span: tuple[int, int] | None) -> str:
    """Mask the middle of a matched secret, keeping 4 chars each side at most."""
    if not secret_span:
        return text
    a, b = secret_span
    s = text[a:b]
    keep = 4 if len(s) > 12 else 0
    masked = (s[:keep] + "…[REDACTED]…" + s[-keep:]) if keep else "[REDACTED]"
    return text[:a] + masked + text[b:]


def make_evidence(line: str, m: re.Match, redact: bool) -> str:
    line = line.rstrip("\n")
    if len(line) > 240:
        start = max(0, m.start() - 80)
        line = ("…" if start else "") + line[start:start + 220] + "…"
        offset = start
    else:
        offset = 0
    span = (m.start() - offset, m.end() - offset) if redact else None
    if span and (span[0] < 0 or span[1] > len(line)):
        span = None
    return mask(line.strip() if not span else line, span).strip()


def is_text(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return b"\0" not in fh.read(2048)
    except OSError:
        return False


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and (Path(dirpath) / d).resolve() != SELF_DIR]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in SKIP_EXTS or p.is_symlink():
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def scan_worktree(root: Path, rules: list[Compiled], include_tests: bool,
                  excluded=None, in_scope=None) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    rels: list[str] = []
    for p in iter_files(root):
        rel = p.relative_to(root).as_posix()
        rels.append(rel)  # excluded files stay in rels so lock-file / repo-structure checks still see them
        if excluded and excluded(rel):
            continue
        if in_scope and not in_scope(rel):  # --files / --pr / --base: only selected files are scanned
            continue
        rel_l, base_l = rel.lower(), p.name.lower()
        test_path = bool(TEST_PATH_RE.search(rel))
        if test_path and not include_tests:
            continue

        # sensitive file names
        if not base_l.endswith(R.SENSITIVE_FILE_SKIP_SUFFIXES):
            for g, sev, title in R.SENSITIVE_FILES:
                gl = g.lower()
                hit = fnmatch.fnmatch(base_l, gl) if "/" not in gl else (rel_l == gl or rel_l.endswith("/" + gl))
                if hit:
                    findings.append(Finding(
                        "SCS-FILE-001", title, sev, "secrets", rel, 1, base_l, R.SENSITIVE_FIX,
                        R.S1, "medium", "worktree", test_path))
                    break

        applicable = [c for c in rules if file_matches(rel_l, base_l, c.files)]
        if not applicable or not is_text(p):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if len(line) > MAX_LINE_CHARS or IGNORE_MARKER in line:
                continue
            for c in applicable:
                m = c.pattern.search(line)
                if not m or (c.ignore and c.ignore.search(line)):
                    continue
                r = c.rule
                findings.append(Finding(
                    r["id"], r["title"], r["severity"], r["category"], rel, n,
                    make_evidence(line, m, r["redact"]), r["fix"], r["ref"], r["confidence"],
                    "worktree", test_path))
    return findings, rels


def scan_history(root: Path, rules: list[Compiled], max_commits: int,
                 rev_range: str | None = None) -> list[Finding]:
    """Scan added lines in git history for high-signal secret rules (rule.history == True).
    rev_range (e.g. 'origin/main..HEAD') limits the scan to a pull request's commits."""
    hist_rules = [c for c in rules if c.rule["history"]]
    cmd = ["git", "-C", str(root), "log", f"-{max_commits}", "-p", "--no-color", "--no-ext-diff",
           "--unified=0", "--format=@@COMMIT %H"]
    cmd += [rev_range, "--relative", "--"] if rev_range else ["--all"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[warn] history scan skipped: {exc}", file=sys.stderr)
        return []
    if proc.returncode != 0:
        print(f"[warn] history scan failed: {proc.stderr.strip()[:200]}", file=sys.stderr)
        return []
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    commit = path = ""
    for line in proc.stdout.splitlines():
        if line.startswith("@@COMMIT "):
            commit = line.split()[1]
        elif line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("+") and not line.startswith("+++") and path:
            body = line[1:]
            if len(body) > MAX_LINE_CHARS or IGNORE_MARKER in body:
                continue
            rel_l, base_l = path.lower(), os.path.basename(path).lower()
            for c in hist_rules:
                if not file_matches(rel_l, base_l, c.files):
                    continue
                m = c.pattern.search(body)
                if not m or (c.ignore and c.ignore.search(body)):
                    continue
                key = (c.rule["id"], path, m.group(0))
                if key in seen:
                    continue
                seen.add(key)
                r = c.rule
                findings.append(Finding(
                    r["id"], r["title"] + " (in git history)", r["severity"], r["category"], path, 0,
                    make_evidence(body, m, True), r["fix"] + " History rewrite (git filter-repo/BFG) is required.",
                    r["ref"], r["confidence"], "history", bool(TEST_PATH_RE.search(path)), commit[:12]))
    return findings


def scan_structure(root: Path, rels: list[str]) -> list[Finding]:
    """Repository-level controls: lockfiles, dependency bots, secret scanning, .gitignore, CODEOWNERS."""
    out: list[Finding] = []
    rel_set = set(rels)
    lower_map = {r.lower(): r for r in rels}

    def add(rid, title, sev, cat, file, evidence, fix, ref, conf="medium"):
        out.append(Finding(rid, title, sev, cat, file, 0, evidence, fix, ref, conf, "structure"))

    # lockfiles next to manifests
    for rel in rels:
        d, base = os.path.split(rel)
        spec = R.LOCKFILES.get(base.lower())
        if not spec:
            continue
        locks, sev = spec
        if any((os.path.join(d, lk).replace("\\", "/") in rel_set) for lk in locks):
            continue
        if base.lower() == "package.json" and re.search(r"(^|/)node_modules/", rel):
            continue
        add("SCS-DEP-100", f"No lock file for {base}", sev, "dependency", rel,
            f"expected one of: {', '.join(locks)}",
            "Commit a lock file so builds are reproducible and integrity-verified.", R.AV2)

    if not any(b.lower() in lower_map for b in R.DEPENDENCY_BOTS):
        add("SCS-DEP-101", "No automated dependency update config (Dependabot/Renovate)", "low",
            "dependency", ".github/dependabot.yml", "not found",
            "Enable Dependabot or Renovate, including the github-actions ecosystem.", R.S2)

    # secret scanning in CI / pre-commit
    ci_blob = ""
    for rel in rels:
        rl = rel.lower()
        if rl.startswith(".github/workflows/") or rl in (".gitlab-ci.yml", ".pre-commit-config.yaml", "jenkinsfile"):
            try:
                ci_blob += (root / rel).read_text(encoding="utf-8", errors="replace").lower()
            except OSError:
                pass
    has_ci = any(r.lower().startswith(".github/workflows/") or r.lower() in (".gitlab-ci.yml", "jenkinsfile") for r in rels)
    if not any(s in ci_blob for s in R.SECRET_SCANNERS):
        add("SCS-CICD-100", "No secret scanning in CI or pre-commit", "medium", "cicd",
            ".github/workflows" if has_ci else ".pre-commit-config.yaml", "gitleaks/trufflehog not referenced",
            "Add gitleaks or trufflehog to CI and a pre-commit hook; enable GitHub secret scanning "
            "and push protection.", R.AV1)
    if has_ci and not re.search(r"slsa|attest|cosign|sigstore|syft|cyclonedx|anchore/sbom|in-toto", ci_blob):
        add("SCS-CICD-101", "No SBOM / provenance / signing step detected in CI", "low", "cicd",
            ".github/workflows", "no syft/cyclonedx/cosign/slsa/attest reference",
            "Generate an SBOM and build provenance (SLSA, Sigstore/cosign) for released artifacts.", R.S4,
            "low")

    # .gitignore coverage
    gi = lower_map.get(".gitignore")
    gi_text = ""
    if gi:
        try:
            gi_text = (root / gi).read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    if not gi:
        add("SCS-SRC-100", "No .gitignore", "low", "secrets", ".gitignore", "missing",
            "Add a .gitignore covering .env, key files, state files and build output.", R.S1)
    elif not re.search(r"^\s*\.env\b", gi_text, re.M):
        add("SCS-SRC-101", ".gitignore does not exclude .env files", "low", "secrets", gi, "no `.env` entry",
            "Add `.env` and `.env.*` (except templates) to .gitignore.", R.S1, "low")

    if not any(c.lower() in lower_map for c in R.CODEOWNERS) and has_ci:
        add("SCS-SRC-102", "No CODEOWNERS for workflow / sensitive paths", "low", "cicd", "CODEOWNERS",
            "not found",
            "Require owner review for .github/workflows/, Dockerfiles and IaC, with branch protection "
            "enforcing it.", R.S1, "low")

    # containers: non-root user
    for rel in rels:
        if fnmatch.fnmatch(os.path.basename(rel).lower(), "dockerfile*") or rel.lower().endswith(".dockerfile"):
            try:
                txt = (root / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not re.search(r"^\s*USER\s+(?!root\b|0\b)\S+", txt, re.M | re.I):
                add("SCS-CTR-003", "Container runs as root (no non-root USER)", "medium", "container", rel,
                    "no USER instruction", "Add a non-root USER near the end of the final stage.", R.S4)
            if re.search(r"^\s*FROM\s+(?!scratch\b)\S+(?<!@sha256)(?::latest)?\s*(?:AS\s+\S+)?\s*$", txt, re.M | re.I) \
                    and not re.search(r"^\s*FROM\s+\S+@sha256:[0-9a-f]{64}", txt, re.M | re.I):
                add("SCS-CTR-006", "Base image not pinned by digest", "low", "container", rel,
                    "FROM without @sha256 digest",
                    "Pin base images to an immutable digest and rebuild regularly.", R.S4, "low")
    return out


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        k = (f.rule_id, f.file, f.line, f.evidence, f.commit)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def resolve_target(target: str, keep: bool, depth: int | None) -> tuple[Path, str, Path | None]:
    """Return (repo_root, display_name, temp_dir_to_cleanup)."""
    p = Path(target).expanduser()
    if p.exists():
        return p.resolve(), str(p.resolve()), None
    url = target
    if GITHUB_SHORT_RE.match(target):
        url = f"https://github.com/{target}.git"
    if not re.match(r"^(https://|git@|ssh://)", url):
        raise SystemExit(f"error: '{target}' is not an existing path or a recognizable git URL")
    tmp = Path(tempfile.mkdtemp(prefix="scs-scan-"))
    cmd = ["git", "clone", "--quiet", "--no-tags"]
    if depth:
        cmd += ["--depth", str(depth)]
    cmd += [url, str(tmp / "repo")]
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if r.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise SystemExit(f"error: git clone failed: {r.stderr.strip()[:300]}")
    return tmp / "repo", url, (None if keep else tmp)


def git(root: Path, *args: str, check: bool = True) -> str:
    r = subprocess.run(["git", "-C", str(root), "-c", "core.quotepath=off", *args],
                       capture_output=True, text=True, errors="replace",
                       env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))
    if check and r.returncode != 0:
        raise SystemExit(f"error: git {' '.join(args[:2])} failed: {r.stderr.strip()[:300]}")
    return r.stdout


def collect_changes(root: Path, spec: list[str]) -> dict[str, set[int] | None]:
    """Map changed (added/copied/modified/renamed) file -> set of added line numbers in the new version."""
    base = ["diff", "--relative", "-M", "--diff-filter=ACMR"]
    out: dict[str, set[int] | None] = {n: set() for n in git(root, *base, "--name-only", "-z", *spec, "--").split("\0") if n}
    cur = None
    for ln in git(root, *base, "-U0", "--no-color", "--no-ext-diff", *spec, "--").splitlines():
        if ln.startswith("+++ "):
            cur = ln[6:].split("\t")[0] if ln.startswith("+++ b/") else None
            if cur is not None:
                out.setdefault(cur, set())
        elif cur and ln.startswith("@@"):
            m = HUNK_RE.match(ln)
            if m:
                start, n = int(m.group(1)), int(m.group(2)) if m.group(2) is not None else 1
                out[cur].update(range(start, start + n))  # type: ignore[union-attr]
    return out


def local_changes(root: Path, base: str) -> tuple[dict[str, set[int] | None], str]:
    """Changes between `base` and the working tree (committed + uncommitted + untracked)."""
    top = git(root, "rev-parse", "--show-toplevel", check=False).strip()
    if not top or Path(top).resolve() != root.resolve():  # a parent directory's repo must not be picked up
        raise SystemExit("error: --base needs the target to be the root of a git repository (no .git here)")
    if not git(root, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}", check=False).strip():
        raise SystemExit(f"error: base ref '{base}' not found; remote targets are cloned with full history, "
                         "local targets need the ref to exist locally")
    mb = git(root, "merge-base", base, "HEAD", check=False).strip() or base
    changes = collect_changes(root, [mb])
    for n in git(root, "ls-files", "--others", "--exclude-standard", "-z").split("\0"):
        if n:
            changes[n] = None  # untracked: every line is new
    return changes, f"{mb}..HEAD"


def resolve_pr(pr: str, target: str | None, base: str | None, keep: bool):
    """Clone the repo, fetch refs/pull/N/head, check it out and diff it against the PR base.
    Returns (root, display_name, tmp_dir_to_cleanup, info). Never touches a local target."""
    pr = pr.strip()
    m = PR_URL_RE.match(pr)
    if m:
        slug, number = m.group(1), int(m.group(2))
    elif pr.lstrip("#").isdigit():
        slug, number = None, int(pr.lstrip("#"))
    else:
        raise SystemExit("error: --pr expects a PR number or https://github.com/org/repo/pull/N")
    if slug:
        url = f"https://github.com/{slug}.git"
    elif target and Path(target).expanduser().exists():
        url = git(Path(target).expanduser().resolve(), "remote", "get-url", "origin", check=False).strip()
        if not url:
            raise SystemExit("error: local target has no 'origin' remote; pass org/repo or a PR URL instead")
    elif target:
        url = f"https://github.com/{target}.git" if GITHUB_SHORT_RE.match(target) else target
    else:
        raise SystemExit("error: --pr <number> needs a target repo (org/repo, URL or a local clone)")
    if not re.match(r"^(https://|git@|ssh://|file://|/)", url):
        raise SystemExit(f"error: '{url}' is not a recognizable git URL")
    safe_url = re.sub(r"//[^/@]+@", "//", url)  # never print embedded credentials

    tmp = Path(tempfile.mkdtemp(prefix="scs-pr-"))
    try:
        root = tmp / "repo"
        git(tmp, "clone", "--quiet", "--no-tags", "--filter=blob:none", "--no-checkout", url, "repo")
        git(root, "fetch", "--quiet", "--no-tags", "origin", f"pull/{number}/head")
        head = git(root, "rev-parse", "FETCH_HEAD").strip()
        base_name = base
        gh_slug = GH_SLUG_RE.search(url)
        if not base_name and gh_slug and shutil.which("gh"):
            r = subprocess.run(["gh", "pr", "view", str(number), "--repo", gh_slug.group(1), "--json",
                                "baseRefName", "-q", ".baseRefName"], capture_output=True, text=True, timeout=30)
            base_name = r.stdout.strip() if r.returncode == 0 else None
        cands = [f"origin/{base_name}", base_name] if base_name else [
            git(root, "symbolic-ref", "--short", "refs/remotes/origin/HEAD", check=False).strip(),
            "origin/main", "origin/master"]
        base_ref = next((c for c in cands if c and git(root, "rev-parse", "--verify", "--quiet",
                                                       f"{c}^{{commit}}", check=False).strip()), None)
        if not base_ref:
            raise SystemExit("error: could not determine the PR base branch; pass --base <branch>")
        git(root, "checkout", "--quiet", "--detach", head)
        changes = collect_changes(root, [f"{base_ref}...HEAD"])
    except SystemExit:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    info = {"number": number, "base": base_ref, "head": head[:12], "changes": changes,
            "range": f"{base_ref}..HEAD"}
    return root, f"{safe_url} (PR #{number})", (None if keep else tmp), info


def normalize_selector(pattern: str, root: Path) -> str:
    """Turn an existing absolute / cwd-relative path under root into a repo-relative pattern."""
    cand = Path(pattern).expanduser()
    if cand.exists():
        try:
            return cand.resolve().relative_to(root).as_posix()
        except ValueError:
            pass
    return pattern


def sort_key(f: Finding):
    return (-SEV_RANK[f.severity], f.category, f.file, f.line)


def render_markdown(name: str, findings: list[Finding], meta: dict) -> str:
    counts = Counter(f.severity for f in findings)
    lines = [f"# SCS Security Scan Report", "",
             f"- **Target:** `{name}`",
             f"- **Files scanned:** {meta['files']}  |  **Rules:** {meta['rules']}  |  "
             f"**History scanned:** {'yes' if meta['history'] else 'no'}"
             + (f"  |  **Scope:** {meta['scope']} ({meta['scoped_files']} files)" if meta.get("scope") else ""),
             f"- **Reference:** SCSforAI.md (NHI threats in software supply chains)", "",
             "## Summary", "", "| Severity | Count |", "|---|---|"]
    for s in R.SEVERITIES:
        lines.append(f"| {s} | {counts.get(s, 0)} |")
    lines.append(f"| **total** | **{len(findings)}** |")
    cats = Counter(f.category for f in findings)
    if cats:
        lines += ["", "By category: " + ", ".join(f"{k} ({v})" for k, v in cats.most_common())]
    if not findings:
        lines += ["", "No findings. Static scanning is not proof of safety; review manually."]
        return "\n".join(lines) + "\n"
    lines += ["", "## Findings"]
    for sev in R.SEVERITIES:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        lines += ["", f"### {sev.capitalize()} ({len(group)})"]
        for f in group:
            loc = f.file + (f":{f.line}" if f.line else "")
            tags = [f.rule_id, f"confidence: {f.confidence}", f.source]
            if f.test_path:
                tags.append("test/example path")
            if f.commit:
                tags.append(f"commit {f.commit}")
            lines += ["", f"**{f.title}** — `{loc}`  ", f"_{' · '.join(tags)}_", "",
                      "```", f.evidence, "```",
                      f"- **SCS vulnerability type:** {f.vuln_type}",
                      f"- **Details:** {f.details}",
                      f"- **Impact:** {f.impact}",
                      f"- **Fix:** {f.fix}", f"- **SCSforAI.md:** {f.ref}"]
    return "\n".join(lines) + "\n"


SCOPED_CHECK = ("Scope was limited to selected files / pull-request changes: the rest of the repository, "
                "unchanged lines and repo-level controls were not assessed")
MANUAL_CHECKS = [
    "Branch protection and required reviews on the default branch",
    "GitHub secret scanning and push protection enabled",
    "Who can trigger workflow_dispatch / approve environments for secret-bearing jobs",
    "Token, GitHub App and OAuth app scopes, expiry and rotation status",
    "Package maintainer 2FA and registry / CI platform access reviews",
    "Git history (run with --history on a real clone) and contents of vendored binaries",
]


def render_html(name: str, findings: list[Finding], meta: dict) -> str:
    """Self-contained static HTML report following the SCS review structure (SKILL.md Step 4)."""
    from html import escape as e
    from datetime import datetime, timezone

    counts = Counter(f.severity for f in findings)
    colors = {"critical": "#a1121f", "high": "#cf222e", "medium": "#bf8700", "low": "#3b82d4", "info": "#57606a"}

    # group related findings: same rule + same file -> one item with several lines
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault((f.rule_id, f.file), []).append(f)

    if not findings:
        verdict = "No findings from the static scan. This is not proof of safety; complete the manual checks below."
    else:
        top = next(s for s in R.SEVERITIES if counts.get(s))
        verdict = (f"{len(findings)} unverified finding(s) in {len(groups)} group(s); "
                   f"highest severity: {top}. Findings have not been triaged by a reviewer.")

    out = [f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>SCS Review Report</title>
<style>
body{{font:15px/1.6 -apple-system,"Segoe UI",system-ui,sans-serif;color:#1f2328;background:#fff;margin:0}}
main{{max-width:760px;margin:0 auto;padding:32px 20px}}
h1{{font-size:24px;margin:0 0 4px}} h2{{font-size:18px;margin:32px 0 8px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}}
.muted{{color:#57606a;font-size:13px}} table{{border-collapse:collapse;width:100%;margin:8px 0}}
td,th{{border:1px solid #e5e7eb;padding:6px 10px;text-align:left;font-size:14px}} th{{background:#f7f8fa}}
.card{{background:#f7f8fa;border:1px solid #e5e7eb;border-radius:4px;padding:12px 14px;margin:12px 0}}
.sev{{display:inline-block;color:#fff;font-size:12px;font-weight:600;padding:1px 8px;border-radius:3px;text-transform:uppercase}}
code,pre{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}}
pre{{background:#fff;border:1px solid #e5e7eb;padding:8px;overflow-x:auto;margin:6px 0;white-space:pre-wrap;word-break:break-all}}
footer{{margin-top:40px;padding-top:12px;border-top:1px solid #e5e7eb;text-align:center;font-size:12px;color:#57606a}}
</style></head><body><main>
<h1>SCS Review Report</h1>
<div class="muted">Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} &middot; Reference: SCSforAI.md</div>

<h2>1. Scope</h2>
<table>
<tr><th>Target</th><td><code>{e(name)}</code></td></tr>
<tr><th>Files scanned</th><td>{meta['files']}</td></tr>
<tr><th>Rules</th><td>{meta['rules']}</td></tr>
<tr><th>Git history included</th><td>{'yes' if meta['history'] else 'no'}</td></tr>
{f"<tr><th>Scope</th><td>{e(meta['scope'])}</td></tr><tr><th>Files in scope</th><td>{meta['scoped_files']}</td></tr>" if meta.get('scope') else ''}
<tr><th>Test files excluded</th><td>{'yes' if meta.get('exclude_tests') else 'no'}</td></tr>
<tr><th>Exclude patterns</th><td>{e(', '.join(meta.get('exclude_patterns') or []) or 'none')}</td></tr>
<tr><th>Files excluded</th><td>{meta.get('excluded_files', 0)}</td></tr>
</table>

<h2>2. Verdict</h2>
<p>{e(verdict)}</p>
<table><tr>{''.join(f'<th>{s}</th>' for s in R.SEVERITIES)}<th>total</th></tr>
<tr>{''.join(f'<td>{counts.get(s, 0)}</td>' for s in R.SEVERITIES)}<td><b>{len(findings)}</b></td></tr></table>
"""]

    out.append("<h2>3. Findings</h2>")
    if not findings:
        out.append("<p>None.</p>")
    for (rid, file), items in sorted(groups.items(), key=lambda kv: sort_key(kv[1][0])):
        f = items[0]
        lines = sorted({i.line for i in items if i.line})
        loc = e(file) + (f" &middot; line{'s' if len(lines) > 1 else ''} {', '.join(map(str, lines))}" if lines else "")
        tags = [f"confidence: {f.confidence}", f.source]
        if any(i.test_path for i in items):
            tags.append("test/example path")
        commits = sorted({i.commit for i in items if i.commit})
        if commits:
            tags.append("commit " + ", ".join(commits[:3]))
        ev = "\n".join(dict.fromkeys(i.evidence for i in items))
        out.append(
            f'<div class="card"><span class="sev" style="background:{colors[f.severity]}">{f.severity}</span> '
            f'<b>{e(f.title)}</b><br><code>{loc}</code><br>'
            f'<span class="muted">{e(rid)} &middot; {" &middot; ".join(e(t) for t in tags)}</span>'
            f'<pre>{e(ev)}</pre>'
            f'<div><b>SCS vulnerability type:</b> {e(f.vuln_type)}</div>'
            f'<div><b>Details:</b> {e(f.details)}</div>'
            f'<div><b>Impact:</b> {e(f.impact)}</div>'
            f'<div><b>Fix:</b> {e(f.fix)}</div><div class="muted">SCSforAI.md: {e(f.ref)}</div></div>')

    out.append("<h2>4. Discarded false positives</h2>"
               "<p>Not applicable to automated output: the scanner does not discard findings. "
               "Review each finding above and record false positives here during triage.</p>")

    checks = MANUAL_CHECKS + ([SCOPED_CHECK] if meta.get("scope") else [])
    out.append("<h2>5. Not covered by static scan</h2><ul>" + "".join(f"<li>{e(m)}</li>" for m in checks) + "</ul>")

    # next steps: one per rule, ranked by severity then count, max 5
    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    ranked = sorted(by_rule.values(), key=lambda v: (-SEV_RANK[v[0].severity], -len(v)))[:5]
    out.append("<h2>6. Recommended next steps</h2>")
    if ranked:
        out.append("<ol>" + "".join(
            f"<li><b>{e(v[0].title)}</b> ({len(v)}, {v[0].severity}): {e(v[0].fix)}</li>" for v in ranked) + "</ol>")
    else:
        out.append("<p>Complete the manual checks in section 5.</p>")

    out.append('<footer>Made with IBM Bob</footer></main></body></html>\n')
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="NHI / supply-chain security scanner for GitHub repos")
    ap.add_argument("target", nargs="?", help="local path, GitHub URL, or org/repo (optional with --pr <URL>)")
    ap.add_argument("--format", choices=["markdown", "json", "html"], default="markdown",
                    help="html writes SCS-ReviewReport.html unless -o is given")
    ap.add_argument("--output", "-o", help="write report to this file instead of stdout")
    ap.add_argument("--min-severity", choices=R.SEVERITIES, default="low",
                    help="hide findings below this severity (default: low)")
    ap.add_argument("--fail-on", choices=R.SEVERITIES, help="exit 1 if any finding at/above this severity")
    ap.add_argument("--history", action="store_true", help="also scan added lines in git history for secrets")
    ap.add_argument("--max-commits", type=int, default=500, help="commits to inspect with --history")
    tg = ap.add_mutually_exclusive_group()
    tg.add_argument("--include-tests", action="store_true",
                    help="also scan test/fixture/example/docs paths (skipped by default)")
    tg.add_argument("--exclude-tests", action="store_true",
                    help="exclude test files and directories (*_test.go, test_*.py, *.spec.ts, tests/, e2e/, "
                         "testdata/, ...) from every check, including history and repo-structure findings")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="exclude paths matching GLOB (repeatable). Forms: dir/  path/*.ext  *.ext  name")
    ap.add_argument("--exclude-list", metavar="FILE",
                    help="file with one exclude pattern per line (# comments allowed); same forms as --exclude")
    ap.add_argument("--category", action="append", choices=["secrets", "cicd", "container", "dependency", "iac", "app"],
                    help="limit to category (repeatable)")
    ap.add_argument("--files", action="append", nargs="+", metavar="PATH",
                    help="scan only these files / dirs / globs (repo-relative or existing paths; repeatable)")
    ap.add_argument("--pr", metavar="N|URL",
                    help="scan only the changes of a GitHub pull request (PR number with a repo target, or PR URL)")
    ap.add_argument("--base", metavar="REF",
                    help="scan only files changed vs REF (local git repo / full clone); with --pr, overrides the PR base")
    ap.add_argument("--changed-lines-only", action="store_true",
                    help="with --pr / --base: keep only findings on added or modified lines")
    ap.add_argument("--keep-clone", action="store_true", help="do not delete the temporary clone")
    a = ap.parse_args(argv)
    if a.target and not a.pr and PR_URL_RE.match(a.target):  # a PR URL as the target implies --pr
        a.pr, a.target = a.target, None

    if not a.target and not a.pr:
        ap.error("target is required (or use --pr <URL>)")
    if a.changed_lines_only and not (a.pr or a.base):
        ap.error("--changed-lines-only needs --pr or --base")

    info = None
    try:
        patterns = list(a.exclude) + (load_exclude_list(a.exclude_list) if a.exclude_list else [])
        if a.pr:
            root, name, tmp, info = resolve_pr(a.pr, a.target, a.base, a.keep_clone)
        else:
            root, name, tmp = resolve_target(str(a.target), a.keep_clone, None if (a.history or a.base) else 1)
    except SystemExit as e:
        print(e, file=sys.stderr)
        return 2
    excluded = make_excluder(patterns, a.exclude_tests) if (patterns or a.exclude_tests) else None
    try:
        changes: dict[str, set[int] | None] | None = None
        rev_range = None
        scope_parts: list[str] = []
        if info:
            changes, rev_range = info["changes"], info["range"]
            scope_parts.append(f"PR #{info['number']} ({info['base']}...{info['head']})")
        elif a.base:
            try:
                changes, rev_range = local_changes(root, a.base)
            except SystemExit as e:
                print(e, file=sys.stderr)
                return 2
            scope_parts.append(f"changes vs {a.base}")
        globs = [normalize_selector(g, root) for grp in (a.files or []) for g in grp]
        if globs:
            scope_parts.append(f"files: {', '.join(globs)}")
        scoped = changes is not None or bool(globs)

        def in_scope(rel: str) -> bool:
            if changes is not None and rel not in changes:
                return False
            return not globs or any(fnmatch.fnmatch(rel, g) or rel == g or rel.startswith(g.rstrip("/") + "/")
                                    for g in globs)

        rules = compile_rules()
        if a.category:
            rules = [c for c in rules if c.rule["category"] in a.category]
        findings, rels = scan_worktree(root, rules, a.include_tests, excluded, in_scope if scoped else None)
        findings += scan_structure(root, rels)
        if a.history:
            if (root / ".git").exists():
                findings += scan_history(root, rules, a.max_commits, rev_range)
            else:
                print("[warn] --history requested but target is not a git repository", file=sys.stderr)
        if scoped:  # drop repo-level / history findings outside the selected files
            findings = [f for f in findings if in_scope(f.file)]
        if a.changed_lines_only and changes is not None:
            findings = [f for f in findings if f.line == 0 or changes.get(f.file) is None
                        or f.line in changes[f.file]]  # type: ignore[operator]
        if excluded:  # also drops structure / history findings located in excluded paths
            findings = [f for f in findings if not excluded(f.file)]
        if a.category:
            findings = [f for f in findings if f.category in a.category]
        floor = SEV_RANK[a.min_severity]
        findings = sorted(dedupe([f for f in findings if SEV_RANK[f.severity] >= floor]), key=sort_key)
        meta = {"files": len(rels), "rules": len(rules), "history": a.history,
                "exclude_tests": a.exclude_tests, "exclude_patterns": patterns,
                "excluded_files": sum(1 for r in rels if excluded(r)) if excluded else 0}
        if scoped:
            if a.changed_lines_only:
                scope_parts.append("added/modified lines only")
            meta["scope"] = "; ".join(scope_parts)
            meta["scoped_files"] = sum(1 for r in rels if in_scope(r) and not (excluded and excluded(r)))
        if a.format == "json":
            report = json.dumps({"target": name, "meta": meta, "findings": [asdict(f) for f in findings]}, indent=2)
        elif a.format == "html":
            report = render_html(name, findings, meta)
            a.output = a.output or "SCS-ReviewReport.html"
        else:
            report = render_markdown(name, findings, meta)
        if a.output:
            Path(a.output).write_text(report, encoding="utf-8")
            print(f"report written to {a.output} ({len(findings)} findings)", file=sys.stderr)
        else:
            print(report)
        if tmp is None and a.keep_clone and (a.pr or not Path(str(a.target)).exists()):
            print(f"clone kept at {root}", file=sys.stderr)
        if a.fail_on and any(SEV_RANK[f.severity] >= SEV_RANK[a.fail_on] for f in findings):
            return 1
        return 0
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
