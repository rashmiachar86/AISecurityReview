"""Detection rules for the scs-security-scan skill.

Every rule maps to a section of SCSforAI.md (the `ref` field) so each finding can be
traced back to the NHI / software-supply-chain threat it addresses.

Rule fields:
    id          unique rule id
    title       short human title
    severity    critical | high | medium | low | info
    category    secrets | cicd | container | dependency | iac | app
    files       glob list matched (case-insensitive) against the repo-relative path or basename
    pattern     regex applied per line
    ignore      optional regex; a matching line is skipped (placeholder / false-positive filter)
    confidence  high | medium | low  (how likely a hit is a real issue)
    redact      True => matched text is masked in the report
    history     True => rule is also applied to added lines in git history (--history)
    fix         remediation guidance
    ref         SCSforAI.md section
"""

from __future__ import annotations

ALL = ["*"]
WORKFLOWS = [".github/workflows/*.yml", ".github/workflows/*.yaml"]
YAML = ["*.yml", "*.yaml"]
DOCKERFILES = ["dockerfile*", "*.dockerfile", "containerfile*"]
CODE = [
    "*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.go", "*.java", "*.kt",
    "*.rb", "*.php", "*.cs", "*.rs", "*.sh",
]
REQUIREMENTS = ["requirements*.txt"]
PLACEHOLDER = (
    r"(?i)example|changeme|change_me|placeholder|your[_-]|xxxx|\*{3,}|dummy|sample|fake|"
    r"redacted|<[^>]+>|\$\{|%\(|%s|os\.environ|getenv|process\.env"
)

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _r(id, title, severity, category, files, pattern, fix, ref, **kw):
    rule = {
        "id": id, "title": title, "severity": severity, "category": category,
        "files": files, "pattern": pattern, "fix": fix, "ref": ref,
        "ignore": None, "confidence": "high", "redact": False, "history": False,
    }
    rule.update(kw)
    return rule


S1 = "5.1 Git History Exposure / Stage 1 Source Code Management"
S2 = "Stage 2 Dependency Management"
S3 = "Stage 3 Build & CI/CD Pipeline"
S4 = "Stage 4 Artifact Storage & Distribution / 5.2 Container Image Secrets"
S5 = "Stage 5 Deployment & Runtime"
AV1 = "4.1 Secret Injection via Pull Requests"
AV2 = "4.2 Compromised Dependencies"
AV3 = "4.3 Build Log Exposure"
AV5 = "4.5 Third-Party GitHub Actions/Plugins"
CS2 = "Case Study 2: Codecov Bash Uploader"
P3 = "5.3 Cloud Metadata Service Exploitation"
P4 = "5.4 Configuration File Exposure"
P5 = "5.5 Log File Leakage"

SECRET_FIX = (
    "Revoke and rotate the credential now, remove it from code, and load it at runtime from a "
    "secret manager or CI secret store. If it was committed, also purge git history."
)

RULES = [
    # ------------------------------------------------------------------ secrets
    _r("SCS-SEC-001", "AWS access key ID", "critical", "secrets", ALL,
       r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", SECRET_FIX, S1, redact=True, history=True),
    _r("SCS-SEC-002", "GitHub token", "critical", "secrets", ALL,
       r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b",
       SECRET_FIX, S1, redact=True, history=True),
    _r("SCS-SEC-003", "Private key material", "critical", "secrets", ALL,
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY",
       SECRET_FIX, S1, redact=True, history=True),
    _r("SCS-SEC-004", "Slack token", "high", "secrets", ALL,
       r"\bxox[abprs]-[A-Za-z0-9-]{10,}", SECRET_FIX, S1, redact=True, history=True),
    _r("SCS-SEC-005", "npm registry token", "critical", "secrets", ALL,
       r"\bnpm_[A-Za-z0-9]{36}\b|//[^\s/]+/:_authToken=(?!\$\{)\S+",
       SECRET_FIX, S2, redact=True, history=True),
    _r("SCS-SEC-006", "PyPI upload token", "critical", "secrets", ALL,
       r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}", SECRET_FIX, S2, redact=True, history=True),
    _r("SCS-SEC-007", "Google API key", "high", "secrets", ALL,
       r"\bAIza[0-9A-Za-z_-]{35}\b", SECRET_FIX, S1, redact=True, history=True),
    _r("SCS-SEC-008", "Azure storage account key", "critical", "secrets", ALL,
       r"AccountKey=[A-Za-z0-9+/]{40,}={0,2}", SECRET_FIX, S5, redact=True, history=True),
    _r("SCS-SEC-009", "Hardcoded credential assignment", "medium", "secrets", ALL,
       r"""(?i)\b[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)\b["']?\s*[:=]\s*["'][^"'\s${}<>]{8,}["']""",
       SECRET_FIX + " Test fixtures should use obviously fake values.", P4,
       ignore=PLACEHOLDER, confidence="medium", redact=True),
    _r("SCS-SEC-010", "Credentials embedded in URL / connection string", "high", "secrets", ALL,
       r"""\b[a-z][a-z0-9+.-]*://[^\s/:@'"]+:[^\s/:@'"${}]{3,}@[^\s'"]+""",
       SECRET_FIX, P4,
       ignore=PLACEHOLDER + r"|user:pass|username:password|\{\w+\}",
       confidence="medium", redact=True, history=True),

    # --------------------------------------------------------------------- CI/CD
    _r("SCS-CICD-001", "Third-party action not pinned to a commit SHA", "medium", "cicd", WORKFLOWS,
       r"^\s*-?\s*uses:\s*(?!\./|docker://)[\w.-]+/[\w./-]+@(?![0-9a-fA-F]{40}\b)\S+",
       "Pin to a full 40-char commit SHA (comment the human-readable tag) and let Dependabot/"
       "Renovate bump it.", AV5, ignore=r"uses:\s*(?:actions|github)/"),
    _r("SCS-CICD-002", "First-party action pinned to a mutable tag", "low", "cicd", WORKFLOWS,
       r"^\s*-?\s*uses:\s*(?:actions|github)/[\w./-]+@(?![0-9a-fA-F]{40}\b)\S+",
       "Prefer SHA pinning for all actions; tags can be moved.", AV5),
    _r("SCS-CICD-003", "pull_request_target trigger", "high", "cicd", WORKFLOWS,
       r"\bpull_request_target\b",
       "Never check out or run untrusted PR code in this context. Use `pull_request` or split "
       "into an unprivileged build and a privileged, artifact-only follow-up workflow.", AV1,
       confidence="medium"),
    _r("SCS-CICD-004", "Untrusted GitHub context interpolated (script injection)", "high", "cicd",
       WORKFLOWS,
       r"\$\{\{\s*(?:github\.head_ref|github\.event\.[\w.\[\]*]*\.(?:title|body|name|label|message|email|ref|head_ref|page_name))\s*\}\}",
       "Pass the value through an `env:` variable and reference it as a shell variable instead of "
       "inlining `${{ }}` into `run:`/`script:`.", AV1, confidence="medium"),
    _r("SCS-CICD-005", "Workflow grants write-all permissions", "high", "cicd", WORKFLOWS,
       r"^\s*permissions:\s*write-all\b",
       "Set `permissions: {}` or `contents: read` at top level; grant per-job scopes only as needed.",
       S3),
    _r("SCS-CICD-006", "All secrets passed to reusable workflow (secrets: inherit)", "medium",
       "cicd", WORKFLOWS, r"\bsecrets:\s*inherit\b",
       "Pass only the specific secrets the called workflow needs.", S3),
    _r("SCS-CICD-007", "Secret echoed to build log", "high", "cicd", WORKFLOWS,
       r"(?i)\b(?:echo|printf|Write-Host|Write-Output)\b.*\$\{\{\s*secrets\.",
       "Never print secrets. Rely on masking only as a backstop; remove the command.", AV3),
    _r("SCS-CICD-008", "Long-lived cloud credentials stored as CI secrets", "medium", "cicd",
       WORKFLOWS,
       r"\$\{\{\s*secrets\.(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AZURE_CLIENT_SECRET|AZURE_CREDENTIALS|GCP_SA_KEY|GOOGLE_CREDENTIALS|GCP_CREDENTIALS)\s*\}\}",
       "Use OIDC federation (short-lived tokens) with a least-privilege role instead.", S3),
    _r("SCS-CICD-009", "Remote script piped into a shell", "high", "cicd",
       YAML + ["*.sh", "makefile", "jenkinsfile", "*.groovy"] + DOCKERFILES,
       r"(?i)\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b",
       "Download, verify checksum/signature, then execute. Pin the version.", CS2),
    _r("SCS-CICD-010", "Environment dumped in CI step", "medium", "cicd", WORKFLOWS + [".gitlab-ci.yml"],
       r"^\s*(?:-\s*)?(?:run:\s*)?(?:env|printenv)\s*$",
       "Remove environment dumps; they leak secrets into build logs.", AV3),

    # ---------------------------------------------------------------- containers
    _r("SCS-CTR-001", "Secret baked into image via ENV/ARG", "high", "container", DOCKERFILES,
       r"""(?i)^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY)\w*(?:=|\s+)(?!\$)["']?[^\s"'$]{3,}""",
       "Use BuildKit `RUN --mount=type=secret` for build-time secrets and inject runtime secrets "
       "at deploy time.", S4, redact=True),
    _r("SCS-CTR-002", "Secret-named build ARG (visible in image history)", "medium", "container",
       DOCKERFILES,
       r"(?i)^\s*ARG\s+\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY)\w*\s*$",
       "Build ARGs are recorded in image metadata; use `--mount=type=secret` instead.", S4,
       confidence="medium"),
    _r("SCS-CTR-004", "ADD from remote URL", "medium", "container", DOCKERFILES,
       r"(?i)^\s*ADD\s+(?:--\S+\s+)*https?://",
       "Use curl/wget with checksum verification in a RUN step, or COPY a vetted artifact.", S4),
    _r("SCS-CTR-005", "Credential file copied into image", "high", "container", DOCKERFILES,
       r"(?i)^\s*(?:COPY|ADD)\s+(?:--\S+\s+)*\S*(?:\.env\b|id_rsa|id_ed25519|\.pem\b|\.npmrc|\.pypirc|\.aws|credentials\.json|\.netrc)",
       "Do not copy credentials into images; add to .dockerignore and mount at runtime.", S4),

    # -------------------------------------------------------------- dependencies
    _r("SCS-DEP-001", "Extra package index (dependency confusion risk)", "high", "dependency",
       REQUIREMENTS + ["pip.conf", "*.sh", "makefile", "*.toml", "*.cfg", "*.ini"] + YAML + DOCKERFILES,
       r"--extra-index-url\b|extra-index-url\s*=",
       "Use a single index (or a proxy that blocks public fallbacks for internal names) and "
       "`--require-hashes`.", S2),
    _r("SCS-DEP-002", "Dependency from VCS/URL without commit pin", "medium", "dependency",
       REQUIREMENTS, r"^\s*(?:-e\s+)?(?:git\+|hg\+|svn\+|https?://)\S+",
       "Pin to an immutable commit SHA or publish to a vetted registry.", AV2,
       ignore=r"@[0-9a-f]{40}\b|#sha256=|--hash"),
    _r("SCS-DEP-003", "Unpinned Python requirement", "low", "dependency", REQUIREMENTS,
       r"^(?![\s#-])[A-Za-z0-9_.-]+(?:\[[^\]]+\])?\s*(?:(?:>=|~=|>|<=|<|!=)[^=#]*)?(?:#.*)?$",
       "Pin exact versions (and hashes) via a lock file such as pip-tools/uv.", AV2),
    _r("SCS-DEP-004", "npm VCS/URL dependency", "medium", "dependency", ["package.json"],
       r'"[^"]+"\s*:\s*"(?:git\+\w+://|git://|github:|https?://)[^"]*"',
       "Depend on a registry version with integrity hash, or pin to a commit SHA.", AV2,
       ignore=r"#[0-9a-f]{40}\b"),
    _r("SCS-DEP-005", "npm install lifecycle script", "low", "dependency", ["package.json"],
       r'"(?:preinstall|install|postinstall)"\s*:\s*"',
       "Lifecycle scripts run with the installer's environment; review them and prefer "
       "`--ignore-scripts` in CI.", AV2, confidence="low"),
    _r("SCS-DEP-006", "Wildcard / latest dependency version", "medium", "dependency",
       ["package.json"], r'"[@\w./-]+"\s*:\s*"(?:\*|latest|x)"',
       "Use exact or caret-bounded versions with a committed lock file.", AV2),
    _r("SCS-DEP-007", "TLS / registry verification disabled or plain HTTP", "medium", "dependency",
       CODE + YAML + ["*.toml", "*.cfg", "*.ini", "*.conf", ".npmrc", "pip.conf", "makefile"] + DOCKERFILES,
       r"""(?i)--trusted-host\b|(?:index-url|registry)\s*[=\s]\s*http://|strict-ssl\s*=\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0|GIT_SSL_NO_VERIFY|\bcurl\b[^\n|]*\s(?:-k|--insecure)\b|\bverify\s*=\s*False\b|InsecureSkipVerify:\s*true""",
       "Keep TLS verification on; fix trust-store problems instead of disabling checks.", AV2),

    # ------------------------------------------------------------------ IaC / k8s
    _r("SCS-IAC-001", "Privileged container", "high", "iac", YAML,
       r"^\s*privileged:\s*true\b", "Drop `privileged`; grant only required capabilities.", S5),
    _r("SCS-IAC-002", "Kubernetes Secret manifest committed", "medium", "iac", YAML,
       r"^kind:\s*Secret\s*$",
       "Use SealedSecrets/External Secrets/SOPS; never commit plain Secret manifests.", S5,
       confidence="medium"),
    _r("SCS-IAC-003", "EC2 IMDSv1 allowed (http_tokens optional)", "high", "iac", ["*.tf"],
       r'http_tokens\s*=\s*"optional"', 'Set `http_tokens = "required"` (IMDSv2).', P3),
    _r("SCS-IAC-004", "Hardcoded credential in Terraform", "high", "iac", ["*.tf", "*.tfvars"],
       r'\b(?:access_key|secret_key|token|password|client_secret)\s*=\s*"(?!\$\{|var\.)[^"\s]{6,}"',
       SECRET_FIX, P4, ignore=PLACEHOLDER, confidence="medium", redact=True),
    _r("SCS-IAC-005", "Wildcard IAM action", "medium", "iac", ["*.tf", "*.json"] + YAML,
       r"""(?i)["']?Action["']?\s*[:=]\s*\[?\s*["']\*["']""",
       "Grant least-privilege, resource-scoped actions to service identities.", S5),
    _r("SCS-IAC-006", "Docker socket mounted", "high", "iac", YAML + ["*.tf", "*.json", "*.sh"] + DOCKERFILES,
       r"/var/run/docker\.sock",
       "Mounting the socket gives root-equivalent host access; use rootless builders (kaniko, "
       "buildah) instead.", S3),
    _r("SCS-IAC-007", "Weak pod security context", "medium", "iac", YAML,
       r"^\s*(?:hostNetwork|hostPID|hostIPC|allowPrivilegeEscalation):\s*true\b|^\s*runAsNonRoot:\s*false\b|^\s*runAsUser:\s*0\s*$",
       "Run as non-root, disallow privilege escalation, avoid host namespaces.", S5),
    _r("SCS-IAC-008", "Public cloud storage ACL", "high", "iac", ["*.tf"],
       r'(?i)\bacl\s*=\s*"public-read(?:-write)?"',
       "Make buckets private and serve through a controlled CDN/identity.", S4),

    # ----------------------------------------------------------------- app code
    _r("SCS-APP-001", "Cloud metadata endpoint referenced (SSRF target)", "low", "app", CODE,
       r"169\.254\.169\.254|metadata\.google\.internal|metadata\.azure",
       "Ensure outbound URL fetching blocks link-local ranges; enforce IMDSv2 and hop limit 1.",
       P3, confidence="low"),
    _r("SCS-APP-002", "Possible secret written to logs", "medium", "app", CODE,
       r"""(?i)\b(?:print|println|printf|console\.(?:log|info|debug|error|warn)|logg?(?:er|ing)?\.(?:debug|info|warning|warn|error|critical|exception|log)|fmt\.Print\w*|System\.out\.print\w*)\s*\(.*\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|authorization|bearer|private[_-]?key)\b""",
       "Log identifiers, not credentials; add redaction filters to the logging pipeline.", P5,
       ignore=r"(?i)\b(?:invalid|missing|expired|required|not\s+(?:found|set|provided)|unauthorized|failed|rotat)",
       confidence="low"),
    _r("SCS-APP-003", "Debug mode enabled", "medium", "app", ["*.py"],
       r"(?i)\bapp\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b",
       "Disable debug and verbose stack traces outside local development.", P5),
    _r("SCS-APP-004", "Weak cryptography (MD5/SHA-1/ECB)", "medium", "app", CODE,
       r"""(?i)hashlib\.(?:md5|sha1)\(|createHash\(\s*['"](?:md5|sha1)['"]|MessageDigest\.getInstance\(\s*"(?:MD5|SHA-?1)"|AES/ECB|MODE_ECB|\b(?:md5|sha1)\.New\(\)""",
       "Use SHA-256+, AES-GCM/ChaCha20-Poly1305, and Argon2id/bcrypt/scrypt for passwords.", P5,
       confidence="medium"),
    _r("SCS-APP-005", "Unsafe execution / deserialization primitive", "medium", "app", ["*.py"],
       r"\bshell\s*=\s*True\b|\bpickle\.loads?\(|\byaml\.load\((?![^)]*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe)Loader)",
       "Avoid shell=True, use yaml.safe_load, and never unpickle untrusted data.", AV1,
       confidence="low"),
]

# Files that should not be in a repository at all (matched on basename / path, lowercase).
# (glob, severity, title)
SENSITIVE_FILES = [
    (".env", "high", "Environment file committed"),
    (".env.*", "high", "Environment file committed"),
    ("id_rsa", "critical", "SSH private key file"),
    ("id_dsa", "critical", "SSH private key file"),
    ("id_ecdsa", "critical", "SSH private key file"),
    ("id_ed25519", "critical", "SSH private key file"),
    ("*.p12", "high", "Keystore/certificate bundle with private key"),
    ("*.pfx", "high", "Keystore/certificate bundle with private key"),
    ("*.jks", "high", "Java keystore"),
    ("*.keystore", "high", "Keystore"),
    ("*.kdbx", "high", "Password-manager database"),
    (".pypirc", "high", "PyPI credentials file"),
    (".netrc", "high", "netrc credentials file"),
    (".git-credentials", "critical", "Stored git credentials"),
    (".htpasswd", "high", "htpasswd credentials file"),
    ("credentials.json", "high", "Credentials file"),
    ("service-account*.json", "high", "Cloud service-account key"),
    ("*.tfstate", "high", "Terraform state (contains secrets)"),
    ("*.tfstate.backup", "high", "Terraform state (contains secrets)"),
    ("*.tfvars", "medium", "Terraform variable file (may contain secrets)"),
    (".aws/credentials", "critical", "AWS credentials file"),
    ("kubeconfig", "high", "Kubernetes credentials"),
    (".kube/config", "high", "Kubernetes credentials"),
]
SENSITIVE_FILE_SKIP_SUFFIXES = (".example", ".sample", ".template", ".dist", ".tpl")
SENSITIVE_FIX = (
    "Remove the file from the repo, add it to .gitignore, rotate any secret it held, and purge "
    "it from git history."
)

# Manifest -> (acceptable lock files, severity)
LOCKFILES = {
    "package.json": (["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
                      "bun.lockb"], "medium"),
    "pipfile": (["Pipfile.lock"], "medium"),
    "gemfile": (["Gemfile.lock"], "medium"),
    "go.mod": (["go.sum"], "medium"),
    "composer.json": (["composer.lock"], "medium"),
    "cargo.toml": (["Cargo.lock"], "low"),
}

SECRET_SCANNERS = ("gitleaks", "trufflehog", "detect-secrets", "git-secrets")
DEPENDENCY_BOTS = [
    ".github/dependabot.yml", ".github/dependabot.yaml", "renovate.json", ".renovaterc",
    ".renovaterc.json", ".github/renovate.json", ".github/renovate.json5", "renovate.json5",
]
CODEOWNERS = ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]

# ---------------------------------------------------------------------------------------------
# Per-rule narrative shown with every finding: (SCS vulnerability type, details, impact).
# Vulnerability types follow the threat names used in SCSforAI.md (section 4 attack vectors,
# section 5 secret-sprawl patterns, section 1 stages).
# ---------------------------------------------------------------------------------------------
VT_HISTORY = "Git History Exposure"
VT_CONFIG = "Configuration File Exposure"
VT_PR = "Secret Injection via Pull Requests"
VT_DEPS = "Compromised Dependencies"
VT_BUILDLOG = "Build Log Exposure"
VT_ACTIONS = "Third-Party GitHub Actions/Plugins"
VT_IMAGE = "Container Image Secrets"
VT_IMDS = "Cloud Metadata Service Exploitation"
VT_LOGLEAK = "Log File Leakage"
VT_PLATFORM = "Compromised CI/CD Platform"
VT_SCRIPT = "Compromised Build Script (Codecov-style)"
VT_RUNTIME = "Insecure Deployment & Runtime"
VT_ARTIFACT = "Artifact Storage & Distribution Exposure"

_LEAK = "Anyone with read access to the repository, its forks or its history (and every clone) holds the credential. "

META = {
    # ---- secrets
    "SCS-SEC-001": (VT_HISTORY, "An AWS access key ID (AKIA/ASIA prefix) is present in repository content.",
                    _LEAK + "It can be used to call AWS APIs as the owning identity; automated scrapers "
                    "harvest such keys within minutes of exposure."),
    "SCS-SEC-002": (VT_HISTORY, "A GitHub personal-access, OAuth or app token is present in repository content.",
                    _LEAK + "The holder can read private repos, push code, alter workflows and pivot "
                    "into CI secrets with the token owner's permissions."),
    "SCS-SEC-003": (VT_HISTORY, "A PEM private key block is present in repository content. Public example keys "
                    "used in tests are harmless; production keys are not.",
                    "A real key lets an attacker impersonate the service or host, decrypt captured traffic "
                    "or sign malicious artifacts, and it stays valid until revoked."),
    "SCS-SEC-004": (VT_HISTORY, "A Slack API/bot/user token is present in repository content.",
                    _LEAK + "The holder can read channel history, impersonate users or bots and phish "
                    "or exfiltrate data through the workspace."),
    "SCS-SEC-005": (VT_DEPS, "An npm registry auth token is present in repository content.",
                    "The holder can publish malicious versions of every package the token can access, "
                    "compromising all downstream consumers (supply-chain poisoning)."),
    "SCS-SEC-006": (VT_DEPS, "A PyPI upload token is present in repository content.",
                    "The holder can upload trojaned releases of the project, which downstream builds "
                    "install automatically."),
    "SCS-SEC-007": (VT_HISTORY, "A Google API key is present in repository content.",
                    "The key can be abused for quota/billing fraud and to reach any Google API enabled "
                    "for that project."),
    "SCS-SEC-008": (VT_CONFIG, "An Azure storage account key is present in a connection string.",
                    "The key grants full read/write/delete control over the storage account's data, "
                    "bypassing identity-based access controls."),
    "SCS-SEC-009": (VT_CONFIG, "A variable named like a password/secret/token is assigned a literal string. "
                    "Often a test fixture or dev default; verify whether the value is real.",
                    "If real, " + _LEAK.lower() + "Hardcoded values also persist in git history and cannot "
                    "be rotated without a code change."),
    "SCS-SEC-010": (VT_CONFIG, "A URL or connection string embeds a username and password "
                    "(scheme://user:pass@host).",
                    "Embedded credentials leak through logs, process listings, shell history, proxies and "
                    "error messages as well as through repository access."),
    "SCS-FILE-001": (VT_CONFIG, "A file type that normally holds credentials or key material (.env, keys, "
                     "keystores, kubeconfig, Terraform state) is committed to the repository.",
                     "Whole sets of secrets are disclosed at once, and they persist in git history even "
                     "after the file is deleted."),
    # ---- CI/CD
    "SCS-CICD-001": (VT_ACTIONS, "A third-party action or reusable workflow is referenced by a mutable tag or "
                     "branch instead of a full commit SHA.",
                     "If the upstream repository or tag is compromised (as with tj-actions and Codecov), the "
                     "attacker's code runs in this pipeline with its secrets and GITHUB_TOKEN."),
    "SCS-CICD-002": (VT_ACTIONS, "A first-party action (actions/*, github/*) is pinned to a mutable tag.",
                     "Tags can be moved; a compromised or retagged release would execute in the pipeline. "
                     "Lower risk than third-party actions."),
    "SCS-CICD-003": (VT_PR, "The workflow uses pull_request_target, which runs in the base repository context "
                     "with secrets and a write-capable token even for pull requests from forks.",
                     "If the job checks out or executes PR code, a malicious pull request can exfiltrate "
                     "secrets and write to the repository."),
    "SCS-CICD-004": (VT_PR, "An attacker-controllable GitHub context value (branch name, PR title/body, label, "
                     "commit message) is interpolated directly into a script with ${{ }}.",
                     "A crafted value executes arbitrary shell commands in the job, exposing secrets and the "
                     "GITHUB_TOKEN."),
    "SCS-CICD-005": (VT_PLATFORM, "The workflow grants the GITHUB_TOKEN write-all permissions.",
                     "Any compromised step or action can push code, publish releases and modify workflows "
                     "across the repository."),
    "SCS-CICD-006": (VT_PLATFORM, "All repository secrets are passed to a reusable workflow with "
                     "'secrets: inherit'.",
                     "The called workflow (and anything it runs) can read every secret, widening the blast "
                     "radius if it or its pinned reference is compromised."),
    "SCS-CICD-007": (VT_BUILDLOG, "A secret is expanded inline in a shell command (echo/printf) in a run step.",
                     "Log masking is best-effort and does not cover decoded or transformed values, so the "
                     "secret can appear in build logs or the process list; special characters can also break "
                     "quoting and enable injection. Logs are readable by everyone with repo access."),
    "SCS-CICD-008": (VT_PLATFORM, "Long-lived cloud access keys are stored as CI secrets.",
                     "Static keys never expire; theft through any CI compromise gives persistent cloud "
                     "access, unlike short-lived OIDC tokens."),
    "SCS-CICD-009": (VT_SCRIPT, "A remote script is downloaded and piped straight into a shell.",
                     "Upstream compromise or a man-in-the-middle runs arbitrary code with the CI "
                     "environment's secrets, as in the 2021 Codecov Bash Uploader incident."),
    "SCS-CICD-010": (VT_BUILDLOG, "The CI step dumps the whole environment (env/printenv).",
                     "Every environment variable, including injected secrets, is written to the build log."),
    "SCS-CICD-100": (VT_HISTORY, "No secret scanner (gitleaks, trufflehog, detect-secrets) is referenced in "
                     "CI or pre-commit configuration.",
                     "Committed credentials go undetected until an attacker finds them."),
    "SCS-CICD-101": (VT_ARTIFACT, "No SBOM, provenance or signing step (syft, cyclonedx, cosign, SLSA, "
                     "attestations) is referenced in CI.",
                     "Consumers cannot verify what was built or quickly identify affected releases when a "
                     "dependency is later found compromised."),
    # ---- containers
    "SCS-CTR-001": (VT_IMAGE, "A secret value is set through ENV/ARG in a Dockerfile.",
                    "The value is baked into image layers and metadata; anyone who can pull the image can "
                    "extract it with docker history or inspect."),
    "SCS-CTR-002": (VT_IMAGE, "A build ARG with a secret-like name is declared.",
                    "Build arguments are recorded in image history, so a secret passed at build time is "
                    "recoverable from the image."),
    "SCS-CTR-003": (VT_RUNTIME, "The image never switches to a non-root USER.",
                    "Code execution inside the container runs as root, which eases container escape and "
                    "access to mounted secrets. Lower risk where a runtime such as AWS Lambda sandboxes it."),
    "SCS-CTR-004": (VT_DEPS, "ADD fetches content from a remote URL during the image build.",
                    "Remote content is unverified and mutable; tampering at the source or in transit puts "
                    "malicious code into the image."),
    "SCS-CTR-005": (VT_IMAGE, "A credential-bearing file (.env, keys, .npmrc, .aws, .netrc) is copied into the "
                    "image.",
                    "The credential is stored in an image layer and exposed to everyone who can pull the "
                    "image or its cache."),
    "SCS-CTR-006": (VT_DEPS, "The base image is referenced by tag rather than an immutable @sha256 digest.",
                    "A moved or poisoned tag silently changes what gets built, and builds are not "
                    "reproducible."),
    # ---- dependencies
    "SCS-DEP-001": (VT_DEPS, "An extra package index is configured next to the default one.",
                    "Dependency confusion: an attacker publishes a higher-versioned package under an "
                    "internal name on the public index and the installer picks it."),
    "SCS-DEP-002": (VT_DEPS, "A Python dependency is installed from a VCS/URL source without a commit pin or "
                    "hash.",
                    "The installed code can change at any time and bypasses registry integrity checks."),
    "SCS-DEP-003": (VT_DEPS, "A Python requirement allows a range of versions instead of an exact version.",
                    "A hijacked or malicious new release is installed automatically on the next build."),
    "SCS-DEP-004": (VT_DEPS, "An npm dependency is resolved from a git/URL source instead of the registry "
                    "or a pinned commit.",
                    "Content is mutable and unverified, so a changed branch or hijacked repository injects "
                    "code into the build."),
    "SCS-DEP-005": (VT_DEPS, "A package runs a preinstall/install/postinstall lifecycle script.",
                    "Install scripts execute with the installer's environment (including CI secrets) and are "
                    "a common malware delivery path."),
    "SCS-DEP-006": (VT_DEPS, "A dependency uses a wildcard or 'latest' version.",
                    "Any new release, including a malicious one, is pulled in without review."),
    "SCS-DEP-007": (VT_DEPS, "TLS or registry verification is disabled, or a plain-HTTP registry is used.",
                    "A network attacker can alter packages, artifacts or API responses in transit "
                    "(man-in-the-middle). In test code the risk is limited to that environment."),
    "SCS-DEP-100": (VT_DEPS, "A dependency manifest has no committed lock file.",
                    "Builds are not reproducible and transitive dependency changes, including malicious "
                    "ones, are not integrity-checked."),
    "SCS-DEP-101": (VT_DEPS, "No Dependabot or Renovate configuration was found.",
                    "Vulnerable or compromised dependencies and outdated actions stay in use because "
                    "nothing proposes updates."),
    # ---- IaC / runtime
    "SCS-IAC-001": (VT_RUNTIME, "A container is configured as privileged.",
                    "A process in the container has near-host-level capabilities, making host takeover "
                    "straightforward after any compromise."),
    "SCS-IAC-002": (VT_CONFIG, "A plain Kubernetes Secret manifest is committed.",
                    "Secret values are only base64-encoded, so anyone with repo access reads them."),
    "SCS-IAC-003": (VT_IMDS, "EC2 instance metadata allows IMDSv1 (http_tokens optional).",
                    "An SSRF flaw or any process on the host can fetch the instance role's credentials "
                    "with a single GET request."),
    "SCS-IAC-004": (VT_CONFIG, "A credential is hardcoded in Terraform configuration.",
                    "The secret is exposed to repo readers and recorded in state files and plans."),
    "SCS-IAC-005": (VT_RUNTIME, "An IAM policy allows the wildcard action '*'.",
                    "A compromised service identity gains unrestricted access to the allowed resources."),
    "SCS-IAC-006": (VT_RUNTIME, "The Docker socket is mounted into a container.",
                    "Access to the socket is root-equivalent on the host: the container can start "
                    "privileged containers and read other workloads' secrets."),
    "SCS-IAC-007": (VT_RUNTIME, "The pod security context allows host namespaces, privilege escalation or "
                    "root.",
                    "A compromised container can escalate privileges or reach the host and neighbouring "
                    "workloads."),
    "SCS-IAC-008": (VT_ARTIFACT, "A cloud storage ACL is public-read or public-read-write.",
                    "Stored artifacts and data are readable (or writable) by anyone on the internet."),
    # ---- application code
    "SCS-APP-001": (VT_IMDS, "Code references the cloud metadata endpoint (169.254.169.254 and similar).",
                    "If an SSRF path reaches it, an attacker can read the instance's temporary credentials. "
                    "Often just test or configuration constants."),
    "SCS-APP-002": (VT_LOGLEAK, "A logging or print call includes a variable named like a password, token or "
                    "key.",
                    "Credentials written to logs persist in log stores and are readable by anyone with log "
                    "access."),
    "SCS-APP-003": (VT_LOGLEAK, "Debug mode is enabled in application code.",
                    "Verbose errors and consoles leak environment variables, secrets and, in some "
                    "frameworks, allow code execution."),
    "SCS-APP-004": (VT_LOGLEAK, "A weak cryptographic primitive (MD5, SHA-1 or ECB mode) is used.",
                    "Weak hashes and modes allow collisions, tampering or recovery of protected secrets."),
    "SCS-APP-005": (VT_PR, "An unsafe execution or deserialization primitive is used (shell=True, "
                    "pickle.load, yaml.load).",
                    "If any part of the input is attacker-controlled, it leads to arbitrary command or "
                    "code execution."),
    # ---- repository controls
    "SCS-SRC-100": (VT_HISTORY, "The repository has no .gitignore.",
                    "Secrets, keys and state files are easily committed by accident and then persist in "
                    "history."),
    "SCS-SRC-101": (VT_HISTORY, "The .gitignore does not exclude .env files.",
                    "Local environment files containing secrets can be committed by accident."),
    "SCS-SRC-102": (VT_PLATFORM, "No CODEOWNERS file protects workflows and other sensitive paths.",
                    "A single contributor can change pipeline definitions to exfiltrate secrets without a "
                    "required owner review."),
}
DEFAULT_META = ("Unclassified", "See the rule title and fix guidance.", "See the referenced SCSforAI.md section.")
