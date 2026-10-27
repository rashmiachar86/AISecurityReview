# NHI Security Threats in Software Supply Chains
## Presentation Talking Points — Speaker Notes

---

## Slide 1 — Title: Non-Human Identity (NHI) Security Threats in Software Supply Chains

**Opening hook (60–90 seconds):**

- Welcome the audience and frame the stakes immediately: "If your organization has more than 50 engineers, you almost certainly have thousands of machine credentials active right now — and most of them are not governed."
- Define the term up front: Non-Human Identities are any credential that isn't tied to a login prompt and a human being. That includes service accounts, API tokens, CI/CD secrets, cloud IAM roles, Kubernetes service accounts, database connection strings — anything a machine uses to authenticate to another machine.
- Land the core tension: we spend enormous energy on human identity — MFA, SSO, privileged access management — but the machine credentials sitting in our pipelines, containers, and config files often have more access, rotate less frequently, and receive almost no governance.
- Set the agenda: this presentation walks through the full software supply chain, maps where NHIs live at each stage, and covers the real incidents that have exploited these gaps — ending with concrete recommendations.

---

## Slide 2 — Executive Summary

**Key points to hit (90 seconds):**

- Start with the scale stat: enterprises typically have 10 to 100 times more NHIs than human identities. For a company with 1,000 employees, that could mean 100,000 machine credentials in circulation.
- The $100M+ damage figure is anchored to SolarWinds — that's a single incident. The real industry-wide cost of NHI-related breaches runs into the billions annually when you factor in credential theft, ransomware, data exfiltration, and regulatory penalties.
- 18,000+ organizations were directly impacted by just one supply chain attack. This isn't a theoretical risk — it has materialized at nation-state scale.
- Make the governance gap tangible: human identity governance has mature tooling — Active Directory, Okta, CyberArk. NHI governance? Most organizations have no centralized inventory, no rotation policy, and no anomaly detection.
- Transition: "So let's understand where these credentials actually live — and where they get stolen."

---

## Slide 3 — What Are Non-Human Identities?

**Key points to hit (90 seconds):**

- Walk through the four categories visually: Developer Tokens are the credentials a developer uses in their workflow — GitHub PATs, SSH keys. These are often created ad-hoc, stored in dotfiles, and never rotated.
- CI/CD Credentials are the machine identities that run your build pipelines — Jenkins service accounts, GitHub Actions OIDC tokens, artifact signing certificates. These credentials often have write access to your production artifact repositories.
- Cloud Identities are the IAM roles and service principals your workloads use to call AWS, Azure, or GCP APIs. When one of these is compromised, attackers get direct access to cloud resources — storage buckets, secrets managers, compute instances.
- Runtime Credentials are what your live applications use — Kubernetes service accounts, database connection strings, Vault tokens, API keys for third-party services.
- Emphasize the "Critical Gap" on the right: the reason NHIs are so dangerous isn't just their count — it's that they're typically long-lived (some never expire), over-privileged ("just in case" permissions), and monitored far less rigorously than a human logging in from an unusual location.

---

## Slide 4 — 5-Stage Supply Chain Attack Surface

**Key points to hit (90 seconds):**

- Use this slide to establish the mental model for the rest of the deck: every software artifact passes through five stages before reaching production, and each stage introduces NHI-specific risks.
- Stage 1 (Source Code): This is where secrets first enter the ecosystem — often by accident. A developer commits a `.env` file, and that credential lives in git history forever.
- Stage 2 (Dependency Management): The trust model here is fundamentally broken. When you run `npm install`, you're executing arbitrary code from thousands of maintainers you've never vetted.
- Stage 3 (Build & CI/CD): This is the most dangerous stage. The build system has to authenticate to everything — source repos, package registries, cloud providers, artifact stores. Compromise the build, and you own the entire downstream chain.
- Stage 4 (Artifact Storage): Container images are a particularly rich target because embedded secrets persist across all deployments of that image.
- Stage 5 (Runtime): This is where attackers monetize the access they've gained upstream — lateral movement, data exfiltration, ransomware deployment.
- Key insight: "An attacker only needs to compromise one stage. Defenders have to secure all five."

---

## Slide 5 — Stage 1 Deep-Dive: Source Code Management

**Key points to hit (90 seconds):**

- The NHI types here — PATs, SSH keys, signing certs — are typically created by individual developers, not centrally governed. Many organizations have no inventory of how many exist.
- The hardcoded secrets problem is larger than most teams realize. Studies from GitGuardian and others have found secrets in 10% or more of public repositories. But the real exposure is in private repos — developers often assume "private" means "safe."
- The git history problem is subtle but critical: even if a developer realizes they committed a secret and deletes it in the next commit, the credential remains in the repository's history indefinitely. The only remedy is history rewriting — and rotating the credential immediately.
- The PR injection attack is increasingly common with AI-assisted coding: an external contributor submits what looks like a helpful pull request, but the code contains logic to exfiltrate environment variables during the CI run.
- Practical takeaway: "Secret scanning in CI is table stakes. Pre-commit hooks are better. And any credential that's ever been committed to version control should be treated as compromised."

---

## Slide 6 — Stage 3 Deep-Dive: Build & CI/CD Pipeline

**Key points to hit (90 seconds):**

- CI/CD systems are the crown jewels of your software supply chain. A CI/CD system that can deploy to production typically has more access than any individual developer — and it runs untrusted code by definition.
- Walk through the incidents: SolarWinds is the canonical example — attackers got into the build system and inserted malicious code that was then digitally signed and distributed to 18,000+ customers as a legitimate software update. Codecov is the everyday version — a modified script in your pipeline silently exfiltrating every secret for two months before anyone notices.
- The long-lived credentials problem: many CI/CD systems store cloud provider credentials as long-lived static secrets. A single leaked CI/CD secret can give an attacker persistent access to your cloud environment even after you've rotated human credentials.
- Third-party GitHub Actions deserve specific attention: when you use `uses: some-vendor/action@v1` in a workflow, you're executing arbitrary code with access to your pipeline secrets. Pinning to a commit SHA rather than a version tag is a critical mitigation — version tags can be moved.
- Transition: "If Source Code Management is where credentials are born, CI/CD is where they're most dangerously concentrated."

---

## Slide 7 — Stage 5 Deep-Dive: Deployment & Runtime

**Key points to hit (60–90 seconds):**

- At runtime, the threat model shifts: instead of preventing credential theft during build, we're focused on containing blast radius if credentials are already compromised.
- The SSRF-to-metadata-service attack is one of the most common cloud credential theft techniques. AWS IMDSv1 had no authentication — any server-side request forgery vulnerability in your web application could be used to query `169.254.169.254` and retrieve a short-lived IAM credential with the permissions of the instance role. IMDSv2 requires a session token, which breaks the simplest SSRF chains, but many environments still run IMDSv1.
- Kubernetes service account tokens are mounted into every pod by default unless explicitly disabled. Over-permissioned service accounts — which can list and read cluster secrets — are an extremely common finding in Kubernetes security assessments.
- Container escape vulnerabilities, while harder to exploit, are highly impactful: once an attacker escapes the container, they have access to host credentials, adjacent container filesystems, and the node's Kubernetes service account token.
- Key principle: "Apply least privilege to every service account. If a workload doesn't need to read secrets, it shouldn't have permission to."

---

## Slide 8 — Real-World NHI Breach Timeline

**Key points to hit (90 seconds):**

- Use this slide to show that NHI-related supply chain attacks are not rare edge cases — they are a continuous, accelerating trend.
- 2018 (event-stream): A malicious actor gained the trust of the npm package maintainer, took over the package, and injected code targeting Bitcoin wallets. This established the playbook: compromise maintainer credentials, push a malicious update.
- 2020 (SolarWinds): The watershed moment. Nation-state actors (APT29/Cozy Bear) compromised a build system and distributed signed malware to 18,000 organizations, including US Treasury, State Department, and DHS.
- 2021 (Codecov): The "quieter" SolarWinds — no nation-state attribution, but affecting hundreds of companies whose CI pipelines silently leaked credentials for over two months.
- 2021 (ua-parser-js): A maintainer's npm account was compromised via phishing. The package had 8 million weekly downloads. A malicious update deployed cryptominers and credential stealers before the maintainer could respond.
- 2022–2023 (GitHub OAuth, CircleCI): Third-party OAuth token theft and secrets management platform breach — showing that the tools we use to manage credentials are themselves targets.
- Punchline: "These aren't outliers. This is the baseline threat landscape for every software team shipping code today."

---

## Slide 9 — Case Study: SolarWinds Supply Chain Attack (2020)

**Key points to hit (90 seconds):**

- SolarWinds is worth examining in depth because it represents the full kill chain: from initial access to NHI compromise to weaponized distribution.
- The attackers didn't break into any customer environment directly. They broke into SolarWinds' build system — a single point of trust — and then used SolarWinds' own legitimate update mechanism to deliver malware to 18,000 customers simultaneously.
- The specific NHI failures: the build system service account had more access than it needed; the code signing process didn't verify build environment integrity before signing; there was no provenance attestation — no cryptographic proof of what source code went into which binary.
- The SUNBURST implant was sophisticated: it lay dormant for 12–14 days after installation, mimicked legitimate SolarWinds network traffic, and only activated if the victim was in a domain that matched a target list.
- The lessons map directly to current frameworks: SLSA (Supply-chain Levels for Software Artifacts) was designed largely in response to attacks like this — requiring signed, verifiable build provenance so that even if a build system is compromised, the resulting artifact can be detected as illegitimate.
- Ask the audience: "Do you know what code signed your last release? Can you prove it came from the exact source you think it did?"

---

## Slide 10 — Case Studies: Codecov (2021) & CircleCI (2023)

**Key points to hit (90 seconds):**

- Codecov and CircleCI are important because they represent the "middle tier" of supply chain attacks — not nation-state operations, but still devastating to the downstream organizations.
- **Codecov specifics**: The attackers modified the Bash Uploader script hosted on Codecov's servers. The script was downloaded and executed by CI pipelines at hundreds of companies. Because CI pipelines run with access to cloud credentials, signing keys, and other secrets as environment variables, every execution of that script silently exfiltrated those credentials. The attack ran undetected for over two months.
- The key vulnerability wasn't a zero-day — it was that Codecov's Docker image build credentials were compromised, allowing modification of a hosted script with no integrity verification on the consumer side. A simple SHA-256 checksum in the CI configuration would have caught this.
- **CircleCI specifics**: An employee's endpoint was compromised, their session token stolen (bypassing 2FA), giving attackers access to CircleCI's internal systems and customer secrets storage. This triggered a mass credential rotation event across thousands of organizations.
- The meta-lesson: "Your security posture is only as strong as the security posture of every CI/CD tool, every script you download, and every third-party service you grant secrets access to."
- Best practice from both incidents: use short-lived, scoped credentials wherever possible. A credential that expires in 15 minutes has dramatically lower blast radius than one that's valid for 90 days.

---

## Slide 11 — Threat Actors & Their Tactics (TTPs)

**Key points to hit (90 seconds):**

- Different threat actor categories have very different motivations and therefore different targeting priorities — understanding this helps organizations prioritize their defenses.
- **Nation-State APTs** (top left): These actors — APT29, APT41, Lazarus Group — are patient, sophisticated, and motivated by strategic objectives: espionage, intellectual property theft, pre-positioning for future disruption. They will spend months in an environment without monetizing their access. For NHIs specifically, they target build systems and source code repositories because software supply chain attacks give them leverage over thousands of downstream victims from a single compromise.
- **Cybercriminal Groups** (top right): TeamTNT and similar groups are financially motivated. They run automated tooling that constantly scans public GitHub repositories, Docker Hub images, and Shodan results for exposed credentials. Once found, those credentials are typically used within minutes — cryptomining, spinning up cloud compute at the victim's expense, or selling the credentials on dark web markets.
- **Insider Threats** (bottom left): These are often overlooked but represent a significant risk. A departing employee who generates API keys or creates a backdoor service account before leaving can maintain persistent access for months. The challenge is that their actions look legitimate from an access-control perspective.
- **Opportunistic Attackers** (bottom right): The lowest-skill tier, but responsible for the most volume. Automated scanners find low-hanging fruit — default credentials, publicly exposed secrets in repos, misconfigured S3 buckets. These actors typically monetize quickly.
- Defense implication: "Automated scanning and least-privilege stop the opportunists. Behavioral monitoring and privileged access governance are what you need for nation-state actors."

---

## Slide 12 — Top 5 Attack Vectors in CI/CD Pipelines

**Key points to hit (90 seconds):**

- Think of these five vectors as the attacker's playbook for targeting CI/CD. Understanding the flow of each attack makes the mitigations intuitive.
- **Vector 1 (Secret Injection via PRs)**: This is the most accessible attack — no credentials required to start. Any external contributor can submit a pull request. If your workflow grants that PR access to secrets during CI, the attacker gets those secrets simply by embedding exfiltration code in the PR diff. GitHub's `pull_request_target` trigger is a common misconfiguration that enables this.
- **Vector 2 (Compromised Dependencies)**: The `npm install` problem. Your build executes install scripts from packages you didn't write. A compromised package can enumerate environment variables, send them to a remote server, and continue with normal installation so nothing looks wrong.
- **Vector 3 (Build Log Exposure)**: Developers commonly add debugging output that inadvertently prints credential values. Some CI systems have automatic secret redaction — but only for secrets they know about. Unknown credentials get logged in the clear.
- **Vector 4 (Compromised CI/CD Platform)**: This is the Codecov and CircleCI scenario — the platform itself is compromised, giving attackers access to all stored secrets across all customers.
- **Vector 5 (Malicious Third-Party Actions)**: An action at `uses: company/action@v2` can be updated by the maintainer at any time. Unless you pin to a specific commit SHA, a compromised action update automatically runs in all your pipelines on next execution.
- Common thread across all five: "Minimize what secrets are accessible at each pipeline step. A pipeline step that only reads code should not have write access to your production cloud environment."

---

## Slide 13 — Secret Sprawl & Exposure Patterns

**Key points to hit (90 seconds):**

- Secret sprawl is what happens when there's no systematic approach to credential lifecycle management. Credentials get created where they're needed, stored wherever is convenient, and forgotten when they're no longer actively used.
- **Git History Exposure**: This is the most common pattern — and the one most developers don't fully appreciate. Even a private repository's history is accessible to everyone with repo access. The BFG Repo-Cleaner can remove secrets from history, but the credential must be treated as compromised and rotated regardless.
- **Container Image Secrets**: Multi-stage Docker builds were introduced specifically to address this — you run your build in one image with credentials available, then copy only the output artifact to a clean production image. Without multi-stage builds, secrets used during build remain in intermediate layers that are trivially extractable.
- **Cloud Metadata SSRF**: This is one of the most reliably exploitable patterns in cloud environments. IMDSv2 significantly reduces the risk, but enforcement requires your application framework to not follow open redirects to the metadata endpoint.
- **Configuration File Exposure**: `.env` files that get accidentally committed, `settings.json` files with connection strings checked into repos "just for development" — these regularly find their way to production.
- **Log File Leakage**: Application logs are often shipped to centralized log platforms (Splunk, Datadog, ELK) with relatively broad access. A secret that appears in an error message or debug log is now accessible to anyone with log read permissions.
- **Private Registry Credential Sprawl**: npm, PyPI, and Maven tokens often exist in developers' local `.npmrc` files, in CI/CD environment variables, and in deployment scripts — with no inventory or rotation policy.

---

## Slide 14 — Frameworks, Tools & Standards

**Key points to hit (60–90 seconds):**

- Think of this slide as the "what good looks like" reference. These frameworks and tools are where security teams should invest to build systematic NHI governance.
- **SLSA Framework**: Supply-chain Levels for Software Artifacts is the most directly relevant standard for this topic. It defines four levels of build integrity guarantees, from basic source version control (Level 1) to full hermetic, reproducible builds with verifiable provenance (Level 4). Start at Level 1 and work up — even Level 1 provides meaningful improvement over the baseline.
- **OWASP CI/CD Top 10**: The most actionable starting checklist for teams assessing their pipeline security. The top items — insufficient flow control mechanisms, inadequate identity and access management in pipelines, dependency chain abuse — map directly to the attack vectors we covered.
- **Secret Scanning Tools**: GitLeaks and TruffleHog are both open-source, actively maintained, and can be integrated as pre-commit hooks and CI steps. GitHub's native secret scanning covers 200+ credential types for free on public repos and at the enterprise tier for private repos.
- **Secrets Management**: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault — these provide dynamic secrets, automatic rotation, and audit logging. The key shift is moving from static credentials in environment variables to just-in-time credential issuance.
- **SBOM + Attestation**: Syft for generating Software Bills of Materials, Sigstore/cosign for signing container images and build artifacts. These tools create a verifiable paper trail from source code to deployed artifact.
- Practical guidance: "You don't need to implement everything at once. Start with secret scanning and a secrets manager — those two changes eliminate the most common attack vectors."

---

## Slide 15 — Key Takeaways & 8 Recommendations

**Closing (2 minutes):**

- Bring it back to the scale problem: most organizations don't have a comprehensive inventory of their NHIs. That's the first thing to fix — you can't govern what you haven't catalogued.
- Walk through the eight recommendations in two tiers:

**Immediate Actions (01–04) — can be started this week:**
- 01 *Inventory All NHIs*: Run an audit across your GitHub orgs, CI/CD platforms, cloud accounts, and Kubernetes clusters. Use tools like Trufflehog, GitHub Secret Scanning, and cloud IAM access analyzers.
- 02 *Enforce Least Privilege*: Review the permissions of your top 10 most-used service accounts and CI/CD credentials. Most will be over-privileged. Scope them down.
- 03 *Deploy Secret Scanning*: Install pre-commit hooks using GitLeaks. Enable GitHub native secret scanning if you're on that platform. Add a secret scanning step to every pipeline.
- 04 *Use Short-Lived Credentials*: GitHub Actions now supports OIDC-based cloud authentication — your pipeline can get a 15-minute AWS credential instead of storing a long-lived access key. This is a zero-cost change for most teams.

**Strategic Initiatives (05–08) — quarter-to-quarter roadmap:**
- 05 *Adopt SLSA*: Start with SLSA Level 1 (signed provenance for builds). It's achievable quickly and establishes the foundation for higher levels.
- 06 *Centralize Secrets Management*: Move away from secrets in CI/CD environment variables and config files into a dedicated secrets manager with rotation and audit logging.
- 07 *Monitor NHI Behavior*: Set up alerting for NHI usage anomalies — credentials used from unusual IPs, at unusual times, accessing resources they've never touched before.
- 08 *Generate & Monitor SBOMs*: Every release should produce a signed SBOM. Subscribe to vulnerability feeds for your dependency graph — so when the next event-stream happens, you know within hours whether you're affected.

- **Close strong**: "NHI security is not a niche concern for platform engineers. It's the primary attack surface for software supply chain attacks — the category of breach that gets nation-state attribution and $100M+ damage estimates. The good news is that the baseline mitigations are not exotic. They're table stakes that most organizations simply haven't prioritized yet."

---

*Total estimated deck runtime: 20–25 minutes with Q&A buffer*

---
*Source: SCSforAI.md — NHI Security Threats in Software Supply Chains Epic Brainstorming Document, 2026-04-27*
