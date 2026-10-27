 # Non-Human Identity (NHI) Security Threats in Software Supply Chains
## Epic Brainstorming Document

**Focus Area:** Security threats and vulnerabilities related to NHI in software supply chains

**Date:** 2026-04-27

---

## Executive Summary

Non-Human Identities (NHIs) represent one of the most critical and under-managed attack surfaces in modern software supply chains. With enterprises typically having 10-100x more NHIs than human identities, and these credentials often possessing elevated privileges, they have become prime targets for sophisticated attackers. This document explores the threat landscape, real-world incidents, and strategic considerations for securing NHIs throughout the software supply chain.

---

## 1. Software Supply Chain Stages & NHI Vulnerabilities

### Stage 1: Source Code Management
**NHI Types:**
- Developer API tokens (GitHub, GitLab, Bitbucket)
- Git SSH keys
- Code signing certificates
- Repository webhooks credentials

**Vulnerabilities:**
- Hardcoded secrets in source code
- Credentials committed to version control history
- Exposed personal access tokens (PATs)
- Compromised developer workstations with stored credentials
- Insufficient branch protection allowing credential injection

**Attack Scenarios:**
- Attacker gains access to repository via leaked token
- Malicious code injection through compromised developer credentials
- Historical credential mining from git history
- Fork and pull request attacks to expose secrets

---

### Stage 2: Dependency Management
**NHI Types:**
- Package registry tokens (npm, PyPI, Maven, NuGet)
- Private registry credentials
- Artifact repository access keys
- Software Bill of Materials (SBOM) signing keys

**Vulnerabilities:**
- Dependency confusion attacks exploiting credential scope
- Compromised package maintainer accounts
- Typosquatting with credential harvesting
- Malicious packages exfiltrating environment variables
- Unverified package signatures

**Attack Scenarios:**
- Attacker publishes malicious package with similar name
- Compromised legitimate package updated with credential-stealing code
- Build process downloads malicious dependency that exfiltrates secrets
- Private package namespace hijacking

**Real-World Examples:**
- **event-stream incident (2018):** Compromised npm package with 2M weekly downloads
- **ua-parser-js attack (2021):** Legitimate package hijacked to steal credentials
- **Codecov breach (2021):** Bash Uploader script modified to exfiltrate credentials

---

### Stage 3: Build & CI/CD Pipeline
**NHI Types:**
- CI/CD service accounts (Jenkins, GitHub Actions, GitLab CI)
- Build agent credentials
- Cloud provider access keys (AWS, Azure, GCP)
- Container registry credentials
- Deployment keys
- Signing certificates for artifacts

**Vulnerabilities:**
- Over-privileged CI/CD service accounts
- Long-lived credentials in pipeline configurations
- Secrets exposed in build logs
- Compromised build agents
- Insufficient pipeline isolation
- Unencrypted secrets in pipeline definitions
- Third-party GitHub Actions with excessive permissions

**Attack Scenarios:**
- Attacker compromises CI/CD system to steal production credentials
- Malicious pull request triggers pipeline to exfiltrate secrets
- Build log scraping for exposed credentials
- Lateral movement from CI/CD to production environments
- Supply chain injection through compromised build process

**Real-World Examples:**
- **SolarWinds (2020):** Build system compromise leading to malicious updates
- **Codecov (2021):** Modified Bash Uploader script in CI/CD
- **Travis CI (2021):** Exposed secrets in build logs
- **CircleCI (2023):** Breach exposing customer secrets and tokens

---

### Stage 4: Artifact Storage & Distribution
**NHI Types:**
- Container registry credentials (Docker Hub, ECR, ACR, GCR)
- Artifact repository tokens
- CDN access keys
- Object storage credentials (S3, Blob Storage)
- Image signing keys

**Vulnerabilities:**
- Public container images with embedded secrets
- Unscanned images with credential-stealing malware
- Weak or missing image signature verification
- Over-permissive registry access policies
- Exposed artifact repository credentials

**Attack Scenarios:**
- Attacker publishes malicious container image
- Legitimate image compromised with backdoor
- Registry credentials leaked allowing image tampering
- Supply chain attack through compromised base images

---

### Stage 5: Deployment & Runtime
**NHI Types:**
- Kubernetes service accounts
- Cloud IAM roles and service principals
- Database connection strings
- API keys for external services
- TLS certificates
- Secrets management system credentials (Vault, AWS Secrets Manager)

**Vulnerabilities:**
- Secrets mounted as environment variables
- Over-privileged service accounts
- Unrotated credentials
- Secrets in container orchestration configs
- Insufficient network segmentation
- Exposed metadata services (AWS IMDS)

**Attack Scenarios:**
- Container escape to access host credentials
- SSRF attacks to steal cloud metadata credentials
- Kubernetes secret extraction
- Lateral movement using over-privileged service accounts

---

## 2. Real-World NHI Breach Cases in Software Supply Chains

### Case Study 1: SolarWinds Supply Chain Attack (2020)
**What Happened:**
- Attackers compromised SolarWinds' build system
- Injected malicious code into Orion software updates
- Affected 18,000+ organizations including US government agencies

**NHI Vulnerabilities Exploited:**
- Compromised build system credentials
- Weak code signing process
- Insufficient build environment isolation
- Over-privileged build service accounts

**Impact:**
- Massive supply chain compromise
- Nation-state level breach
- Estimated $100M+ in damages

**Lessons Learned:**
- Build systems are critical infrastructure requiring maximum security
- Code signing alone is insufficient without build integrity
- Need for build provenance and attestation
- Importance of build environment isolation

---

### Case Study 2: Codecov Bash Uploader Compromise (2021)
**What Happened:**
- Attackers modified Codecov's Bash Uploader script
- Script exfiltrated environment variables from CI/CD pipelines
- Affected hundreds of customers over 2+ months

**NHI Vulnerabilities Exploited:**
- Compromised Docker image creation credentials
- Secrets exposed as environment variables in CI/CD
- Insufficient integrity checking of downloaded scripts
- Long-lived credentials in CI/CD environments

**Impact:**
- Exposure of customer credentials and secrets
- Potential access to production environments
- Supply chain trust violation

**Lessons Learned:**
- Verify integrity of all downloaded scripts
- Minimize secrets in CI/CD environment variables
- Implement secret scanning in pipelines
- Use short-lived credentials where possible

---

### Case Study 3: GitHub OAuth Token Theft (2022)
**What Happened:**
- Attackers stole GitHub OAuth tokens from Heroku and Travis CI
- Used tokens to access private repositories
- Downloaded private npm packages

**NHI Vulnerabilities Exploited:**
- Long-lived OAuth tokens
- Insufficient token scope restrictions
- Lack of token usage monitoring
- Third-party integration risks

**Impact:**
- Unauthorized access to private repositories
- Potential for supply chain attacks
- Exposure of proprietary code

**Lessons Learned:**
- Implement token rotation policies
- Use minimal scope for OAuth tokens
- Monitor token usage for anomalies
- Regular third-party integration audits

---

### Case Study 4: CircleCI Security Incident (2023)
**What Happened:**
- Unauthorized access to CircleCI's systems
- Customer secrets and tokens potentially compromised
- Affected thousands of organizations

**NHI Vulnerabilities Exploited:**
- Compromised employee credentials leading to NHI access
- Centralized secrets storage
- Insufficient access controls on secrets management

**Impact:**
- Mass credential rotation required
- Supply chain trust concerns
- Potential downstream compromises

**Lessons Learned:**
- Secrets management systems are high-value targets
- Need for secrets rotation automation
- Importance of secrets usage monitoring
- Customer-managed encryption keys

---

### Case Study 5: PyPI and npm Package Hijacking (Ongoing)
**What Happened:**
- Multiple incidents of legitimate packages being hijacked
- Malicious code injected to steal credentials
- Examples: event-stream, ua-parser-js, coa, rc

**NHI Vulnerabilities Exploited:**
- Compromised package maintainer accounts
- Weak 2FA enforcement
- Insufficient package update verification
- Credential harvesting from build environments

**Impact:**
- Millions of downloads of compromised packages
- Widespread credential theft
- Supply chain trust erosion

**Lessons Learned:**
- Enforce 2FA for package maintainers
- Implement package signing and verification
- Monitor dependency updates for anomalies
- Use Software Bill of Materials (SBOM)

---

## 3. NHI Threat Actors & Their Tactics (TTPs)

### Threat Actor Profile 1: Nation-State APT Groups
**Motivation:** Espionage, strategic advantage, intellectual property theft

**Tactics:**
- Long-term persistent access through compromised NHIs
- Build system compromise for supply chain attacks
- Sophisticated credential theft techniques
- Living-off-the-land using legitimate NHIs

**Techniques:**
- Compromise developer workstations to steal credentials
- Target CI/CD systems for production access
- Use stolen cloud credentials for data exfiltration
- Maintain persistence through service accounts

**Examples:**
- APT29 (Cozy Bear) - SolarWinds attack
- APT41 - Supply chain attacks on software vendors
- Lazarus Group - Cryptocurrency exchange attacks via supply chain

---

### Threat Actor Profile 2: Cybercriminal Groups
**Motivation:** Financial gain, ransomware, cryptomining

**Tactics:**
- Automated scanning for exposed credentials
- Exploitation of leaked API keys
- Cryptomining using stolen cloud credentials
- Ransomware deployment via compromised CI/CD

**Techniques:**
- GitHub/GitLab credential scraping
- AWS/Azure key enumeration
- Automated exploitation of exposed secrets
- Lateral movement using service accounts

**Examples:**
- TeamTNT - Cloud credential theft and cryptomining
- Rocke Group - Container escape and credential theft
- Various ransomware groups targeting CI/CD systems

---

### Threat Actor Profile 3: Insider Threats
**Motivation:** Revenge, financial gain, negligence

**Tactics:**
- Abuse of legitimate access to NHIs
- Exfiltration using authorized credentials
- Creation of backdoor service accounts
- Credential sharing with external parties

**Techniques:**
- Service account creation for persistent access
- API key generation for data exfiltration
- Credential theft before departure
- Intentional credential exposure

---

### Threat Actor Profile 4: Opportunistic Attackers
**Motivation:** Easy targets, credential collection, botnet building

**Tactics:**
- Mass scanning for exposed secrets
- Automated exploitation of public repositories
- Credential stuffing attacks
- Exploitation of default credentials

**Techniques:**
- GitHub secret scanning
- Docker Hub credential mining
- Public S3 bucket enumeration
- Shodan/Censys scanning for exposed services

---

## 4. NHI Attack Vectors in CI/CD Pipelines

### Attack Vector 1: Secret Injection via Pull Requests
**Description:** Attacker submits malicious PR that exfiltrates secrets during CI/CD execution

**Attack Flow:**
```
1. Attacker forks repository
2. Adds malicious code to exfiltrate environment variables
3. Submits PR triggering CI/CD pipeline
4. Pipeline runs with access to secrets
5. Secrets exfiltrated to attacker-controlled server
```

**Mitigations:**
- Restrict PR pipeline access to secrets
- Use separate pipelines for untrusted code
- Implement secret scanning in pipelines
- Review all external contributions carefully

---

### Attack Vector 2: Compromised Dependencies
**Description:** Malicious or compromised package steals credentials during build

**Attack Flow:**
```
1. Attacker compromises legitimate package or publishes malicious one
2. Build process downloads compromised dependency
3. Package installation script accesses environment variables
4. Credentials exfiltrated during build
5. Attacker gains access to production systems
```

**Mitigations:**
- Dependency pinning and lock files
- Package signature verification
- Isolated build environments
- Minimal secrets in build process
- SBOM generation and monitoring

---

### Attack Vector 3: Build Log Exposure
**Description:** Secrets accidentally logged during build process

**Attack Flow:**
```
1. Developer or tool logs sensitive information
2. Secrets appear in CI/CD build logs
3. Logs accessible to unauthorized users or public
4. Attacker scrapes logs for credentials
5. Stolen credentials used for unauthorized access
```

**Mitigations:**
- Secret redaction in logs
- Restricted log access
- Automated secret scanning of logs
- Developer training on secure logging

---

### Attack Vector 4: Compromised CI/CD Platform
**Description:** Direct compromise of CI/CD system to steal all stored secrets

**Attack Flow:**
```
1. Attacker compromises CI/CD platform (Jenkins, CircleCI, etc.)
2. Access to all stored secrets and credentials
3. Lateral movement to connected systems
4. Production environment compromise
5. Data exfiltration or ransomware deployment
```

**Mitigations:**
- Harden CI/CD infrastructure
- Use external secrets management
- Implement least privilege for CI/CD
- Regular security audits
- Network segmentation

---

### Attack Vector 5: Third-Party GitHub Actions/Plugins
**Description:** Malicious or compromised CI/CD plugins steal credentials

**Attack Flow:**
```
1. Developer uses third-party GitHub Action or Jenkins plugin
2. Action/plugin has excessive permissions
3. Malicious code in action exfiltrates secrets
4. Credentials sent to attacker infrastructure
5. Unauthorized access to repositories or cloud resources
```

**Mitigations:**
- Vet all third-party actions/plugins
- Use minimal permissions for actions
- Pin actions to specific versions
- Monitor action/plugin updates
- Prefer official/verified actions

---

## 5. Secret Sprawl & Credential Exposure Patterns

### Pattern 1: Git History Exposure
**Description:** Secrets committed to version control, even if later removed

**Common Locations:**
- `.env` files
- Configuration files
- Test files
- Documentation
- Infrastructure-as-Code templates

**Detection Methods:**
- Tools: GitLeaks, TruffleHog, git-secrets
- Pre-commit hooks
- Repository scanning
- Historical analysis

**Remediation:**
- Git history rewriting (BFG Repo-Cleaner)
- Credential rotation
- Secret scanning automation
- Developer training

---

### Pattern 2: Container Image Secrets
**Description:** Credentials embedded in container images

**Common Locations:**
- Environment variables in Dockerfile
- Copied configuration files
- Build-time secrets not removed
- Base image secrets

**Detection Methods:**
- Image scanning tools (Trivy, Grype, Clair)
- Layer-by-layer analysis
- Registry scanning
- Admission controllers

**Remediation:**
- Multi-stage builds
- Secret mounting at runtime
- Image rebuilding
- Registry cleanup

---

### Pattern 3: Cloud Metadata Service Exploitation
**Description:** SSRF attacks to steal cloud credentials from metadata services

**Vulnerable Services:**
- AWS EC2 Instance Metadata Service (IMDS)
- Azure Instance Metadata Service
- GCP Metadata Server

**Attack Scenarios:**
- SSRF in web applications
- Container escape
- Compromised application code

**Mitigations:**
- IMDSv2 (session-based)
- Network policies
- Least privilege IAM roles
- Application-level SSRF protection

---

### Pattern 4: Configuration File Exposure
**Description:** Secrets in configuration files accessible to unauthorized users

**Common Locations:**
- `config.yaml`, `settings.json`
- `.env` files in production
- Database connection strings
- API configuration files

**Detection Methods:**
- File system scanning
- Configuration management audits
- Access control reviews

**Remediation:**
- Secrets management systems
- Encrypted configuration
- Access control enforcement
- Configuration externalization

---

### Pattern 5: Log File Leakage
**Description:** Secrets inadvertently logged to files or monitoring systems

**Common Sources:**
- Application logs
- Web server logs
- Database query logs
- Error messages
- Debug output

**Detection Methods:**
- Log analysis tools
- Pattern matching
- Automated secret scanning

**Remediation:**
- Log sanitization
- Secret redaction
- Structured logging
- Developer guidelines


### Frameworks & Standards
- SLSA (Supply-chain Levels for Software Artifacts)
- NIST Cybersecurity Framework
- CIS Controls
- OWASP Top 10 CI/CD Security Risks

### Tools & Technologies
- **Secret Scanning:** GitLeaks, TruffleHog, git-secrets, GitHub Secret Scanning
- **Secrets Management:** HashiCorp Vault, AWS Secrets Manager, Azure Key Vault
- **Container Security:** Trivy, Grype, Clair, Anchore
- **SBOM:** Syft, CycloneDX, SPDX
- **Build Attestation:** in-toto, Sigstore, SLSA

### Further Reading
- "Securing the Software Supply Chain" - CISA
- "SLSA Framework" - OpenSSF
- "The State of Software Supply Chain Security" - Sonatype
- "Non-Human Identity Security Report" - CyberArk
