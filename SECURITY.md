# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in agentdocker-lite, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use one of the following:

1. **GitHub Security Advisory** (preferred): [Report a vulnerability](https://github.com/opensage-agent/agentdocker-lite/security/advisories/new)
2. **Email**: rucnyz@gmail.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment (sandbox escape, privilege escalation, etc.)
- Any suggested fix (optional)

## Response Timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 1 week
- **Fix or mitigation**: best effort, depending on severity

## Scope

The following are in scope:
- Sandbox escape (breaking out of namespace/chroot isolation)
- Privilege escalation (gaining host root from within sandbox)
- seccomp-bpf filter bypass
- Landlock policy bypass
- Resource limit bypass (cgroup escape)
- Information disclosure from host to sandbox

Out of scope:
- Denial of service via resource exhaustion (sandboxes share the host kernel by design)
- Issues requiring host root access to exploit
- Vulnerabilities in upstream dependencies (report those to the respective projects)

## Supported Versions

Security fixes are applied to the latest release only.
