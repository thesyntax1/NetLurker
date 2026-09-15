# Security policy

NetLurker is pre-release software. No independent security audit or guaranteed response
SLA is claimed. Do not use a heuristic score as the sole basis for a security decision.

## Reporting a vulnerability

Do not post exploitable details, private targets, API keys or raw exports in a public issue.
Use GitHub **Report a vulnerability** under the repository's Security tab if private
vulnerability reporting is enabled. If that option is absent, open a public issue containing
only a request for a private contact channel—no exploit or sensitive attachment.

Useful private report details: affected commit/version, platform, minimal reproduction,
impact, expected behavior and a proposed fix if available. Sanitize environment-specific data.

Before public launch, the maintainer should enable private vulnerability reporting and
complete the release security checklist. Only the latest tested release candidate is a
maintenance target; old development artifacts are not supported releases.

## Threat boundaries

- IPs, DNS answers, certificates, server banners, process names and AI responses are untrusted input.
- Remote AI text is advice, not permission to execute commands or terminate processes.
- Keys currently rely on OS file/app isolation; they are not encrypted by this app.
- TLS inspection intentionally accepts presented certificates to inspect them. It does not
  make the API/AI HTTP client trust arbitrary certificates.
- Configured plugins execute local programs. Install only definitions and executables you trust.
- Run probes only against systems you own or are authorized to investigate.

Read [Privacy](PRIVACY.md) and [Data accuracy](docs/DATA-ACCURACY.md) before use.
