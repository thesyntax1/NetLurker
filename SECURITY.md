# Security policy

NetLurker is in development and has not had an independent security audit.
Do not use a risk score as the sole basis for a security decision.

## Reporting a vulnerability

Email [user2102392109@proton.me](mailto:user2102392109@proton.me), or use GitHub
**Report a vulnerability** if private vulnerability reporting is enabled for the repository.
Do not post exploit details, API keys or private network data in public issues or TikTok comments.

Include the affected version/commit, platform, reproduction steps and likely impact.
Redact personal data; send only what is needed to reproduce the issue. There is no fixed
response-time commitment.

Reports should be checked against the latest source or release candidate. Older
development artifacts are not maintained separately. The
[release checklist](docs/RELEASE-CHECKLIST.md) tracks outstanding validation.

## Threat boundaries

- IPs, DNS answers, certificates, server banners, process names and AI responses are untrusted input.
- Remote AI text is advice, not permission to execute commands or terminate processes.
- Keys currently rely on OS file/app isolation; they are not encrypted by this app.
- TLS inspection intentionally accepts presented certificates to inspect them. It does not
  make the API/AI HTTP client trust arbitrary certificates.
- Configured plugins execute local programs. Install only definitions and executables you trust.
- Run probes only against systems you own or are authorized to investigate.

Read [Privacy](PRIVACY.md) and [Data accuracy](docs/DATA-ACCURACY.md) before use.
