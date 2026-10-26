# Security Policy

## Reporting a vulnerability

Please do not publish exploitable security issues, leaked credentials, or personal data in a public issue.
Use GitHub's private vulnerability reporting feature when it is enabled for this repository.

## Secrets

Never commit `config.json`, `.env` files, browser profiles, generated reports, API keys, SMTP credentials, cookies, or session data.
If a credential is accidentally committed, revoke/rotate it immediately and remove it from Git history before publishing.

## Scope and safe use

REACTOR is intended to help report suspected phishing and scam infrastructure to legitimate abuse-reporting channels. It should not be used to attack, disrupt, probe, or gain unauthorized access to third-party systems. Verify targets before submitting reports to reduce false positives.
