# Contributing

Contributions that improve phishing/scam reporting coverage, reliability, safety, documentation, and tests are welcome.

## Before opening a pull request

1. Do not include real API keys, credentials, cookies, personal information, browser profiles, or generated case reports.
2. Keep submission actions explicit and reviewable. Do not add CAPTCHA bypasses or automatic acceptance of third-party terms.
3. Test changes against legitimate reporting endpoints without visiting suspected phishing pages directly.
4. Keep provider-specific logic isolated where practical so integrations are easy to review and maintain.

## Local setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
cp config.example.json config.json
./run.sh
```
