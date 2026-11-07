# eml-phish-triage

A small, explainable command-line tool for triaging suspicious email. Point it at a `.eml` file and it reports:

- whether SPF / DKIM / DMARC checks failed,
- sender and Reply-To / Return-Path mismatches,
- lookalike or brand-impersonating sender domains,
- link tricks (display text vs. real destination, raw IP links, punycode, URL shorteners),
- risky attachment types (executables, scripts, macro-enabled Office files),
- urgency or account-threat wording,

and then combines them into a score and a `low` / `medium` / `high` verdict. Every point in the score comes with a reason, so you can see *why* an email was flagged.

The tool is read-only. It never opens attachments, follows links, or makes network requests.

## Install

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Usage

```bash
phish-triage samples/phish_lookalike.eml          # human-readable report
phish-triage samples/phish_lookalike.eml --json   # machine-readable report
python -m phish_triage samples/benign_newsletter.eml
```

Exit codes: `0` for low or medium, `1` for high, `2` if the file can't be read.

## How scoring works

Each rule adds a weight when it fires. The total score maps to a verdict:

| Verdict | Score |
|---------|-------|
| high    | 6 or more |
| medium  | 3 to 5 |
| low     | 0 to 2 |

Thresholds live in `src/phish_triage/scoring.py`. Trusted brand domains live in `src/phish_triage/rules.py` (`TRUSTED_DOMAINS`). Edit both to fit your environment.

## Rules

| Rule | Weight | What it looks for |
|------|--------|-------------------|
| `spf_*`, `dkim_*`, `dmarc_*` | 3 each | Authentication result is `fail`, `softfail`, or `permerror` |
| `no_auth_results` | 1 | No `Authentication-Results` header to check |
| `reply_to_mismatch` | 2 | Reply-To domain differs from From domain |
| `return_path_mismatch` | 1 | Return-Path domain differs from From domain |
| `lookalike_sender` | 4 | Sender domain is 1 to 2 edits away from a trusted brand (e.g. `micr0soft`) |
| `brand_in_sender_domain` | 3 | Sender domain contains a trusted brand name but isn't that domain |
| `display_url_mismatch` | 3 | Link text shows one domain but the href goes to another |
| `ip_address_link` | 3 | Link points to a raw IP address |
| `punycode_link` | 2 | Link host uses punycode (`xn--`) |
| `url_shortener` | 1 | Link uses a known URL shortener |
| `risky_attachment` | 4 | Executable, script, or archive-style extension (`.exe`, `.js`, `.iso`, `.lnk`, ...) |
| `macro_attachment` | 3 | Macro-enabled Office file (`.docm`, `.xlsm`, ...) |
| `urgency_language` | 2 | Account-threat or urgency phrases |

## Project layout

```
src/phish_triage/
  parser.py    reads a .eml file into a ParsedEmail (no network, no attachment execution)
  rules.py     rule checks that produce Findings
  scoring.py   sums weights and maps the total to a verdict
  cli.py       command-line interface and report formatting
samples/       synthetic example emails (reserved domains and TEST-NET IPs only)
tests/         pytest suite
```

## Running the tests

```bash
pytest
```

## Limitations

- Heuristics, not a verdict oracle. Expect false positives (bulk senders with unusual headers) and false negatives (well-crafted phishing from compromised legitimate accounts).
- No sandboxing or live URL reputation lookups. Pair it with your mail gateway and threat intel.
- Brand matching uses the second-level label, so multi-part public suffixes like `example.co.uk` are not handled precisely.
- Links are only read from HTML anchors and bare URLs in the plain-text body.

## Safety

Do not click links or open attachments from suspicious emails. Keep sample emails synthetic. Don't commit real employee or customer email content.

## License

MIT. See [LICENSE](LICENSE).
