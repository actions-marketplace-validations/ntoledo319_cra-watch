# cra-watch

**Does anything you ship have a known-exploited vulnerability right now?**

On **11 September 2026** the EU Cyber Resilience Act's reporting obligations became
enforceable. Under Article 14 of Regulation (EU) 2024/2847, a manufacturer of a
product with digital elements made available on the EU market must report an
**actively exploited** vulnerability to their coordinating national CSIRT and ENISA
**within 24 hours** of becoming aware of it.

Note the wording. Not "critical". Not "CVSS 9.8". Not "there's a PoC on GitHub".
**Actively exploited.** That is a far smaller set than your vulnerability scanner's
output — and it is the only set that starts a 24-hour clock.

**No install?** Paste a lockfile or SBOM into the free browser checker — it runs
entirely client-side, your file contents never leave your machine:
<https://cra.toledotechnologies.com/check/>

Most tools hand you 400 CVEs and let you work out which ones matter. `cra-watch`
answers one question:

> Of everything I actually ship, is any of it on the list of things being exploited
> in the wild today?

```
  2 KEV MATCH(ES) - MANUAL DECISION REQUIRED NOW

  CVE-2021-44228  (GHSA-jfh8-c2jp-5v3q)
    component      org.apache.logging.log4j:log4j-core 2.14.1  [Maven]
    known as       Apache Log4j2 Remote Code Execution Vulnerability
    KEV listed     2021-12-10   ransomware use: Known

  If you confirm exploitation in your product, the clock is:

    Early warning     within 24h    2026-09-15 08:40:10 UTC
    Notification      within 72h    2026-09-17 08:40:10 UTC
    Final report      within 14d    2026-09-28 08:40:10 UTC
```

## Install

No account, no signup, no telemetry. Standard library only — Python 3.9+.

```bash
curl -fsSL https://raw.githubusercontent.com/ntoledo319/cra-watch/main/cra_watch.py -o cra-watch
chmod +x cra-watch
./cra-watch scan
```

Or clone:

```bash
git clone https://github.com/ntoledo319/cra-watch.git
cd cra-watch && python3 cra_watch.py scan /path/to/your/project
```

Homebrew:

```bash
brew tap ntoledo319/cra
brew install cra-watch
```

As a pre-commit hook — runs only when a lockfile changes, so it never blocks a
commit in a repo that has no dependency manifest:

```yaml
repos:
  - repo: https://github.com/ntoledo319/cra-watch
    rev: v1.0.0
    hooks:
      - id: cra-watch
```

Exit codes are CI-shaped: `0` nothing on KEV, `1` at least one KEV match, `2` no
dependency manifests found.

## Use

```bash
cra-watch scan                      # scan the current directory
cra-watch scan /path/to/project     # scan somewhere else
cra-watch scan --sbom sbom.json     # scan a CycloneDX or SPDX SBOM
cra-watch scan --json               # machine-readable, for CI
cra-watch clock --at 2026-09-14T09:00:00Z   # what are my deadlines?
```

**Exit codes** — designed to be a CI gate:

| code | meaning |
|---|---|
| `0` | no KEV matches |
| `1` | at least one KEV match, human decision required |
| `2` | nothing scannable found |

### In CI

```yaml
# .github/workflows/cra-watch.yml
name: cra-watch
on:
  schedule: [{ cron: "0 6 * * *" }]   # the KEV catalogue changes; your answer can too
  push:
jobs:
  kev:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl -fsSL https://raw.githubusercontent.com/ntoledo319/cra-watch/main/cra_watch.py -o cra-watch.py
      - run: python3 cra-watch.py scan --json > cra-watch.json || true
      - run: python3 cra-watch.py scan
```

Run it on a **schedule**, not just on push. The KEV catalogue gains entries
continuously. A repository that was clean yesterday can be a reporting question
today without a single line of your code changing. That is the whole reason this
needs to be a cron job and not a one-off audit.

## What it reads

Walks your tree (skipping `node_modules`, `vendor`, `target`, `.venv`, …) and parses:

| Ecosystem | Files |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` |
| PyPI | `requirements*.txt` (pinned `==`), `poetry.lock`, `Pipfile.lock` |
| Go | `go.sum` |
| crates.io | `Cargo.lock` |
| RubyGems | `Gemfile.lock` |
| Packagist | `composer.lock` |
| NuGet | `packages.lock.json` |
| Maven | `gradle.lockfile` |
| SBOM | CycloneDX JSON, SPDX JSON (`--sbom`) |

## How it decides

```
your lockfiles  ──▶  OSV.dev  ──▶  advisories  ──▶  CVE aliases
                                                         │
              CISA Known Exploited Vulnerabilities  ──────┤
                                                         ▼
                                              the intersection
                                        = your reporting shortlist
```

Two free, authoritative, public sources. [OSV.dev](https://osv.dev) resolves
package+version to advisories. The [CISA KEV
catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is the
closest thing to a public register of what is genuinely being exploited. The
intersection is small enough to act on.

KEV is cached locally for 6 hours (`--refresh` to force).

## The honest caveats

**This is engineering tooling, not legal advice.** It does not tell you whether to
file. It tells you which handful of components deserve the ten minutes of human
thought that produce that decision.

Three things it deliberately does not claim:

1. **A KEV listing is not proof of exploitation in *your* product.** Article 14's
   test is whether the vulnerability is being actively exploited in the product
   you placed on the market. If the vulnerable code path is unreachable in your
   build, the answer may be no. The Commission's July 2026 guidance is explicit
   that reachability matters for third-party components. `cra-watch` cannot judge
   reachability. A person has to.
2. **KEV is not the legal definition of "actively exploited."** It is a US
   government catalogue, it lags, and it is not exhaustive. Your own telemetry,
   an incident report from a customer, or a credible threat-intel feed can start
   the clock before CISA ever lists the CVE.
3. **Clean output is not a compliance certificate.** It means these two public
   sources do not currently intersect for your dependency graph. That is a useful
   fact and a dated, reproducible one. It is not immunity.

What you should do with either result is the same: **write down what you knew, when
you knew it, and why you decided as you did.** That contemporaneous record is what
defends the decision months later — far more than any scanner's output.

## Scope, plainly

`cra-watch` covers **third-party components you declare in a lockfile**. It does not
scan your own source for vulnerabilities, does not do reachability analysis, does
not read binaries or container images, and does not detect vendored or
statically-linked code that never appears in a manifest. Those are real gaps and
you should know about them rather than discover them.

## Related

The free tool finds the shortlist. Deciding and filing under a 24-hour clock is a
process problem — who is accountable, what the early warning says when you still
know almost nothing, what evidence defends a decision *not* to report.

The **CRA 24-Hour Reporting Kit** covers that: decision tree, the three clocks,
fill-in-the-blank early-warning / 72-hour / final-report templates, an evidence
log, and a 30-minute tabletop dry-run. <https://cra.toledotechnologies.com>

## Further reading

[The EU Cyber Resilience Act and the new Product Liability Directive - what an engineer actually
has to do](https://dev.to/nicholas_toledo_5a6f9e576/the-eu-cyber-resilience-act-and-the-new-product-liability-directive-what-an-engineer-actually-has-1l2a) - the two dates, the two different questions they ask, real commands against the
KEV/OSV/endoflife APIs, and the things the law does not say. No account needed to read it.

## Licence

MIT © Toledo Technologies LLC. Use it, fork it, ship it in your pipeline.

Not affiliated with, endorsed by, or connected to ENISA, the European Commission,
or CISA. Data is fetched from their public feeds at runtime.
