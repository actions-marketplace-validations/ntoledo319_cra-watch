# Security policy

## Reporting a vulnerability

Email **dev@toledotechnologies.com** with `[security]` in the subject.

Include what you found, how to reproduce it, and what you think the impact is.
You will get an acknowledgement within **3 working days**. If you do not, assume
the mail went missing and send it again rather than assuming it was ignored.

Please do not open a public issue for a security problem until it has been
fixed, or until 90 days have passed, whichever comes first.

## Scope

In scope: the scanner itself - parsing of dependency manifests and SBOMs, the
KEV intersection logic, exit-code behaviour, and anything that could cause the
tool to report a **false clean result**. A silent miss is the most serious bug
class here: an empty result and a broken detector look identical in the output.

## What this project does with your data

Nothing. It has **no telemetry, no analytics, no phone-home, and no accounts**.
It reads files you point it at and queries public APIs (OSV.dev and the CISA KEV catalogue). Package names
and versions are sent to those APIs as part of a lookup. Nothing else leaves the
machine, and nothing is sent anywhere controlled by Toledo Technologies LLC.

## Supply chain

- **Zero runtime dependencies.** Standard library only, Python 3.9+. There is no
  dependency tree to compromise.
- Single file. You can read the whole thing in one sitting, and you should.
- MIT licensed.

## Supported versions

The latest release on `main` receives fixes. This project is young and there is
exactly one released version; when that changes this section will say so rather
than implying a support matrix that does not exist.

## A note on what this project is not

It is engineering tooling. It is **not legal advice**, not a certification, and
not a compliance determination. It cannot tell you whether you have a reporting
obligation or whether a product is defective. Those are judgements for you, and
where they matter, for a lawyer.
