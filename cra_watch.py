#!/usr/bin/env python3
"""
cra-watch - Does anything you ship have a KNOWN-EXPLOITED vulnerability right now?

The EU Cyber Resilience Act's reporting obligations (Regulation (EU) 2024/2847,
Article 14) became enforceable on 11 September 2026. From that date, manufacturers
of products with digital elements made available on the EU market must report an
ACTIVELY EXPLOITED vulnerability within 24 hours of becoming aware of it.

Note the word. Not "critical". Not "high CVSS". Not "has a public PoC".
ACTIVELY EXPLOITED. That is a much smaller set, and it is the only set that starts
a 24-hour clock.

cra-watch reads your dependency manifests, resolves them against OSV.dev, and
intersects the result with the CISA Known Exploited Vulnerabilities catalogue --
the closest thing to an authoritative public list of what is being exploited in
the wild. What comes out is not another wall of CVEs. It is a reporting posture:
either nothing you ship is on the KEV list, or here is precisely what is, and here
is the clock you are on.

Free, MIT licensed, standard library only, no account, no telemetry, no network
calls other than to OSV.dev and CISA.

  https://github.com/ntoledo319/cra-watch

This tool is engineering tooling, not legal advice. A KEV listing is strong
evidence a vulnerability is exploited somewhere in the world; it is not by itself
proof that it is exploited IN YOUR PRODUCT, which is the actual Article 14 test.
Use it to find the short list worth a human decision, then make that decision and
write down why.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

__version__ = "1.0.0"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
USER_AGENT = f"cra-watch/{__version__} (+https://github.com/ntoledo319/cra-watch)"

CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "cra-watch"

# ---------------------------------------------------------------- terminal bits

def _supports_colour() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    return os.environ.get("TERM", "") not in ("", "dumb")


class C:
    on = _supports_colour()

    @classmethod
    def _w(cls, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if cls.on else s

    @classmethod
    def red(cls, s): return cls._w("31;1", s)
    @classmethod
    def green(cls, s): return cls._w("32;1", s)
    @classmethod
    def yellow(cls, s): return cls._w("33;1", s)
    @classmethod
    def blue(cls, s): return cls._w("34;1", s)
    @classmethod
    def dim(cls, s): return cls._w("2", s)
    @classmethod
    def bold(cls, s): return cls._w("1", s)
    @classmethod
    def invred(cls, s): return cls._w("41;37;1", s)


def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)


# ------------------------------------------------------------------- http/cache

def _fetch(url: str, data: bytes | None = None, timeout: int = 45) -> bytes:
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        **({"Content-Type": "application/json"} if data else {}),
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def load_kev(refresh: bool = False, max_age_h: int = 6) -> dict:
    """CISA KEV catalogue, cached locally so repeat runs are instant and offline-ish."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache = CACHE_DIR / "kev.json"
    if cache.exists() and not refresh:
        age_h = (datetime.now(timezone.utc).timestamp() - cache.stat().st_mtime) / 3600
        if age_h < max_age_h:
            try:
                return json.loads(cache.read_text())
            except Exception:
                pass
    try:
        raw = _fetch(KEV_URL)
        cache.write_bytes(raw)
        return json.loads(raw)
    except Exception as e:
        if cache.exists():
            eprint(C.yellow(f"warning: could not refresh KEV ({e}); using cached copy"))
            return json.loads(cache.read_text())
        raise SystemExit(C.red(f"error: could not fetch the CISA KEV catalogue: {e}"))


# ------------------------------------------------------------------- ecosystems

# manifest filename -> (osv ecosystem, parser name)
PARSERS: dict[str, str] = {
    "package-lock.json": "npm_lock",
    "npm-shrinkwrap.json": "npm_lock",
    "yarn.lock": "yarn_lock",
    "pnpm-lock.yaml": "pnpm_lock",
    "requirements.txt": "requirements",
    "requirements-dev.txt": "requirements",
    "poetry.lock": "poetry_lock",
    "Pipfile.lock": "pipfile_lock",
    "go.sum": "go_sum",
    "Cargo.lock": "cargo_lock",
    "Gemfile.lock": "gemfile_lock",
    "composer.lock": "composer_lock",
    "packages.lock.json": "nuget_lock",
    "gradle.lockfile": "gradle_lock",
}

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv",
    "__pycache__", ".tox", ".mypy_cache", ".next", ".nuxt", "site-packages",
    ".gradle", ".idea", ".terraform", "bower_components",
}


def _norm(name: str) -> str:
    return name.strip()


def parse_npm_lock(text: str):
    out = []
    try:
        d = json.loads(text)
    except Exception:
        return out
    if isinstance(d.get("packages"), dict):          # lockfileVersion 2/3
        for path, meta in d["packages"].items():
            if not path or not isinstance(meta, dict):
                continue
            ver = meta.get("version")
            name = meta.get("name") or path.split("node_modules/")[-1]
            if name and ver:
                out.append(("npm", name, ver))
    if isinstance(d.get("dependencies"), dict):      # lockfileVersion 1
        def walk(deps):
            for name, meta in deps.items():
                if isinstance(meta, dict):
                    if meta.get("version"):
                        out.append(("npm", name, meta["version"]))
                    if isinstance(meta.get("dependencies"), dict):
                        walk(meta["dependencies"])
        walk(d["dependencies"])
    return out


def parse_yarn_lock(text: str):
    out, name = [], None
    for line in text.splitlines():
        s = line.strip()
        if not line.startswith(" ") and s and not s.startswith("#") and s.endswith(":"):
            first = s[:-1].split(",")[0].strip().strip('"')
            name = first[1:].rsplit("@", 1)[0] if first.startswith("@") else first.rsplit("@", 1)[0]
            if first.startswith("@"):
                name = "@" + name
        elif s.startswith("version") and name:
            m = re.search(r'"?([0-9][^"\s]*)"?\s*$', s)
            if m:
                out.append(("npm", name, m.group(1)))
    return out


def parse_pnpm_lock(text: str):
    out = []
    for m in re.finditer(r"^\s{2,}/?((?:@[\w.-]+/)?[\w.-]+)[@/]([0-9][\w.+-]*)[:(]", text, re.M):
        out.append(("npm", m.group(1), m.group(2)))
    return out


def parse_requirements(text: str):
    out = []
    for line in text.splitlines():
        s = line.split("#")[0].strip()
        if not s or s.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([0-9][\w.!+-]*)", s)
        if m:
            out.append(("PyPI", m.group(1), m.group(2)))
    return out


def parse_poetry_lock(text: str):
    out, name = [], None
    for line in text.splitlines():
        s = line.strip()
        if s == "[[package]]":
            name = None
        elif s.startswith("name ="):
            name = s.split("=", 1)[1].strip().strip('"')
        elif s.startswith("version =") and name:
            out.append(("PyPI", name, s.split("=", 1)[1].strip().strip('"')))
            name = None
    return out


def parse_pipfile_lock(text: str):
    out = []
    try:
        d = json.loads(text)
    except Exception:
        return out
    for section in ("default", "develop"):
        for name, meta in (d.get(section) or {}).items():
            v = (meta or {}).get("version", "")
            if v.startswith("=="):
                out.append(("PyPI", name, v[2:]))
    return out


def parse_go_sum(text: str):
    out, seen = [], set()
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 2 and p[1].startswith("v"):
            ver = p[1].replace("/go.mod", "")
            key = (p[0], ver)
            if key not in seen:
                seen.add(key)
                out.append(("Go", p[0], ver.lstrip("v")))
    return out


def parse_cargo_lock(text: str):
    out, name = [], None
    for line in text.splitlines():
        s = line.strip()
        if s == "[[package]]":
            name = None
        elif s.startswith("name ="):
            name = s.split("=", 1)[1].strip().strip('"')
        elif s.startswith("version =") and name:
            out.append(("crates.io", name, s.split("=", 1)[1].strip().strip('"')))
            name = None
    return out


def parse_gemfile_lock(text: str):
    out, inspecs = [], False
    for line in text.splitlines():
        if re.match(r"^\s{0,4}(GEM|PATH|GIT)\s*$", line):
            inspecs = False
        if line.strip() == "specs:":
            inspecs = True
            continue
        if inspecs:
            m = re.match(r"^\s{4}([A-Za-z0-9._-]+) \(([0-9][\w.]*)\)", line)
            if m:
                out.append(("RubyGems", m.group(1), m.group(2)))
    return out


def parse_composer_lock(text: str):
    out = []
    try:
        d = json.loads(text)
    except Exception:
        return out
    for section in ("packages", "packages-dev"):
        for p in d.get(section) or []:
            if p.get("name") and p.get("version"):
                out.append(("Packagist", p["name"], p["version"].lstrip("v")))
    return out


def parse_nuget_lock(text: str):
    out = []
    try:
        d = json.loads(text)
    except Exception:
        return out
    for _fw, deps in (d.get("dependencies") or {}).items():
        for name, meta in (deps or {}).items():
            v = (meta or {}).get("resolved")
            if v:
                out.append(("NuGet", name, v))
    return out


def parse_gradle_lock(text: str):
    out = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#") or not s or "=" not in s:
            continue
        coord = s.split("=", 1)[0]
        parts = coord.split(":")
        if len(parts) == 3:
            out.append(("Maven", f"{parts[0]}:{parts[1]}", parts[2]))
    return out


def parse_cyclonedx(d: dict):
    eco_map = {"npm": "npm", "pypi": "PyPI", "cargo": "crates.io", "gem": "RubyGems",
               "golang": "Go", "maven": "Maven", "composer": "Packagist", "nuget": "NuGet"}
    out = []
    for c in d.get("components") or []:
        name, ver, purl = c.get("name"), c.get("version"), c.get("purl") or ""
        if not name or not ver:
            continue
        eco = None
        m = re.match(r"pkg:([a-z]+)/", purl)
        if m:
            eco = eco_map.get(m.group(1))
        if eco == "Maven" and "/" in purl:
            grp = purl.split("pkg:maven/", 1)[-1].split("@")[0]
            if "/" in grp:
                name = grp.replace("/", ":", 1)
        if eco:
            out.append((eco, name, ver))
    return out


def parse_spdx(d: dict):
    eco_map = {"npm": "npm", "pypi": "PyPI", "cargo": "crates.io", "gem": "RubyGems",
               "golang": "Go", "maven": "Maven", "composer": "Packagist", "nuget": "NuGet"}
    out = []
    for p in d.get("packages") or []:
        name, ver = p.get("name"), p.get("versionInfo")
        if not name or not ver:
            continue
        eco = None
        for ref in p.get("externalRefs") or []:
            loc = ref.get("referenceLocator") or ""
            m = re.match(r"pkg:([a-z]+)/", loc)
            if m:
                eco = eco_map.get(m.group(1))
                break
        if eco:
            out.append((eco, name, ver))
    return out


PARSER_FUNCS = {
    "npm_lock": parse_npm_lock, "yarn_lock": parse_yarn_lock, "pnpm_lock": parse_pnpm_lock,
    "requirements": parse_requirements, "poetry_lock": parse_poetry_lock,
    "pipfile_lock": parse_pipfile_lock, "go_sum": parse_go_sum, "cargo_lock": parse_cargo_lock,
    "gemfile_lock": parse_gemfile_lock, "composer_lock": parse_composer_lock,
    "nuget_lock": parse_nuget_lock, "gradle_lock": parse_gradle_lock,
}


def discover(root: Path, max_depth: int = 6):
    """Walk for known manifests, skipping vendored trees."""
    found = []
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        rel_depth = len(Path(dirpath).relative_to(root).parts)
        if rel_depth >= max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn in PARSERS:
                found.append(Path(dirpath) / fn)
    return sorted(found)


def load_sbom(path: Path):
    d = json.loads(path.read_text())
    if d.get("bomFormat") == "CycloneDX" or "components" in d:
        return parse_cyclonedx(d), "CycloneDX"
    if "spdxVersion" in d or "packages" in d:
        return parse_spdx(d), "SPDX"
    raise SystemExit(C.red(f"error: {path} is not a recognisable CycloneDX or SPDX document"))


# ------------------------------------------------------------------------- OSV

def osv_batch(components, quiet=False):
    """Query OSV.dev in batches. Returns {(eco,name,ver): [vuln_id,...]}."""
    queries, keys = [], []
    for eco, name, ver in components:
        queries.append({"package": {"name": name, "ecosystem": eco}, "version": ver})
        keys.append((eco, name, ver))

    results = {}
    B = 500
    total_batches = (len(queries) + B - 1) // B
    for bi in range(total_batches):
        chunk = queries[bi * B:(bi + 1) * B]
        chunk_keys = keys[bi * B:(bi + 1) * B]
        if not quiet and total_batches > 1:
            eprint(C.dim(f"  querying OSV.dev, batch {bi+1}/{total_batches} ..."))
        try:
            raw = _fetch(OSV_BATCH_URL, data=json.dumps({"queries": chunk}).encode(), timeout=90)
            data = json.loads(raw)
        except Exception as e:
            eprint(C.yellow(f"warning: OSV batch {bi+1} failed ({e}); those components are unchecked"))
            continue
        for key, res in zip(chunk_keys, data.get("results", [])):
            ids = [v.get("id") for v in (res.get("vulns") or []) if v.get("id")]
            if ids:
                results[key] = ids
    return results


def osv_aliases(vuln_ids, quiet=False):
    """Resolve OSV ids -> the set of CVE ids they alias. Cached on disk."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / "osv_aliases.json"
    cache = {}
    if cache_file.exists():
        try:
            cache = json.loads(cache_file.read_text())
        except Exception:
            cache = {}

    todo = [v for v in vuln_ids if v not in cache]
    for i, vid in enumerate(todo, 1):
        if not quiet and len(todo) > 8 and i % 25 == 0:
            eprint(C.dim(f"  resolving advisory {i}/{len(todo)} ..."))
        try:
            d = json.loads(_fetch(OSV_VULN_URL + vid, timeout=30))
            al = [a for a in (d.get("aliases") or []) if a.startswith("CVE-")]
            if vid.startswith("CVE-"):
                al.append(vid)
            cache[vid] = sorted(set(al))
        except Exception:
            cache[vid] = [vid] if vid.startswith("CVE-") else []
    try:
        cache_file.write_text(json.dumps(cache))
    except Exception:
        pass
    return {v: cache.get(v, []) for v in vuln_ids}


# ---------------------------------------------------------------------- report

def clocks(now: datetime) -> dict:
    return {
        "early_warning": now + timedelta(hours=24),
        "notification": now + timedelta(hours=72),
        "final_report": now + timedelta(days=14),
    }


def fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def run_scan(args) -> int:
    root = Path(args.path).resolve()
    quiet = args.json

    components, sources = [], []
    if args.sbom:
        comps, kind = load_sbom(Path(args.sbom))
        components.extend(comps)
        sources.append(f"{args.sbom} ({kind}, {len(comps)} components)")
    else:
        if not root.exists():
            raise SystemExit(C.red(f"error: path not found: {root}"))
        manifests = discover(root, max_depth=args.depth)
        if not manifests:
            if not quiet:
                print()
                print(C.yellow("No dependency manifests found under ") + str(root))
                print()
                print("cra-watch looks for: " + ", ".join(sorted(PARSERS)))
                print("Or point it at an SBOM:  " + C.bold("cra-watch scan --sbom sbom.json"))
                print()
            return 2
        for m in manifests:
            try:
                comps = PARSER_FUNCS[PARSERS[m.name]](m.read_text(errors="replace"))
            except Exception as e:
                eprint(C.yellow(f"warning: could not parse {m}: {e}"))
                continue
            if comps:
                components.extend(comps)
                try:
                    rel = m.relative_to(root)
                except ValueError:
                    rel = m
                sources.append(f"{rel} ({len(comps)})")

    # dedupe
    components = sorted(set(components))
    if not components:
        if not quiet:
            print(C.yellow("\nFound manifests, but could not resolve any pinned component versions.\n"))
        return 2

    if not quiet:
        print()
        print(C.bold("cra-watch ") + C.dim(f"v{__version__}"))
        print(C.dim("EU Cyber Resilience Act, Article 14 - actively-exploited screen"))
        print()
        print(f"  Scope    {root}")
        for s in sources[:12]:
            print(C.dim(f"           {s}"))
        if len(sources) > 12:
            print(C.dim(f"           ... and {len(sources)-12} more"))
        print(f"  Unique   {len(components)} components")
        print()
        eprint(C.dim("  querying OSV.dev ..."))

    hits = osv_batch(components, quiet=quiet)

    all_ids = sorted({v for ids in hits.values() for v in ids})
    alias_map = osv_aliases(all_ids, quiet=quiet) if all_ids else {}

    kev = load_kev(refresh=args.refresh)
    kev_index = {e["cveID"]: e for e in kev.get("vulnerabilities", [])}

    findings = []
    for (eco, name, ver), vuln_ids in sorted(hits.items()):
        for vid in vuln_ids:
            for cve in alias_map.get(vid, []):
                if cve in kev_index:
                    k = kev_index[cve]
                    findings.append({
                        "ecosystem": eco, "package": name, "version": ver,
                        "cve": cve, "osv_id": vid,
                        "vendor": k.get("vendorProject"), "product": k.get("product"),
                        "name": k.get("vulnerabilityName"),
                        "date_added_to_kev": k.get("dateAdded"),
                        "ransomware": k.get("knownRansomwareCampaignUse"),
                        "required_action": k.get("requiredAction"),
                        "due_date": k.get("dueDate"),
                    })

    # unique by (package, version, cve)
    seen, uniq = set(), []
    for f in findings:
        key = (f["package"], f["version"], f["cve"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    findings = uniq

    now = datetime.now(timezone.utc)
    cl = clocks(now)

    if args.json:
        print(json.dumps({
            "tool": "cra-watch", "version": __version__,
            "scanned_at": now.isoformat(),
            "scope": str(root),
            "sources": sources,
            "components_scanned": len(components),
            "components_with_any_advisory": len(hits),
            "kev_catalog_version": kev.get("catalogVersion"),
            "kev_entries": kev.get("count"),
            "kev_matches": len(findings),
            "findings": findings,
            "clocks_if_confirmed_now": {k: v.isoformat() for k, v in cl.items()},
            "disclaimer": ("A KEV listing evidences exploitation in the wild, not exploitation "
                           "in your product. Article 14 requires the latter. Human decision required."),
        }, indent=2))
        return 1 if findings else 0

    vulnerable_components = len(hits)
    print(f"  Advisories  {vulnerable_components} component(s) carry at least one known advisory")
    print(f"  KEV feed    {kev.get('count')} entries, catalogue {kev.get('catalogVersion')}")
    print()
    print(C.dim("  " + "-" * 68))
    print()

    if not findings:
        print("  " + C.green("NO KEV MATCHES."))
        print()
        print("  Nothing in your dependency graph appears on the CISA Known Exploited")
        print("  Vulnerabilities catalogue. On this evidence there is no Article 14")
        print("  24-hour reporting trigger from a listed component today.")
        print()
        if vulnerable_components:
            print(C.dim(f"  You do still have advisories on {vulnerable_components} component(s)."))
            print(C.dim("  Those are ordinary patching work, not a reporting clock. Article 14"))
            print(C.dim("  is about ACTIVE EXPLOITATION, not severity."))
            print()
        print(C.dim("  Re-run this in CI. The KEV catalogue changes; your answer can change"))
        print(C.dim("  overnight without a single line of your code changing."))
        print()
        return 0

    print("  " + C.invred(f" {len(findings)} KEV MATCH(ES) - MANUAL DECISION REQUIRED NOW "))
    print()
    for f in findings:
        ransom = f.get("ransomware") or "Unknown"
        print("  " + C.red(f["cve"]) + C.dim(f"  ({f['osv_id']})"))
        print(f"    component      {C.bold(f['package'])} {f['version']}  [{f['ecosystem']}]")
        if f.get("name"):
            print(f"    known as       {f['name']}")
        print(f"    KEV listed     {f['date_added_to_kev']}   ransomware use: {ransom}")
        if f.get("required_action"):
            action = f["required_action"]
            print(f"    CISA action    {action[:100]}{'...' if len(action) > 100 else ''}")
        print()

    print(C.dim("  " + "-" * 68))
    print()
    print("  " + C.bold("What this does and does not mean"))
    print()
    print("  It DOES mean: a vulnerability present in your dependency graph is being")
    print("  exploited in the wild somewhere. That is the strongest public signal")
    print("  available that you may be inside Article 14's perimeter.")
    print()
    print("  It does NOT mean you must file. Article 14 asks whether the vulnerability")
    print("  is actively exploited " + C.bold("in your product") + ". If the vulnerable code path is")
    print("  unreachable in your build, it may not be. That is a human judgement, and")
    print("  the judgement itself is the thing you must be able to evidence later.")
    print()
    print("  " + C.bold("If you confirm exploitation in your product, the clock is:"))
    print()
    print(f"    Early warning     within 24h    {C.yellow(fmt(cl['early_warning']))}")
    print(f"    Notification      within 72h    {C.yellow(fmt(cl['notification']))}")
    print(f"    Final report      within 14d    {C.yellow(fmt(cl['final_report']))}")
    print()
    print(C.dim("    (measured from now; the real clock runs from when you became aware."))
    print(C.dim("     For a severe incident the final report is due one month after the"))
    print(C.dim("     incident notification instead.)"))
    print()
    print("  Reports go to your coordinating national CSIRT and ENISA.")
    print()
    print(C.dim("  Write down, today: what you knew, when you knew it, and why you decided"))
    print(C.dim("  to file or not to file. That record is what defends the decision."))
    print()
    return 1


def cmd_clock(args) -> int:
    if args.at:
        try:
            base = datetime.fromisoformat(args.at.replace("Z", "+00:00"))
            if base.tzinfo is None:
                base = base.replace(tzinfo=timezone.utc)
        except ValueError:
            raise SystemExit(C.red("error: --at must be ISO-8601, e.g. 2026-09-14T08:00:00Z"))
    else:
        base = datetime.now(timezone.utc)
    cl = clocks(base)
    now = datetime.now(timezone.utc)
    print()
    print(C.bold("  Article 14 reporting clock"))
    print(C.dim(f"  awareness established   {fmt(base)}"))
    print()
    for label, key, window in (("Early warning", "early_warning", "24 hours"),
                               ("Notification", "notification", "72 hours"),
                               ("Final report", "final_report", "14 days")):
        due = cl[key]
        left = due - now
        if left.total_seconds() < 0:
            state = C.red(f"OVERDUE by {-left.days}d {int(-left.total_seconds() % 86400 // 3600)}h")
        else:
            state = C.green(f"{left.days}d {int(left.total_seconds() % 86400 // 3600)}h remaining")
        print(f"  {label:<16} {window:<9} {fmt(due)}   {state}")
    print()
    print(C.dim("  Severe incident: final report is due one month after the incident"))
    print(C.dim("  notification rather than 14 days. Check which track you are on."))
    print()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="cra-watch",
        description="Screen your dependencies against the CISA KEV catalogue for EU CRA Article 14 exposure.",
        epilog="Engineering tooling, not legal advice. https://github.com/ntoledo319/cra-watch",
    )
    p.add_argument("--version", action="version", version=f"cra-watch {__version__}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan a project or SBOM for known-exploited components")
    s.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    s.add_argument("--sbom", help="scan a CycloneDX or SPDX JSON SBOM instead of walking the tree")
    s.add_argument("--json", action="store_true", help="machine-readable output (for CI)")
    s.add_argument("--refresh", action="store_true", help="force re-download of the KEV catalogue")
    s.add_argument("--depth", type=int, default=6, help="max directory depth to walk (default 6)")
    s.set_defaults(func=run_scan)

    c = sub.add_parser("clock", help="compute the 24h/72h/14d deadlines from an awareness timestamp")
    c.add_argument("--at", help="ISO-8601 time you became aware (default: now)")
    c.set_defaults(func=cmd_clock)

    args = p.parse_args(argv)
    if not args.cmd:
        args = p.parse_args(["scan"] + (argv or []))
    try:
        return args.func(args)
    except KeyboardInterrupt:
        eprint("\ninterrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
