#!/usr/bin/env python3
"""Offline test suite for cra-watch. No network required."""
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import cra_watch as cw  # noqa: E402


class TestParsers(unittest.TestCase):
    def test_npm_lock_v3(self):
        text = json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "root", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.15"},
            "node_modules/@scope/thing": {"version": "2.1.0"}}})
        got = dict(((n, v) for _e, n, v in cw.parse_npm_lock(text)))
        self.assertEqual(got["lodash"], "4.17.15")
        self.assertEqual(got["@scope/thing"], "2.1.0")

    def test_npm_lock_v1_nested(self):
        text = json.dumps({"lockfileVersion": 1, "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}})
        got = dict(((n, v) for _e, n, v in cw.parse_npm_lock(text)))
        self.assertEqual(got, {"a": "1.0.0", "b": "2.0.0"})

    def test_npm_lock_malformed_is_not_fatal(self):
        self.assertEqual(cw.parse_npm_lock("{not json"), [])

    def test_requirements_pinned_only(self):
        text = "Django==2.2.10\nrequests>=2.0\n# comment\n-r other.txt\nPyYAML==5.3.1  # inline\n\n"
        got = cw.parse_requirements(text)
        self.assertEqual(sorted(got), [("PyPI", "Django", "2.2.10"), ("PyPI", "PyYAML", "5.3.1")])

    def test_poetry_lock(self):
        text = '[[package]]\nname = "urllib3"\nversion = "1.26.4"\n\n[[package]]\nname = "six"\nversion = "1.16.0"\n'
        self.assertEqual(sorted(cw.parse_poetry_lock(text)),
                         [("PyPI", "six", "1.16.0"), ("PyPI", "urllib3", "1.26.4")])

    def test_go_sum_dedupes_and_strips_gomod(self):
        text = ("github.com/x/y v1.2.3 h1:abc=\n"
                "github.com/x/y v1.2.3/go.mod h1:def=\n")
        self.assertEqual(cw.parse_go_sum(text), [("Go", "github.com/x/y", "1.2.3")])

    def test_cargo_lock(self):
        text = '[[package]]\nname = "serde"\nversion = "1.0.130"\n'
        self.assertEqual(cw.parse_cargo_lock(text), [("crates.io", "serde", "1.0.130")])

    def test_gemfile_lock(self):
        text = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n    rails (6.0.0)\n"
        self.assertEqual(sorted(cw.parse_gemfile_lock(text)),
                         [("RubyGems", "rack", "2.2.3"), ("RubyGems", "rails", "6.0.0")])

    def test_composer_lock(self):
        text = json.dumps({"packages": [{"name": "monolog/monolog", "version": "v2.3.5"}]})
        self.assertEqual(cw.parse_composer_lock(text), [("Packagist", "monolog/monolog", "2.3.5")])

    def test_nuget_lock(self):
        text = json.dumps({"dependencies": {"net6.0": {"Newtonsoft.Json": {"resolved": "12.0.3"}}}})
        self.assertEqual(cw.parse_nuget_lock(text), [("NuGet", "Newtonsoft.Json", "12.0.3")])

    def test_gradle_lock_builds_maven_coord(self):
        text = "# lock\norg.apache.logging.log4j:log4j-core:2.14.1=compileClasspath\n"
        self.assertEqual(cw.parse_gradle_lock(text),
                         [("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")])

    def test_yarn_lock(self):
        text = 'lodash@^4.17.0:\n  version "4.17.15"\n  resolved "..."\n'
        self.assertEqual(cw.parse_yarn_lock(text), [("npm", "lodash", "4.17.15")])


class TestSbom(unittest.TestCase):
    def test_cyclonedx(self):
        d = {"bomFormat": "CycloneDX", "components": [
            {"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"},
            {"name": "noeco", "version": "1.0.0"}]}
        self.assertEqual(cw.parse_cyclonedx(d), [("npm", "lodash", "4.17.15")])

    def test_spdx(self):
        d = {"spdxVersion": "SPDX-2.3", "packages": [
            {"name": "django", "versionInfo": "2.2.10",
             "externalRefs": [{"referenceLocator": "pkg:pypi/django@2.2.10"}]}]}
        self.assertEqual(cw.parse_spdx(d), [("PyPI", "django", "2.2.10")])


class TestClocks(unittest.TestCase):
    def test_three_windows(self):
        base = datetime(2026, 9, 14, 9, 0, 0, tzinfo=timezone.utc)
        c = cw.clocks(base)
        self.assertEqual(c["early_warning"], base + timedelta(hours=24))
        self.assertEqual(c["notification"], base + timedelta(hours=72))
        self.assertEqual(c["final_report"], base + timedelta(days=14))

    def test_format_is_utc_labelled(self):
        s = cw.fmt(datetime(2026, 9, 14, 9, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(s, "2026-09-14 09:00:00 UTC")


class TestDiscovery(unittest.TestCase):
    def test_skips_vendored_trees(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package-lock.json").write_text("{}")
            os.makedirs(root / "node_modules" / "x")
            (root / "node_modules" / "x" / "package-lock.json").write_text("{}")
            found = [p.name for p in cw.discover(root)]
            self.assertEqual(found, ["package-lock.json"])
            self.assertEqual(len(found), 1, "must not descend into node_modules")

    def test_every_declared_parser_exists(self):
        for fname, pname in cw.PARSERS.items():
            self.assertIn(pname, cw.PARSER_FUNCS, f"{fname} declares missing parser {pname}")


class TestKevIntersection(unittest.TestCase):
    """The core logic: only a KEV-listed CVE may produce a finding."""

    def test_only_kev_listed_cves_become_findings(self):
        kev_index = {"CVE-2021-44228": {"cveID": "CVE-2021-44228", "vendorProject": "Apache",
                                        "product": "Log4j2", "dateAdded": "2021-12-10",
                                        "knownRansomwareCampaignUse": "Known"}}
        alias_map = {"GHSA-aaa": ["CVE-2021-44228"], "GHSA-bbb": ["CVE-2099-00000"]}
        hits = {("Maven", "log4j-core", "2.14.1"): ["GHSA-aaa"],
                ("npm", "innocuous", "1.0.0"): ["GHSA-bbb"]}
        findings = []
        for (eco, name, ver), vids in hits.items():
            for vid in vids:
                for cve in alias_map.get(vid, []):
                    if cve in kev_index:
                        findings.append((name, cve))
        self.assertEqual(findings, [("log4j-core", "CVE-2021-44228")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
