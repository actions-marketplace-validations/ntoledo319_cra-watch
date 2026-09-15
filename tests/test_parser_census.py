"""Parser census for cra-watch: a guard against silently parsing FEWER formats.

The existing unit tests prove each lockfile parser works in isolation. They do
not catch the failure mode that matters most in a security scanner: a change
that makes the tool quietly stop recognising one ecosystem while still printing
a plausible report and still exiting 0.

A clean result from a working scanner and a clean result from a broken one are
the same bytes on screen. That is the whole problem.

This file pins the recognised-format census. Lose a format and the failure
message names which one. Gain one and it fails until it is added to EXPECTED
deliberately, because a parser appearing unreviewed is its own kind of bug.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import cra_watch as cw

# Pinned deliberately. cra_watch.PARSERS maps a manifest filename to the name
# of its parser function; PARSER_FUNCS resolves that name to the callable.
EXPECTED_MANIFESTS = {
    "Cargo.lock", "Gemfile.lock", "Pipfile.lock", "composer.lock",
    "go.sum", "gradle.lockfile", "npm-shrinkwrap.json", "package-lock.json",
    "packages.lock.json", "pnpm-lock.yaml", "poetry.lock",
    "requirements-dev.txt", "requirements.txt", "yarn.lock",
}

# Minimum input each parser must still turn into at least one component.
FIXTURES = {
    "package-lock.json": '{"name":"x","lockfileVersion":3,"packages":'
                         '{"node_modules/lodash":{"version":"4.17.21"}}}',
    "requirements.txt": "django==3.2.0\nrequests==2.31.0\n",
    "go.sum": ("github.com/pkg/errors v0.9.1 h1:abc=\n"
               "github.com/pkg/errors v0.9.1/go.mod h1:def=\n"),
    "Cargo.lock": '[[package]]\nname = "serde"\nversion = "1.0.0"\n',
    "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n",
    "composer.lock": '{"packages":[{"name":"monolog/monolog","version":"2.8.0"}]}',
}


class TestManifestCensus(unittest.TestCase):

    def test_no_manifest_format_silently_disappeared(self):
        actual = set(cw.PARSERS)
        missing = EXPECTED_MANIFESTS - actual
        self.assertFalse(
            missing,
            "\n\nThese manifest formats are documented but no longer in PARSERS.\n"
            "The tool would still report cleanly on those projects:\n"
            + "\n".join("  " + m for m in sorted(missing)),
        )

    def test_no_unreviewed_manifest_format_appeared(self):
        extra = set(cw.PARSERS) - EXPECTED_MANIFESTS
        self.assertFalse(
            extra,
            "\n\nNew manifest formats appeared that are not in the census. If "
            "intentional, add them to EXPECTED_MANIFESTS in the same commit:\n"
            + "\n".join("  " + m for m in sorted(extra)),
        )

    def test_every_parser_name_resolves_to_a_callable(self):
        """A dangling parser name means a whole ecosystem stops being scanned."""
        funcs = getattr(cw, "PARSER_FUNCS", None)
        self.assertIsNotNone(funcs, "cra_watch.PARSER_FUNCS is gone")
        dangling = sorted({n for n in cw.PARSERS.values() if n not in funcs})
        self.assertFalse(
            dangling,
            "\n\nParser names in PARSERS with no function in PARSER_FUNCS:\n"
            + "\n".join("  " + d for d in dangling),
        )

    def test_fixtures_still_parse_to_components(self):
        funcs = cw.PARSER_FUNCS
        lost = []
        for filename, body in FIXTURES.items():
            fn = funcs[cw.PARSERS[filename]]
            try:
                got = list(fn(body))
            except Exception as exc:
                lost.append(f"{filename}: raised {exc!r}")
                continue
            if not got:
                lost.append(f"{filename}: parsed to zero components")
        self.assertFalse(
            lost,
            "\n\nA parser stopped producing components from valid input:\n"
            + "\n".join("  " + x for x in lost),
        )


class TestCleanResultIsHonest(unittest.TestCase):
    """An empty answer must be distinguishable from a broken detector."""

    def test_no_manifests_exits_2_not_0(self):
        d = Path(tempfile.mkdtemp())
        (d / "README.md").write_text("nothing here")
        rc = cw.main(["scan", str(d)])
        self.assertEqual(
            rc, 2,
            "A directory with no dependency manifest must exit 2 (nothing to "
            "check), never 0 (clean). Conflating those is how a scanner lies.",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
