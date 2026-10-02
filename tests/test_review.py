import unittest
from dfxmlextentreview import inspect

N = "http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML"
D = (
    '<dfxml xmlns="'
    + N
    + '" version="1.0"><fileobject><filename>/synthetic/private</filename><filesize>4</filesize><hashdigest type="sha256">'
    + "a" * 64
    + '</hashdigest><byte_runs><byte_run file_offset="0" img_offset="12" len="4"/></byte_runs></fileobject></dfxml>'
).encode()


class Tests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(inspect(D)["status"], "PASS")

    def test_private(self):
        self.assertNotIn("private", str(inspect(D)))

    def test_extent(self):
        self.assertEqual(inspect(D.replace(b'len="4"', b'len="5"'))["status"], "FAIL")

    def test_overlap(self):
        self.assertEqual(
            inspect(
                D.replace(
                    b"</byte_runs>", b'<byte_run file_offset="1" len="1"/></byte_runs>'
                )
            )["status"],
            "FAIL",
        )

    def test_digest(self):
        self.assertEqual(inspect(D.replace(b"a" * 64, b"x" * 64))["status"], "FAIL")

    def test_unknown(self):
        self.assertEqual(
            inspect(D.replace(b'version="1.0"', b'version="5.0"'))["status"], "OPEN"
        )

    def test_extensions(self):
        self.assertEqual(
            inspect(
                D.replace(b"</fileobject>", b'<x xmlns="urn:extension"/></fileobject>')
            )["status"],
            "OPEN",
        )

    def test_duplicate(self):
        self.assertEqual(
            inspect(D.replace(b"</filesize>", b"</filesize><filesize>4</filesize>"))[
                "status"
            ],
            "FAIL",
        )

    def test_entity(self):
        self.assertEqual(
            inspect(b'<!DOCTYPE x [<!ENTITY a "x">]>' + D)["status"], "FAIL"
        )

    def test_truncated(self):
        self.assertEqual(inspect(D[:-1])["status"], "FAIL")

    def test_depth(self):
        self.assertEqual(inspect(("<x>" * 65 + "</x>" * 65).encode())["status"], "FAIL")

    def test_fixed_schema_checked_fixture(self):
        from pathlib import Path

        r = inspect(
            (
                Path(__file__).resolve().parents[1] / "examples/schema_checked.xml"
            ).read_bytes()
        )
        self.assertEqual(r["status"], "PASS")

    def test_large_integer_and_zero_extent(self):
        self.assertEqual(
            inspect(D.replace(b"<filesize>4", b"<filesize>" + b"9" * 5000))["status"],
            "FAIL",
        )
        self.assertEqual(inspect(D.replace(b'len="4"', b'len="0"'))["status"], "PASS")
