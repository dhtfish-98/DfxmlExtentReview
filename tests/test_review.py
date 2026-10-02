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

    def test_selected_scalar_nodes_cannot_hide_children(self):
        for old, new in ((b"</filesize>", b"<filesize>bad</filesize></filesize>"), (b"</hashdigest>", b'<hashdigest type="sha256">bad</hashdigest></hashdigest>')):
            result = inspect(D.replace(old, new))
            self.assertEqual(result["status"], "FAIL")
            self.assertFalse(result["complete"])

    def test_physical_extent_computed_end_limit(self):
        for attribute in (b"img_offset", b"fs_offset"):
            raw = D.replace(b'img_offset="12"', attribute + b'="9223372036854775807"')
            self.assertIn("physical_extent_range_limit", inspect(raw)["findings"])
            raw = D.replace(b'img_offset="12"', attribute + b'="9223372036854775802"')
            self.assertEqual(inspect(raw)["status"], "PASS")

    def test_attributes_outside_selected_profile_open(self):
        for old, new in ((b"<filesize>", b'<filesize xmlns:x="urn:unknown" x:facet="other">'), (b'<hashdigest type="sha256">', b'<hashdigest type="sha256" encoding="other">'), (b"<byte_runs>", b'<byte_runs unexpected="yes">')):
            result = inspect(D.replace(old, new))
            self.assertEqual(result["status"], "OPEN")
            self.assertFalse(result["complete"])

    def test_encoded_entity_declarations_rejected(self):
        document = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE dfxml [<!ENTITY size "4">]><dfxml xmlns="' + N + '" version="1.0"><fileobject><filesize>&size;</filesize></fileobject></dfxml>'
        for encoding in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be", "utf-16"):
            raw = document.replace("UTF-16", "UTF-32" if "32" in encoding else "UTF-16").encode(encoding)
            result = inspect(raw)
            self.assertEqual(result["status"], "FAIL", encoding)
            self.assertFalse(result["complete"])

    def test_utf8_declaration_bom_and_unsupported_encoding(self):
        for prefix in (b'<?xml version="1.0" encoding="UTF-8"?>', b'\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8"?>'):
            self.assertEqual(inspect(prefix + D)["status"], "PASS")
        for encoding in ("UTF-16", "UTF-7", "unknown-codec", "ISO-8859-1"):
            raw = ('<?xml version="1.0" encoding="' + encoding + '"?>').encode() + D
            result = inspect(raw)
            self.assertEqual(result["status"], "OPEN")
            self.assertFalse(result["complete"])
