import argparse
import hashlib
import json
import os
import stat
import struct

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100000


class Invalid(ValueError):
    pass


class Unsupported(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Invalid(code)


def unpack(fmt, data, offset=0):
    require(
        offset >= 0 and offset + struct.calcsize(fmt) <= len(data), "truncated_field"
    )
    return struct.unpack_from(fmt, data, offset)


def text(data, encoding="utf-8"):
    try:
        return data.decode(encoding)
    except UnicodeError:
        raise Invalid("invalid_text_encoding") from None


def inspect(data):
    if not isinstance(data, bytes):
        raise TypeError("input must be bytes")
    digest = hashlib.sha256(data).hexdigest()
    try:
        require(len(data) <= MAX_BYTES, "input_limit")
        result = analyze(data)
        result.setdefault("status", "PASS")
        result.setdefault("complete", result["status"] == "PASS")
        result.setdefault("findings", [])
    except Unsupported as exc:
        result = {"status": "OPEN", "complete": False, "findings": [str(exc)]}
    except Invalid as exc:
        result = {"status": "FAIL", "complete": False, "findings": [str(exc)]}
    result.update(
        {
            "input_sha256": digest,
            "input_bytes": len(data),
            "claim": "Recorded format checks only; no authenticity, runtime or CVP approval conclusion.",
        }
    )
    return result


def read_local(path):
    fd = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), "regular_file_required")
        require(info.st_size <= MAX_BYTES, "input_limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        require(len(data) <= MAX_BYTES, "input_limit")
        after = os.fstat(fd)
        require(
            (info.st_size, info.st_mtime_ns, info.st_ino)
            == (after.st_size, after.st_mtime_ns, after.st_ino),
            "input_changed_during_read",
        )
        return data
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(
        description="Read an explicitly supplied local evidence file and print a private-safe JSON report."
    )
    parser.add_argument("input")
    args = parser.parse_args()
    try:
        report = inspect(read_local(args.input))
    except (OSError, Invalid):
        report = {
            "status": "FAIL",
            "complete": False,
            "findings": ["input_read_failed"],
        }
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]


import io
import re
import xml.etree.ElementTree as ET

NS = "http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML"


def analyze(data):
    document = text(data)
    require(
        "<!DOCTYPE" not in document.upper() and "<!ENTITY" not in document.upper(),
        "xml_declaration_forbidden",
    )
    depth = nodes = 0
    try:
        for event, elem in ET.iterparse(io.BytesIO(data), events=("start", "end")):
            if event == "start":
                depth += 1
                nodes += 1
                require(depth <= 64 and nodes <= MAX_RECORDS, "xml_resource_limit")
            else:
                depth -= 1
        root = elem
    except ET.ParseError:
        raise Invalid("invalid_xml") from None
    require(root.tag == "{" + NS + "}dfxml", "dfxml_namespace_required")
    version = root.attrib.get("version")
    if version not in ("1.0", "1.1", "1.2"):
        raise Unsupported("unsupported_dfxml_version")
    records = []
    unknown = False
    for element in root.iter():
        if not element.tag.startswith("{" + NS + "}"):
            unknown = True
    for index, obj in enumerate(root.iter("{" + NS + "}fileobject"), 1):
        fields = {}
        for child in obj:
            local = child.tag.rsplit("}", 1)[-1]
            require(
                local not in fields or local in ("hashdigest", "filename"),
                "duplicate_fileobject_field",
            )
            fields.setdefault(local, []).append(child)
        size_elem = fields.get("filesize", [])
        size = None
        if size_elem:
            value = size_elem[0].text or ""
            require(
                len(value) <= 19
                and re.fullmatch(r"[0-9]+", value)
                and int(value) < 2**63,
                "invalid_filesize",
            )
            size = int(value)
        extents = []
        for group in fields.get("byte_runs", []):
            facet = group.attrib.get("facet", "data")
            if facet != "data":
                unknown = True
                continue
            for run in group:
                if run.tag != "{" + NS + "}byte_run":
                    unknown = True
                    continue
                if "len" not in run.attrib:
                    raise Unsupported("extent_length_not_declared")
                numeric = {}
                for key in ("len", "file_offset", "img_offset", "fs_offset"):
                    if key in run.attrib:
                        v = run.attrib[key]
                        require(
                            len(v) <= 19
                            and re.fullmatch(r"[0-9]+", v)
                            and int(v) < 2**63,
                            "invalid_extent_integer",
                        )
                        numeric[key] = int(v)
                if "file_offset" not in numeric:
                    raise Unsupported("file_offset_not_declared")
                end = numeric["file_offset"] + numeric["len"]
                require(
                    end < 2**63 and (size is None or end <= size), "extent_exceeds_file"
                )
                require(len(extents) < MAX_RECORDS, "extent_limit")
                if set(run.attrib) - {
                    "len",
                    "file_offset",
                    "img_offset",
                    "fs_offset",
                } or len(run):
                    unknown = True
                extents.append(numeric)
        ordered = sorted(extents, key=lambda e: e["file_offset"])
        require(
            all(
                ordered[i]["file_offset"] + ordered[i]["len"]
                <= ordered[i + 1]["file_offset"]
                for i in range(len(ordered) - 1)
            ),
            "overlapping_file_extents",
        )
        digests = []
        for entry in fields.get("hashdigest", []):
            algorithm = (entry.attrib.get("type") or "").lower().replace("-", "")
            value = entry.text or ""
            sizes = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
            if algorithm not in sizes:
                unknown = True
                continue
            require(
                len(value) == sizes[algorithm] and re.fullmatch(r"[0-9a-fA-F]+", value),
                "invalid_hash_declaration",
            )
            require(algorithm not in digests, "duplicate_hash_algorithm")
            digests.append(algorithm)
        records.append(
            {
                "fileobject": index,
                "declared_size": size,
                "byte_runs": extents,
                "hash_algorithms": digests,
                "filename_present": bool(fields.get("filename")),
            }
        )
    require(records, "no_fileobjects")
    return {
        "records": records,
        "record_count": len(records),
        "status": "OPEN" if unknown else "PASS",
        "complete": not unknown,
        "findings": ["extension_or_unsupported_facet_or_digest"] if unknown else [],
        "scope": "Selected DFXML 1.x fileobject extents/hash declaration consistency; no XSD conformance, evidence hashing, acquisition or provenance authenticity validation.",
    }
