#!/usr/bin/env python3
"""Validate local PAO artifacts against pinned complete schemas, without installs/network."""

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path, PurePosixPath
import socket
import stat
import sys
import urllib.request
import uuid
import zipfile

sys.dont_write_bytecode = True
MAX_JSON_BYTES = 16 << 20
PIN_VERSION = "pao.dev/schema-validation-pins/v1"
CORPUS_VERSION = "pao.dev/synthetic-schema-corpus/v1"
PACKAGES = {
    "jsonschema": "4.17.3", "attrs": "23.2.0", "pyrsistent": "0.20.0",
    "rfc3339-validator": "0.1.4", "rfc3986-validator": "0.1.1", "six": "1.17.0",
    "rfc3987-syntax": "1.1.0", "lark": "1.2.2",
}
EXTERNAL_SCHEMAS = {
    "sarif-2.1.0": "sarif/sarif-2.1.0.schema.json",
    "cyclonedx-1.5": "cyclonedx/bom-1.5.schema.json",
    "spdx-2.3": "spdx/spdx-2.3.schema.json",
}
EXACT_VERSIONS = {
    "sarif-2.1.0": ("version", "2.1.0"),
    "cyclonedx-1.5": ("specVersion", "1.5"),
    "spdx-2.3": ("spdxVersion", "SPDX-2.3"),
}
PAO_PROVENANCE_PROFILE = "release-provenance-v1"


def reject_network(*_args, **_kwargs):
    raise RuntimeError("NETWORK_FORBIDDEN")


def deny_network():
    # Defense in depth beside the RefResolver allowlist. No reference handler
    # can fetch unknown http/https/file resources during validation.
    socket.socket.connect = reject_network
    socket.socket.connect_ex = reject_network
    socket.socket.sendto = reject_network
    socket.create_connection = reject_network
    urllib.request.urlopen = reject_network


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("NONFINITE_JSON_NUMBER")


def read_json(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("JSON_SIZE_LIMIT")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def inside(base, relative):
    name = PurePosixPath(relative)
    if name.is_absolute() or ".." in name.parts or "\\" in relative or ":" in relative:
        raise ValueError("UNSAFE_RELATIVE_PATH")
    path = base.joinpath(*name.parts)
    if not path.resolve().is_relative_to(base.resolve()) or path.is_symlink():
        raise ValueError("PATH_OUTSIDE_BOUNDARY")
    return path


def verify_pins(vendor):
    pins = read_json(vendor / "pins.json")
    if pins.get("version") != PIN_VERSION or not isinstance(pins.get("entries"), list):
        raise ValueError("INVALID_PIN_MANIFEST")
    seen = set()
    packages = {}
    for entry in pins["entries"]:
        relative = entry["path"]
        if relative in seen:
            raise ValueError("DUPLICATE_PIN")
        seen.add(relative)
        path = inside(vendor, relative)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError("PIN_SHA256_MISMATCH")
        if entry["kind"] == "wheel":
            if entry["package"] in packages:
                raise ValueError("DUPLICATE_WHEEL_PACKAGE")
            packages[entry["package"]] = entry["version"]
            if entry["pypi_sha256"] != entry["sha256"]:
                raise ValueError("PYPI_SHA256_MISMATCH")
    if packages != PACKAGES:
        raise ValueError("UNEXPECTED_VALIDATOR_DEPENDENCIES")
    required_schemas = set(EXTERNAL_SCHEMAS.values()) | {
        "cyclonedx/spdx.schema.json", "cyclonedx/jsf-0.82.schema.json",
    }
    if not required_schemas.issubset(seen):
        raise ValueError("MISSING_UPSTREAM_SCHEMA_PIN")
    return pins


def unpack_wheels(vendor, pins, scratch):
    if not scratch.is_absolute() or scratch.is_symlink():
        raise ValueError("EXPLICIT_ABSOLUTE_SCRATCH_REQUIRED")
    scratch.mkdir(parents=True, exist_ok=True)
    modules = scratch / ("validator-" + uuid.uuid4().hex)
    modules.mkdir(mode=0o700)
    for entry in pins["entries"]:
        if entry["kind"] != "wheel":
            continue
        with zipfile.ZipFile(inside(vendor, entry["path"])) as archive:
            if sum(info.file_size for info in archive.infolist()) > 20 << 20:
                raise ValueError("WHEEL_SIZE_LIMIT")
            for info in archive.infolist():
                if stat.S_ISLNK(info.external_attr >> 16) or info.filename.lower().endswith((".dll", ".so", ".pyd", ".exe")):
                    raise ValueError("NONPURE_WHEEL_MEMBER")
                destination = inside(modules, info.filename)
                if info.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    if destination.exists():
                        raise ValueError("OVERLAPPING_WHEEL_MEMBER")
                    destination.write_bytes(archive.read(info))
    sys.path.insert(0, str(modules))
    for package, version in PACKAGES.items():
        if importlib.metadata.version(package) != version:
            raise ValueError("LOADED_VALIDATOR_VERSION_MISMATCH")
    return modules


def schema_formats(value):
    if isinstance(value, dict):
        if isinstance(value.get("format"), str):
            yield value["format"]
        for child in value.values():
            yield from schema_formats(child)
    elif isinstance(value, list):
        for child in value:
            yield from schema_formats(child)


class Harness:
    def __init__(self, repo, scratch):
        if sys.version_info < (3, 9):
            raise ValueError("PYTHON_3_9_OR_NEWER_REQUIRED")
        deny_network()
        vendor = repo / "schemas" / "vendor"
        pins = verify_pins(vendor)
        self.modules = unpack_wheels(vendor, pins, scratch)
        import jsonschema
        import rfc3987_syntax
        self.jsonschema = jsonschema
        checker = jsonschema.FormatChecker()

        @checker.checks("iri-reference")
        def check_iri_reference(value):
            return not isinstance(value, str) or rfc3987_syntax.is_valid_syntax_iri_reference(value)

        self.schemas = {}
        self.store = {}
        self.paths = {}
        for path in sorted((repo / "schemas").glob("*.json")):
            self.add_schema(path.stem, path)
        for name, relative in EXTERNAL_SCHEMAS.items():
            self.add_schema(name, vendor / relative)
        for relative in ("cyclonedx/spdx.schema.json", "cyclonedx/jsf-0.82.schema.json"):
            self.add_schema("upstream-" + Path(relative).stem, vendor / relative)
        self.validators = {}
        for name, schema in self.schemas.items():
            missing = set(schema_formats(schema)) - set(checker.checkers)
            if missing:
                raise ValueError("UNSUPPORTED_SCHEMA_FORMAT")
            validator_type = jsonschema.validators.validator_for(schema, default=None)
            if validator_type is None:
                raise ValueError("UNSUPPORTED_SCHEMA_DRAFT")
            validator_type.check_schema(schema)
            resolver = jsonschema.RefResolver.from_schema(
                schema, store=self.store,
                handlers={"http": reject_network, "https": reject_network, "file": reject_network},
            )
            self.validators[name] = validator_type(schema, resolver=resolver, format_checker=checker)

    def add_schema(self, name, path):
        schema = read_json(path)
        if not isinstance(schema, dict) or "$schema" not in schema:
            raise ValueError("SCHEMA_DECLARATION_REQUIRED")
        self.schemas[name] = schema
        self.paths[name] = path
        self.store[path.resolve().as_uri()] = schema
        if "$id" in schema:
            self.store[schema["$id"]] = schema

    def errors(self, name, document):
        validator = self.validators[name]
        # Exact export version is an independent PAO contract requirement.
        # Some upstream schemas (CycloneDX 1.5/SPDX 2.3) allow a broad string.
        errors = []
        if name in EXACT_VERSIONS:
            key, value = EXACT_VERSIONS[name]
            if not isinstance(document, dict) or document.get(key) != value:
                errors.append({"pointer": "/" + key, "keyword": "exact-format-version"})
        for error in validator.iter_errors(document):
            pointer = "/" + "/".join(str(part).replace("~", "~0").replace("/", "~1") for part in error.absolute_path)
            errors.append({"pointer": pointer, "keyword": str(error.validator)})
        return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--schema")
    parser.add_argument("--document", type=Path)
    args = parser.parse_args()
    if (args.corpus is None) == (args.document is None) or (args.document is not None and args.schema is None):
        parser.error("select either --corpus, or --schema with --document")
    harness = Harness(args.repo.resolve(), args.scratch)
    if args.corpus is not None:
        corpus = read_json(args.corpus / "corpus.json")
        if corpus.get("version") != CORPUS_VERSION or not isinstance(corpus.get("entries"), list) or not corpus["entries"]:
            raise ValueError("INVALID_CORPUS")
        cases = [(entry["name"], entry["schema"], inside(args.corpus, entry["path"])) for entry in corpus["entries"]]
    else:
        cases = [("requested-document", args.schema, args.document)]
    results = []
    for name, schema, path in cases:
        document = read_json(path)
        errors = harness.errors(schema, document)
        results.append({"case": name, "schema": schema, "status": "PASS" if not errors else "FAIL", "errors": errors})
    passed = all(result["status"] == "PASS" for result in results)
    summary = {
        "status": "PASS" if passed else "FAIL", "network_allowed": False,
        "validator": "jsonschema==4.17.3", "full_json_schema_validation": passed,
        "validation_scope": "only the listed documents against complete selected schemas, pinned external schemas and declared exact versions",
        "signature_verified": False, "release_approved": False, "results": results,
    }
    profile_results = [result for result in results if result["schema"] == PAO_PROVENANCE_PROFILE]
    if profile_results:
        summary.update({
            "full_pao_release_provenance_profile_validation": all(result["status"] == "PASS" for result in profile_results),
            "provenance_profile": "https://pao.dev/schemas/release-provenance/v1",
            "upstream_official_provenance_json_schema": False,
            "slsa_level_verified": False, "builder_trust_verified": False,
        })
    print(json.dumps(summary, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        # No instance values, filesystem contents or private paths are printed.
        print(json.dumps({"status": "FAIL", "diagnostic": type(error).__name__,
                          "full_json_schema_validation": False, "network_allowed": False}))
        sys.exit(1)
