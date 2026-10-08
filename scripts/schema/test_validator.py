#!/usr/bin/env python3
"""Meaningful offline validator regression corpus, pin and network checks."""

import argparse
import copy
import importlib.util
import json
from pathlib import Path
import socket
import sys
import uuid

sys.dont_write_bytecode = True
location = Path(__file__).with_name("validate.py")
spec = importlib.util.spec_from_file_location("pao_offline_schema_validation", location)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    args = parser.parse_args()
    harness = validator.Harness(args.repo.resolve(), args.scratch)
    corpus = validator.read_json(args.corpus / "corpus.json")
    if corpus.get("version") != validator.CORPUS_VERSION:
        raise AssertionError("INVALID_CORPUS_VERSION")
    cases = {}
    count = 0
    for entry in corpus["entries"]:
        doc = validator.read_json(validator.inside(args.corpus, entry["path"]))
        if harness.errors(entry["schema"], doc):
            raise AssertionError("POSITIVE_CORPUS_REJECTED")
        cases[entry["name"]] = (entry["schema"], doc)
        count += 1

    def reject(case, edit, expected_pointer=None, expected_keyword=None):
        nonlocal count
        schema, original = cases[case]
        changed = copy.deepcopy(original)
        edit(changed)
        errors = harness.errors(schema, changed)
        if changed == original or not errors:
            raise AssertionError("NEGATIVE_CORPUS_ACCEPTED")
        if expected_pointer is not None and not any(
                error["pointer"] == expected_pointer and
                (expected_keyword is None or error["keyword"] == expected_keyword)
                for error in errors):
            raise AssertionError("EXPECTED_NESTED_SCHEMA_ERROR_NOT_FOUND")
        count += 1

    def at(document, path):
        for part in path:
            document = document[part]
        return document

    def replace(path, value):
        def edit(document):
            at(document, path[:-1])[path[-1]] = value
        return edit

    def remove(path):
        return lambda document: at(document, path[:-1]).pop(path[-1])

    def pointer(path):
        return "/" + "/".join(str(part).replace("~", "~0").replace("/", "~1") for part in path)

    # Exact unknown-field and required-field checks are exercised separately for
    # each distinct producer, rather than using one envelope test for all formats.
    representatives = ["sarif-findings", "cyclonedx-findings", "spdx-findings",
                       "canonical-finding", "library-portable-finding", "adapter-syft",
                       "plan-go", "public-report-go", "audit-config-v1", "audit-config-v2",
                       "docker-provider", "toolchain-catalog",
                       "release-provenance-local", "release-provenance-hosted"]
    for case in representatives:
        reject(case, lambda doc: doc.__setitem__("UNKNOWN_PUBLIC_FIELD", True))
        schema = harness.schemas[cases[case][0]]
        required = schema.get("required", [])
        if not required:
            raise AssertionError("REQUIRED_FIELDS_NOT_TESTED")
        reject(case, lambda doc, key=required[0]: doc.pop(key))
    for case, key in [("sarif-findings", "version"), ("cyclonedx-findings", "specVersion"),
                      ("spdx-findings", "spdxVersion"), ("canonical-finding", "version"),
                      ("adapter-syft", "api_version"), ("plan-go", "version"),
                      ("public-report-go", "version"), ("audit-config-v1", "version"),
                      ("audit-config-v2", "version"), ("docker-provider", "api_version"),
                      ("toolchain-catalog", "api_version")]:
        reject(case, lambda doc, key=key: doc.__setitem__(key, "UNKNOWN_FUTURE_VERSION"))
    reject("cyclonedx-findings", lambda doc: doc.__setitem__("serialNumber", "urn:uuid:" + "a" * 32))
    reject("cyclonedx-findings", lambda doc: doc["metadata"].__setitem__("timestamp", "tomorrow"))
    reject("cyclonedx-findings", lambda doc: doc["metadata"]["component"].__setitem__("type", "UNKNOWN_COMPONENT_TYPE"))
    # This license goes through the complete cached spdx.schema.json $ref, proving
    # that remote reference fetching is not necessary for nested validation.
    reject("cyclonedx-findings", lambda doc: doc["metadata"]["component"].__setitem__("licenses", [{"license": {"id": "NOT-A-LICENSE"}}]))
    reject("cyclonedx-findings", lambda doc: doc["metadata"]["component"].__setitem__("externalReferences", [{"type": "website", "url": "http://invalid whitespace"}]))
    reject("sarif-findings", lambda doc: doc["runs"][0]["results"][0].__setitem__("level", "danger"))
    reject("sarif-findings", lambda doc: doc["runs"][0]["tool"]["driver"].__setitem__("name", []))
    reject("spdx-findings", lambda doc: doc.__setitem__("creationInfo", {}))
    reject("adapter-syft", lambda doc: doc.__setitem__("writes_target", None))
    reject("adapter-syft", lambda doc: doc.__setitem__("max_output_bytes", 0))
    reject("adapter-syft", lambda doc: doc.__setitem__("success_exit_codes", [0, 0]))
    reject("adapter-syft", lambda doc: doc.__setitem__("compatible_tool_versions", None))
    reject("adapter-syft", lambda doc: doc.__setitem__("compatible_tool_versions", ["1.51.1", "1.51.1"]))
    reject("adapter-syft", lambda doc: doc.__setitem__("compatible_tool_versions", [" 1.51.1"]))
    reject("plan-go", lambda doc: doc["sandbox"].__setitem__("network", "allowed"))
    reject("plan-go", lambda doc: doc["nodes"][0].__setitem__("future_runtime_grant", True))
    reject("public-report-go", lambda doc: doc["coverage"][0].__setitem__("observations", -1))
    reject("public-report-go", lambda doc: doc.__setitem__("parser_version", "pao-native-projection/unknown"))
    reject("public-report-go", lambda doc: doc["report_producer"].__setitem__("executable_sha256", "UNVERIFIED"))
    reject("public-report-go", lambda doc: doc["report_producer"].__setitem__("go_version", "PRIVATE_PATH_OR_UNKNOWN_VERSION"))
    reject("public-report-go", lambda doc: doc["report_producer"].__setitem__("identity_status", "RELEASE_CANDIDATE"))
    reject("toolchain-catalog", lambda doc: doc.__setitem__("tools", []))
    reject("toolchain-catalog", lambda doc: doc["tools"][0]["record"].__setitem__("sha256", "UNVERIFIED"))
    reject("toolchain-catalog", lambda doc: doc["tools"][0].__setitem__("database", "syft/db"))
    reject("toolchain-catalog", lambda doc: doc["tools"][0].__setitem__("binary", "../outside/tool"))
    reject("docker-provider", lambda doc: doc["runtime_approval"].__setitem__("expires_at", "tomorrow"))

    # Every field in PAO's unsigned release provenance is validated at its
    # actual nested path. These are strict producer-profile rules, not a claim
    # that every conforming upstream SLSA/in-toto document uses this shape.
    provenance = "release-provenance-local"
    definition = ("predicate", "buildDefinition")
    details = ("predicate", "runDetails")
    required_paths = [
        ("subject",), ("predicateType",), ("predicate",),
        ("subject", 0, "name"), ("subject", 0, "digest"), ("subject", 0, "digest", "sha256"),
        ("predicate", "buildDefinition"), ("predicate", "runDetails"),
        definition + ("buildType",), definition + ("externalParameters",),
        definition + ("internalParameters",), definition + ("resolvedDependencies",),
        definition + ("externalParameters", "version"),
        definition + ("internalParameters", "go_version"),
        definition + ("internalParameters", "source_state"),
        definition + ("internalParameters", "source_tree_sha256"),
        definition + ("resolvedDependencies", 0, "uri"),
        definition + ("resolvedDependencies", 0, "digest"),
        definition + ("resolvedDependencies", 0, "digest", "gitCommit"),
        details + ("builder",), details + ("metadata",), details + ("builder", "id"),
        details + ("metadata", "startedOn"), details + ("metadata", "finishedOn"),
    ]
    for path in required_paths:
        reject(provenance, remove(path), pointer(path[:-1]), "required")
    typed_paths = [
        (("_type",), []), (("predicateType",), []), (("subject",), {}),
        (("subject", 0), []), (("subject", 0, "name"), []),
        (("subject", 0, "digest"), []), (("subject", 0, "digest", "sha256"), []),
        (("predicate",), []), (definition, []), (definition + ("buildType",), []),
        (definition + ("externalParameters",), []), (definition + ("externalParameters", "version"), 2),
        (definition + ("internalParameters",), []), (definition + ("internalParameters", "go_version"), []),
        (definition + ("internalParameters", "source_state"), True),
        (definition + ("internalParameters", "source_tree_sha256"), []),
        (definition + ("resolvedDependencies",), {}),
        (definition + ("resolvedDependencies", 0), []),
        (definition + ("resolvedDependencies", 0, "uri"), []),
        (definition + ("resolvedDependencies", 0, "digest"), []),
        (definition + ("resolvedDependencies", 0, "digest", "gitCommit"), []),
        (details, []), (details + ("builder",), []), (details + ("builder", "id"), 2),
        (details + ("metadata",), []), (details + ("metadata", "startedOn"), 2),
        (details + ("metadata", "finishedOn"), []),
    ]
    for path, value in typed_paths:
        reject(provenance, replace(path, value), pointer(path), "type")
    for path in [("predicate",), definition, definition + ("externalParameters",),
                 definition + ("internalParameters",), details + ("builder",),
                 details + ("metadata",), ("subject", 0, "digest")]:
        reject(provenance, replace(path, None), pointer(path), "type")
    closed_objects = [(), ("predicate",), definition, definition + ("externalParameters",),
                      definition + ("internalParameters",), definition + ("resolvedDependencies", 0),
                      definition + ("resolvedDependencies", 0, "digest"), details,
                      details + ("builder",), details + ("metadata",), ("subject", 0),
                      ("subject", 0, "digest")]
    for path in closed_objects:
        reject(provenance, lambda doc, path=path: at(doc, path).__setitem__("pao_unrecognized_extension", True),
               pointer(path), "additionalProperties")
    for path, value, keyword in [
        (("_type",), "https://in-toto.io/Statement/v0.1", "const"),
        (("predicateType",), "https://slsa.dev/provenance/v0.2", "const"),
        (definition + ("buildType",), "relative/build/type", "const"),
        (definition + ("buildType",), "https://pao.dev/release/v2", "const"),
        (definition + ("externalParameters", "version"), "UNKNOWN_FUTURE_VERSION", "pattern"),
        (definition + ("externalParameters", "version"), "0.2.0\n", "not"),
        (definition + ("internalParameters", "go_version"), "go1.27", "pattern"),
        (definition + ("internalParameters", "go_version"), "go1.27.1\n", "not"),
        (definition + ("internalParameters", "source_state"), "unknown", "enum"),
        (definition + ("internalParameters", "source_tree_sha256"), "a" * 63, "minLength"),
        (definition + ("internalParameters", "source_tree_sha256"), "A" * 64, "pattern"),
        (definition + ("resolvedDependencies", 0, "uri"), "http://invalid whitespace", "format"),
        (definition + ("resolvedDependencies", 0, "uri"), "git+https://GITHUB.COM/sSOFTINn/ProjectAuditOrchestrator", "const"),
        (definition + ("resolvedDependencies", 0, "uri"), "git+https://github.com/unexpected/repository", "const"),
        (definition + ("resolvedDependencies", 0, "digest", "gitCommit"), "b" * 39, "minLength"),
        (definition + ("resolvedDependencies", 0, "digest", "gitCommit"), "b" * 64, "maxLength"),
        (definition + ("resolvedDependencies", 0, "digest", "gitCommit"), "g" * 40, "pattern"),
        (("subject", 0, "name"), "../BUILD-METADATA.json", "anyOf"),
        (("subject", 0, "name"), "BUILD-METADATA.json\n", "not"),
        (("subject", 0, "digest", "sha256"), "a" * 63, "minLength"),
        (("subject", 0, "digest", "sha256"), "a" * 65, "maxLength"),
        (("subject", 0, "digest", "sha256"), "A" * 64, "pattern"),
        (("subject", 0, "digest", "sha256"), "g" * 64, "pattern"),
        (details + ("builder", "id"), "relative/builder", "format"),
        (details + ("builder", "id"), "https://unrecognized.invalid/builder", "enum"),
        (details + ("metadata", "startedOn"), "2026-02-30T12:00:00Z", "format"),
        (details + ("metadata", "finishedOn"), "2026-10-02T25:00:00Z", "format"),
        (details + ("metadata", "startedOn"), "2026-10-02T12:00:00+00:00", "pattern"),
        (details + ("metadata", "finishedOn"), "2026-10-02T12:00:00z", "pattern"),
    ]:
        reject(provenance, replace(path, value), pointer(path), keyword)
    reject(provenance, replace(("subject",), []), "/subject", "minItems")
    reject(provenance, lambda doc: doc["subject"].append(copy.deepcopy(doc["subject"][0])), "/subject", "maxItems")
    reject(provenance, lambda doc: doc["subject"].__setitem__(3, copy.deepcopy(doc["subject"][0])), "/subject", "uniqueItems")

    def duplicate_name_different_digest(document):
        document["subject"][3] = copy.deepcopy(document["subject"][0])
        document["subject"][3]["digest"]["sha256"] = "f" * 64
    reject(provenance, duplicate_name_different_digest, "/subject", "maxContains")
    reject(provenance, replace(definition + ("resolvedDependencies",), []), pointer(definition + ("resolvedDependencies",)), "minItems")
    reject(provenance, lambda doc: at(doc, definition + ("resolvedDependencies",)).append(copy.deepcopy(at(doc, definition + ("resolvedDependencies", 0)))),
           pointer(definition + ("resolvedDependencies",)), "maxItems")
    reject(provenance, lambda doc: doc["subject"][0]["digest"].__setitem__("sha512", "f" * 128), "/subject/0/digest", "additionalProperties")
    reject(provenance, lambda doc: at(doc, details + ("metadata",)).__setitem__("invocationId", "123"), pointer(details + ("metadata",)), "not")
    hosted = "release-provenance-hosted"
    invocation = details + ("metadata", "invocationId")
    reject(hosted, remove(invocation), pointer(details + ("metadata",)), "required")
    reject(hosted, replace(invocation, 123), pointer(invocation), "type")
    reject(hosted, replace(invocation, "opaque-not-a-github-run-number"), pointer(invocation), "pattern")
    reject(hosted, replace(invocation, "123\n"), pointer(invocation), "not")
    # Subjects are unordered and RFC3339 UTC timestamps can have fractions.
    for case in [provenance, hosted]:
        schema, original = cases[case]
        changed = copy.deepcopy(original)
        changed["subject"].reverse()
        at(changed, details + ("metadata",))["startedOn"] = "2026-10-02T12:00:00.125Z"
        at(changed, details + ("metadata",))["finishedOn"] = "2026-10-02T12:00:01.500Z"
        if harness.errors(schema, changed):
            raise AssertionError("VALID_UNORDERED_OR_FRACTIONAL_PROVENANCE_REJECTED")
        count += 1

    # JSON Schema works on parsed data; our wire reader separately refuses
    # duplicate keys, trailing JSON, NaN, invalid UTF-8 and bounded-input overflow.
    invalid_wire = [b'{"version":"one","version":"two"}',
                    b'{"version":"one","\\u0076ersion":"two"}', b'{} {}',
                    b'{"value":NaN}', b'\xff', b' ' * (validator.MAX_JSON_BYTES + 1)]
    wire_dir = args.scratch / ("invalid-wire-" + uuid.uuid4().hex)
    wire_dir.mkdir()
    for index, raw in enumerate(invalid_wire):
        path = wire_dir / (str(index) + ".json")
        path.write_bytes(raw)
        try:
            validator.read_json(path)
        except (ValueError, UnicodeDecodeError):
            count += 1
        else:
            raise AssertionError("INVALID_JSON_WIRE_ACCEPTED")

    # Every byte pin is verified before importing any wheel. A changed artifact
    # is refused; the test modifies only an inert copied file in scratch.
    copied_vendor = args.scratch / ("invalid-pin-" + uuid.uuid4().hex)
    copied_vendor.mkdir()
    (copied_vendor / "inert.txt").write_bytes(b"modified synthetic bytes")
    pins = {"version": validator.PIN_VERSION, "entries": [{
        "path": "inert.txt", "kind": "license", "sha256": "a" * 64,
    }]}
    (copied_vendor / "pins.json").write_text(json.dumps(pins))
    try:
        validator.verify_pins(copied_vendor)
    except ValueError as error:
        if str(error) != "PIN_SHA256_MISMATCH":
            raise
        count += 1
    else:
        raise AssertionError("CHANGED_PIN_ACCEPTED")

    # A missing external $ref fails closed, with no HTTP/file fallback. The
    # socket guard is also tested without opening a connection.
    remote = {"$schema": "http://json-schema.org/draft-07/schema#",
              "$ref": "https://unavailable.invalid/schema.json"}
    resolver = harness.jsonschema.RefResolver.from_schema(
        remote, store=harness.store,
        handlers={"http": validator.reject_network, "https": validator.reject_network,
                  "file": validator.reject_network},
    )
    try:
        list(harness.jsonschema.Draft7Validator(remote, resolver=resolver).iter_errors({}))
    except harness.jsonschema.exceptions.RefResolutionError:
        count += 1
    else:
        raise AssertionError("UNKNOWN_REMOTE_REFERENCE_ACCEPTED")
    try:
        socket.create_connection(("unavailable.invalid", 443))
    except RuntimeError as error:
        if str(error) != "NETWORK_FORBIDDEN":
            raise
        count += 1
    else:
        raise AssertionError("NETWORK_GUARD_INACTIVE")
    print(json.dumps({"status": "PASS", "checks": count, "network_allowed": False,
                      "validator": "jsonschema==4.17.3", "release_approved": False}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"status": "FAIL", "diagnostic": type(error).__name__,
                          "network_allowed": False, "release_approved": False}))
        sys.exit(1)
