"""Run bounded synthetic workflow/transfer acceptance, entirely offline."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import unittest


def module(name):
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("pao_workflow_" + name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


contracts = module("contracts")
transfer = module("transfer")
REPO = None
SCRATCH = None


class WorkflowTests(unittest.TestCase):
    def test_current_workflows(self):
        for kind in ("ci", "release"):
            with self.subTest(kind=kind):
                contracts.validate(contracts.load(REPO, kind), kind)

    def test_provenance_record_covers_every_action_pin(self):
        path = REPO / "scripts" / "workflow-security" / "action-pins.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual({item["action"]: item["commit"] for item in record["actions"]}, contracts.PINS)
        self.assertEqual(len(record["actions"]), len(contracts.PINS))
        for item in record["actions"]:
            with self.subTest(action=item["action"]):
                self.assertTrue(item["github_commit_verified"])
                self.assertEqual(item["runtime"], "node24")
                self.assertEqual(item["tag_source"], "https://api.github.com/repos/" + item["action"] + "/git/ref/tags/" + item["tag"])
                self.assertEqual(item["commit_source"], "https://api.github.com/repos/" + item["action"] + "/commits/" + item["commit"])
                self.assertEqual(item["definition_source"], "https://raw.githubusercontent.com/" + item["action"] + "/" + item["commit"] + "/action.yml")

    def test_negative_security_contracts(self):
        original = contracts.load(REPO, "release")
        cases = []

        def variant(name, mutate):
            value = copy.deepcopy(original)
            mutate(value)
            cases.append((name, value))

        variant("global-write", lambda w: w["permissions"].update(contents="write"))
        variant("build-signing", lambda w: w["jobs"]["build"]["permissions"].update({"id-token": "write"}))
        variant("build-attestation-token", lambda w: w["jobs"]["build"]["permissions"].update({"attestations": "write"}))
        variant("build-all-write", lambda w: w["jobs"]["build"]["permissions"].update(actions="write"))
        variant("public-attestation-job", lambda w: w["jobs"].update(attest=copy.deepcopy(w["jobs"]["build"])))
        variant("mutable-checkout", lambda w: contracts.use(w["jobs"]["build"]["steps"], "actions/checkout")["with"].update(ref="main"))
        variant("persistent-credentials", lambda w: contracts.use(w["jobs"]["build"]["steps"], "actions/checkout")["with"].update({"persist-credentials": True}))
        variant("missing-main-history", lambda w: contracts.use(w["jobs"]["build"]["steps"], "actions/checkout")["with"].pop("fetch-depth"))
        variant("mutable-action", lambda w: contracts.use(w["jobs"]["build"]["steps"], "actions/checkout").update(uses="actions/checkout@v7"))
        variant("replace-upload", lambda w: contracts.use(w["jobs"]["build"]["steps"], "actions/upload-artifact")["with"].update(overwrite=True))
        for path in ("${{ runner.temp }}/pao-release-transfer", "${{ runner.temp }}/pao-release-first/evidence",
                     "${{ runner.temp }}/pao-release-first", "${{ runner.temp }}/pao-release-transfer/**"):
            variant("private-upload-" + path, lambda w, path=path: contracts.use(w["jobs"]["build"]["steps"], "actions/upload-artifact")["with"].update(path=path))
        variant("hidden-files-upload", lambda w: contracts.use(w["jobs"]["build"]["steps"], "actions/upload-artifact")["with"].update({"include-hidden-files": True}))
        variant("public-attestation-action", lambda w: w["jobs"]["build"]["steps"].append({"uses": "actions/attest@" + contracts.PINS["actions/attest"]}))
        variant("second-upload", lambda w: w["jobs"]["build"]["steps"].append(copy.deepcopy(contracts.use(w["jobs"]["build"]["steps"], "actions/upload-artifact"))))

        def run_step(workflow, token):
            return next(step for step in workflow["jobs"]["build"]["steps"] if token in step.get("run", ""))

        def replace_run(workflow, token, before, after):
            step = run_step(workflow, token)
            step["run"] = step["run"].replace(before, after)

        variant("one-build", lambda w: replace_run(w, "build-public-package.ps1", "./scripts/release/build-public-package.ps1 -OutputPath (Join-Path $env:RUNNER_TEMP 'pao-release-second')", "./removed-build.ps1 -OutputPath (Join-Path $env:RUNNER_TEMP 'pao-release-second')"))
        variant("shared-build-cache", lambda w: replace_run(w, "build-public-package.ps1", "pao-release-second-go-cache", "pao-release-first-go-cache"))
        variant("shared-build-output", lambda w: replace_run(w, "build-public-package.ps1", "'pao-release-second'", "'pao-release-first'"))
        variant("dirty-build", lambda w: run_step(w, "build-public-package.ps1").update(run=run_step(w, "build-public-package.ps1")["run"] + "\n# -AllowDirty\n"))
        variant("comparison-removed", lambda w: w["jobs"]["build"].update(steps=[step for step in w["jobs"]["build"]["steps"] if "compare-public-builds.ps1" not in step.get("run", "")]))
        variant("comparison-same-output", lambda w: replace_run(w, "compare-public-builds.ps1", "pao-release-second/dist", "pao-release-first/dist"))
        variant("metadata-in-public-payload", lambda w: replace_run(w, "transfer.py create", "pao-release-first/evidence/BUILD-METADATA.json", "pao-release-first/dist/BUILD-METADATA.json"))
        variant("inspection-in-public-payload", lambda w: replace_run(w, "self-audit.ps1", "'pao-self-inspect.json'", "'pao-release-first/dist/self-inspect.json'"))
        variant("main-identity-check-removed", lambda w: replace_run(w, "refs/remotes/origin/main^{commit}", "$mainCommit -cne $commit", "$false"))
        variant("upload-before-verification", lambda w: w["jobs"]["build"]["steps"].insert(2, w["jobs"]["build"]["steps"].pop(-2)))
        variant("untrusted-shell-expression", lambda w: w["jobs"]["build"]["steps"][2].update(run="echo ${{ inputs.version }}"))
        variant("unexpected-container", lambda w: w["jobs"]["build"].update(container="untrusted:latest"))
        variant("publication-script", lambda w: w["jobs"]["build"]["steps"][2].update(run="gh release create v0.2.0"))
        variant("secret-script-env", lambda w: w["jobs"]["build"]["steps"][2]["env"].update(TOKEN="${{ secrets.TOKEN }}"))
        variant("pr-target", lambda w: w["on"].update(pull_request_target=None))
        for name, workflow in cases:
            with self.subTest(case=name), self.assertRaises(ValueError):
                contracts.validate(workflow, "release")

    def test_negative_ci_contracts(self):
        original = contracts.load(REPO, "ci")
        for name in ("missing-os", "mutable-runner", "race-no-cgo", "race-removed", "schema-removed", "write-token"):
            workflow = copy.deepcopy(original)
            if name == "missing-os":
                workflow["jobs"]["test"]["strategy"]["matrix"]["os"] = ["ubuntu-24.04"]
            elif name == "mutable-runner":
                workflow["jobs"]["test"]["strategy"]["matrix"]["os"] = ["windows-latest", "ubuntu-latest"]
            elif name == "race-no-cgo":
                workflow["jobs"]["race"]["steps"][-1]["env"]["CGO_ENABLED"] = "0"
            elif name == "race-removed":
                workflow["jobs"].pop("race")
            elif name == "schema-removed":
                workflow["jobs"]["test"]["steps"] = [step for step in workflow["jobs"]["test"]["steps"] if "scripts/schema/corpus" not in step.get("run", "")]
            else:
                workflow["jobs"]["test"]["permissions"] = {"contents": "write"}
            with self.subTest(case=name), self.assertRaises(ValueError):
                contracts.validate(workflow, "ci")

    def test_yaml_subset(self):
        parsed = contracts.parse("on:\n  push:\njobs:\n  test:\n    steps:\n      - run: |\n          echo '#safe'\n          echo ok\n        shell: bash\n")
        self.assertIn("on", parsed)
        self.assertEqual(parsed["jobs"]["test"]["steps"][0]["run"], "echo '#safe'\necho ok\n")
        for invalid in ("x: a\nx: b\n", "x: &anchor a\n", "x: *anchor\n", "x: >\n  text\n", "x: {}\n", "x:\n   a: b\n", "\tx: a\n", "x: 'unterminated\n", "- x: a\n", "x: a\n  y: b\n", "x: [a\n"):
            with self.subTest(yaml=invalid), self.assertRaises((ValueError, json.JSONDecodeError)):
                contracts.parse(invalid)


class TransferTests(unittest.TestCase):
    serial = 0

    def setUp(self):
        TransferTests.serial += 1
        self.root = SCRATCH / ("case-" + str(TransferTests.serial))
        self.root.mkdir()
        self.identity = transfer.context("0.2.0", "sSOFTINn/ProjectAuditOrchestrator", "a" * 40,
                                         "refs/tags/v0.2.0", "1001", "1", True)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        metadata = {"version": "0.2.0", "revision": "a" * 40, "source_state": "clean", "source_tree_sha256": "b" * 64}
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.metadata = self.evidence / "BUILD-METADATA.json"
        self.metadata.write_text(json.dumps(metadata) + "\n", encoding="utf-8")
        for name in transfer.asset_names("0.2.0"):
            if name == "SHA256SUMS.txt":
                continue
            value = ("INERT SYNTHETIC " + name + "\n").encode()
            (self.dist / name).write_bytes(value)
        self.seal_checksums()
        self.output = self.root / "transfer"
        self.manifest_digest = transfer.create(self.dist, self.output, self.identity, self.metadata)

    def seal_checksums(self, directory=None):
        directory = directory or self.dist
        lines = [transfer.digest((directory / name).read_bytes()) + "  " + name for name in transfer.asset_names("0.2.0") if name != "SHA256SUMS.txt"]
        (directory / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def reseal_manifest(self):
        data, source_digest = transfer.payload(self.output / "payload", self.identity, self.metadata)
        path = self.output / "transfer.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["source_tree_sha256"] = source_digest
        value["files"] = [{"name": name, "bytes": len(data[name]), "sha256": transfer.digest(data[name])} for name in sorted(data)]
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        return transfer.digest(path.read_bytes())

    def test_positive_exact_bytes_and_context(self):
        value = transfer.verify(self.output, self.identity, self.manifest_digest, self.metadata, "12345", "sha256:" + "c" * 64)
        self.assertEqual(value["source"], self.identity)
        for name in transfer.asset_names("0.2.0"):
            self.assertEqual((self.dist / name).read_bytes(), (self.output / "payload" / name).read_bytes())
        self.assertEqual({path.name for path in (self.output / "payload").iterdir()},
                         {"pao-0.2.0-windows-amd64.zip", "pao-0.2.0-linux-amd64.tar.gz", "SHA256SUMS.txt"})
        self.assertNotIn("BUILD-METADATA.json", {path.name for path in self.output.rglob("*")})

    def test_source_version_commit_ref_run_substitution(self):
        for field, wrong in (("version", "0.2.1"), ("repository", "other/ProjectAuditOrchestrator"), ("commit", "c" * 40), ("ref", "refs/tags/v0.2.1"), ("run_id", "1002"), ("run_attempt", "2")):
            identity = dict(self.identity, **{field: wrong})
            with self.subTest(field=field), self.assertRaises(ValueError):
                transfer.verify(self.output, identity, self.manifest_digest, self.metadata)

    def test_wrong_manifest_and_transport_identity(self):
        for manifest, artifact, transport in (("c" * 64, "12345", "c" * 64), (self.manifest_digest, "latest", "c" * 64), (self.manifest_digest, "12345", "wrong"), (self.manifest_digest, "0", "c" * 64)):
            with self.subTest(artifact=artifact, manifest=manifest), self.assertRaises(ValueError):
                transfer.verify(self.output, self.identity, manifest, self.metadata, artifact, transport)

    def test_payload_corruption_with_original_build_manifest(self):
        path = self.output / "payload" / "pao-0.2.0-windows-amd64.zip"
        path.write_bytes(b"inert tamper")
        with self.assertRaises(ValueError):
            transfer.verify(self.output, self.identity, self.manifest_digest, self.metadata)
        self.seal_checksums(self.output / "payload")
        with self.assertRaises(ValueError):
            transfer.verify(self.output, self.identity, self.manifest_digest, self.metadata)
        forged_manifest = self.reseal_manifest()
        with self.assertRaises(ValueError):
            transfer.verify(self.output, self.identity, self.manifest_digest, self.metadata)
        self.assertNotEqual(forged_manifest, self.manifest_digest)

    def test_unexpected_and_missing_entries(self):
        (self.output / "payload" / "extra.exe").write_bytes(b"inert")
        with self.assertRaises(ValueError):
            transfer.verify(self.output, self.identity, self.manifest_digest, self.metadata)
        (self.output / "payload" / "extra.exe").unlink()
        (self.output / "extra").mkdir()
        with self.assertRaises(ValueError):
            transfer.verify(self.output, self.identity, self.manifest_digest, self.metadata)
        (self.output / "extra").rmdir()
        (self.output / "payload" / "pao-0.2.0-linux-amd64.tar.gz").unlink()
        with self.assertRaises(ValueError):
            transfer.verify(self.output, self.identity, self.manifest_digest, self.metadata)

    def test_metadata_mismatch_even_with_resealed_checksums(self):
        path = self.metadata
        original = path.read_bytes()
        for field, wrong in (("version", "0.2.1"), ("revision", "c" * 40), ("source_state", "modified"), ("source_tree_sha256", "bad"), ("source_tree_sha256", "c" * 64)):
            value = json.loads(original)
            value[field] = wrong
            path.write_text(json.dumps(value), encoding="utf-8")
            self.seal_checksums(self.output / "payload")
            with self.subTest(field=field), self.assertRaises(ValueError):
                transfer.verify(self.output, self.identity, self.manifest_digest, self.metadata)
        path.write_bytes(original)

    def test_public_payload_rejects_every_private_evidence_kind(self):
        public = self.output / "payload"
        for name in ("BUILD-METADATA.json", "pao-0.2.0.cdx.json", "pao-provenance.intoto.json",
                     "transfer.json", "native-acceptance-report.json"):
            path = public / name
            path.write_bytes(b"inert synthetic private evidence")
            with self.subTest(name=name), self.assertRaises(ValueError):
                transfer.verify(self.output, self.identity, self.manifest_digest, self.metadata)
            path.unlink()
        path = public / "reports"
        path.mkdir()
        with self.assertRaises(ValueError):
            transfer.verify(self.output, self.identity, self.manifest_digest, self.metadata)
        path.rmdir()

    def test_checksum_list_cannot_reference_private_evidence(self):
        sums = self.output / "payload" / "SHA256SUMS.txt"
        original = sums.read_bytes()
        for name in ("BUILD-METADATA.json", "pao-0.2.0.cdx.json", "pao-provenance.intoto.json", "transfer.json"):
            sums.write_bytes(original + ("a" * 64 + "  " + name + "\n").encode())
            with self.subTest(name=name), self.assertRaises(ValueError):
                transfer.verify(self.output, self.identity, self.manifest_digest, self.metadata)
        sums.write_bytes(original)

    def test_external_metadata_cannot_be_a_public_archive(self):
        with self.assertRaises(ValueError):
            transfer.payload(self.dist, self.identity, self.dist / "pao-0.2.0-windows-amd64.zip")

    def test_duplicate_json_key_with_matching_expected_digest(self):
        path = self.output / "transfer.json"
        raw = path.read_bytes().replace(b'"schema_version":', b'"schema_version":"fake","schema_version":', 1)
        path.write_bytes(raw)
        with self.assertRaises(ValueError):
            transfer.verify(self.output, self.identity, transfer.digest(raw), self.metadata)

    def test_existing_output_refused(self):
        before = (self.output / "transfer.json").read_bytes()
        with self.assertRaises(ValueError):
            transfer.create(self.dist, self.output, self.identity, self.metadata)
        self.assertEqual(before, (self.output / "transfer.json").read_bytes())

    def test_bounded_input(self):
        path = self.root / "bounded"
        path.write_bytes(b"123456789")
        with self.assertRaises(ValueError):
            transfer.read_file(path, 8)

    def test_total_read_limit_applies_before_next_payload_read(self):
        previous = transfer.MAX_TOTAL
        transfer.MAX_TOTAL = 4
        try:
            with self.assertRaises(ValueError):
                transfer.payload(self.dist, self.identity, self.metadata)
        finally:
            transfer.MAX_TOTAL = previous

    def test_rejects_linked_payload(self):
        name = "pao-0.2.0-windows-amd64.zip"
        path = self.output / "payload" / name
        target = self.root / "outside-inert"
        shutil.copyfile(path, target)
        path.unlink()
        try:
            os.symlink(target, path)
        except OSError:
            if os.name != "nt":
                raise
            # An unprivileged Windows account may not create symlinks. A
            # synthetic directory junction exercises the same reparse guard.
            import subprocess
            junction = self.output / "payload" / "junction"
            subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(self.root)], check=True, capture_output=True)
            with self.assertRaises(ValueError):
                transfer.checked_path(junction)
            junction.rmdir()
            return
        with self.assertRaises(ValueError):
            transfer.verify(self.output, self.identity, self.manifest_digest, self.metadata)

    def test_exact_tag_required(self):
        for repository, ref in (("other/repo", "refs/tags/v0.2.0"), (self.identity["repository"], "refs/heads/main"), (self.identity["repository"], "refs/tags/v0.2.1")):
            with self.subTest(repository=repository, ref=ref), self.assertRaises(ValueError):
                transfer.context("0.2.0", repository, "a" * 40, ref, "1001", "1", True)


def main():
    global REPO, SCRATCH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--scratch", required=True)
    args = parser.parse_args()
    REPO = transfer.checked_path(args.repo)
    SCRATCH = transfer.checked_path(args.scratch)
    transfer.require(REPO.is_dir() and not SCRATCH.exists() and REPO not in SCRATCH.parents and SCRATCH not in REPO.parents,
                     "repository and NEW isolated scratch directory must not overlap")
    SCRATCH.mkdir(mode=0o700)
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(test) for test in (WorkflowTests, TransferTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
