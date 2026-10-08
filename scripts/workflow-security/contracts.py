"""Offline lint for the deliberately small YAML subset used by PAO workflows.

This is a restrictive syntax/structure and security-contract check, not the full
GitHub workflow schema, actionlint, or evidence of hosted runner execution.
"""
import json
from pathlib import Path
import re

PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-go": "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/attest": "1e69f48acb82d1966a394da916b4c1698aa569d6",
}
HOSTED_RUNNERS = ("windows-2025", "ubuntu-24.04")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def uncomment(text):
    quote = None
    escape = False
    for i, char in enumerate(text):
        if escape:
            escape = False
        elif quote == '"' and char == "\\":
            escape = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "'\"" and (i == 0 or text[i - 1].isspace() or text[i - 1] in "[:,("):
            quote = char
        elif char == "#" and (i == 0 or text[i - 1].isspace()):
            return text[:i].rstrip()
    require(quote is None, "unclosed scalar quote")
    return text.rstrip()


def scalar(text):
    text = text.strip()
    if text == "":
        return None
    if text.startswith("'"):
        require(text.endswith("'") and len(text) >= 2, "invalid quoted scalar")
        return text[1:-1].replace("''", "'")
    if text.startswith('"'):
        value = json.loads(text)
        require(isinstance(value, str), "quoted scalar must be a string")
        return value
    if text.startswith("["):
        require(text.endswith("]"), "unclosed inline list")
        inner = text[1:-1]
        if not inner.strip():
            return []
        require("[" not in inner and "]" not in inner,
                "nested inline lists are outside the supported subset")
        return [scalar(item) for item in inner.split(",")]
    require(not text.startswith(("!", "&", "*", "{", ">", "|", "---", "...")), "unsupported YAML construct")
    require(": " not in text and " #" not in text, "unsupported plain scalar")
    if text in ("true", "false"):
        return text == "true"
    if text == "null":
        return None
    if re.fullmatch(r"0|[1-9][0-9]*", text):
        return int(text)
    return text


def parse(text):
    require(isinstance(text, str) and len(text) <= 128 << 10 and "\t" not in text and "\r" not in text,
            "workflow text must be bounded LF YAML without tabs")
    lines = text.splitlines()
    tokens = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        number = i + 1
        i += 1
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        require(indent % 2 == 0, "indentation must use pairs of spaces")
        body = uncomment(raw[indent:])
        literal = None
        if body.endswith(": |"):
            literal_indent = indent + 2 if body.startswith("- ") else indent
            gathered = []
            while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip(" ")) > literal_indent):
                gathered.append(lines[i])
                i += 1
            require(bool(gathered), "empty literal block")
            nonempty = [len(item) - len(item.lstrip(" ")) for item in gathered if item.strip()]
            require(bool(nonempty) and min(nonempty) > literal_indent, "invalid literal block indentation")
            base = min(nonempty)
            literal = "\n".join(item[base:] if item.strip() else "" for item in gathered) + "\n"
        if body.startswith("- "):
            tokens.append((number, indent, "-", None))
            tokens.append((number, indent + 2, body[2:], literal))
        else:
            tokens.append((number, indent, body, literal))
    require(tokens and tokens[0][1] == 0, "root mapping is required")

    def block(index, indent):
        require(index < len(tokens) and tokens[index][1] == indent, "invalid nested indentation")
        is_list = tokens[index][2] == "-"
        result = [] if is_list else {}
        while index < len(tokens) and tokens[index][1] == indent:
            number, _, body, literal = tokens[index]
            index += 1
            if is_list:
                require(body == "-" and literal is None, "mixed mapping and sequence")
                require(index < len(tokens) and tokens[index][1] == indent + 2, "empty sequence entry")
                value, index = block(index, indent + 2)
                result.append(value)
                continue
            match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_-]*):(?: (.*))?", body)
            require(match is not None, "invalid mapping entry at line " + str(number))
            key, raw = match[1], match[2] or ""
            require(key not in result, "duplicate YAML mapping key: " + key)
            if literal is not None:
                require(raw == "|", "invalid literal marker")
                value = literal
            elif raw:
                value = scalar(raw)
            elif index < len(tokens) and tokens[index][1] > indent:
                require(tokens[index][1] == indent + 2, "nested indentation skips a level")
                value, index = block(index, indent + 2)
            else:
                value = None
            result[key] = value
        require(index == len(tokens) or tokens[index][1] < indent, "unattached nested YAML entry")
        return result, index

    result, end = block(0, 0)
    require(end == len(tokens) and isinstance(result, dict), "workflow must be one mapping")
    return result


def use(steps, action):
    matches = [step for step in steps if str(step.get("uses", "")).split("@")[0] == action]
    require(len(matches) == 1, "expected exactly one " + action)
    return matches[0]


def run_text(steps):
    return "\n".join(step.get("run", "") for step in steps)


def validate(workflow, kind):
    require(set(workflow) == {"name", "on", "permissions", "env", "jobs"}, "unexpected workflow fields")
    require(workflow["permissions"] == {"contents": "read"}, "workflow permissions must be read-only")
    require(workflow["env"] == {"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"}, "offline Go settings differ")
    events = workflow["on"]
    require(isinstance(events, dict) and "pull_request_target" not in events, "unsafe event")
    if kind == "ci":
        require(events == {"push": {"branches": ["main"]}, "pull_request": None, "workflow_dispatch": None}, "unexpected CI events")
        require(set(workflow["jobs"]) == {"test", "race"}, "unexpected CI jobs")
    else:
        require(set(events) == {"push", "workflow_dispatch"} and events["push"] == {"tags": ["v*"]}, "unexpected release events")
        require(events["workflow_dispatch"]["inputs"]["version"]["type"] == "string" and
                events["workflow_dispatch"]["inputs"]["version"]["required"] is True, "release version input differs")
        require(set(workflow["jobs"]) == {"build"}, "release verification must not publish or attest")
    for name, job in workflow["jobs"].items():
        require(isinstance(job, dict), "job mapping is required")
        fields = {"runs-on", "permissions", "steps"}
        fields |= {"name", "strategy"} if kind == "ci" and name == "test" else set()
        fields |= {"name"} if kind == "ci" and name == "race" else set()
        fields |= {"outputs"} if kind == "release" and name == "build" else set()
        require(set(job) <= fields, "unexpected job fields")
        require(job.get("permissions", workflow["permissions"]) == {"contents": "read"}, "build/test permission escalation")
        require(job.get("runs-on") in (*HOSTED_RUNNERS, "${{ matrix.os }}"), "unapproved runner")
        steps = job["steps"]
        require(isinstance(steps, list) and bool(steps), "steps must be a nonempty sequence")
        ids = set()
        for step in steps:
            require(isinstance(step, dict) and set(step) <= {"name", "id", "uses", "with", "if", "shell", "env", "run"}, "unexpected step fields")
            require(("uses" in step) != ("run" in step), "step must execute one action or script")
            if "id" in step:
                require(step["id"] not in ids, "duplicate step ID")
                ids.add(step["id"])
            if "uses" in step:
                require(set(step) <= {"name", "id", "uses", "with", "if"}, "unexpected action environment or script")
                parts = step["uses"].split("@")
                require(len(parts) == 2 and PINS.get(parts[0]) == parts[1], "action source is not an approved immutable pin")
                require(parts[0] in ("actions/checkout", "actions/setup-go", "actions/upload-artifact"),
                        "public signing, attestation or download actions are outside verification")
            else:
                require(isinstance(step["run"], str) and "${{" not in step["run"], "expression interpolation inside shell script")
                require(step.get("shell") in ("bash", "pwsh"), "shell must be explicit")
                require(re.search(r"\b(?:git\s+push|gh\s+(?:release|api)|pip(?:3)?\s+install|npm\s+install|curl|wget)\b", step["run"], re.IGNORECASE) is None,
                        "publication or implicit network preparation inside workflow script")
                require(all("${{ secrets." not in str(value) for value in step.get("env", {}).values()), "secret injection into script environment")
        checkout = use(steps, "actions/checkout")
        checkout_contract = {"ref": "${{ github.sha }}", "persist-credentials": False}
        if kind == "release":
            checkout_contract["fetch-depth"] = 0
        require(checkout["with"] == checkout_contract, "checkout source/credentials/history contract differs")
        setup = use(steps, "actions/setup-go")
        require(setup["with"] == {"go-version": "1.27.1", "check-latest": False, "cache": False}, "Go action configuration differs")
    if kind == "ci":
        test = workflow["jobs"]["test"]
        require(test.get("name") == "hosted-${{ matrix.os }}" and
                test["strategy"] == {"fail-fast": False, "matrix": {"os": list(HOSTED_RUNNERS)}},
                "required hosted Windows/Linux CI matrix differs")
        text = run_text(test["steps"])
        for required in ("test_contracts.py", "go test ./...", "go vet ./...", "./cmd/pao-sandbox", "scripts/schema/corpus", "scripts/schema/validate.py", "scripts/schema/test_validator.py", "test_stage_osv_pypi_database.py", "verify-state-acl.ps1", "test-state-acl.ps1"):
            require(required in text, "missing CI check: " + required)
        race = workflow["jobs"]["race"]
        require(race.get("name") == "hosted-ubuntu-cgo-race" and race["runs-on"] == "ubuntu-24.04",
                "hosted Linux race job differs")
        race_step = next(step for step in race["steps"] if "run" in step)
        require(race_step.get("env") == {"CGO_ENABLED": "1"} and "go test -race ./..." in race_step["run"], "Linux race check requires CGO")
        return
    build = workflow["jobs"]["build"]
    require(build["runs-on"] == "windows-2025", "release hosted build runner differs")
    require(build["outputs"] == {"version": "${{ steps.source.outputs.version }}", "commit": "${{ steps.source.outputs.commit }}", "artifact-id": "${{ steps.candidate.outputs.artifact-id }}", "artifact-digest": "${{ steps.candidate.outputs.artifact-digest }}"}, "build artifact outputs differ")
    text = run_text(build["steps"])
    for required in ("test_contracts.py", "go test ./...", "go vet ./...", "scripts/schema/corpus", "scripts/schema/validate.py", "scripts/schema/test_validator.py", "test-release-metadata.ps1", "-FixtureEvidencePath", "self-audit.ps1", "transfer.py create", "$commit -cne $env:GITHUB_SHA", '"refs/tags/v$version"', "if ($version -notmatch '-')", "refs/remotes/origin/main^{commit}", "$mainCommit -cne $commit"):
        require(required in text, "missing release check: " + required)
    build_steps = [step for step in build["steps"] if "build-public-package.ps1" in step.get("run", "")]
    require(len(build_steps) == 1 and build_steps[0]["run"].count("./scripts/release/build-public-package.ps1 ") == 2,
            "two independently invoked candidate builds are required")
    sources = [step for step in build["steps"] if step.get("id") == "source"]
    require(len(sources) == 1 and sources[0].get("env") == {"RELEASE_VERSION": "${{ inputs.version }}"} and
            build["steps"].index(sources[0]) < build["steps"].index(build_steps[0]),
            "candidate source/version binding must precede builds")
    require(build_steps[0].get("env") == {"RELEASE_VERSION": "${{ steps.source.outputs.version }}"},
            "both builds must use the source-bound version")
    require(build_steps[0]["run"].count("-Version $env:RELEASE_VERSION -AsOf $asOf -GoPath (Get-Command go).Source") == 2 and
            "git show -s --format=%cI HEAD" in build_steps[0]["run"],
            "both builds must use the same version, toolchain and source timestamp")
    for label in ("first", "second"):
        require("-OutputPath (Join-Path $env:RUNNER_TEMP 'pao-release-" + label + "')" in build_steps[0]["run"] and
                "$env:GOCACHE = Join-Path $env:RUNNER_TEMP 'pao-release-" + label + "-go-cache'" in build_steps[0]["run"],
                "independent fresh output/cache is required for each build")
    require("-AllowDirty" not in text, "hosted candidates must use clean source")
    inspections = [step for step in build["steps"] if "self-audit.ps1" in step.get("run", "")]
    require(len(inspections) == 1 and
            "-OutputPath (Join-Path $env:RUNNER_TEMP 'pao-self-inspect.json')" in inspections[0]["run"],
            "inspection report must stay outside exact public/private package inventories")
    comparisons = [step for step in build["steps"] if "compare-public-builds.ps1" in step.get("run", "")]
    require(len(comparisons) == 1 and build["steps"].index(comparisons[0]) > build["steps"].index(build_steps[0]),
            "byte comparison must follow both builds")
    for required in ("-FirstDistributionPath (Join-Path $env:RUNNER_TEMP 'pao-release-first/dist')",
                     "-SecondDistributionPath (Join-Path $env:RUNNER_TEMP 'pao-release-second/dist')"):
        require(required in comparisons[0]["run"], "comparison must use both independent distributions")
    seals = [step for step in build["steps"] if "transfer.py create" in step.get("run", "")]
    require(len(seals) == 1 and seals[0].get("id") == "transfer" and
            build["steps"].index(seals[0]) > build["steps"].index(comparisons[0]),
            "local public-payload sealing must follow byte comparison")
    require(seals[0].get("env") == {"RELEASE_VERSION": "${{ steps.source.outputs.version }}"},
            "local transfer must use the source-bound version")
    for required in ("--dist (Join-Path $env:RUNNER_TEMP 'pao-release-first/dist')",
                     "--build-metadata (Join-Path $env:RUNNER_TEMP 'pao-release-first/evidence/BUILD-METADATA.json')",
                     "--output (Join-Path $env:RUNNER_TEMP 'pao-release-transfer')",
                     "--version $env:RELEASE_VERSION", "--repository $env:GITHUB_REPOSITORY",
                     "--commit $env:GITHUB_SHA", "--ref $env:GITHUB_REF",
                     "--run-id $env:GITHUB_RUN_ID", "--run-attempt $env:GITHUB_RUN_ATTEMPT"):
        require(required in seals[0]["run"], "missing local transfer identity: " + required)
    upload = use(build["steps"], "actions/upload-artifact")
    require(upload["id"] == "candidate" and upload["with"] == {"name": "pao-release-candidate-${{ github.sha }}-${{ github.run_attempt }}", "path": "${{ runner.temp }}/pao-release-transfer/payload", "if-no-files-found": "error", "overwrite": False, "include-hidden-files": False, "retention-days": 30}, "upload must contain only allowlisted public payload; private evidence stays local")
    require(build["steps"].index(upload) > build["steps"].index(seals[0]), "upload precedes public-payload verification")


def load(repo, kind):
    path = Path(repo) / ".github" / "workflows" / (kind + ".yml")
    return parse(path.read_text(encoding="utf-8").replace("\r\n", "\n"))
