# BIO Pipeline Check

A lightweight, dependency-light Python tool that scans **Ansible** playbooks/roles,
**Helm** charts, and **OpenShift** manifests (Route, SecurityContextConstraints,
KubeVirt `VirtualMachine`) for common security-hardening issues, mapped to
**Baseline Informatiebeveiliging Overheid (BIO2)** control categories. Built to run
as a gate in a CI/CD pipeline — it exits non-zero when findings meet a configurable
severity threshold.

> [!IMPORTANT]
> The `control_category` on each finding (e.g. *"Toegangsbeveiliging"*,
> *"Hardening"*, *"Cryptografie"*) is a **generic BIO2 control category**, not a
> verbatim official BIO2 article/measure number. This tool is a heuristic security
> linter, not a certified compliance attestation — cross-check findings against the
> authoritative BIO2 document and BIO2 v1.3 control list from
> [bio-overheid.nl](https://www.bio-overheid.nl/) before relying on it for formal
> compliance reporting.

## Features

- ✅ **Ansible** — hardcoded secrets, disabled TLS validation, missing `no_log` on
  sensitive tasks, unpinned privilege escalation, disabled SSH host-key checking
- ✅ **Helm** — `latest`/missing image tags, privileged containers, root execution,
  `hostNetwork`/`hostPID`/`hostIPC`, dangerous capabilities, missing resource
  limits/probes
- ✅ **OpenShift** — insecure `Route` TLS policy, permissive
  `SecurityContextConstraints`, KubeVirt `VirtualMachine` hardening (resource
  limits, cloud-init credential handling, eviction strategy)
- ✅ Tolerant YAML parsing — handles custom tags like `!vault` (ansible-vault) and
  `!reference` (GitLab CI) without aborting the whole file
- ✅ JSON or text output, configurable `--fail-on` severity gate for CI/CD
- ✅ Zero heavy dependencies (just `PyYAML`), single-file script
- ✅ 60+ passing pytest tests

## Requirements

- Python 3.10+
- [PyYAML](https://pypi.org/project/PyYAML/)

## Installation

```bash
git clone https://github.com/<your-org>/bio-pipeline-check.git
cd bio-pipeline-check
pip install -r requirements.txt   # or: pip install pyyaml
```

No packaging/install step is required beyond the dependency — `bio_pipeline_check.py`
is a standalone script.

## Usage

```bash
# Check an Ansible tree, a Helm chart directory, and raw OpenShift manifests
python bio_pipeline_check.py \
  --ansible-path ./ansible \
  --helm-path ./charts \
  --openshift-path ./manifests

# JSON report written to a file, only fail the pipeline on critical findings
python bio_pipeline_check.py --helm-path ./charts --format json -o report.json --fail-on critical

# Only OpenShift objects that live outside a Helm chart
# (Route/SecurityContextConstraints/VirtualMachine templated *inside* a chart
# are already checked automatically via --helm-path)
python bio_pipeline_check.py --openshift-path ./manifests --fail-on high
```

### CLI options

| Flag | Description |
|---|---|
| `--ansible-path PATH` | File or directory with Ansible playbooks/roles |
| `--helm-path PATH` | Directory containing one or more Helm charts (anything with a `Chart.yaml`) |
| `--openshift-path PATH` | File or directory with raw OpenShift manifests not already covered by `--helm-path` |
| `--format {text,json}` | Output format (default: `text`) |
| `-o, --output FILE` | Write the report to a file instead of stdout |
| `--fail-on {low,medium,high,critical}` | Minimum severity that triggers a non-zero exit code (default: `high`) |

At least one of `--ansible-path`, `--helm-path`, `--openshift-path` is required.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at/above `--fail-on` severity |
| `1` | Findings at/above `--fail-on` severity — pipeline should fail |
| `2` | Usage or runtime error |

## CI/CD examples

<details>
<summary>GitHub Actions</summary>

```yaml
name: BIO baseline check
on: [push, pull_request]

jobs:
  bio-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install pyyaml
      - run: |
          python bio_pipeline_check.py \
            --ansible-path ./ansible \
            --helm-path ./charts \
            --openshift-path ./manifests \
            --fail-on high
```
</details>

<details>
<summary>GitLab CI</summary>

```yaml
bio-compliance-check:
  stage: test
  image: python:3.12-slim
  script:
    - pip install pyyaml
    - python bio_pipeline_check.py --ansible-path ./ansible --helm-path ./charts --format json -o bio-report.json --fail-on high
  artifacts:
    when: always
    paths:
      - bio-report.json
```
</details>

## Checks reference

### Ansible (`ANS0xx`)

| ID | Severity | Category | Description |
|---|---|---|---|
| `ANS000` | Low | Configuratiebeheer | File could not be parsed as YAML |
| `ANS001` | Critical | Cryptografie / Sleutelbeheer | Possible hardcoded secret in `vars` (not vault/lookup/Jinja) |
| `ANS002` | High | Cryptografie | TLS certificate validation disabled (`validate_certs: false`) |
| `ANS003` | High | Logging en monitoring | Task handles a sensitive field without `no_log: true` |
| `ANS004` | Medium | Toegangsbeveiliging | `become: true` without an explicit `become_user` |
| `ANS005` | High | Netwerkbeveiliging | SSH `StrictHostKeyChecking` disabled |

### Helm (`HLM0xx`)

| ID | Severity | Category | Description |
|---|---|---|---|
| `HLM000` | Low | Configuratiebeheer | `values.yaml` could not be parsed |
| `HLM001` | Medium | Wijzigingsbeheer | `image.tag` in `values.yaml` is `latest` or missing |
| `HLM002` | Medium | Wijzigingsbeheer | Container image uses the `latest` tag |
| `HLM003` | Critical | Hardening | Container runs `privileged: true` |
| `HLM004` | Medium/High | Toegangsbeveiliging | `runAsNonRoot` missing or explicitly `false` |
| `HLM005` | High | Toegangsbeveiliging | Container explicitly runs as UID 0 (root) |
| `HLM006` | High | Netwerkbeveiliging | Pod uses `hostNetwork: true` |
| `HLM007` | High | Hardening | Pod shares host PID or IPC namespace |
| `HLM008` | High | Hardening | `allowPrivilegeEscalation: true` |
| `HLM009` | Critical | Hardening | All Linux capabilities added (`capabilities.add: ALL`) |
| `HLM010` | Low | Hardening | `readOnlyRootFilesystem: false` |
| `HLM011` | Medium | Continuïteit / Capaciteitsbeheer | No resource requests/limits defined |
| `HLM012` | Low | Continuïteit | No `livenessProbe` defined |
| `HLM013` | Low | Continuïteit | No `readinessProbe` defined |

### OpenShift (`OCP0xx`)

| ID | Severity | Category | Description |
|---|---|---|---|
| `OCP001` | High | Cryptografie / Transportbeveiliging | `Route` has no `tls:` block |
| `OCP002` | Medium | Cryptografie / Transportbeveiliging | `Route` allows `insecureEdgeTerminationPolicy: Allow` |
| `OCP003` | Critical | Hardening | `SecurityContextConstraints` allows `allowPrivilegedContainer: true` |
| `OCP004` | High | Netwerkbeveiliging | SCC allows host network, host PID, or host ports |
| `OCP005` | Medium | Toegangsbeveiliging | SCC uses `runAsUser.type: RunAsAny` |
| `OCP006` | High | Hardening | SCC allows `allowPrivilegeEscalation: true` |
| `OCP007` | Medium | Continuïteit / Capaciteitsbeheer | KubeVirt `VirtualMachine` has no `spec.domain.resources` |
| `OCP008` | Critical | Cryptografie / Sleutelbeheer | Plaintext password in cloud-init `userData` |
| `OCP009` | High | Toegangsbeveiliging | VM access configured via cloud-init instead of `accessCredentials` |
| `OCP010` | Low | Continuïteit | `runStrategy: Always` without an `evictionStrategy` |

## Testing

```bash
pip install pytest pyyaml
pytest -v test_bio_pipeline_check.py
```

## Extending

Add a new check by adding a method to `AnsibleChecker`, `HelmChecker`, or
`OpenShiftChecker` in `bio_pipeline_check.py`, returning `Finding` objects, then
add matching test cases (good + bad fixtures) to `test_bio_pipeline_check.py`.

## Limitations

- Helm/OpenShift templates are checked via targeted regex on raw text (Go template
  syntax like `{{ .Values.x }}` isn't valid YAML, so a text-based approach is more
  robust than parsing), not a full Helm render — deeply nested or unusually
  formatted manifests may be missed.
- This is a heuristic linter, not a substitute for `kube-linter`, `checkov`,
  `ansible-lint`, or an official BIO2 audit.
- Control-category labels are illustrative, not authoritative BIO2 clause numbers.

## License

Add a license of your choice (e.g. MIT, Apache-2.0) before publishing.

## Contributing

Issues and pull requests welcome. Please include a test case (good + bad fixture)
for any new check.
