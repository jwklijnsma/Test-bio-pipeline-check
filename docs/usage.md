# Usage

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

## CLI options

| Flag | Description |
|---|---|
| `--ansible-path PATH` | File or directory with Ansible playbooks/roles |
| `--helm-path PATH` | Directory containing one or more Helm charts (anything with a `Chart.yaml`) |
| `--openshift-path PATH` | File or directory with raw OpenShift manifests not already covered by `--helm-path` |
| `--format {text,json}` | Output format (default: `text`) |
| `-o, --output FILE` | Write the report to a file instead of stdout |
| `--fail-on {low,medium,high,critical}` | Minimum severity that triggers a non-zero exit code (default: `high`) |

At least one of `--ansible-path`, `--helm-path`, `--openshift-path` is required.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at/above `--fail-on` severity |
| `1` | Findings at/above `--fail-on` severity — pipeline should fail |
| `2` | Usage or runtime error |
