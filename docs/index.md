# BIO Pipeline Check

**A security gate for your pipeline**: scans Ansible playbooks and roles, Helm charts and
OpenShift manifests for hardening issues, mapped to BIO2 control categories, and exits
non-zero when findings reach the severity you choose.

<div class="grid cards" markdown>

-   :material-rocket-launch: **[Install](install.md)**

    One script, only `PyYAML`.

-   :material-console: **[Usage](usage.md)**

    Text or JSON output, `--fail-on` severity gate.

-   :material-pipe: **[CI/CD examples](ci.md)**

    GitHub Actions and GitLab CI.

-   :material-format-list-checks: **[Checks reference](checks.md)**

    Every rule, its severity and BIO2 category.

</div>

## Features

| Scans | What it finds |
|---|---|
| **Ansible** | Hardcoded secrets, disabled TLS validation, missing `no_log`, unpinned privilege escalation, disabled host-key checking |
| **Helm** | `latest` or missing image tags, privileged or root containers, `hostNetwork`/`hostPID`/`hostIPC`, dangerous capabilities, missing limits and probes |
| **OpenShift** | Insecure Route TLS, permissive SCCs, KubeVirt `VirtualMachine` hardening |
| **Tolerant YAML** | Custom tags like `!vault` and `!reference` don't abort a file |
| **Tested** | 60+ pytest tests |

!!! warning "Heuristic linter, not an attestation"
    `control_category` is a generic BIO2 category, not an official measure number. Check
    findings against the BIO2 documents on [bio-overheid.nl](https://www.bio-overheid.nl/).
