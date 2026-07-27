#!/usr/bin/env python3
"""
bio_pipeline_check.py
======================

Baseline Informatiebeveiliging Overheid (BIO2) style compliance checker
for Ansible playbooks/roles and Helm charts, meant to run as a gate in a
CI/CD pipeline.

IMPORTANT: The "control" labels used here are generic BIO2 control
*categories* (e.g. "Toegangsbeveiliging", "Cryptografie", "Hardening"),
not verbatim official BIO2 article/measure numbers. Always cross-check
against the authoritative BIO2 document / Excel from bio-overheid.nl
before treating this as a formal compliance attestation.

Usage:
    python bio_pipeline_check.py --ansible-path ./playbooks --helm-path ./charts
    python bio_pipeline_check.py --ansible-path ./playbooks --format json -o report.json
    python bio_pipeline_check.py --helm-path ./charts --fail-on medium

Exit codes:
    0 -> no findings at/above --fail-on severity
    1 -> findings at/above --fail-on severity (pipeline should fail)
    2 -> usage / runtime error
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
from enum import Enum
from pathlib import Path
from typing import Iterable

import yaml


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls[value.upper()]

    def __str__(self) -> str:
        return self.name


@dataclasses.dataclass
class Finding:
    check_id: str          # short machine id, e.g. ANS001
    control_category: str  # generic BIO2 control category
    severity: Severity
    message: str
    file: str
    line: int | None = None

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["severity"] = str(self.severity)
        return d


# --------------------------------------------------------------------------- #
# Ansible checks (operate on parsed YAML)
# --------------------------------------------------------------------------- #

SECRET_KEY_PATTERN = re.compile(
    r"(password|secret|token|api_key|apikey|private_key|passwd)$", re.IGNORECASE
)
# Values that indicate the secret is NOT hardcoded (vault, lookup, env, jinja var)
SAFE_VALUE_PATTERN = re.compile(
    r"^\s*(\{\{.*\}\}|\$ANSIBLE_VAULT|!vault)", re.IGNORECASE | re.DOTALL
)


# --------------------------------------------------------------------------- #
# Tolerant YAML loading
# --------------------------------------------------------------------------- #
#
# Real Ansible/CI repos use custom YAML tags that plain yaml.safe_load()
# rejects outright, which previously made the checker abandon the *entire*
# file (reported only as a single ANS000 parse-error finding) instead of
# still running the real checks on the rest of the document:
#
#   - !vault   -> ansible-vault encrypted scalar (e.g. `password: !vault |`)
#   - !reference -> GitLab CI YAML anchor/reference shorthand
#
# TolerantSafeLoader resolves any *unrecognized* "!tag" as its underlying
# scalar/sequence/mapping value instead of raising, so the rest of the
# document still gets checked. This also means a `!vault` encrypted value
# is now correctly recognized as NOT a hardcoded secret (its decrypted-form
# text starts with "$ANSIBLE_VAULT;..."), rather than silently skipped
# because the whole file failed to parse.

class TolerantSafeLoader(yaml.SafeLoader):
    pass


def _construct_unknown(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return None


# Matches any locally-defined tag ("!vault", "!reference", "!include", ...).
# Standard YAML core tags resolve to "tag:yaml.org,2002:..." URIs and are
# unaffected by this.
TolerantSafeLoader.add_multi_constructor("!", _construct_unknown)


def load_yaml_documents(text: str) -> list:
    return list(yaml.load_all(text, Loader=TolerantSafeLoader))


class AnsibleChecker:
    """Runs BIO-style checks against parsed Ansible YAML documents."""

    def check_file(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            text = path.read_text(encoding="utf-8")
            docs = load_yaml_documents(text)
        except yaml.YAMLError as exc:
            return [
                Finding(
                    "ANS000", "Configuratiebeheer", Severity.LOW,
                    f"Could not parse YAML: {exc}", str(path),
                )
            ]

        for doc in docs:
            if doc is None:
                continue
            findings.extend(self._check_document(doc, path))
        return findings

    def _check_document(self, doc, path: Path) -> list[Finding]:
        findings: list[Finding] = []

        # A playbook is normally a list of plays; a role's vars/tasks file
        # is normally a list of tasks or a dict of vars.
        if isinstance(doc, list):
            for item in doc:
                if not isinstance(item, dict):
                    continue
                findings.extend(self._check_vars_block(item.get("vars", {}), path))
                tasks = item.get("tasks") or ([item] if "module" not in item and self._looks_like_task(item) else [])
                for task in item.get("tasks", []) or []:
                    findings.extend(self._check_task(task, path))
                # role-file style: whole doc is a list of tasks
                if self._looks_like_task(item):
                    findings.extend(self._check_task(item, path))
        elif isinstance(doc, dict):
            findings.extend(self._check_vars_block(doc.get("vars", {}), path))

        return findings

    @staticmethod
    def _looks_like_task(item: dict) -> bool:
        # Heuristic: dict has a 'name' plus at least one key that isn't a
        # known play-level key -> treat as a task.
        play_keys = {"hosts", "vars", "tasks", "roles", "become", "handlers", "pre_tasks", "post_tasks"}
        return isinstance(item, dict) and bool(set(item.keys()) - play_keys)

    def _check_vars_block(self, variables, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(variables, dict):
            return findings
        for key, value in variables.items():
            if SECRET_KEY_PATTERN.search(str(key)) and isinstance(value, str):
                if not SAFE_VALUE_PATTERN.match(value):
                    findings.append(
                        Finding(
                            "ANS001",
                            "Cryptografie / Sleutelbeheer",
                            Severity.CRITICAL,
                            f"Mogelijk hardcoded secret in var '{key}'. Gebruik ansible-vault "
                            f"of een lookup plugin in plaats van platte tekst.",
                            str(path),
                        )
                    )
        return findings

    def _check_task(self, task: dict, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(task, dict):
            return findings

        task_name = task.get("name", "<unnamed task>")

        # 1. TLS / certificate validation disabled
        for mod_name in ("uri", "get_url", "ansible.builtin.uri", "ansible.builtin.get_url"):
            mod = task.get(mod_name)
            if isinstance(mod, dict) and mod.get("validate_certs") is False:
                findings.append(
                    Finding(
                        "ANS002", "Cryptografie", Severity.HIGH,
                        f"Task '{task_name}' disables TLS certificate validation "
                        f"(validate_certs: false).",
                        str(path),
                    )
                )

        # 2. no_log missing on tasks that clearly handle secrets
        module_names = [k for k in task.keys() if k not in (
            "name", "become", "become_user", "when", "tags", "register",
            "no_log", "loop", "with_items", "vars", "notify", "changed_when",
            "failed_when", "ignore_errors", "delegate_to",
        )]
        for mod_name in module_names:
            mod_args = task.get(mod_name)
            if isinstance(mod_args, dict):
                for arg_key, arg_val in mod_args.items():
                    if SECRET_KEY_PATTERN.search(str(arg_key)) and task.get("no_log") is not True:
                        findings.append(
                            Finding(
                                "ANS003", "Logging en monitoring", Severity.HIGH,
                                f"Task '{task_name}' verwerkt een gevoelig veld "
                                f"('{arg_key}') zonder no_log: true, risico op "
                                f"lekken van gevoelige data in logs.",
                                str(path),
                            )
                        )
                        break

        # 3. become without become_user pinned (privilege escalation hardening)
        if task.get("become") is True and "become_user" not in task:
            findings.append(
                Finding(
                    "ANS004", "Toegangsbeveiliging", Severity.MEDIUM,
                    f"Task '{task_name}' gebruikt 'become: true' zonder expliciete "
                    f"'become_user'; escaleert impliciet naar root.",
                    str(path),
                )
            )

        # 4. SSH host key checking disabled via shell/command/env trick
        for mod_name in ("shell", "command", "ansible.builtin.shell", "ansible.builtin.command"):
            mod = task.get(mod_name)
            cmd_text = mod if isinstance(mod, str) else (mod or {}).get("cmd", "") if isinstance(mod, dict) else ""
            if cmd_text and "StrictHostKeyChecking=no" in cmd_text:
                findings.append(
                    Finding(
                        "ANS005", "Netwerkbeveiliging", Severity.HIGH,
                        f"Task '{task_name}' schakelt SSH StrictHostKeyChecking uit.",
                        str(path),
                    )
                )

        return findings


# --------------------------------------------------------------------------- #
# Helm checks
# --------------------------------------------------------------------------- #

# Helm templates use Go template syntax ({{ ... }}) which is not valid YAML,
# so templates are checked with targeted regexes on raw text. values.yaml /
# Chart.yaml are plain YAML and parsed normally.

class HelmChecker:
    IMAGE_LATEST_RE = re.compile(r"image:\s*[\"']?[\w./\-:]+:latest[\"']?", re.IGNORECASE)
    IMAGE_NO_TAG_RE = re.compile(r"image:\s*[\"']?[\w./\-]+[\"']?\s*$", re.MULTILINE)
    PRIVILEGED_RE = re.compile(r"privileged:\s*true", re.IGNORECASE)
    RUN_AS_NONROOT_FALSE_RE = re.compile(r"runAsNonRoot:\s*false", re.IGNORECASE)
    RUN_AS_USER_ROOT_RE = re.compile(r"runAsUser:\s*0\b")
    HOST_NETWORK_RE = re.compile(r"hostNetwork:\s*true", re.IGNORECASE)
    HOST_PID_RE = re.compile(r"hostPID:\s*true", re.IGNORECASE)
    HOST_IPC_RE = re.compile(r"hostIPC:\s*true", re.IGNORECASE)
    ALLOW_PRIV_ESC_RE = re.compile(r"allowPrivilegeEscalation:\s*true", re.IGNORECASE)
    CAP_ADD_ALL_RE = re.compile(r"add:\s*\n\s*-\s*[\"']?ALL[\"']?", re.IGNORECASE)
    READ_ONLY_ROOT_FS_FALSE_RE = re.compile(r"readOnlyRootFilesystem:\s*false", re.IGNORECASE)
    CONTAINER_BLOCK_RE = re.compile(r"^\s*-?\s*name:\s*\S+", re.MULTILINE)

    def check_chart(self, chart_dir: Path) -> list[Finding]:
        findings: list[Finding] = []

        values_file = chart_dir / "values.yaml"
        if values_file.exists():
            findings.extend(self._check_values_yaml(values_file))

        templates_dir = chart_dir / "templates"
        search_dir = templates_dir if templates_dir.exists() else chart_dir
        openshift_checker = OpenShiftChecker()
        for tpl_path in sorted(search_dir.rglob("*.yaml")) + sorted(search_dir.rglob("*.yml")):
            findings.extend(self._check_template_text(tpl_path))
            # Charts can also carry OpenShift-specific objects (Route, SCC,
            # KubeVirt VirtualMachine); check those too.
            findings.extend(openshift_checker.check_manifest_text(tpl_path))

        return findings

    def _check_values_yaml(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = yaml.load(path.read_text(encoding="utf-8"), Loader=TolerantSafeLoader) or {}
        except yaml.YAMLError as exc:
            return [
                Finding("HLM000", "Configuratiebeheer", Severity.LOW,
                        f"Could not parse values.yaml: {exc}", str(path))
            ]

        image = data.get("image")
        if isinstance(image, dict):
            tag = image.get("tag")
            if tag in (None, "", "latest"):
                findings.append(
                    Finding(
                        "HLM001", "Wijzigingsbeheer", Severity.MEDIUM,
                        "image.tag in values.yaml is 'latest' of ontbreekt; gebruik "
                        "een vaste, traceerbare versie/digest.",
                        str(path),
                    )
                )
        return findings

    def _check_template_text(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        text = path.read_text(encoding="utf-8")

        def add(check_id, category, severity, message):
            findings.append(Finding(check_id, category, severity, message, str(path)))

        if self.IMAGE_LATEST_RE.search(text):
            add("HLM002", "Wijzigingsbeheer", Severity.MEDIUM,
                "Container image gebruikt de 'latest' tag; niet reproduceerbaar/traceerbaar.")

        if self.PRIVILEGED_RE.search(text):
            add("HLM003", "Hardening", Severity.CRITICAL,
                "Container draait 'privileged: true'; volledige host-toegang, vermijd dit.")

        if self.RUN_AS_NONROOT_FALSE_RE.search(text) or "runAsNonRoot" not in text:
            severity = Severity.HIGH if self.RUN_AS_NONROOT_FALSE_RE.search(text) else Severity.MEDIUM
            reason = ("runAsNonRoot: false is expliciet gezet"
                      if self.RUN_AS_NONROOT_FALSE_RE.search(text)
                      else "runAsNonRoot ontbreekt (mogelijk root-uitvoering)")
            add("HLM004", "Toegangsbeveiliging", severity,
                f"securityContext.{reason} in {path.name}.")

        if self.RUN_AS_USER_ROOT_RE.search(text):
            add("HLM005", "Toegangsbeveiliging", Severity.HIGH,
                "Container is expliciet geconfigureerd om als UID 0 (root) te draaien.")

        if self.HOST_NETWORK_RE.search(text):
            add("HLM006", "Netwerkbeveiliging", Severity.HIGH,
                "Pod gebruikt hostNetwork: true; omzeilt netwerksegmentatie van het cluster.")

        if self.HOST_PID_RE.search(text) or self.HOST_IPC_RE.search(text):
            add("HLM007", "Hardening", Severity.HIGH,
                "Pod deelt host PID- of IPC-namespace; verzwakt procesisolatie.")

        if self.ALLOW_PRIV_ESC_RE.search(text):
            add("HLM008", "Hardening", Severity.HIGH,
                "allowPrivilegeEscalation: true staat toe dat een proces meer rechten krijgt dan de parent.")

        if self.CAP_ADD_ALL_RE.search(text):
            add("HLM009", "Hardening", Severity.CRITICAL,
                "Container voegt alle Linux capabilities toe (capabilities.add: ALL).")

        if self.READ_ONLY_ROOT_FS_FALSE_RE.search(text):
            add("HLM010", "Hardening", Severity.LOW,
                "readOnlyRootFilesystem: false; overweeg een read-only root filesystem.")

        if "resources:" not in text and self.CONTAINER_BLOCK_RE.search(text) and "containers:" in text:
            add("HLM011", "Continuiteit / Capaciteitsbeheer", Severity.MEDIUM,
                "Geen resources (requests/limits) gedefinieerd voor container(s).")

        if "containers:" in text and "livenessProbe:" not in text:
            add("HLM012", "Continuiteit", Severity.LOW,
                "Geen livenessProbe gedefinieerd voor container(s).")

        if "containers:" in text and "readinessProbe:" not in text:
            add("HLM013", "Continuiteit", Severity.LOW,
                "Geen readinessProbe gedefinieerd voor container(s).")

        return findings


# --------------------------------------------------------------------------- #
# OpenShift checks: Route, SecurityContextConstraints, KubeVirt VirtualMachine
# --------------------------------------------------------------------------- #

class OpenShiftChecker:
    """
    Regex-based checks (same rationale as HelmChecker: manifests may be Helm
    templates with Go template syntax, so raw text scanning is more robust
    than YAML parsing) for OpenShift-specific resources:

      - Route                      (kind: Route)
      - SecurityContextConstraints (kind: SecurityContextConstraints)
      - VirtualMachine              (kind: VirtualMachine, kubevirt.io/v1)
    """

    KIND_RE = re.compile(r"^\s*kind:\s*[\"']?(\w+)[\"']?\s*$", re.MULTILINE)

    # Route
    TLS_BLOCK_RE = re.compile(r"^\s*tls:\s*$", re.MULTILINE)
    INSECURE_EDGE_ALLOW_RE = re.compile(r"insecureEdgeTerminationPolicy:\s*[\"']?Allow[\"']?", re.IGNORECASE)

    # SecurityContextConstraints
    SCC_ALLOW_PRIVILEGED_RE = re.compile(r"allowPrivilegedContainer:\s*true", re.IGNORECASE)
    SCC_ALLOW_HOST_NETWORK_RE = re.compile(r"allowHostNetwork:\s*true", re.IGNORECASE)
    SCC_ALLOW_HOST_PID_RE = re.compile(r"allowHostPID:\s*true", re.IGNORECASE)
    SCC_ALLOW_HOST_PORTS_RE = re.compile(r"allowHostPorts:\s*true", re.IGNORECASE)
    SCC_RUN_AS_USER_ANY_RE = re.compile(r"runAsUser:\s*\n\s*type:\s*RunAsAny", re.IGNORECASE)
    SCC_ALLOW_PRIV_ESC_RE = re.compile(r"allowPrivilegeEscalation:\s*true", re.IGNORECASE)

    # KubeVirt VirtualMachine
    DOMAIN_BLOCK_RE = re.compile(r"^\s*domain:\s*$", re.MULTILINE)
    DOMAIN_RESOURCES_RE = re.compile(r"domain:.*?resources:", re.IGNORECASE | re.DOTALL)
    CLOUD_INIT_RE = re.compile(r"cloudInitNoCloud|cloudInitConfigDrive", re.IGNORECASE)
    PLAINTEXT_PASSWORD_IN_USERDATA_RE = re.compile(
        r"userData:\s*\|?[\s\S]{0,400}?password:\s*(?!\{\{)[\"']?[\w!@#$%^&*\-]{3,}", re.IGNORECASE
    )
    ACCESS_CREDENTIALS_RE = re.compile(r"accessCredentials:", re.IGNORECASE)
    EVICTION_STRATEGY_RE = re.compile(r"evictionStrategy:", re.IGNORECASE)
    RUN_STRATEGY_ALWAYS_RE = re.compile(r"runStrategy:\s*[\"']?Always[\"']?", re.IGNORECASE)

    def check_manifest_text(self, path: Path) -> list[Finding]:
        text = path.read_text(encoding="utf-8")
        kinds = set(self.KIND_RE.findall(text))
        findings: list[Finding] = []

        if "Route" in kinds:
            findings.extend(self._check_route(text, path))
        if "SecurityContextConstraints" in kinds:
            findings.extend(self._check_scc(text, path))
        if "VirtualMachine" in kinds or "kubevirt.io" in text:
            findings.extend(self._check_virtual_machine(text, path))

        return findings

    def _check_route(self, text: str, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        if not self.TLS_BLOCK_RE.search(text):
            findings.append(
                Finding(
                    "OCP001", "Cryptografie / Transportbeveiliging", Severity.HIGH,
                    "Route heeft geen 'tls:' configuratie; verkeer wordt mogelijk "
                    "onversleuteld over HTTP aangeboden.",
                    str(path),
                )
            )
        if self.INSECURE_EDGE_ALLOW_RE.search(text):
            findings.append(
                Finding(
                    "OCP002", "Cryptografie / Transportbeveiliging", Severity.MEDIUM,
                    "Route staat 'insecureEdgeTerminationPolicy: Allow' toe; onversleuteld "
                    "verkeer wordt niet geweigerd of doorgestuurd. Gebruik 'Redirect' of 'None'.",
                    str(path),
                )
            )
        return findings

    def _check_scc(self, text: str, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        if self.SCC_ALLOW_PRIVILEGED_RE.search(text):
            findings.append(
                Finding(
                    "OCP003", "Hardening", Severity.CRITICAL,
                    "SecurityContextConstraints staat 'allowPrivilegedContainer: true' toe.",
                    str(path),
                )
            )
        if (self.SCC_ALLOW_HOST_NETWORK_RE.search(text)
                or self.SCC_ALLOW_HOST_PID_RE.search(text)
                or self.SCC_ALLOW_HOST_PORTS_RE.search(text)):
            findings.append(
                Finding(
                    "OCP004", "Netwerkbeveiliging", Severity.HIGH,
                    "SecurityContextConstraints staat toegang tot host-netwerk, "
                    "host-PID-namespace of host-poorten toe.",
                    str(path),
                )
            )
        if self.SCC_RUN_AS_USER_ANY_RE.search(text):
            findings.append(
                Finding(
                    "OCP005", "Toegangsbeveiliging", Severity.MEDIUM,
                    "SecurityContextConstraints gebruikt 'runAsUser.type: RunAsAny'; "
                    "pods kunnen als een willekeurige (incl. root) UID draaien. "
                    "Overweeg MustRunAsRange of MustRunAsNonRoot.",
                    str(path),
                )
            )
        if self.SCC_ALLOW_PRIV_ESC_RE.search(text):
            findings.append(
                Finding(
                    "OCP006", "Hardening", Severity.HIGH,
                    "SecurityContextConstraints staat 'allowPrivilegeEscalation: true' toe.",
                    str(path),
                )
            )
        return findings

    def _check_virtual_machine(self, text: str, path: Path) -> list[Finding]:
        findings: list[Finding] = []

        if self.DOMAIN_BLOCK_RE.search(text) and not self.DOMAIN_RESOURCES_RE.search(text):
            findings.append(
                Finding(
                    "OCP007", "Continuiteit / Capaciteitsbeheer", Severity.MEDIUM,
                    "VirtualMachine (KubeVirt) definieert geen resources "
                    "(spec.domain.resources) voor CPU/geheugen.",
                    str(path),
                )
            )

        if self.CLOUD_INIT_RE.search(text) and self.PLAINTEXT_PASSWORD_IN_USERDATA_RE.search(text):
            findings.append(
                Finding(
                    "OCP008", "Cryptografie / Sleutelbeheer", Severity.CRITICAL,
                    "cloudInit userData bevat een mogelijk hardcoded wachtwoord in "
                    "platte tekst. Gebruik een Secret en accessCredentials in plaats "
                    "hiervan.",
                    str(path),
                )
            )

        if self.CLOUD_INIT_RE.search(text) and not self.ACCESS_CREDENTIALS_RE.search(text) \
                and self.PLAINTEXT_PASSWORD_IN_USERDATA_RE.search(text):
            findings.append(
                Finding(
                    "OCP009", "Toegangsbeveiliging", Severity.HIGH,
                    "VM-toegang is geconfigureerd via cloudInit userData in plaats van "
                    "'accessCredentials' (bijv. ssh-public-key uit een Secret).",
                    str(path),
                )
            )

        if self.RUN_STRATEGY_ALWAYS_RE.search(text) and not self.EVICTION_STRATEGY_RE.search(text):
            findings.append(
                Finding(
                    "OCP010", "Continuiteit", Severity.LOW,
                    "VirtualMachine met runStrategy: Always heeft geen "
                    "evictionStrategy; gedrag bij node drain/onderhoud is impliciet.",
                    str(path),
                )
            )

        return findings


# --------------------------------------------------------------------------- #
# Runner / CLI
# --------------------------------------------------------------------------- #

def collect_ansible_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(
        p for p in root.rglob("*.yml")
        if "templates" not in p.parts  # avoid accidentally slurping helm templates
    ) + sorted(
        p for p in root.rglob("*.yaml")
        if "templates" not in p.parts
    )


def collect_helm_chart_dirs(root: Path) -> list[Path]:
    if (root / "Chart.yaml").exists():
        return [root]
    return sorted({p.parent for p in root.rglob("Chart.yaml")})


def collect_openshift_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(root.rglob("*.yaml")) + sorted(root.rglob("*.yml"))


def run_checks(
    ansible_path: str | None,
    helm_path: str | None,
    openshift_path: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if ansible_path:
        ansible_checker = AnsibleChecker()
        for f in collect_ansible_files(Path(ansible_path)):
            findings.extend(ansible_checker.check_file(f))

    if helm_path:
        helm_checker = HelmChecker()
        for chart_dir in collect_helm_chart_dirs(Path(helm_path)):
            findings.extend(helm_checker.check_chart(chart_dir))

    if openshift_path:
        openshift_checker = OpenShiftChecker()
        for f in collect_openshift_files(Path(openshift_path)):
            findings.extend(openshift_checker.check_manifest_text(f))

    return findings


def format_text(findings: list[Finding]) -> str:
    if not findings:
        return "BIO baseline check: no findings. \u2713"
    lines = [f"BIO baseline check: {len(findings)} finding(s)\n"]
    for f in sorted(findings, key=lambda x: -x.severity.value):
        lines.append(
            f"[{f.severity}] {f.check_id} ({f.control_category}) - {f.file}"
            + (f":{f.line}" if f.line else "")
        )
        lines.append(f"    {f.message}")
    return "\n".join(lines)


def format_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BIO2-style baseline compliance checker for Ansible and Helm, for CI/CD pipelines."
    )
    parser.add_argument("--ansible-path", help="File or directory with Ansible playbooks/roles")
    parser.add_argument("--helm-path", help="Directory containing one or more Helm charts (Chart.yaml)")
    parser.add_argument(
        "--openshift-path",
        help="File or directory with raw OpenShift manifests (Route, SecurityContextConstraints, "
             "KubeVirt VirtualMachine) not already covered by --helm-path",
    )
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("-o", "--output", help="Write report to this file instead of stdout")
    parser.add_argument(
        "--fail-on", choices=["low", "medium", "high", "critical"], default="high",
        help="Minimum severity that causes a non-zero exit code (pipeline gate). Default: high",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.ansible_path and not args.helm_path and not args.openshift_path:
        parser.error("Provide at least one of --ansible-path, --helm-path or --openshift-path")

    try:
        findings = run_checks(args.ansible_path, args.helm_path, args.openshift_path)
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        print(f"ERROR running BIO checks: {exc}", file=sys.stderr)
        return 2

    report = format_json(findings) if args.format == "json" else format_text(findings)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report)

    threshold = Severity.from_str(args.fail_on)
    if any(f.severity.value >= threshold.value for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
