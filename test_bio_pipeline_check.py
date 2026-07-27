"""
Tests for bio_pipeline_check.py

Run with:
    pytest -v test_bio_pipeline_check.py
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from bio_pipeline_check import (
    AnsibleChecker,
    HelmChecker,
    OpenShiftChecker,
    Severity,
    collect_ansible_files,
    collect_helm_chart_dirs,
    collect_openshift_files,
    run_checks,
    main,
)


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #

def write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


CLEAN_PLAYBOOK = """
- hosts: all
  vars:
    admin_password: "{{ vault_admin_password }}"
  tasks:
    - name: Fetch a page securely
      uri:
        url: https://example.org
        validate_certs: true
    - name: Set a password safely
      ansible.builtin.user:
        name: svc
        password: "{{ vault_admin_password }}"
      no_log: true
    - name: Escalate with pinned user
      become: true
      become_user: deploy
      ansible.builtin.command: /usr/local/bin/deploy.sh
"""

BAD_PLAYBOOK = """
- hosts: all
  vars:
    db_password: "SuperSecret123"
  tasks:
    - name: Download insecurely
      get_url:
        url: https://example.org/file
        dest: /tmp/file
        validate_certs: false
    - name: Set a password without no_log
      ansible.builtin.user:
        name: svc
        password: "hunter2"
    - name: Become root implicitly
      become: true
      ansible.builtin.command: whoami
    - name: Disable host key checking
      ansible.builtin.shell: "ssh -o StrictHostKeyChecking=no user@host uptime"
"""

GOOD_HELM_TEMPLATE = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
        - name: myapp
          image: myregistry/myapp:1.4.2
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 250m
              memory: 256Mi
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
"""

BAD_HELM_TEMPLATE = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  hostNetwork: true
  hostPID: true
  containers:
    - name: myapp
      image: myregistry/myapp:latest
      securityContext:
        privileged: true
        runAsNonRoot: false
        runAsUser: 0
        allowPrivilegeEscalation: true
        capabilities:
          add:
            - "ALL"
        readOnlyRootFilesystem: false
"""


GOOD_ROUTE = """
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: myapp
spec:
  host: myapp.apps.example.com
  to:
    kind: Service
    name: myapp
  tls:
    termination: edge
    insecureEdgeTerminationPolicy: Redirect
"""

BAD_ROUTE = """
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: myapp
spec:
  host: myapp.apps.example.com
  to:
    kind: Service
    name: myapp
"""

BAD_ROUTE_ALLOW_INSECURE = """
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: myapp
spec:
  host: myapp.apps.example.com
  to:
    kind: Service
    name: myapp
  tls:
    termination: edge
    insecureEdgeTerminationPolicy: Allow
"""

GOOD_SCC = """
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: restricted-plus
allowPrivilegedContainer: false
allowHostNetwork: false
allowHostPID: false
allowHostPorts: false
allowPrivilegeEscalation: false
runAsUser:
  type: MustRunAsRange
"""

BAD_SCC = """
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: super-permissive
allowPrivilegedContainer: true
allowHostNetwork: true
allowPrivilegeEscalation: true
runAsUser:
  type: RunAsAny
"""

GOOD_VM = """
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata:
  name: myvm
spec:
  runStrategy: Always
  template:
    spec:
      evictionStrategy: LiveMigrate
      accessCredentials:
        - sshPublicKey:
            source:
              secret:
                secretName: myvm-ssh-key
          propagationMethod:
            noCloud: {}
      domain:
        resources:
          requests:
            memory: 2Gi
            cpu: "1"
"""

BAD_VM = """
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata:
  name: myvm
spec:
  runStrategy: Always
  template:
    spec:
      domain:
        devices: {}
      volumes:
        - name: cloudinitdisk
          cloudInitNoCloud:
            userData: |
              #cloud-config
              user: cloud-user
              password: SuperSecret123
              chpasswd: { expire: False }
"""


@pytest.fixture
def clean_ansible_file(tmp_path):
    return write(tmp_path / "site.yml", CLEAN_PLAYBOOK)


@pytest.fixture
def bad_ansible_file(tmp_path):
    return write(tmp_path / "site.yml", BAD_PLAYBOOK)


@pytest.fixture
def good_helm_chart(tmp_path):
    chart_dir = tmp_path / "mychart"
    write(chart_dir / "Chart.yaml", "apiVersion: v2\nname: mychart\nversion: 0.1.0\n")
    write(chart_dir / "values.yaml", "image:\n  repository: myregistry/myapp\n  tag: 1.4.2\n")
    write(chart_dir / "templates" / "deployment.yaml", GOOD_HELM_TEMPLATE)
    return chart_dir


@pytest.fixture
def bad_helm_chart(tmp_path):
    chart_dir = tmp_path / "mychart"
    write(chart_dir / "Chart.yaml", "apiVersion: v2\nname: mychart\nversion: 0.1.0\n")
    write(chart_dir / "values.yaml", "image:\n  repository: myregistry/myapp\n  tag: latest\n")
    write(chart_dir / "templates" / "deployment.yaml", BAD_HELM_TEMPLATE)
    return chart_dir


# --------------------------------------------------------------------------- #
# AnsibleChecker tests
# --------------------------------------------------------------------------- #

class TestAnsibleChecker:
    def test_clean_playbook_has_no_high_or_critical_findings(self, clean_ansible_file):
        findings = AnsibleChecker().check_file(clean_ansible_file)
        severe = [f for f in findings if f.severity.value >= Severity.HIGH.value]
        assert severe == []

    def test_detects_hardcoded_secret_in_vars(self, bad_ansible_file):
        findings = AnsibleChecker().check_file(bad_ansible_file)
        ids = {f.check_id for f in findings}
        assert "ANS001" in ids
        finding = next(f for f in findings if f.check_id == "ANS001")
        assert finding.severity == Severity.CRITICAL

    def test_detects_disabled_tls_validation(self, bad_ansible_file):
        findings = AnsibleChecker().check_file(bad_ansible_file)
        assert any(f.check_id == "ANS002" for f in findings)

    def test_detects_missing_no_log_on_sensitive_task(self, bad_ansible_file):
        findings = AnsibleChecker().check_file(bad_ansible_file)
        assert any(f.check_id == "ANS003" for f in findings)

    def test_no_log_true_suppresses_ans003(self, clean_ansible_file):
        findings = AnsibleChecker().check_file(clean_ansible_file)
        assert not any(f.check_id == "ANS003" for f in findings)

    def test_detects_unpinned_become_user(self, bad_ansible_file):
        findings = AnsibleChecker().check_file(bad_ansible_file)
        assert any(f.check_id == "ANS004" for f in findings)

    def test_pinned_become_user_does_not_flag(self, clean_ansible_file):
        findings = AnsibleChecker().check_file(clean_ansible_file)
        assert not any(f.check_id == "ANS004" for f in findings)

    def test_detects_disabled_host_key_checking(self, bad_ansible_file):
        findings = AnsibleChecker().check_file(bad_ansible_file)
        assert any(f.check_id == "ANS005" for f in findings)

    def test_vault_reference_is_not_flagged_as_hardcoded(self, clean_ansible_file):
        findings = AnsibleChecker().check_file(clean_ansible_file)
        assert not any(f.check_id == "ANS001" for f in findings)

    def test_invalid_yaml_produces_low_severity_parse_finding(self, tmp_path):
        bad_yaml = write(tmp_path / "broken.yml", "- hosts: all\n  vars: [unterminated\n")
        findings = AnsibleChecker().check_file(bad_yaml)
        assert len(findings) == 1
        assert findings[0].check_id == "ANS000"
        assert findings[0].severity == Severity.LOW

    def test_empty_file_produces_no_findings(self, tmp_path):
        empty = write(tmp_path / "empty.yml", "")
        assert AnsibleChecker().check_file(empty) == []

    def test_vault_tagged_var_does_not_break_file_parsing(self, tmp_path):
        # Real ansible-vault encrypted scalar: the plaintext content of a
        # !vault block always starts with "$ANSIBLE_VAULT;...".
        vault_playbook = """
- hosts: all
  vars:
    reporting_api_key: !vault |
      $ANSIBLE_VAULT;1.1;AES256
      66386439653236336462626566653063336164663966303231363934653561363964363833
    plain_admin_password: "hunter2"
  tasks:
    - name: noop
      ansible.builtin.debug:
        msg: hello
"""
        f = write(tmp_path / "vault.yml", vault_playbook)
        findings = AnsibleChecker().check_file(f)
        # File must be parsed (no ANS000 parse-error finding)...
        assert not any(fi.check_id == "ANS000" for fi in findings)
        # ...the vault-encrypted var must NOT be flagged as a hardcoded secret...
        ans001 = [fi for fi in findings if fi.check_id == "ANS001"]
        assert not any("reporting_api_key" in fi.message for fi in ans001)
        # ...but a genuinely plaintext secret elsewhere in the same file still is.
        assert any("plain_admin_password" in fi.message for fi in ans001)

    def test_gitlab_reference_tag_does_not_break_parsing(self, tmp_path):
        # !reference is GitLab CI syntax, not Ansible, but repos sometimes get
        # scanned broadly; the loader should tolerate it rather than aborting.
        ci_like_yaml = """
job:
  rules:
    - !reference [.infra-rules]
  variables:
    FOO: bar
"""
        f = write(tmp_path / "pipeline.yml", ci_like_yaml)
        findings = AnsibleChecker().check_file(f)
        assert not any(fi.check_id == "ANS000" for fi in findings)

    def test_genuinely_malformed_yaml_still_reports_ans000(self, tmp_path):
        bad_yaml = write(tmp_path / "broken2.yml", "- hosts: all\n  vars: [unterminated\n")
        findings = AnsibleChecker().check_file(bad_yaml)
        assert any(fi.check_id == "ANS000" for fi in findings)


# --------------------------------------------------------------------------- #
# HelmChecker tests
# --------------------------------------------------------------------------- #

class TestHelmChecker:
    def test_good_chart_has_no_critical_or_high_findings(self, good_helm_chart):
        findings = HelmChecker().check_chart(good_helm_chart)
        severe = [f for f in findings if f.severity.value >= Severity.HIGH.value]
        assert severe == [], f"Unexpected severe findings: {severe}"

    def test_detects_privileged_container(self, bad_helm_chart):
        findings = HelmChecker().check_chart(bad_helm_chart)
        assert any(f.check_id == "HLM003" for f in findings)
        f = next(f for f in findings if f.check_id == "HLM003")
        assert f.severity == Severity.CRITICAL

    def test_detects_latest_tag_in_template(self, bad_helm_chart):
        findings = HelmChecker().check_chart(bad_helm_chart)
        assert any(f.check_id == "HLM002" for f in findings)

    def test_detects_latest_tag_in_values_yaml(self, bad_helm_chart):
        findings = HelmChecker().check_chart(bad_helm_chart)
        assert any(f.check_id == "HLM001" for f in findings)

    def test_detects_run_as_root_uid(self, bad_helm_chart):
        findings = HelmChecker().check_chart(bad_helm_chart)
        assert any(f.check_id == "HLM005" for f in findings)

    def test_detects_host_network(self, bad_helm_chart):
        findings = HelmChecker().check_chart(bad_helm_chart)
        assert any(f.check_id == "HLM006" for f in findings)

    def test_detects_host_pid(self, bad_helm_chart):
        findings = HelmChecker().check_chart(bad_helm_chart)
        assert any(f.check_id == "HLM007" for f in findings)

    def test_detects_allow_privilege_escalation(self, bad_helm_chart):
        findings = HelmChecker().check_chart(bad_helm_chart)
        assert any(f.check_id == "HLM008" for f in findings)

    def test_detects_capabilities_add_all(self, bad_helm_chart):
        findings = HelmChecker().check_chart(bad_helm_chart)
        assert any(f.check_id == "HLM009" for f in findings)

    def test_detects_missing_resource_limits(self, bad_helm_chart):
        findings = HelmChecker().check_chart(bad_helm_chart)
        assert any(f.check_id == "HLM011" for f in findings)

    def test_good_chart_has_resource_limits_defined(self, good_helm_chart):
        findings = HelmChecker().check_chart(good_helm_chart)
        assert not any(f.check_id == "HLM011" for f in findings)

    def test_good_chart_has_probes_defined(self, good_helm_chart):
        findings = HelmChecker().check_chart(good_helm_chart)
        assert not any(f.check_id in ("HLM012", "HLM013") for f in findings)


# --------------------------------------------------------------------------- #
# OpenShiftChecker tests (Route / SCC / KubeVirt VirtualMachine)
# --------------------------------------------------------------------------- #

class TestOpenShiftChecker:
    def test_good_route_has_no_findings(self, tmp_path):
        route_file = write(tmp_path / "route.yaml", GOOD_ROUTE)
        findings = OpenShiftChecker().check_manifest_text(route_file)
        assert findings == []

    def test_route_without_tls_is_flagged(self, tmp_path):
        route_file = write(tmp_path / "route.yaml", BAD_ROUTE)
        findings = OpenShiftChecker().check_manifest_text(route_file)
        assert any(f.check_id == "OCP001" for f in findings)
        f = next(f for f in findings if f.check_id == "OCP001")
        assert f.severity == Severity.HIGH

    def test_route_insecure_edge_policy_allow_is_flagged(self, tmp_path):
        route_file = write(tmp_path / "route.yaml", BAD_ROUTE_ALLOW_INSECURE)
        findings = OpenShiftChecker().check_manifest_text(route_file)
        assert any(f.check_id == "OCP002" for f in findings)

    def test_non_route_yaml_is_not_flagged_by_route_checks(self, tmp_path):
        f = write(tmp_path / "service.yaml", "apiVersion: v1\nkind: Service\nspec:\n  ports: []\n")
        findings = OpenShiftChecker().check_manifest_text(f)
        assert not any(fi.check_id.startswith("OCP00") and fi.check_id <= "OCP002" for fi in findings)

    def test_good_scc_has_no_findings(self, tmp_path):
        scc_file = write(tmp_path / "scc.yaml", GOOD_SCC)
        findings = OpenShiftChecker().check_manifest_text(scc_file)
        assert findings == []

    def test_scc_allow_privileged_container_is_critical(self, tmp_path):
        scc_file = write(tmp_path / "scc.yaml", BAD_SCC)
        findings = OpenShiftChecker().check_manifest_text(scc_file)
        f = next(f for f in findings if f.check_id == "OCP003")
        assert f.severity == Severity.CRITICAL

    def test_scc_allow_host_network_is_flagged(self, tmp_path):
        scc_file = write(tmp_path / "scc.yaml", BAD_SCC)
        findings = OpenShiftChecker().check_manifest_text(scc_file)
        assert any(f.check_id == "OCP004" for f in findings)

    def test_scc_run_as_user_any_is_flagged(self, tmp_path):
        scc_file = write(tmp_path / "scc.yaml", BAD_SCC)
        findings = OpenShiftChecker().check_manifest_text(scc_file)
        assert any(f.check_id == "OCP005" for f in findings)

    def test_scc_allow_privilege_escalation_is_flagged(self, tmp_path):
        scc_file = write(tmp_path / "scc.yaml", BAD_SCC)
        findings = OpenShiftChecker().check_manifest_text(scc_file)
        assert any(f.check_id == "OCP006" for f in findings)

    def test_good_vm_has_no_findings(self, tmp_path):
        vm_file = write(tmp_path / "vm.yaml", GOOD_VM)
        findings = OpenShiftChecker().check_manifest_text(vm_file)
        assert findings == []

    def test_vm_missing_domain_resources_is_flagged(self, tmp_path):
        vm_file = write(tmp_path / "vm.yaml", BAD_VM)
        findings = OpenShiftChecker().check_manifest_text(vm_file)
        assert any(f.check_id == "OCP007" for f in findings)

    def test_vm_plaintext_password_in_userdata_is_critical(self, tmp_path):
        vm_file = write(tmp_path / "vm.yaml", BAD_VM)
        findings = OpenShiftChecker().check_manifest_text(vm_file)
        f = next(f for f in findings if f.check_id == "OCP008")
        assert f.severity == Severity.CRITICAL

    def test_vm_using_cloudinit_credentials_instead_of_access_credentials_is_flagged(self, tmp_path):
        vm_file = write(tmp_path / "vm.yaml", BAD_VM)
        findings = OpenShiftChecker().check_manifest_text(vm_file)
        assert any(f.check_id == "OCP009" for f in findings)

    def test_vm_with_access_credentials_not_flagged_for_ocp009(self, tmp_path):
        vm_file = write(tmp_path / "vm.yaml", GOOD_VM)
        findings = OpenShiftChecker().check_manifest_text(vm_file)
        assert not any(f.check_id == "OCP009" for f in findings)

    def test_run_strategy_always_without_eviction_strategy_is_flagged(self, tmp_path):
        vm_file = write(tmp_path / "vm.yaml", BAD_VM)
        findings = OpenShiftChecker().check_manifest_text(vm_file)
        assert any(f.check_id == "OCP010" for f in findings)

    def test_run_strategy_always_with_eviction_strategy_not_flagged(self, tmp_path):
        vm_file = write(tmp_path / "vm.yaml", GOOD_VM)
        findings = OpenShiftChecker().check_manifest_text(vm_file)
        assert not any(f.check_id == "OCP010" for f in findings)

    def test_detects_kubevirt_by_apiversion_even_without_exact_kind_match(self, tmp_path):
        # kubevirt.io present in apiVersion should still trigger VM checks,
        # even if 'kind' were something unexpected/templated.
        text = (
            "apiVersion: kubevirt.io/v1\n"
            "kind: VirtualMachine\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      domain:\n"
            "        devices: {}\n"
        )
        vm_file = write(tmp_path / "vm.yaml", text)
        findings = OpenShiftChecker().check_manifest_text(vm_file)
        assert any(f.check_id == "OCP007" for f in findings)


class TestOpenShiftIntegration:
    """OpenShift objects embedded inside a Helm chart should also be caught."""

    def test_helm_chart_with_embedded_bad_route_is_flagged(self, tmp_path):
        chart_dir = tmp_path / "mychart"
        write(chart_dir / "Chart.yaml", "apiVersion: v2\nname: mychart\nversion: 0.1.0\n")
        write(chart_dir / "templates" / "route.yaml", BAD_ROUTE)
        findings = HelmChecker().check_chart(chart_dir)
        assert any(f.check_id == "OCP001" for f in findings)

    def test_openshift_path_scans_raw_manifests_end_to_end(self, tmp_path):
        manifests_dir = tmp_path / "manifests"
        write(manifests_dir / "scc.yaml", BAD_SCC)
        write(manifests_dir / "vm.yaml", BAD_VM)
        findings = run_checks(ansible_path=None, helm_path=None, openshift_path=str(manifests_dir))
        ids = {f.check_id for f in findings}
        assert "OCP003" in ids
        assert "OCP008" in ids

    def test_main_gates_pipeline_on_critical_scc_finding(self, tmp_path):
        manifests_dir = tmp_path / "manifests"
        write(manifests_dir / "scc.yaml", BAD_SCC)
        exit_code = main(["--openshift-path", str(manifests_dir), "--fail-on", "critical"])
        assert exit_code == 1

    def test_main_exits_zero_for_clean_openshift_manifests(self, tmp_path):
        manifests_dir = tmp_path / "manifests"
        write(manifests_dir / "route.yaml", GOOD_ROUTE)
        write(manifests_dir / "scc.yaml", GOOD_SCC)
        write(manifests_dir / "vm.yaml", GOOD_VM)
        exit_code = main(["--openshift-path", str(manifests_dir), "--fail-on", "low"])
        assert exit_code == 0


# --------------------------------------------------------------------------- #
# File / chart discovery tests
# --------------------------------------------------------------------------- #

class TestDiscovery:
    def test_collect_ansible_files_ignores_helm_templates_dir(self, tmp_path):
        write(tmp_path / "site.yml", CLEAN_PLAYBOOK)
        write(tmp_path / "templates" / "deployment.yaml", GOOD_HELM_TEMPLATE)
        files = collect_ansible_files(tmp_path)
        assert (tmp_path / "site.yml") in files
        assert all("templates" not in f.parts for f in files)

    def test_collect_ansible_files_single_file(self, clean_ansible_file):
        files = collect_ansible_files(clean_ansible_file)
        assert files == [clean_ansible_file]

    def test_collect_helm_chart_dirs_finds_nested_charts(self, tmp_path):
        chart1 = tmp_path / "charts" / "a"
        chart2 = tmp_path / "charts" / "b"
        write(chart1 / "Chart.yaml", "name: a\n")
        write(chart2 / "Chart.yaml", "name: b\n")
        dirs = collect_helm_chart_dirs(tmp_path / "charts")
        assert set(dirs) == {chart1, chart2}

    def test_collect_helm_chart_dirs_root_is_chart(self, good_helm_chart):
        dirs = collect_helm_chart_dirs(good_helm_chart)
        assert dirs == [good_helm_chart]

    def test_collect_openshift_files_finds_all_yaml(self, tmp_path):
        manifests_dir = tmp_path / "manifests"
        write(manifests_dir / "route.yaml", GOOD_ROUTE)
        write(manifests_dir / "scc.yml", GOOD_SCC)
        files = collect_openshift_files(manifests_dir)
        assert len(files) == 2

    def test_collect_openshift_files_single_file(self, tmp_path):
        f = write(tmp_path / "vm.yaml", GOOD_VM)
        assert collect_openshift_files(f) == [f]


# --------------------------------------------------------------------------- #
# End-to-end run_checks / CLI tests
# --------------------------------------------------------------------------- #

class TestRunChecksAndCli:
    def test_run_checks_combines_ansible_and_helm(self, bad_ansible_file, bad_helm_chart):
        findings = run_checks(str(bad_ansible_file), str(bad_helm_chart))
        sources = {f.check_id[:3] for f in findings}
        assert "ANS" in sources
        assert "HLM" in sources

    def test_main_exits_zero_for_clean_inputs(self, clean_ansible_file, good_helm_chart):
        exit_code = main([
            "--ansible-path", str(clean_ansible_file),
            "--helm-path", str(good_helm_chart),
            "--fail-on", "high",
        ])
        assert exit_code == 0

    def test_main_exits_nonzero_for_bad_inputs_default_threshold(self, bad_ansible_file, bad_helm_chart):
        exit_code = main([
            "--ansible-path", str(bad_ansible_file),
            "--helm-path", str(bad_helm_chart),
        ])
        assert exit_code == 1

    def test_main_fail_on_critical_ignores_medium_findings(self, tmp_path):
        # Chart with only a medium-severity finding (missing resource limits)
        chart_dir = tmp_path / "mychart"
        write(chart_dir / "Chart.yaml", "name: mychart\n")
        write(chart_dir / "values.yaml", "image:\n  tag: 1.0.0\n")
        write(
            chart_dir / "templates" / "deployment.yaml",
            """
apiVersion: apps/v1
kind: Deployment
spec:
  containers:
    - name: myapp
      image: myregistry/myapp:1.0.0
      securityContext:
        runAsNonRoot: true
        allowPrivilegeEscalation: false
      livenessProbe:
        httpGet:
          path: /healthz
      readinessProbe:
        httpGet:
          path: /ready
""",
        )
        exit_code = main(["--helm-path", str(chart_dir), "--fail-on", "critical"])
        assert exit_code == 0

    def test_main_errors_without_any_path(self):
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code == 2

    def test_main_writes_json_report_to_file(self, bad_ansible_file, tmp_path):
        out_file = tmp_path / "report.json"
        main([
            "--ansible-path", str(bad_ansible_file),
            "--format", "json",
            "-o", str(out_file),
            "--fail-on", "critical",
        ])
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        assert any(item["check_id"] == "ANS001" for item in data)

    def test_cli_invocation_as_subprocess(self, bad_ansible_file):
        result = subprocess.run(
            [sys.executable, "bio_pipeline_check.py",
             "--ansible-path", str(bad_ansible_file),
             "--format", "json", "--fail-on", "critical"],
            cwd=Path(__file__).parent,
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        data = json.loads(result.stdout)
        assert any(item["check_id"] == "ANS001" for item in data)
