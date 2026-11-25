"""Edge cases for bio_pipeline_check.py: custom YAML tags, unparsable files,
odd document shapes, and how a play-level `become` is reported."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from bio_pipeline_check import AnsibleChecker, HelmChecker, TolerantSafeLoader


def write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def ids(findings):
    return sorted(f.check_id for f in findings)


@pytest.mark.parametrize("text,expected", [
    ("pw: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6162\n", {"pw": "$ANSIBLE_VAULT;1.1;AES256\n6162\n"}),
    ("x: !reference [.base, script]\n", {"x": [".base", "script"]}),
    ("x: !include {file: a.yml}\n", {"x": {"file": "a.yml"}}),
])
def test_unknown_tags_load_as_plain_data(text, expected):
    assert yaml.load(text, Loader=TolerantSafeLoader) == expected


def test_vaulted_secret_is_not_reported(tmp_path):
    p = write(tmp_path, "group_vars/all.yml",
              "- hosts: all\n  vars:\n    db_password: !vault |\n      $ANSIBLE_VAULT;1.1;AES256\n      61626364\n")
    assert "ANS001" not in ids(AnsibleChecker().check_file(p))


def test_unparsable_ansible_yaml_is_a_low_finding(tmp_path):
    p = write(tmp_path, "site.yml", "- hosts: all\n  tasks: [unclosed\n")
    findings = AnsibleChecker().check_file(p)
    assert ids(findings) == ["ANS000"]
    assert "Could not parse YAML" in findings[0].message


@pytest.mark.parametrize("text", [
    "---\n...\n",                       # empty document
    "- just a string\n- 42\n",          # list items that are not dicts
    "vars: not-a-dict\n",               # vars that are not a mapping
    "- hosts: all\n  tasks:\n    - plain string task\n",
])
def test_odd_shapes_do_not_crash(tmp_path, text):
    assert AnsibleChecker().check_file(write(tmp_path, "x.yml", text)) == []


def test_multi_document_files_are_all_checked(tmp_path):
    p = write(tmp_path, "x.yml", "vars:\n  api_token: abc123\n---\nvars:\n  root_password: s3cret\n")
    assert ids(AnsibleChecker().check_file(p)) == ["ANS001", "ANS001"]


def test_play_level_become_is_reported_like_a_task(tmp_path):
    # A named play also matches the task heuristic, so play-level `become`
    # without `become_user` is flagged (it does escalate to root), worded as a task.
    p = write(tmp_path, "site.yml",
              "- name: Web\n  hosts: web\n  become: true\n  tasks:\n    - name: ping\n      ansible.builtin.ping:\n")
    findings = AnsibleChecker().check_file(p)
    assert ids(findings) == ["ANS004"]
    assert "'Web'" in findings[0].message


def test_unparsable_values_yaml_is_a_low_finding(tmp_path):
    chart = tmp_path / "chart"
    write(chart, "Chart.yaml", "apiVersion: v2\nname: c\nversion: 0.1.0\n")
    write(chart, "values.yaml", "image: {repository: [\n")
    findings = HelmChecker().check_chart(chart)
    assert "HLM000" in ids(findings)
