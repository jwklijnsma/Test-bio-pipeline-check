# CI/CD examples

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
